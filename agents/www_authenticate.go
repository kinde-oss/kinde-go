package agents

import "strings"

// challenge is one parsed WWW-Authenticate challenge.
type challenge struct {
	scheme string            // lower-cased
	params map[string]string // lower-cased names, unquoted values
}

// buildBearerChallenge formats an RFC 6750 Bearer challenge. Empty values are skipped.
func buildBearerChallenge(params ...[2]string) string {
	var b strings.Builder
	b.WriteString("Bearer")
	first := true
	for _, p := range params {
		if p[1] == "" {
			continue
		}
		if first {
			b.WriteString(" ")
			first = false
		} else {
			b.WriteString(", ")
		}
		b.WriteString(p[0])
		b.WriteString(`="`)
		b.WriteString(strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(p[1]))
		b.WriteString(`"`)
	}
	return b.String()
}

// parseChallenges parses every challenge in the given WWW-Authenticate header values.
// It handles several challenges per header, quoted strings with escapes, commas inside
// quotes, and case-insensitive scheme and parameter names.
func parseChallenges(headers []string) []challenge {
	var result []challenge
	for _, h := range headers {
		p := &challengeParser{s: h}
		for p.i < len(p.s) {
			p.skip(" \t,")
			scheme := p.token()
			if scheme == "" {
				// Skip a stray '=' or '"' (e.g. from a token68) and keep going.
				if p.i < len(p.s) {
					p.i++
				}
				continue
			}
			c := challenge{scheme: strings.ToLower(scheme), params: map[string]string{}}
			for {
				p.skip(" \t")
				start := p.i
				name := p.token()
				p.skip(" \t")
				if name == "" || !p.consume('=') {
					// Not a parameter: the start of the next challenge (or a token68).
					p.i = start
					break
				}
				p.skip(" \t")
				c.params[strings.ToLower(name)] = p.value()
				p.skip(" \t")
				if !p.consume(',') {
					break
				}
			}
			result = append(result, c)
		}
	}
	return result
}

// bearerParam returns a parameter of the first Bearer challenge in headers.
func bearerParam(headers []string, name string) string {
	for _, c := range parseChallenges(headers) {
		if c.scheme == "bearer" {
			return c.params[name]
		}
	}
	return ""
}

type challengeParser struct {
	s string
	i int
}

func (p *challengeParser) skip(chars string) {
	for p.i < len(p.s) && strings.IndexByte(chars, p.s[p.i]) >= 0 {
		p.i++
	}
}

func (p *challengeParser) consume(c byte) bool {
	if p.i < len(p.s) && p.s[p.i] == c {
		p.i++
		return true
	}
	return false
}

func (p *challengeParser) token() string {
	start := p.i
	for p.i < len(p.s) && strings.IndexByte(" \t,=\"", p.s[p.i]) < 0 {
		p.i++
	}
	return p.s[start:p.i]
}

func (p *challengeParser) value() string {
	if !p.consume('"') {
		return p.token()
	}
	var b strings.Builder
	for p.i < len(p.s) {
		c := p.s[p.i]
		p.i++
		switch {
		case c == '\\' && p.i < len(p.s):
			b.WriteByte(p.s[p.i])
			p.i++
		case c == '"':
			return b.String()
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
