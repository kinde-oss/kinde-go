package jwt

import (
	"fmt"
	"slices"
	"strings"
	"time"

	golangjwt "github.com/golang-jwt/jwt/v5"
)

const (
	// AcrMFA is the authentication context for a second factor.
	AcrMFA = "mfa"
	// AcrPHR is the phishing-resistant authentication context (a passkey with
	// the user verified by the device). It also meets an AcrMFA requirement.
	AcrPHR = "phr"

	// authTimeFutureSkew is how far ahead of the local clock an auth_time may
	// be before it is treated as invalid rather than as clock skew.
	authTimeFutureSkew = 60 * time.Second
)

// acrRank orders the authentication contexts: none < mfa < phr.
var acrRank = map[string]int{
	AcrMFA: 1,
	AcrPHR: 2,
}

type (
	// AuthenticationContext describes how and when the user last authenticated
	// (RFC 9470), as read from the acr, amr and auth_time claims.
	AuthenticationContext struct {
		// Acr is the authentication context that was met: AcrMFA or AcrPHR.
		// Empty for a single-factor sign-in, where Kinde omits the claim.
		Acr string
		// Amr lists the authentication methods used. Empty (never nil) when
		// the claim is absent. Informational only: never decide access on it.
		Amr []string
		// AuthTime is when the user last actively authenticated. The zero
		// time (AuthTime.IsZero()) means the claim is absent.
		AuthTime time.Time
	}

	// AuthenticationRequirement is the authentication context an operation
	// needs. The zero value requires nothing.
	AuthenticationRequirement struct {
		// Acr is the required context: AcrMFA, AcrPHR, or empty for none.
		Acr string
		// MaxAge is the maximum age, in seconds, of the user's last
		// authentication. nil means no recency requirement; 0 is valid.
		// Example: MaxAge: new(300).
		MaxAge *int
	}
)

// Validate reports whether the requirement can be checked and requested:
// Acr must be empty, AcrMFA or AcrPHR, and MaxAge must not be negative.
func (r AuthenticationRequirement) Validate() error {
	if r.Acr != "" {
		if _, ok := acrRank[normalizeAcr(r.Acr)]; !ok {
			return fmt.Errorf("unsupported acr %q: expected %q or %q", r.Acr, AcrMFA, AcrPHR)
		}
	}
	if r.MaxAge != nil && *r.MaxAge < 0 {
		return fmt.Errorf("invalid max age %d: expected a non-negative number of seconds", *r.MaxAge)
	}
	return nil
}

// HasAuthenticationContext reports whether an authentication context meets a
// requirement at the given time.
//
// An absent Acr is the baseline and meets no Acr requirement, AcrPHR meets an
// AcrMFA requirement, and a missing AuthTime never meets a MaxAge requirement.
// Amr is not consulted. An invalid requirement is never met.
//
// Only pass a context read from a verified token.
func HasAuthenticationContext(authContext AuthenticationContext, requirement AuthenticationRequirement, now time.Time) bool {
	if requirement.Validate() != nil {
		return false
	}
	if requirement.Acr != "" && acrRank[normalizeAcr(authContext.Acr)] < acrRank[normalizeAcr(requirement.Acr)] {
		return false
	}
	if requirement.MaxAge != nil {
		if authContext.AuthTime.IsZero() {
			return false
		}
		age := now.Unix() - authContext.AuthTime.Unix()
		if age > int64(*requirement.MaxAge) || age < -int64(authTimeFutureSkew/time.Second) {
			return false
		}
	}
	return true
}

// GetAuthenticationContext returns the acr, amr and auth_time claims of the token.
//
// Only verified claims are read. A token that failed validation (IsValid is
// false) has no authentication context: the result is empty.
//
// acr and amr are read from the access token. auth_time is read from the ID
// token when there is one, because Kinde only adds it to the access token when
// it can establish it. The ID token is verified first, with the same key
// function and parser options as the access token, and must be unexpired and
// issued by the same issuer, for the same user, to the same client: its azp
// (or, without one, its aud) must name the access token's azp. Otherwise it is
// ignored and auth_time is read from the access token.
//
// The claims are returned as they are. On a Kinde environment that does not
// advertise acr_values_supported, auth_time can be the time the token was
// issued, so do not use it for recency there.
func (j *Token) GetAuthenticationContext() AuthenticationContext {
	authContext := AuthenticationContext{Amr: []string{}}
	if !j.isValid {
		return authContext
	}

	accessClaims := j.GetClaims()
	if acr, ok := accessClaims["acr"].(string); ok {
		authContext.Acr = acr
	}
	if amr := extractStringArray(accessClaims["amr"]); len(amr) > 0 {
		authContext.Amr = amr
	}

	for _, claims := range []map[string]any{j.verifiedIDTokenClaims(), accessClaims} {
		if authTime, ok := numericDate(claims["auth_time"]); ok {
			authContext.AuthTime = authTime
			break
		}
	}

	return authContext
}

// HasAuthenticationContext reports whether the token meets the requirement now.
// A token that failed validation never does. See the package-level
// HasAuthenticationContext for the rules.
func (j *Token) HasAuthenticationContext(requirement AuthenticationRequirement) bool {
	if !j.isValid {
		return false
	}
	return HasAuthenticationContext(j.GetAuthenticationContext(), requirement, time.Now())
}

// verifiedIDTokenClaims returns the claims of the ID token, or nil when there
// is none or it cannot be tied to the verified access token: its signature and
// expiry are checked like the access token's, and its issuer, subject and
// client must match the access token's issuer, subject and authorized party.
func (j *Token) verifiedIDTokenClaims() map[string]any {
	idToken, ok := j.GetIdToken()
	if !ok || idToken == "" || j.processing.keyFunc == nil {
		return nil
	}
	parsed, err := golangjwt.Parse(idToken, j.processing.keyFunc, j.processing.parsingOptions...)
	if err != nil || !parsed.Valid {
		return nil
	}
	claims, ok := parsed.Claims.(golangjwt.MapClaims)
	if !ok {
		return nil
	}

	if subject, _ := claims.GetSubject(); subject == "" || subject != j.GetSubject() {
		return nil
	}
	if issuer, _ := claims.GetIssuer(); issuer == "" || issuer != j.GetIssuer() {
		return nil
	}
	// Kinde names the client in azp on both tokens (the ID token's aud is the
	// Kinde domain). An ID token that names it in aud, as OpenID Connect
	// describes, is accepted as well.
	client := j.GetAuthorizedParty()
	if client == "" {
		return nil
	}
	if authorizedParty, _ := claims["azp"].(string); authorizedParty != client {
		if audience, _ := claims.GetAudience(); authorizedParty != "" || !slices.Contains(audience, client) {
			return nil
		}
	}
	return claims
}

func normalizeAcr(acr string) string {
	return strings.ToLower(strings.TrimSpace(acr))
}

// numericDate converts a JSON numeric date claim (seconds since the epoch) to a time.
func numericDate(value any) (time.Time, bool) {
	var seconds int64
	switch v := value.(type) {
	case float64:
		seconds = int64(v)
	case int64:
		seconds = v
	case int:
		seconds = int64(v)
	default:
		return time.Time{}, false
	}
	if seconds <= 0 {
		return time.Time{}, false
	}
	return time.Unix(seconds, 0), true
}
