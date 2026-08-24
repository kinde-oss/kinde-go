//go:build ignore
// +build ignore

package main

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// This tool patches the generated oas_json_gen.go file to stop ambiguous oneOf
// decoding from silently defaulting to variant 0. When one oneOf variant has
// no fields unique to it, ogen makes it the sum type's default mapping and
// falls back to it whenever no discriminating key matches, which can misroute
// a payload (e.g. decode a SAML/enterprise connection config as a plain OAuth
// one) once sibling variants share field names. This makes it fail closed.

const targetFile = "oas_json_gen.go"

// Matches the generated "if !found { s.Type = <value> }" fallback. <value> is
// checked separately for the "X0X" sum-type-variant-0 shape (Go's regexp
// package has no backreferences), e.g.
// CreateConnectionReqOptions0CreateConnectionReqOptions.
var fallbackPattern = regexp.MustCompile(`if !found \{\n\t\ts\.Type = (\w+)\n\t\}`)

// remainingFallbackPattern is a looser tripwire: any `if !found` block that
// still assigns s.Type before its closing brace. If it matches after the
// patch pass, the generated shape has drifted past fallbackPattern (or a sum
// type gained a non-variant-0 default) and the generate run must fail rather
// than ship the silent-default behaviour.
var remainingFallbackPattern = regexp.MustCompile(`if !found \{[^}]*s\.Type\s*=`)

// isVariant0Assignment reports whether value has the "X0X" shape ogen uses
// for a sum type's zero-variant constant.
func isVariant0Assignment(value string) bool {
	n := len(value)
	if n < 3 || n%2 == 0 {
		return false
	}
	half := (n - 1) / 2
	return value[half] == '0' && value[:half] == value[half+1:]
}

func main() {
	fmt.Printf("Patching %s for ambiguous oneOf handling...\n", targetFile)

	content, err := os.ReadFile(targetFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	patched := 0
	newContent := fallbackPattern.ReplaceAllFunc(content, func(match []byte) []byte {
		sub := fallbackPattern.FindSubmatch(match)
		if sub == nil || !isVariant0Assignment(string(sub[1])) {
			return match
		}
		patched++
		return []byte(`if !found {
		return errors.New("unable to detect sum type variant")
	}`)
	})

	if patched > 0 {
		if err := os.WriteFile(targetFile, newContent, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing patched file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Patched %d ambiguous oneOf fallback(s) to fail closed\n", patched)
	}

	if locs := remainingFallbackPattern.FindAllIndex(newContent, -1); len(locs) > 0 {
		fmt.Fprintf(os.Stderr, "Error: %d oneOf fallback(s) still assign s.Type after patching:\n", len(locs))
		for _, loc := range locs {
			line := 1 + bytes.Count(newContent[:loc[0]], []byte("\n"))
			snippet := strings.Join(strings.Fields(string(newContent[loc[0]:loc[1]])), " ")
			fmt.Fprintf(os.Stderr, "  %s:%d: %s\n", targetFile, line, snippet)
		}
		fmt.Fprintln(os.Stderr, "The generated shape has likely changed (ogen upgrade?) - update fix_oneof.go")
		os.Exit(1)
	}

	if patched == 0 {
		fmt.Println("No ambiguous oneOf fallback found - already patched or no longer generated")
	}
}
