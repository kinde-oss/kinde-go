//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"os"
	"regexp"
)

// This tool patches the generated oas_json_gen.go file to stop ambiguous oneOf
// decoding from silently defaulting to variant 0. ogen currently falls back to
// the first variant when no discriminator key matches, which can misroute a
// payload (e.g. decode a SAML/enterprise connection config as a plain OAuth
// one) once sibling variants share field names. This makes it fail closed.
// See: https://github.com/ogen-go/ogen/issues/XXX

const targetFile = "oas_json_gen.go"

// Matches the generated "if !found { s.Type = <value> }" fallback. <value> is
// checked separately for the "X0X" sum-type-variant-0 shape (Go's regexp
// package has no backreferences), e.g.
// CreateConnectionReqOptions0CreateConnectionReqOptions.
var fallbackPattern = regexp.MustCompile(`if !found \{\n\t\ts\.Type = (\w+)\n\t\}`)

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

	if patched == 0 {
		fmt.Println("No ambiguous oneOf fallback found - either already patched or ogen version changed")
		fmt.Println("Please verify the generated code manually")
		os.Exit(0)
	}

	if err := os.WriteFile(targetFile, newContent, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing patched file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ Patched %d ambiguous oneOf fallback(s) to fail closed\n", patched)
	fmt.Println("Note: This is a temporary fix until ogen/the spec addresses this upstream")
}
