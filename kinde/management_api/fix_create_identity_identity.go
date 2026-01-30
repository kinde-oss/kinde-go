//go:build ignore
// +build ignore

package main

import (
	"bytes"
	"fmt"
	"os"
)

// This tool patches the generated oas_json_gen.go so that CreateIdentityResponseIdentity.Decode()
// accepts the "identity_id" field returned by the Kinde API (e.g. when creating identity with
// existing enterprise identity). The OpenAPI schema uses "id" but the API may return "identity_id".

const (
	targetFile = "oas_json_gen.go"
)

// Exact block that appears only in CreateIdentityResponseIdentity.Decode (full ObjBytes callback
// including the unique wrap "decode CreateIdentityResponseIdentity" so we match exactly once).
var oldBlock = []byte(`	if err := d.ObjBytes(func(d *jx.Decoder, k []byte) error {
		switch string(k) {
		case "id":
			if err := func() error {
				s.ID.Reset()
				if err := s.ID.Decode(d); err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"id\"")
			}
		default:
			return d.Skip()
		}
		return nil
	}); err != nil {
		return errors.Wrap(err, "decode CreateIdentityResponseIdentity")
	}`)

// Same block with identity_id case inserted before default.
var newBlock = []byte(`	if err := d.ObjBytes(func(d *jx.Decoder, k []byte) error {
		switch string(k) {
		case "id":
			if err := func() error {
				s.ID.Reset()
				if err := s.ID.Decode(d); err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"id\"")
			}
		case "identity_id":
			// API returns identity_id (e.g. for existing enterprise identity); map to ID for compatibility.
			if err := func() error {
				s.ID.Reset()
				if err := s.ID.Decode(d); err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"identity_id\"")
			}
		default:
			return d.Skip()
		}
		return nil
	}); err != nil {
		return errors.Wrap(err, "decode CreateIdentityResponseIdentity")
	}`)

func main() {
	fmt.Printf("Patching %s for CreateIdentityResponseIdentity identity_id...\n", targetFile)

	content, err := os.ReadFile(targetFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	// Only replace the first occurrence (CreateIdentityResponseIdentity is the only decoder with this exact block).
	if bytes.Contains(content, []byte("case \"identity_id\":\n\t\t\t// API returns identity_id")) {
		fmt.Println("Already patched - identity_id case present")
		os.Exit(0)
	}

	count := bytes.Count(content, oldBlock)
	if count == 0 {
		fmt.Println("Pattern not found - generator output may have changed")
		fmt.Println("Please verify CreateIdentityResponseIdentity.Decode manually")
		os.Exit(1)
	}
	if count > 1 {
		fmt.Fprintf(os.Stderr, "Pattern matched %d times; expected 1 (CreateIdentityResponseIdentity). Refusing to patch.\n", count)
		os.Exit(1)
	}

	newContent := bytes.Replace(content, oldBlock, newBlock, 1)
	if bytes.Equal(content, newContent) {
		fmt.Println("No changes made")
		os.Exit(0)
	}

	if err := os.WriteFile(targetFile, newContent, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing file: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Successfully patched CreateIdentityResponseIdentity.Decode() for identity_id")
}
