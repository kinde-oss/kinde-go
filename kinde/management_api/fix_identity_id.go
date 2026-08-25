//go:build ignore
// +build ignore

package main

import (
	"bytes"
	"fmt"
	"os"
)

// This tool patches the generated CreateIdentityResponseIdentity type to also
// accept "identity_id". The Kinde API returns "id" when creating a new
// identity but returns "identity_id" instead when the identity already
// exists on an enterprise connection. The published OpenAPI spec only
// documents "id", so ogen never generates the "identity_id" field on its own.
// See EffectiveIdentityID() in create_identity_response_helpers.go for the
// helper that reads whichever field is populated.

const (
	schemasFile = "oas_schemas_gen.go"
	jsonFile    = "oas_json_gen.go"
)

var (
	oldSchema = `type CreateIdentityResponseIdentity struct {
	// The identity's ID.
	ID OptString ` + "`json:\"id\"`" + `
}

// GetID returns the value of ID.
func (s *CreateIdentityResponseIdentity) GetID() OptString {
	return s.ID
}

// SetID sets the value of ID.
func (s *CreateIdentityResponseIdentity) SetID(val OptString) {
	s.ID = val
}`

	newSchema = `type CreateIdentityResponseIdentity struct {
	// The identity's ID.
	ID OptString ` + "`json:\"id\"`" + `
	// The identity's ID, returned instead of "id" when the identity already
	// exists on an enterprise connection.
	IdentityID OptString ` + "`json:\"identity_id\"`" + `
}

// GetID returns the value of ID.
func (s *CreateIdentityResponseIdentity) GetID() OptString {
	return s.ID
}

// GetIdentityID returns the value of IdentityID.
func (s *CreateIdentityResponseIdentity) GetIdentityID() OptString {
	return s.IdentityID
}

// SetID sets the value of ID.
func (s *CreateIdentityResponseIdentity) SetID(val OptString) {
	s.ID = val
}

// SetIdentityID sets the value of IdentityID.
func (s *CreateIdentityResponseIdentity) SetIdentityID(val OptString) {
	s.IdentityID = val
}`

	oldJSON = `func (s *CreateIdentityResponseIdentity) encodeFields(e *jx.Encoder) {
	{
		if s.ID.Set {
			e.FieldStart("id")
			s.ID.Encode(e)
		}
	}
}

var jsonFieldsNameOfCreateIdentityResponseIdentity = [1]string{
	0: "id",
}`

	newJSON = `func (s *CreateIdentityResponseIdentity) encodeFields(e *jx.Encoder) {
	{
		if s.ID.Set {
			e.FieldStart("id")
			s.ID.Encode(e)
		}
	}
	{
		if s.IdentityID.Set {
			e.FieldStart("identity_id")
			s.IdentityID.Encode(e)
		}
	}
}

var jsonFieldsNameOfCreateIdentityResponseIdentity = [2]string{
	0: "id",
	1: "identity_id",
}`

	oldDecode = `		case "id":
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
	}`

	newDecode = `		case "id":
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
			if err := func() error {
				s.IdentityID.Reset()
				if err := s.IdentityID.Decode(d); err != nil {
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
	}`
)

func patch(file string, replacements [][2]string) error {
	content, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("reading %s: %w", file, err)
	}

	newContent := content
	for _, r := range replacements {
		old, want := r[0], r[1]
		if bytes.Contains(newContent, []byte(want)) {
			// Already patched.
			continue
		}
		if !bytes.Contains(newContent, []byte(old)) {
			return fmt.Errorf("%s: expected pattern not found - the generated shape has likely changed (ogen upgrade?), update fix_identity_id.go:\n%s", file, old)
		}
		newContent = bytes.Replace(newContent, []byte(old), []byte(want), 1)
	}

	if bytes.Equal(content, newContent) {
		fmt.Printf("%s already patched, skipping\n", file)
		return nil
	}

	if err := os.WriteFile(file, newContent, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", file, err)
	}
	fmt.Printf("✅ Patched %s for CreateIdentityResponseIdentity.identity_id\n", file)
	return nil
}

func main() {
	if err := patch(schemasFile, [][2]string{{oldSchema, newSchema}}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := patch(jsonFile, [][2]string{{oldJSON, newJSON}, {oldDecode, newDecode}}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
