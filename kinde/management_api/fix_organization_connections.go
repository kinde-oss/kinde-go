//go:build ignore
// +build ignore

package main

import (
	"bytes"
	"fmt"
	"os"
)

// This tool patches GetConnectionsResponse.Connections to decode as
// []ConnectionConnection instead of []Connection. The published OpenAPI spec
// defines get_connections_response.connections items as a $ref to the
// "connection" schema, which is really the envelope for a single-connection
// endpoint response ({code, message, connection: {...}}). In practice the
// Kinde API returns plain connection objects (id, name, display_name,
// strategy) directly in that array, so decoding each element as the envelope
// type left every field empty.

const (
	schemasFile = "oas_schemas_gen.go"
	jsonFile    = "oas_json_gen.go"
)

var (
	oldSchema = `	Connections []Connection ` + "`json:\"connections\"`" + `
	// Whether more records exist.
	HasMore OptBool ` + "`json:\"has_more\"`" + `
}

// GetCode returns the value of Code.
func (s *GetConnectionsResponse) GetCode() OptString {
	return s.Code
}

// GetMessage returns the value of Message.
func (s *GetConnectionsResponse) GetMessage() OptString {
	return s.Message
}

// GetConnections returns the value of Connections.
func (s *GetConnectionsResponse) GetConnections() []Connection {
	return s.Connections
}`

	newSchema = `	Connections []ConnectionConnection ` + "`json:\"connections\"`" + `
	// Whether more records exist.
	HasMore OptBool ` + "`json:\"has_more\"`" + `
}

// GetCode returns the value of Code.
func (s *GetConnectionsResponse) GetCode() OptString {
	return s.Code
}

// GetMessage returns the value of Message.
func (s *GetConnectionsResponse) GetMessage() OptString {
	return s.Message
}

// GetConnections returns the value of Connections.
func (s *GetConnectionsResponse) GetConnections() []ConnectionConnection {
	return s.Connections
}`

	oldSetter = `// SetConnections sets the value of Connections.
func (s *GetConnectionsResponse) SetConnections(val []Connection) {
	s.Connections = val
}`

	newSetter = `// SetConnections sets the value of Connections.
func (s *GetConnectionsResponse) SetConnections(val []ConnectionConnection) {
	s.Connections = val
}`

	oldDecode = `		case "connections":
			if err := func() error {
				s.Connections = make([]Connection, 0)
				if err := d.Arr(func(d *jx.Decoder) error {
					var elem Connection
					if err := elem.Decode(d); err != nil {
						return err
					}
					s.Connections = append(s.Connections, elem)
					return nil
				}); err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"connections\"")
			}`

	newDecode = `		case "connections":
			if err := func() error {
				s.Connections = make([]ConnectionConnection, 0)
				if err := d.Arr(func(d *jx.Decoder) error {
					var elem ConnectionConnection
					if err := elem.Decode(d); err != nil {
						return err
					}
					s.Connections = append(s.Connections, elem)
					return nil
				}); err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return errors.Wrap(err, "decode field \"connections\"")
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
			return fmt.Errorf("%s: expected pattern not found - the generated shape has likely changed (ogen upgrade?), update fix_organization_connections.go:\n%s", file, old)
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
	fmt.Printf("✅ Patched %s for GetConnectionsResponse.Connections\n", file)
	return nil
}

func main() {
	if err := patch(schemasFile, [][2]string{{oldSchema, newSchema}, {oldSetter, newSetter}}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := patch(jsonFile, [][2]string{{oldDecode, newDecode}}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
