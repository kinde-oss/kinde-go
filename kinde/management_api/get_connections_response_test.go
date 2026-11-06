package management_api

import (
	"testing"

	"github.com/go-faster/jx"
)

func TestGetConnectionsResponse_Decode_WithConnectionObjects(t *testing.T) {
	// This test verifies that GetConnectionsResponse correctly decodes
	// connection objects directly (ConnectionConnection) rather than
	// wrapped Connection objects
	json := `{
		"code": "OK",
		"message": "Success",
		"connections": [
			{
				"id": "conn_123",
				"name": "saml",
				"display_name": "SAML Connection",
				"strategy": "saml"
			},
			{
				"id": "conn_456",
				"name": "oauth",
				"display_name": "OAuth Connection",
				"strategy": "oauth"
			}
		],
		"has_more": false
	}`

	d := jx.DecodeBytes([]byte(json))
	var response GetConnectionsResponse

	err := response.Decode(d)

	if err != nil {
		t.Fatalf("GetConnectionsResponse.Decode() unexpected error = %v", err)
	}

	// Verify the response was decoded correctly
	if len(response.Connections) != 2 {
		t.Fatalf("Expected 2 connections, got %d", len(response.Connections))
	}

	// Verify first connection
	conn1 := response.Connections[0]
	if id, ok := conn1.ID.Get(); !ok || id != "conn_123" {
		t.Errorf("Connection 1 ID: expected 'conn_123', got ok=%v, value=%v", ok, id)
	}
	if name, ok := conn1.Name.Get(); !ok || name != "saml" {
		t.Errorf("Connection 1 Name: expected 'saml', got ok=%v, value=%v", ok, name)
	}
	if displayName, ok := conn1.DisplayName.Get(); !ok || displayName != "SAML Connection" {
		t.Errorf("Connection 1 DisplayName: expected 'SAML Connection', got ok=%v, value=%v", ok, displayName)
	}
	if strategy, ok := conn1.Strategy.Get(); !ok || strategy != "saml" {
		t.Errorf("Connection 1 Strategy: expected 'saml', got ok=%v, value=%v", ok, strategy)
	}

	// Verify second connection
	conn2 := response.Connections[1]
	if id, ok := conn2.ID.Get(); !ok || id != "conn_456" {
		t.Errorf("Connection 2 ID: expected 'conn_456', got ok=%v, value=%v", ok, id)
	}
	if name, ok := conn2.Name.Get(); !ok || name != "oauth" {
		t.Errorf("Connection 2 Name: expected 'oauth', got ok=%v, value=%v", ok, name)
	}
	if displayName, ok := conn2.DisplayName.Get(); !ok || displayName != "OAuth Connection" {
		t.Errorf("Connection 2 DisplayName: expected 'OAuth Connection', got ok=%v, value=%v", ok, displayName)
	}
	if strategy, ok := conn2.Strategy.Get(); !ok || strategy != "oauth" {
		t.Errorf("Connection 2 Strategy: expected 'oauth', got ok=%v, value=%v", ok, strategy)
	}

	// Verify response metadata
	if code, ok := response.Code.Get(); !ok || code != "OK" {
		t.Errorf("Code: expected 'OK', got ok=%v, value=%v", ok, code)
	}
	if message, ok := response.Message.Get(); !ok || message != "Success" {
		t.Errorf("Message: expected 'Success', got ok=%v, value=%v", ok, message)
	}
	if hasMore, ok := response.HasMore.Get(); !ok || hasMore != false {
		t.Errorf("HasMore: expected false, got ok=%v, value=%v", ok, hasMore)
	}
}

func TestGetConnectionsResponse_Decode_WithEmptyConnections(t *testing.T) {
	// Test with empty connections array
	json := `{
		"code": "OK",
		"message": "No connections found",
		"connections": [],
		"has_more": false
	}`

	d := jx.DecodeBytes([]byte(json))
	var response GetConnectionsResponse

	err := response.Decode(d)

	if err != nil {
		t.Fatalf("GetConnectionsResponse.Decode() unexpected error = %v", err)
	}

	if len(response.Connections) != 0 {
		t.Errorf("Expected 0 connections, got %d", len(response.Connections))
	}
}

func TestGetConnectionsResponse_Decode_WithOptionalFields(t *testing.T) {
	// Test with some optional fields missing
	json := `{
		"code": "OK",
		"connections": [
			{
				"id": "conn_789",
				"name": "google",
				"strategy": "google"
			}
		]
	}`

	d := jx.DecodeBytes([]byte(json))
	var response GetConnectionsResponse

	err := response.Decode(d)

	if err != nil {
		t.Fatalf("GetConnectionsResponse.Decode() unexpected error = %v", err)
	}

	if len(response.Connections) != 1 {
		t.Fatalf("Expected 1 connection, got %d", len(response.Connections))
	}

	conn := response.Connections[0]
	if id, ok := conn.ID.Get(); !ok || id != "conn_789" {
		t.Errorf("Connection ID: expected 'conn_789', got ok=%v, value=%v", ok, id)
	}
	if name, ok := conn.Name.Get(); !ok || name != "google" {
		t.Errorf("Connection Name: expected 'google', got ok=%v, value=%v", ok, name)
	}
	// display_name is optional and not provided, so it should be unset
	if conn.DisplayName.IsSet() {
		t.Error("DisplayName should not be set when not provided in JSON")
	}
	if strategy, ok := conn.Strategy.Get(); !ok || strategy != "google" {
		t.Errorf("Connection Strategy: expected 'google', got ok=%v, value=%v", ok, strategy)
	}
}

func TestConnectionConnection_Decode(t *testing.T) {
	tests := []struct {
		name      string
		json      string
		wantErr   bool
		wantID    string
		wantName  string
		wantDisp  string
		wantStrat string
	}{
		{
			name:      "full connection object",
			json:      `{"id": "conn_1", "name": "saml", "display_name": "SAML", "strategy": "saml"}`,
			wantErr:   false,
			wantID:    "conn_1",
			wantName:  "saml",
			wantDisp:  "SAML",
			wantStrat: "saml",
		},
		{
			name:      "connection with minimal fields",
			json:      `{"id": "conn_2", "name": "oauth"}`,
			wantErr:   false,
			wantID:    "conn_2",
			wantName:  "oauth",
			wantDisp:  "",
			wantStrat: "",
		},
		{
			name:    "empty object",
			json:    `{}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := jx.DecodeBytes([]byte(tt.json))
			var conn ConnectionConnection

			err := conn.Decode(d)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ConnectionConnection.Decode() expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ConnectionConnection.Decode() unexpected error = %v", err)
				return
			}

			if tt.wantID != "" {
				if id, ok := conn.ID.Get(); !ok || id != tt.wantID {
					t.Errorf("ID = %v (ok=%v), want %v", id, ok, tt.wantID)
				}
			}

			if tt.wantName != "" {
				if name, ok := conn.Name.Get(); !ok || name != tt.wantName {
					t.Errorf("Name = %v (ok=%v), want %v", name, ok, tt.wantName)
				}
			}

			if tt.wantDisp != "" {
				if disp, ok := conn.DisplayName.Get(); !ok || disp != tt.wantDisp {
					t.Errorf("DisplayName = %v (ok=%v), want %v", disp, ok, tt.wantDisp)
				}
			}

			if tt.wantStrat != "" {
				if strat, ok := conn.Strategy.Get(); !ok || strat != tt.wantStrat {
					t.Errorf("Strategy = %v (ok=%v), want %v", strat, ok, tt.wantStrat)
				}
			}
		})
	}
}

func TestGetConnectionsResponse_Encode(t *testing.T) {
	// Test encoding to ensure round-trip works
	response := &GetConnectionsResponse{
		Code:    NewOptString("OK"),
		Message: NewOptString("Success"),
		Connections: []ConnectionConnection{
			{
				ID:          NewOptString("conn_123"),
				Name:        NewOptString("saml"),
				DisplayName: NewOptString("SAML Connection"),
				Strategy:    NewOptString("saml"),
			},
		},
		HasMore: NewOptBool(false),
	}

	// Encode
	e := jx.Encoder{}
	response.Encode(&e)
	encoded := e.Bytes()

	// Decode back
	d := jx.DecodeBytes(encoded)
	var decoded GetConnectionsResponse
	err := decoded.Decode(d)

	if err != nil {
		t.Fatalf("Failed to decode encoded response: %v", err)
	}

	// Verify round-trip
	if len(decoded.Connections) != 1 {
		t.Fatalf("Expected 1 connection after round-trip, got %d", len(decoded.Connections))
	}

	conn := decoded.Connections[0]
	if id, ok := conn.ID.Get(); !ok || id != "conn_123" {
		t.Errorf("Round-trip ID: expected 'conn_123', got ok=%v, value=%v", ok, id)
	}
	if name, ok := conn.Name.Get(); !ok || name != "saml" {
		t.Errorf("Round-trip Name: expected 'saml', got ok=%v, value=%v", ok, name)
	}
}
