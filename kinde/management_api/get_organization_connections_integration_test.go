package management_api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-faster/jx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetOrganizationConnections_Integration(t *testing.T) {
	// Mock API response matching the actual Kinde API structure
	mockResponse := GetConnectionsResponse{
		Code:    NewOptString("OK"),
		Message: NewOptString("Success"),
		Connections: []ConnectionConnection{
			{
				ID:          NewOptString("conn_abc123"),
				Name:        NewOptString("saml"),
				DisplayName: NewOptString("SAML Connection"),
				Strategy:    NewOptString("saml"),
			},
			{
				ID:          NewOptString("conn_def456"),
				Name:        NewOptString("oauth"),
				DisplayName: NewOptString("OAuth Connection"),
				Strategy:    NewOptString("oauth"),
			},
		},
		HasMore: NewOptBool(false),
	}

	// Create mock server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request
		assert.Equal(t, "/api/v1/organizations/test_org/connections", r.URL.Path, "Unexpected path")
		assert.Equal(t, "GET", r.Method, "Unexpected method")
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer", "Missing authorization header")

		// Return mock response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// Encode the response as JSON
		encoder := jx.Encoder{}
		mockResponse.Encode(&encoder)
		w.Write(encoder.Bytes())
	}))
	defer mockServer.Close()

	// Create a mock security source
	mockSecurity := &mockSecuritySource{token: "mock_token"}

	// Create client with mock server URL
	client, err := NewClient(mockServer.URL, mockSecurity)
	require.NoError(t, err, "Failed to create client")

	// Call GetOrganizationConnections
	ctx := context.Background()
	params := GetOrganizationConnectionsParams{
		OrganizationCode: "test_org",
	}

	res, err := client.GetOrganizationConnections(ctx, params)
	require.NoError(t, err, "GetOrganizationConnections should not return an error")

	// Verify response type
	response, ok := res.(*GetConnectionsResponse)
	require.True(t, ok, "Response should be *GetConnectionsResponse, got %T", res)

	// Verify response properties are populated
	assert.True(t, response.Code.IsSet(), "Code should be set")
	if code, ok := response.Code.Get(); ok {
		assert.Equal(t, "OK", code, "Code should be 'OK'")
	}

	assert.True(t, response.Message.IsSet(), "Message should be set")
	if message, ok := response.Message.Get(); ok {
		assert.Equal(t, "Success", message, "Message should be 'Success'")
	}

	// Verify connections array is populated
	assert.Len(t, response.Connections, 2, "Should have 2 connections")

	// Verify first connection properties
	conn1 := response.Connections[0]
	assert.True(t, conn1.ID.IsSet(), "Connection 1 ID should be set")
	if id, ok := conn1.ID.Get(); ok {
		assert.Equal(t, "conn_abc123", id, "Connection 1 ID should be 'conn_abc123'")
	}
	assert.True(t, conn1.Name.IsSet(), "Connection 1 Name should be set")
	if name, ok := conn1.Name.Get(); ok {
		assert.Equal(t, "saml", name, "Connection 1 Name should be 'saml'")
	}
	assert.True(t, conn1.DisplayName.IsSet(), "Connection 1 DisplayName should be set")
	if displayName, ok := conn1.DisplayName.Get(); ok {
		assert.Equal(t, "SAML Connection", displayName, "Connection 1 DisplayName should be 'SAML Connection'")
	}
	assert.True(t, conn1.Strategy.IsSet(), "Connection 1 Strategy should be set")
	if strategy, ok := conn1.Strategy.Get(); ok {
		assert.Equal(t, "saml", strategy, "Connection 1 Strategy should be 'saml'")
	}

	// Verify second connection properties
	conn2 := response.Connections[1]
	assert.True(t, conn2.ID.IsSet(), "Connection 2 ID should be set")
	if id, ok := conn2.ID.Get(); ok {
		assert.Equal(t, "conn_def456", id, "Connection 2 ID should be 'conn_def456'")
	}
	assert.True(t, conn2.Name.IsSet(), "Connection 2 Name should be set")
	if name, ok := conn2.Name.Get(); ok {
		assert.Equal(t, "oauth", name, "Connection 2 Name should be 'oauth'")
	}
	assert.True(t, conn2.DisplayName.IsSet(), "Connection 2 DisplayName should be set")
	if displayName, ok := conn2.DisplayName.Get(); ok {
		assert.Equal(t, "OAuth Connection", displayName, "Connection 2 DisplayName should be 'OAuth Connection'")
	}
	assert.True(t, conn2.Strategy.IsSet(), "Connection 2 Strategy should be set")
	if strategy, ok := conn2.Strategy.Get(); ok {
		assert.Equal(t, "oauth", strategy, "Connection 2 Strategy should be 'oauth'")
	}

	// Verify has_more
	assert.True(t, response.HasMore.IsSet(), "HasMore should be set")
	if hasMore, ok := response.HasMore.Get(); ok {
		assert.False(t, hasMore, "HasMore should be false")
	}
}

func TestGetOrganizationConnections_Integration_EmptyResponse(t *testing.T) {
	// Test with empty connections array
	mockResponse := GetConnectionsResponse{
		Code:        NewOptString("OK"),
		Message:     NewOptString("No connections found"),
		Connections: []ConnectionConnection{},
		HasMore:     NewOptBool(false),
	}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		encoder := jx.Encoder{}
		mockResponse.Encode(&encoder)
		w.Write(encoder.Bytes())
	}))
	defer mockServer.Close()

	mockSecurity := &mockSecuritySource{token: "mock_token"}
	client, err := NewClient(mockServer.URL, mockSecurity)
	require.NoError(t, err)

	ctx := context.Background()
	params := GetOrganizationConnectionsParams{
		OrganizationCode: "test_org",
	}

	res, err := client.GetOrganizationConnections(ctx, params)
	require.NoError(t, err)

	response, ok := res.(*GetConnectionsResponse)
	require.True(t, ok)

	assert.Len(t, response.Connections, 0, "Should have 0 connections")
}

func TestGetOrganizationConnections_Integration_ErrorResponses(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		responseBody   string
		expectedType   string
		wantErr        bool
		checkErrorType func(t *testing.T, res GetOrganizationConnectionsRes)
	}{
		{
			name:       "400 Bad Request",
			statusCode: http.StatusBadRequest,
			responseBody: `{
				"code": "BAD_REQUEST",
				"message": "Invalid organization code"
			}`,
			expectedType: "*GetOrganizationConnectionsBadRequest",
			wantErr:      false,
			checkErrorType: func(t *testing.T, res GetOrganizationConnectionsRes) {
				_, ok := res.(*GetOrganizationConnectionsBadRequest)
				assert.True(t, ok, "Should be GetOrganizationConnectionsBadRequest")
			},
		},
		{
			name:       "403 Forbidden",
			statusCode: http.StatusForbidden,
			responseBody: `{
				"code": "FORBIDDEN",
				"message": "Insufficient permissions"
			}`,
			expectedType: "*GetOrganizationConnectionsForbidden",
			wantErr:      false,
			checkErrorType: func(t *testing.T, res GetOrganizationConnectionsRes) {
				_, ok := res.(*GetOrganizationConnectionsForbidden)
				assert.True(t, ok, "Should be GetOrganizationConnectionsForbidden")
			},
		},
		{
			name:       "429 Too Many Requests",
			statusCode: http.StatusTooManyRequests,
			responseBody: `{
				"code": "TOO_MANY_REQUESTS",
				"message": "Rate limit exceeded"
			}`,
			expectedType: "*GetOrganizationConnectionsTooManyRequests",
			wantErr:      false,
			checkErrorType: func(t *testing.T, res GetOrganizationConnectionsRes) {
				_, ok := res.(*GetOrganizationConnectionsTooManyRequests)
				assert.True(t, ok, "Should be GetOrganizationConnectionsTooManyRequests")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.responseBody))
			}))
			defer mockServer.Close()

			mockSecurity := &mockSecuritySource{token: "mock_token"}
			client, err := NewClient(mockServer.URL, mockSecurity)
			require.NoError(t, err)

			ctx := context.Background()
			params := GetOrganizationConnectionsParams{
				OrganizationCode: "test_org",
			}

			res, err := client.GetOrganizationConnections(ctx, params)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				tt.checkErrorType(t, res)
			}
		})
	}
}

// mockSecuritySource is a helper to provide security tokens in tests
type mockSecuritySource struct {
	token string
}

func (m *mockSecuritySource) KindeBearerAuth(ctx context.Context, operationName OperationName) (KindeBearerAuth, error) {
	return KindeBearerAuth{Token: m.token}, nil
}
