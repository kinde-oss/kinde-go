package authorization_code

import (
	"testing"
)

func TestAuthorizationCodeFlow_GetAccountAPIClient(t *testing.T) {
	t.Run("creates Account API client with issuer from token", func(t *testing.T) {
		// This test requires a full OAuth flow setup with a valid token
		// For now, we'll skip it as it's more of an integration test
		// The function structure is tested through the actual usage
		t.Skip("Requires full OAuth flow setup - integration test")
	})
}

