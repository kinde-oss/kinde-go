package authorization_code

import (
	"encoding/base64"
	"testing"

	"github.com/kinde-oss/kinde-go/jwt"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func TestWithAuthParameter(t *testing.T) {
	t.Parallel()

	t.Run("adds new auth parameter", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{
			authURLOptions: make(map[string][]string),
		}

		WithAuthParameter("custom_param", "value1")(flow)
		assert.Equal(t, []string{"value1"}, flow.authURLOptions["custom_param"])
	})

	t.Run("appends to existing auth parameter", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{
			authURLOptions: map[string][]string{
				"custom_param": {"value1"},
			},
		}

		WithAuthParameter("custom_param", "value2")(flow)
		assert.Equal(t, []string{"value1", "value2"}, flow.authURLOptions["custom_param"])
	})

	t.Run("does not duplicate values", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{
			authURLOptions: map[string][]string{
				"custom_param": {"value1"},
			},
		}

		WithAuthParameter("custom_param", "value1")(flow)
		assert.Equal(t, []string{"value1"}, flow.authURLOptions["custom_param"])
	})
}

func TestWithAudience(t *testing.T) {
	t.Parallel()

	t.Run("adds audience parameter", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{
			authURLOptions: make(map[string][]string),
		}

		WithAudience("http://my.api.com/api")(flow)
		assert.Equal(t, []string{"http://my.api.com/api"}, flow.authURLOptions["audience"])
	})
}

func TestWithPrompt(t *testing.T) {
	t.Parallel()

	t.Run("adds prompt parameter", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{
			authURLOptions: make(map[string][]string),
		}

		WithPrompt("login")(flow)
		assert.Equal(t, []string{"login"}, flow.authURLOptions["prompt"])
	})
}

func TestWithOffline(t *testing.T) {
	t.Parallel()

	t.Run("adds offline scope", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{
			config: oauth2.Config{
				Scopes: []string{"openid", "profile"},
			},
		}

		WithOffline()(flow)
		assert.Contains(t, flow.config.Scopes, "offline")
	})
}

func TestWithCustomStateGenerator(t *testing.T) {
	t.Parallel()

	t.Run("sets custom state generator", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{}
		customGenerator := func(*AuthorizationCodeFlow) string {
			return "custom_state"
		}

		WithCustomStateGenerator(customGenerator)(flow)
		assert.NotNil(t, flow.stateGenerator)
		assert.Equal(t, "custom_state", flow.stateGenerator(flow))
	})
}

func TestWithSessionHooks(t *testing.T) {
	t.Parallel()

	t.Run("sets session hooks", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{}
		mockHooks := newTestSessionHooks()

		WithSessionHooks(mockHooks)(flow)
		assert.Equal(t, mockHooks, flow.sessionHooks)
	})
}

func TestWithClientID(t *testing.T) {
	t.Parallel()

	t.Run("sets client ID", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{
			config: oauth2.Config{},
		}

		WithClientID("test_client_id")(flow)
		assert.Equal(t, "test_client_id", flow.config.ClientID)
	})
}

func TestWithClientSecret(t *testing.T) {
	t.Parallel()

	t.Run("sets client secret", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{
			config: oauth2.Config{},
		}

		WithClientSecret("test_client_secret")(flow)
		assert.Equal(t, "test_client_secret", flow.config.ClientSecret)
	})
}

func TestWithScopes(t *testing.T) {
	t.Parallel()

	t.Run("replaces scopes", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{
			config: oauth2.Config{
				Scopes: []string{"openid", "profile"},
			},
		}

		WithScopes("openid", "email", "offline")(flow)
		assert.Equal(t, []string{"openid", "email", "offline"}, flow.config.Scopes)
	})
}

func TestWithAdditionalScope(t *testing.T) {
	t.Parallel()

	t.Run("adds scope to existing list", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{
			config: oauth2.Config{
				Scopes: []string{"openid", "profile"},
			},
		}

		WithAdditionalScope("email")(flow)
		assert.Contains(t, flow.config.Scopes, "openid")
		assert.Contains(t, flow.config.Scopes, "profile")
		assert.Contains(t, flow.config.Scopes, "email")
	})
}

func TestWithTokenValidation(t *testing.T) {
	t.Parallel()

	t.Run("adds JWKS validation when enabled", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{
			JWKS_URL:     "https://test.kinde.com/.well-known/jwks",
			tokenOptions: []func(*jwt.Token){},
		}

		WithTokenValidation(true)(flow)
		assert.NotEmpty(t, flow.tokenOptions)
	})

	t.Run("adds custom token options", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{
			JWKS_URL:     "https://test.kinde.com/.well-known/jwks",
			tokenOptions: []func(*jwt.Token){},
		}

		customOption := jwt.WillValidateAlgorithm("RS256")
		WithTokenValidation(false, customOption)(flow)
		assert.Len(t, flow.tokenOptions, 1)
	})
}

func TestWithPKCE(t *testing.T) {
	t.Parallel()

	t.Run("enables PKCE with S256", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{
			sessionHooks: newTestSessionHooks(),
		}

		WithPKCE()(flow)
		assert.True(t, flow.usePKCE)
		assert.Equal(t, "S256", flow.challengeMethod)
		assert.NotEmpty(t, flow.codeChallenge)
	})

	t.Run("generates code verifier and challenge", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{
			sessionHooks: newTestSessionHooks(),
		}

		WithPKCE()(flow)
		assert.NotEmpty(t, flow.codeChallenge)
	})
}

func TestWithPKCEChallengeMethod(t *testing.T) {
	t.Parallel()

	t.Run("sets S256 challenge method", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{
			sessionHooks: newTestSessionHooks(),
		}

		WithPKCEChallengeMethod("S256")(flow)
		assert.True(t, flow.usePKCE)
		assert.Equal(t, "S256", flow.challengeMethod)
	})

	t.Run("sets plain challenge method", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{
			sessionHooks: newTestSessionHooks(),
		}

		WithPKCEChallengeMethod("plain")(flow)
		assert.True(t, flow.usePKCE)
		assert.Equal(t, "plain", flow.challengeMethod)
	})

	t.Run("defaults to S256 for invalid method", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{
			sessionHooks: newTestSessionHooks(),
		}

		WithPKCEChallengeMethod("invalid")(flow)
		assert.True(t, flow.usePKCE)
		assert.Equal(t, "S256", flow.challengeMethod)
	})
}

func TestWithSupportsReauth(t *testing.T) {
	t.Parallel()

	t.Run("adds supports_reauth parameter as true", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{
			authURLOptions: make(map[string][]string),
		}

		WithSupportsReauth(true)(flow)
		assert.Equal(t, []string{"true"}, flow.authURLOptions["supports_reauth"])
	})

	t.Run("adds supports_reauth parameter as false", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{
			authURLOptions: make(map[string][]string),
		}

		WithSupportsReauth(false)(flow)
		assert.Equal(t, []string{"false"}, flow.authURLOptions["supports_reauth"])
	})
}

func TestWithReauthState(t *testing.T) {
	t.Parallel()

	t.Run("decodes and merges valid reauth state", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{
			authURLOptions: make(map[string][]string),
		}

		// Create a valid Base64-encoded JSON
		reauthParams := `{"org_code":"org123","audience":"api.example.com","login_hint":"user@example.com"}`
		encoded := base64.StdEncoding.EncodeToString([]byte(reauthParams))

		WithReauthState(encoded)(flow)

		assert.Equal(t, []string{"org123"}, flow.authURLOptions["org_code"])
		assert.Equal(t, []string{"api.example.com"}, flow.authURLOptions["audience"])
		assert.Equal(t, []string{"user@example.com"}, flow.authURLOptions["login_hint"])
	})

	t.Run("maps camelCase to snake_case", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{
			authURLOptions: make(map[string][]string),
		}

		reauthParams := `{"orgCode":"org123","orgName":"Test Org","loginHint":"user@example.com","connectionId":"conn1","isCreateOrg":true,"hasSuccessPage":false,"workflowDeploymentId":"wf1","planInterest":"pro","pricingTableKey":"table1","pagesMode":"preview"}`
		encoded := base64.StdEncoding.EncodeToString([]byte(reauthParams))

		WithReauthState(encoded)(flow)

		assert.Equal(t, []string{"org123"}, flow.authURLOptions["org_code"])
		assert.Equal(t, []string{"Test Org"}, flow.authURLOptions["org_name"])
		assert.Equal(t, []string{"user@example.com"}, flow.authURLOptions["login_hint"])
		assert.Equal(t, []string{"conn1"}, flow.authURLOptions["connection_id"])
		assert.Equal(t, []string{"true"}, flow.authURLOptions["is_create_org"])
		assert.Equal(t, []string{"false"}, flow.authURLOptions["has_success_page"])
		assert.Equal(t, []string{"wf1"}, flow.authURLOptions["workflow_deployment_id"])
		assert.Equal(t, []string{"pro"}, flow.authURLOptions["plan_interest"])
		assert.Equal(t, []string{"table1"}, flow.authURLOptions["pricing_table_key"])
		assert.Equal(t, []string{"preview"}, flow.authURLOptions["pages_mode"])
	})

	t.Run("handles empty reauth state gracefully", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{
			authURLOptions: make(map[string][]string),
		}

		WithReauthState("")(flow)

		// Should not add any parameters
		assert.Empty(t, flow.authURLOptions)
	})

	t.Run("handles invalid Base64 gracefully", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{
			authURLOptions: make(map[string][]string),
		}

		WithReauthState("!!!invalid base64!!!")(flow)

		// Should not add any parameters (error is silently ignored)
		assert.Empty(t, flow.authURLOptions)
	})

	t.Run("handles invalid JSON gracefully", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{
			authURLOptions: make(map[string][]string),
		}

		// Valid Base64 but invalid JSON
		invalidJSON := base64.StdEncoding.EncodeToString([]byte("not valid json"))
		WithReauthState(invalidJSON)(flow)

		// Should not add any parameters (error is silently ignored)
		assert.Empty(t, flow.authURLOptions)
	})

	t.Run("handles array values", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{
			authURLOptions: make(map[string][]string),
		}

		reauthParams := `{"audience":["api1.example.com","api2.example.com"]}`
		encoded := base64.StdEncoding.EncodeToString([]byte(reauthParams))

		WithReauthState(encoded)(flow)

		// Arrays should be joined with space
		assert.Equal(t, []string{"api1.example.com api2.example.com"}, flow.authURLOptions["audience"])
	})

	t.Run("does not overwrite existing parameters", func(t *testing.T) {
		flow := &AuthorizationCodeFlow{
			authURLOptions: map[string][]string{
				"org_code": {"existing_org"},
			},
		}

		reauthParams := `{"org_code":"new_org"}`
		encoded := base64.StdEncoding.EncodeToString([]byte(reauthParams))

		WithReauthState(encoded)(flow)

		// Should keep existing value
		assert.Equal(t, []string{"existing_org"}, flow.authURLOptions["org_code"])
	})
}
