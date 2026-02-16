package client_credentials

import (
	"net/url"
	"testing"

	"github.com/kinde-oss/kinde-go/jwt"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2/clientcredentials"
)

func TestWithAuthParameter(t *testing.T) {
	t.Parallel()

	t.Run("adds new auth parameter", func(t *testing.T) {
		flow := &ClientCredentialsFlow{
			config: clientcredentials.Config{
				EndpointParams: make(map[string][]string),
			},
		}

		WithAuthParameter("custom_param", "value1")(flow)
		assert.Equal(t, []string{"value1"}, flow.config.EndpointParams["custom_param"])
	})

	t.Run("appends to existing auth parameter", func(t *testing.T) {
		flow := &ClientCredentialsFlow{
			config: clientcredentials.Config{
				EndpointParams: map[string][]string{
					"custom_param": {"value1"},
				},
			},
		}

		WithAuthParameter("custom_param", "value2")(flow)
		assert.Equal(t, []string{"value1", "value2"}, flow.config.EndpointParams["custom_param"])
	})
}

func TestWithAudience(t *testing.T) {
	t.Parallel()

	t.Run("adds audience parameter", func(t *testing.T) {
		flow := &ClientCredentialsFlow{
			config: clientcredentials.Config{
				EndpointParams: make(map[string][]string),
			},
		}

		WithAudience("http://my.api.com/api")(flow)
		assert.Equal(t, []string{"http://my.api.com/api"}, flow.config.EndpointParams["audience"])
	})
}

func TestWithSessionHooks(t *testing.T) {
	t.Parallel()

	t.Run("sets session hooks", func(t *testing.T) {
		flow := &ClientCredentialsFlow{}
		mockHooks := newTestSessionHooks()

		WithSessionHooks(mockHooks)(flow)
		assert.Equal(t, mockHooks, flow.sessionHooks)
	})
}

func TestWithKindeManagementAPI(t *testing.T) {
	t.Parallel()

	t.Run("adds management API audience from domain string", func(t *testing.T) {
		flow := &ClientCredentialsFlow{
			config: clientcredentials.Config{
				EndpointParams: make(map[string][]string),
			},
		}

		WithKindeManagementAPI("my_kinde_tenant")(flow)
		audiences := flow.config.EndpointParams["audience"]
		assert.Contains(t, audiences, "https://my_kinde_tenant.kinde.com/api")
	})

	t.Run("adds management API audience from full URL", func(t *testing.T) {
		flow := &ClientCredentialsFlow{
			config: clientcredentials.Config{
				EndpointParams: make(map[string][]string),
			},
		}

		WithKindeManagementAPI("https://my_kinde_tenant.kinde.com")(flow)
		audiences := flow.config.EndpointParams["audience"]
		assert.Contains(t, audiences, "https://my_kinde_tenant.kinde.com/api")
	})

	t.Run("handles invalid URL gracefully", func(t *testing.T) {
		flow := &ClientCredentialsFlow{
			config: clientcredentials.Config{
				EndpointParams: make(map[string][]string),
			},
		}

		// Invalid URL should not panic
		WithKindeManagementAPI("://invalid")(flow)
		// Should not add audience for invalid URL
		audiences := flow.config.EndpointParams["audience"]
		assert.Nil(t, audiences)
	})

	t.Run("extracts hostname correctly", func(t *testing.T) {
		flow := &ClientCredentialsFlow{
			config: clientcredentials.Config{
				EndpointParams: make(map[string][]string),
			},
		}

		WithKindeManagementAPI("https://subdomain.my_kinde_tenant.kinde.com:8080")(flow)
		audiences := flow.config.EndpointParams["audience"]
		// Should extract the hostname correctly
		assert.NotNil(t, audiences)
	})
}

func TestWithTokenValidation(t *testing.T) {
	t.Parallel()

	t.Run("adds JWKS validation when enabled", func(t *testing.T) {
		flow := &ClientCredentialsFlow{
			JWKS_URL:     "https://test.kinde.com/.well-known/jwks",
			tokenOptions: []func(*jwt.Token){},
		}

		WithTokenValidation(true)(flow)
		assert.NotEmpty(t, flow.tokenOptions)
	})

	t.Run("adds custom token options", func(t *testing.T) {
		flow := &ClientCredentialsFlow{
			JWKS_URL:     "https://test.kinde.com/.well-known/jwks",
			tokenOptions: []func(*jwt.Token){},
		}

		customOption := jwt.WillValidateAlgorithm("RS256")
		WithTokenValidation(false, customOption)(flow)
		assert.Len(t, flow.tokenOptions, 1)
	})
}

// Helper function to test URL parsing
func TestURLParsing(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple domain",
			input:    "my_kinde_tenant",
			expected: "https://my_kinde_tenant.kinde.com/api",
		},
		{
			name:     "full URL",
			input:    "https://my_kinde_tenant.kinde.com",
			expected: "https://my_kinde_tenant.kinde.com/api",
		},
		{
			name:     "URL with path",
			input:    "https://my_kinde_tenant.kinde.com/some/path",
			expected: "https://my_kinde_tenant.kinde.com/api",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			flow := &ClientCredentialsFlow{
				config: clientcredentials.Config{
					EndpointParams: make(map[string][]string),
				},
			}

			WithKindeManagementAPI(tc.input)(flow)
			audiences := flow.config.EndpointParams["audience"]
			if tc.expected != "" {
				assert.Contains(t, audiences, tc.expected)
			}
		})
	}
}

// Test URL parsing edge cases
func TestURLParsingEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("handles empty string", func(t *testing.T) {
		flow := &ClientCredentialsFlow{
			config: clientcredentials.Config{
				EndpointParams: make(map[string][]string),
			},
		}

		WithKindeManagementAPI("")(flow)
		// Should handle gracefully without panic
		audiences := flow.config.EndpointParams["audience"]
		assert.Nil(t, audiences, "Empty input should not add audience")
	})

	t.Run("handles URL with port", func(t *testing.T) {
		// This test just checks URL parsing, doesn't need a flow

		parsedURL, _ := url.Parse("https://my_kinde_tenant.kinde.com:8080")
		hostname := parsedURL.Hostname()
		assert.Equal(t, "my_kinde_tenant.kinde.com", hostname)
	})
}
