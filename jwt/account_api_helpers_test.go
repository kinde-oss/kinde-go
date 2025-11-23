package jwt

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/kinde-oss/kinde-go/kinde/account_api"
	"golang.org/x/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToken_GetPermissionsWithAPI(t *testing.T) {
	t.Run("reads from token when forceAPI is false", func(t *testing.T) {
		token := createTestToken(t, map[string]interface{}{
			"permissions": []interface{}{"read:users", "write:users"},
			"org_code":    "org123",
		})

		apiClient, _ := account_api.NewClient("https://example.com", func(ctx context.Context) (string, error) {
			return "token", nil
		})

		result, err := token.GetPermissionsWithAPI(context.Background(), apiClient, GetPermissionsOptions{ForceAPI: false})
		require.NoError(t, err)
		assert.Equal(t, "org123", result.OrgCode)
		assert.Equal(t, []string{"read:users", "write:users"}, result.Permissions)
	})

	t.Run("fetches from API when forceAPI is true", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(account_api.BaseAccountResponse{
				Metadata: account_api.Metadata{
					HasMore: false,
				},
				Data: map[string]interface{}{
					"org_code": "org456",
					"permissions": []map[string]string{
						{"id": "1", "name": "Read Users", "key": "read:users"},
						{"id": "2", "name": "Write Users", "key": "write:users"},
					},
				},
			})
		}))
		defer server.Close()

		token := createTestToken(t, map[string]interface{}{})
		apiClient, _ := account_api.NewClient(server.URL, func(ctx context.Context) (string, error) {
			return "token", nil
		})

		result, err := token.GetPermissionsWithAPI(context.Background(), apiClient, GetPermissionsOptions{ForceAPI: true})
		require.NoError(t, err)
		assert.Equal(t, "org456", result.OrgCode)
		assert.Contains(t, result.Permissions, "read:users")
		assert.Contains(t, result.Permissions, "write:users")
	})
}

func TestToken_GetRolesWithAPI(t *testing.T) {
	t.Run("reads from token when forceAPI is false", func(t *testing.T) {
		token := createTestToken(t, map[string]interface{}{
			"roles": []interface{}{
				map[string]interface{}{"id": "1", "name": "Admin", "key": "admin"},
			},
		})

		apiClient, _ := account_api.NewClient("https://example.com", func(ctx context.Context) (string, error) {
			return "token", nil
		})

		result, err := token.GetRolesWithAPI(context.Background(), apiClient, false)
		require.NoError(t, err)
		assert.Len(t, result, 1)
		assert.Equal(t, "admin", result[0].Key)
	})

	t.Run("fetches from API when forceAPI is true", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(account_api.BaseAccountResponse{
				Metadata: account_api.Metadata{
					HasMore: false,
				},
				Data: map[string]interface{}{
					"org_code": "org123",
					"roles": []map[string]string{
						{"id": "1", "name": "Admin", "key": "admin"},
						{"id": "2", "name": "User", "key": "user"},
					},
				},
			})
		}))
		defer server.Close()

		token := createTestToken(t, map[string]interface{}{})
		apiClient, _ := account_api.NewClient(server.URL, func(ctx context.Context) (string, error) {
			return "token", nil
		})

		result, err := token.GetRolesWithAPI(context.Background(), apiClient, true)
		require.NoError(t, err)
		assert.Len(t, result, 2)
		assert.Equal(t, "admin", result[0].Key)
		assert.Equal(t, "user", result[1].Key)
	})
}

func TestToken_GetFeatureFlagsWithAPI(t *testing.T) {
	t.Run("reads from token when forceAPI is false", func(t *testing.T) {
		token := createTestToken(t, map[string]interface{}{
			"feature_flags": map[string]interface{}{
				"flag1": map[string]interface{}{
					"t": "b",
					"v": true,
				},
			},
		})

		apiClient, _ := account_api.NewClient("https://example.com", func(ctx context.Context) (string, error) {
			return "token", nil
		})

		result, err := token.GetFeatureFlagsWithAPI(context.Background(), apiClient, false)
		require.NoError(t, err)
		assert.Contains(t, result, "flag1")
		assert.Equal(t, "b", result["flag1"].Type)
	})

	t.Run("fetches from API when forceAPI is true", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(account_api.BaseAccountResponse{
				Metadata: account_api.Metadata{
					HasMore: false,
				},
				Data: map[string]interface{}{
					"feature_flags": []map[string]interface{}{
						{"id": "1", "name": "Flag 1", "key": "flag1", "type": "b", "value": true},
						{"id": "2", "name": "Flag 2", "key": "flag2", "type": "s", "value": "test"},
					},
				},
			})
		}))
		defer server.Close()

		token := createTestToken(t, map[string]interface{}{})
		apiClient, _ := account_api.NewClient(server.URL, func(ctx context.Context) (string, error) {
			return "token", nil
		})

		result, err := token.GetFeatureFlagsWithAPI(context.Background(), apiClient, true)
		require.NoError(t, err)
		assert.Contains(t, result, "flag1")
		assert.Contains(t, result, "flag2")
		assert.Equal(t, "b", result["flag1"].Type)
		assert.Equal(t, true, result["flag1"].Value)
	})
}

func TestToken_GetEntitlements(t *testing.T) {
	t.Run("fetches entitlements from API", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(account_api.BaseAccountResponse{
				Metadata: account_api.Metadata{
					HasMore: false,
				},
				Data: map[string]interface{}{
					"org_code": "org123",
					"plans": []map[string]string{
						{"key": "pro", "subscribed_on": "2024-01-01"},
					},
					"entitlements": []map[string]interface{}{
						{
							"id":                  "ent1",
							"fixed_charge":        10.0,
							"price_name":          "Basic",
							"unit_amount":         5.0,
							"feature_key":         "feature1",
							"feature_name":        "Feature 1",
							"entitlement_limit_max": 100,
							"entitlement_limit_min": 0,
						},
					},
				},
			})
		}))
		defer server.Close()

		token := createTestToken(t, map[string]interface{}{})
		apiClient, _ := account_api.NewClient(server.URL, func(ctx context.Context) (string, error) {
			return "token", nil
		})

		result, err := token.GetEntitlements(context.Background(), apiClient)
		require.NoError(t, err)

		// Assert org code
		assert.Equal(t, "org123", result.OrgCode)

		// Assert plans
		assert.Len(t, result.Plans, 1)
		assert.Equal(t, "pro", result.Plans[0].Key)
		assert.Equal(t, "2024-01-01", result.Plans[0].SubscribedOn)

		// Assert all entitlement fields (complete coverage)
		assert.Len(t, result.Entitlements, 1)
		ent := result.Entitlements[0]
		assert.Equal(t, "ent1", ent.ID)
		assert.Equal(t, 10.0, ent.FixedCharge)
		assert.Equal(t, "Basic", ent.PriceName)
		assert.Equal(t, 5.0, ent.UnitAmount)
		assert.Equal(t, "feature1", ent.FeatureKey)
		assert.Equal(t, "Feature 1", ent.FeatureName)
		assert.Equal(t, 100, ent.EntitlementLimitMax)
		assert.Equal(t, 0, ent.EntitlementLimitMin)
	})

	t.Run("returns error when API call fails", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		token := createTestToken(t, map[string]interface{}{})
		apiClient, _ := account_api.NewClient(server.URL, func(ctx context.Context) (string, error) {
			return "token", nil
		})

		result, err := token.GetEntitlements(context.Background(), apiClient)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to fetch entitlements from API")
	})
}

// Helper function to create a test token with claims
func createTestToken(t *testing.T, claims map[string]interface{}) *Token {
	t.Helper()
	// Create a token with the claims directly set
	// For testing, we'll create a token with parsed claims
	token := &Token{
		processing: tokenProcessing{
			parsed: &golangjwt.Token{
				Claims: golangjwt.MapClaims(claims),
			},
		},
		rawToken: &oauth2.Token{
			AccessToken: "test-access-token",
		},
	}
	return token
}

