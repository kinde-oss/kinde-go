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

func TestToken_GetPermission(t *testing.T) {
	t.Run("reads from token when forceAPI is false", func(t *testing.T) {
		token := createTestToken(t, map[string]interface{}{
			"permissions": []interface{}{"read:users", "write:posts"},
			"org_code":    "org123",
		})

		apiClient, _ := account_api.NewClient("https://example.com", func(ctx context.Context) (string, error) {
			return "token", nil
		})

		result, err := token.GetPermission(context.Background(), apiClient, "read:users", GetPermissionOptions{ForceAPI: false})
		require.NoError(t, err)
		assert.Equal(t, "read:users", result.PermissionKey)
		assert.Equal(t, "org123", result.OrgCode)
		assert.True(t, result.IsGranted)
	})

	t.Run("returns false when permission not in token", func(t *testing.T) {
		token := createTestToken(t, map[string]interface{}{
			"permissions": []interface{}{"read:users"},
			"org_code":    "org123",
		})

		apiClient, _ := account_api.NewClient("https://example.com", func(ctx context.Context) (string, error) {
			return "token", nil
		})

		result, err := token.GetPermission(context.Background(), apiClient, "write:posts", GetPermissionOptions{ForceAPI: false})
		require.NoError(t, err)
		assert.Equal(t, "write:posts", result.PermissionKey)
		assert.False(t, result.IsGranted)
	})

	t.Run("fetches from API when forceAPI is true", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// The API returns the data wrapped in a struct matching AccountPermissionData
			// Following the pattern from GetEntitlement, the response includes org_code and is_granted
			json.NewEncoder(w).Encode(map[string]interface{}{
				"org_code":   "org456",
				"is_granted": true,
				"permission": map[string]interface{}{
					"id":   "perm1",
					"name": "Read Users",
					"key":  "read:users",
				},
			})
		}))
		defer server.Close()

		token := createTestToken(t, map[string]interface{}{})
		apiClient, _ := account_api.NewClient(server.URL, func(ctx context.Context) (string, error) {
			return "token", nil
		})

		result, err := token.GetPermission(context.Background(), apiClient, "read:users", GetPermissionOptions{ForceAPI: true})
		require.NoError(t, err)
		assert.Equal(t, "read:users", result.PermissionKey)
		assert.Equal(t, "org456", result.OrgCode)
		assert.True(t, result.IsGranted)
	})

	t.Run("fetches from API when permission object is missing", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// Test with minimal response structure (without nested permission object)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"org_code":   "org789",
				"is_granted": false,
			})
		}))
		defer server.Close()

		token := createTestToken(t, map[string]interface{}{})
		apiClient, _ := account_api.NewClient(server.URL, func(ctx context.Context) (string, error) {
			return "token", nil
		})

		result, err := token.GetPermission(context.Background(), apiClient, "write:posts", GetPermissionOptions{ForceAPI: true})
		require.NoError(t, err)
		assert.Equal(t, "write:posts", result.PermissionKey)
		assert.Equal(t, "org789", result.OrgCode)
		assert.False(t, result.IsGranted)
	})
}

func TestToken_GetFlag(t *testing.T) {
	t.Run("reads from token when forceAPI is false", func(t *testing.T) {
		token := createTestToken(t, map[string]interface{}{
			"feature_flags": map[string]interface{}{
				"flag1": map[string]interface{}{
					"t": "b",
					"v": true,
				},
				"flag2": map[string]interface{}{
					"t": "s",
					"v": "test_value",
				},
			},
		})

		apiClient, _ := account_api.NewClient("https://example.com", func(ctx context.Context) (string, error) {
			return "token", nil
		})

		// Test boolean flag
		result, err := token.GetFlag(context.Background(), apiClient, "flag1", false)
		require.NoError(t, err)
		assert.Equal(t, true, result)

		// Test string flag
		result, err = token.GetFlag(context.Background(), apiClient, "flag2", false)
		require.NoError(t, err)
		assert.Equal(t, "test_value", result)
	})

	t.Run("returns nil when flag not found in token", func(t *testing.T) {
		token := createTestToken(t, map[string]interface{}{
			"feature_flags": map[string]interface{}{},
		})

		apiClient, _ := account_api.NewClient("https://example.com", func(ctx context.Context) (string, error) {
			return "token", nil
		})

		result, err := token.GetFlag(context.Background(), apiClient, "nonexistent", false)
		require.NoError(t, err)
		assert.Nil(t, result)
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
					},
				},
			})
		}))
		defer server.Close()

		token := createTestToken(t, map[string]interface{}{})
		apiClient, _ := account_api.NewClient(server.URL, func(ctx context.Context) (string, error) {
			return "token", nil
		})

		// Use key (not name) for consistency with token lookup
		result, err := token.GetFlag(context.Background(), apiClient, "flag1", true)
		require.NoError(t, err)
		assert.Equal(t, true, result)
	})
}

func TestToken_GetEntitlement(t *testing.T) {
	t.Run("fetches entitlement from API", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// The API returns the data directly, not wrapped in BaseAccountResponse for single entitlement
			json.NewEncoder(w).Encode(map[string]interface{}{
				"org_code": "org123",
				"entitlement": map[string]interface{}{
					"id":                  "ent1",
					"fixed_charge":        10.0,
					"price_name":          "Basic",
					"unit_amount":         5.0,
					"feature_key":         "feature1",
					"feature_name":        "Feature 1",
					"entitlement_limit_max": 100,
					"entitlement_limit_min": 0,
				},
			})
		}))
		defer server.Close()

		token := createTestToken(t, map[string]interface{}{})
		apiClient, _ := account_api.NewClient(server.URL, func(ctx context.Context) (string, error) {
			return "token", nil
		})

		result, err := token.GetEntitlement(context.Background(), apiClient, "entitlement_key")
		require.NoError(t, err)
		assert.Equal(t, "ent1", result.ID)
		assert.Equal(t, 10.0, result.FixedCharge)
		assert.Equal(t, "Basic", result.PriceName)
		assert.Equal(t, 5.0, result.UnitAmount)
		assert.Equal(t, "feature1", result.FeatureKey)
		assert.Equal(t, "Feature 1", result.FeatureName)
		assert.Equal(t, 100, result.EntitlementLimitMax)
		assert.Equal(t, 0, result.EntitlementLimitMin)
	})

	t.Run("returns error when API call fails", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		token := createTestToken(t, map[string]interface{}{})
		apiClient, _ := account_api.NewClient(server.URL, func(ctx context.Context) (string, error) {
			return "token", nil
		})

		result, err := token.GetEntitlement(context.Background(), apiClient, "entitlement_key")
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to fetch entitlement from API")
	})
}

func TestToken_HasPermissions(t *testing.T) {
	t.Run("returns true when all permissions are granted", func(t *testing.T) {
		token := createTestToken(t, map[string]interface{}{
			"permissions": []interface{}{"read:users", "write:posts"},
			"org_code":    "org123",
		})

		apiClient, _ := account_api.NewClient("https://example.com", func(ctx context.Context) (string, error) {
			return "token", nil
		})

		result, err := token.HasPermissions(context.Background(), apiClient, []string{"read:users", "write:posts"}, HasPermissionsOptions{ForceAPI: false})
		require.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("returns false when any permission is missing", func(t *testing.T) {
		token := createTestToken(t, map[string]interface{}{
			"permissions": []interface{}{"read:users"},
			"org_code":    "org123",
		})

		apiClient, _ := account_api.NewClient("https://example.com", func(ctx context.Context) (string, error) {
			return "token", nil
		})

		result, err := token.HasPermissions(context.Background(), apiClient, []string{"read:users", "write:posts"}, HasPermissionsOptions{ForceAPI: false})
		require.NoError(t, err)
		assert.False(t, result)
	})

	t.Run("returns true when no permissions provided", func(t *testing.T) {
		token := createTestToken(t, map[string]interface{}{})
		apiClient, _ := account_api.NewClient("https://example.com", func(ctx context.Context) (string, error) {
			return "token", nil
		})

		result, err := token.HasPermissions(context.Background(), apiClient, []string{}, HasPermissionsOptions{ForceAPI: false})
		require.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("applies custom conditions", func(t *testing.T) {
		token := createTestToken(t, map[string]interface{}{
			"permissions": []interface{}{"read:users"},
			"org_code":    "org123",
		})

		apiClient, _ := account_api.NewClient("https://example.com", func(ctx context.Context) (string, error) {
			return "token", nil
		})

		// Custom condition that requires specific org code
		customConditions := map[string]PermissionCondition{
			"read:users": func(key, orgCode string) bool {
				return orgCode == "org123"
			},
		}

		result, err := token.HasPermissions(context.Background(), apiClient, []string{"read:users"}, HasPermissionsOptions{
			ForceAPI:        false,
			CustomConditions: customConditions,
		})
		require.NoError(t, err)
		assert.True(t, result)

		// Test with wrong org code
		customConditions["read:users"] = func(key, orgCode string) bool {
			return orgCode == "wrong_org"
		}

		result, err = token.HasPermissions(context.Background(), apiClient, []string{"read:users"}, HasPermissionsOptions{
			ForceAPI:        false,
			CustomConditions: customConditions,
		})
		require.NoError(t, err)
		assert.False(t, result)
	})
}

func TestToken_HasRolesWithAPI(t *testing.T) {
	t.Run("returns true when all roles are present", func(t *testing.T) {
		token := createTestToken(t, map[string]interface{}{
			"roles": []interface{}{
				map[string]interface{}{"id": "1", "name": "Admin", "key": "admin"},
				map[string]interface{}{"id": "2", "name": "Editor", "key": "editor"},
			},
		})

		apiClient, _ := account_api.NewClient("https://example.com", func(ctx context.Context) (string, error) {
			return "token", nil
		})

		result, err := token.HasRolesWithAPI(context.Background(), apiClient, []string{"admin", "editor"}, HasRolesOptions{ForceAPI: false})
		require.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("returns false when any role is missing", func(t *testing.T) {
		token := createTestToken(t, map[string]interface{}{
			"roles": []interface{}{
				map[string]interface{}{"id": "1", "name": "Admin", "key": "admin"},
			},
		})

		apiClient, _ := account_api.NewClient("https://example.com", func(ctx context.Context) (string, error) {
			return "token", nil
		})

		result, err := token.HasRolesWithAPI(context.Background(), apiClient, []string{"admin", "editor"}, HasRolesOptions{ForceAPI: false})
		require.NoError(t, err)
		assert.False(t, result)
	})

	t.Run("applies custom conditions", func(t *testing.T) {
		token := createTestToken(t, map[string]interface{}{
			"roles": []interface{}{
				map[string]interface{}{"id": "1", "name": "Admin", "key": "admin"},
			},
		})

		apiClient, _ := account_api.NewClient("https://example.com", func(ctx context.Context) (string, error) {
			return "token", nil
		})

		customConditions := map[string]RoleCondition{
			"admin": func(role Role) bool {
				return role.Name == "Admin"
			},
		}

		result, err := token.HasRolesWithAPI(context.Background(), apiClient, []string{"admin"}, HasRolesOptions{
			ForceAPI:        false,
			CustomConditions: customConditions,
		})
		require.NoError(t, err)
		assert.True(t, result)
	})
}

func TestToken_HasFeatureFlags(t *testing.T) {
	t.Run("returns true when all flags exist", func(t *testing.T) {
		token := createTestToken(t, map[string]interface{}{
			"feature_flags": map[string]interface{}{
				"flag1": map[string]interface{}{"t": "b", "v": true},
				"flag2": map[string]interface{}{"t": "s", "v": "test"},
			},
		})

		apiClient, _ := account_api.NewClient("https://example.com", func(ctx context.Context) (string, error) {
			return "token", nil
		})

		result, err := token.HasFeatureFlags(context.Background(), apiClient, []string{"flag1", "flag2"}, HasFeatureFlagsOptions{ForceAPI: false})
		require.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("returns false when any flag is missing", func(t *testing.T) {
		token := createTestToken(t, map[string]interface{}{
			"feature_flags": map[string]interface{}{
				"flag1": map[string]interface{}{"t": "b", "v": true},
			},
		})

		apiClient, _ := account_api.NewClient("https://example.com", func(ctx context.Context) (string, error) {
			return "token", nil
		})

		result, err := token.HasFeatureFlags(context.Background(), apiClient, []string{"flag1", "flag2"}, HasFeatureFlagsOptions{ForceAPI: false})
		require.NoError(t, err)
		assert.False(t, result)
	})

	t.Run("checks value matching when condition provided", func(t *testing.T) {
		token := createTestToken(t, map[string]interface{}{
			"feature_flags": map[string]interface{}{
				"flag1": map[string]interface{}{"t": "b", "v": true},
				"flag2": map[string]interface{}{"t": "s", "v": "test"},
			},
		})

		apiClient, _ := account_api.NewClient("https://example.com", func(ctx context.Context) (string, error) {
			return "token", nil
		})

		conditions := map[string]FeatureFlagCondition{
			"flag1": {Value: true},
			"flag2": {Value: "test"},
		}

		result, err := token.HasFeatureFlags(context.Background(), apiClient, []string{"flag1", "flag2"}, HasFeatureFlagsOptions{
			ForceAPI:  false,
			Conditions: conditions,
		})
		require.NoError(t, err)
		assert.True(t, result)

		// Test with wrong value
		conditions["flag1"] = FeatureFlagCondition{Value: false}
		result, err = token.HasFeatureFlags(context.Background(), apiClient, []string{"flag1"}, HasFeatureFlagsOptions{
			ForceAPI:  false,
			Conditions: conditions,
		})
		require.NoError(t, err)
		assert.False(t, result)
	})

	t.Run("handles numeric type mismatches correctly", func(t *testing.T) {
		// JSON unmarshaling produces float64, but condition might be int
		// This test verifies that 100.0 (float64) == 100 (int)
		token := createTestToken(t, map[string]interface{}{
			"feature_flags": map[string]interface{}{
				"max_users": map[string]interface{}{"t": "i", "v": 100.0}, // JSON produces float64
			},
		})

		apiClient, _ := account_api.NewClient("https://example.com", func(ctx context.Context) (string, error) {
			return "token", nil
		})

		// Test with int condition (should match float64 from token)
		conditions := map[string]FeatureFlagCondition{
			"max_users": {Value: 100}, // int
		}

		result, err := token.HasFeatureFlags(context.Background(), apiClient, []string{"max_users"}, HasFeatureFlagsOptions{
			ForceAPI:  false,
			Conditions: conditions,
		})
		require.NoError(t, err)
		assert.True(t, result, "int 100 should match float64 100.0")

		// Test with int64 condition
		conditions["max_users"] = FeatureFlagCondition{Value: int64(100)}
		result, err = token.HasFeatureFlags(context.Background(), apiClient, []string{"max_users"}, HasFeatureFlagsOptions{
			ForceAPI:  false,
			Conditions: conditions,
		})
		require.NoError(t, err)
		assert.True(t, result, "int64 100 should match float64 100.0")

		// Test with different value (should not match)
		conditions["max_users"] = FeatureFlagCondition{Value: 200}
		result, err = token.HasFeatureFlags(context.Background(), apiClient, []string{"max_users"}, HasFeatureFlagsOptions{
			ForceAPI:  false,
			Conditions: conditions,
		})
		require.NoError(t, err)
		assert.False(t, result, "int 200 should not match float64 100.0")
	})
}

func TestToken_HasBillingEntitlements(t *testing.T) {
	t.Run("returns true when all entitlements exist", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(account_api.BaseAccountResponse{
				Metadata: account_api.Metadata{
					HasMore: false,
				},
				Data: map[string]interface{}{
					"org_code": "org123",
					"entitlements": []map[string]interface{}{
						{
							"id":                  "ent1",
							"price_name":          "Basic",
							"feature_key":         "feature1",
							"fixed_charge":        10.0,
							"unit_amount":         5.0,
							"feature_name":        "Feature 1",
							"entitlement_limit_max": 100,
							"entitlement_limit_min": 0,
						},
						{
							"id":                  "ent2",
							"price_name":          "Pro",
							"feature_key":         "feature2",
							"fixed_charge":        20.0,
							"unit_amount":         10.0,
							"feature_name":        "Feature 2",
							"entitlement_limit_max": 200,
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

		result, err := token.HasBillingEntitlements(context.Background(), apiClient, []string{"Basic", "Pro"}, HasBillingEntitlementsOptions{})
		require.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("returns false when any entitlement is missing", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(account_api.BaseAccountResponse{
				Metadata: account_api.Metadata{
					HasMore: false,
				},
				Data: map[string]interface{}{
					"org_code": "org123",
					"entitlements": []map[string]interface{}{
						{
							"id":         "ent1",
							"price_name": "Basic",
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

		result, err := token.HasBillingEntitlements(context.Background(), apiClient, []string{"Basic", "Pro"}, HasBillingEntitlementsOptions{})
		require.NoError(t, err)
		assert.False(t, result)
	})

	t.Run("applies custom conditions", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(account_api.BaseAccountResponse{
				Metadata: account_api.Metadata{
					HasMore: false,
				},
				Data: map[string]interface{}{
					"org_code": "org123",
					"entitlements": []map[string]interface{}{
						{
							"id":                  "ent1",
							"price_name":          "Basic",
							"fixed_charge":        10.0,
							"entitlement_limit_max": 100,
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

		customConditions := map[string]EntitlementCondition{
			"Basic": func(ent Entitlement) bool {
				return ent.FixedCharge >= 10.0 && ent.EntitlementLimitMax >= 100
			},
		}

		result, err := token.HasBillingEntitlements(context.Background(), apiClient, []string{"Basic"}, HasBillingEntitlementsOptions{
			CustomConditions: customConditions,
		})
		require.NoError(t, err)
		assert.True(t, result)

		// Test with condition that fails
		customConditions["Basic"] = func(ent Entitlement) bool {
			return ent.FixedCharge > 100.0
		}

		result, err = token.HasBillingEntitlements(context.Background(), apiClient, []string{"Basic"}, HasBillingEntitlementsOptions{
			CustomConditions: customConditions,
		})
		require.NoError(t, err)
		assert.False(t, result)
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

