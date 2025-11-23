package account_api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	t.Run("creates client with base URL", func(t *testing.T) {
		getToken := func(ctx context.Context) (string, error) {
			return "test-token", nil
		}

		client, err := NewClient("https://example.com", getToken)
		require.NoError(t, err)
		assert.NotNil(t, client)
		assert.Equal(t, "https://example.com", client.baseURL)
	})

	t.Run("removes trailing slash from base URL", func(t *testing.T) {
		getToken := func(ctx context.Context) (string, error) {
			return "test-token", nil
		}

		client, err := NewClient("https://example.com/", getToken)
		require.NoError(t, err)
		assert.Equal(t, "https://example.com", client.baseURL)
	})

	t.Run("applies options", func(t *testing.T) {
		getToken := func(ctx context.Context) (string, error) {
			return "test-token", nil
		}

		customClient := &http.Client{}
		client, err := NewClient("https://example.com", getToken, WithHTTPClient(customClient))
		require.NoError(t, err)
		assert.Equal(t, customClient, client.httpClient)
	})
}

func TestClient_CallAccountAPI(t *testing.T) {
	t.Run("makes successful request", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			assert.Equal(t, "/account_api/v1/test", r.URL.Path)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]string{
					"key": "value",
				},
			})
		}))
		defer server.Close()

		getToken := func(ctx context.Context) (string, error) {
			return "test-token", nil
		}

		client, err := NewClient(server.URL, getToken)
		require.NoError(t, err)

		var result map[string]interface{}
		err = client.CallAccountAPI(context.Background(), "account_api/v1/test", &result)
		require.NoError(t, err)
		assert.Equal(t, "value", result["data"].(map[string]interface{})["key"])
	})

	t.Run("returns error on non-200 status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
		}))
		defer server.Close()

		getToken := func(ctx context.Context) (string, error) {
			return "test-token", nil
		}

		client, err := NewClient(server.URL, getToken)
		require.NoError(t, err)

		var result map[string]interface{}
		err = client.CallAccountAPI(context.Background(), "account_api/v1/test", &result)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "401")
	})

	t.Run("returns error when token is empty", func(t *testing.T) {
		getToken := func(ctx context.Context) (string, error) {
			return "", nil
		}

		client, err := NewClient("https://example.com", getToken)
		require.NoError(t, err)

		var result map[string]interface{}
		err = client.CallAccountAPI(context.Background(), "account_api/v1/test", &result)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "access token is empty")
	})
}

func TestClient_CallAccountAPIPaginated(t *testing.T) {
	t.Run("handles single page response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(BaseAccountResponse{
				Metadata: Metadata{
					HasMore: false,
				},
				Data: []map[string]string{
					{"id": "1", "name": "test1"},
				},
			})
		}))
		defer server.Close()

		getToken := func(ctx context.Context) (string, error) {
			return "test-token", nil
		}

		client, err := NewClient(server.URL, getToken)
		require.NoError(t, err)

		var result []map[string]string
		err = client.CallAccountAPIPaginated(context.Background(), "account_api/v1/test", &result)
		require.NoError(t, err)
		assert.Len(t, result, 1)
		assert.Equal(t, "test1", result[0]["name"])
	})

	t.Run("handles paginated array response", func(t *testing.T) {
		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			if callCount == 1 {
				json.NewEncoder(w).Encode(BaseAccountResponse{
					Metadata: Metadata{
						HasMore:              true,
						NextPageStartingAfter: "cursor1",
					},
					Data: []map[string]string{
						{"id": "1", "name": "test1"},
					},
				})
			} else {
				assert.Equal(t, "cursor1", r.URL.Query().Get("starting_after"))
				json.NewEncoder(w).Encode(BaseAccountResponse{
					Metadata: Metadata{
						HasMore: false,
					},
					Data: []map[string]string{
						{"id": "2", "name": "test2"},
					},
				})
			}
		}))
		defer server.Close()

		getToken := func(ctx context.Context) (string, error) {
			return "test-token", nil
		}

		client, err := NewClient(server.URL, getToken)
		require.NoError(t, err)

		var result []map[string]string
		err = client.CallAccountAPIPaginated(context.Background(), "account_api/v1/test", &result)
		require.NoError(t, err)
		assert.Len(t, result, 2)
		assert.Equal(t, 2, callCount)
	})

	t.Run("handles paginated object response", func(t *testing.T) {
		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			if callCount == 1 {
				json.NewEncoder(w).Encode(BaseAccountResponse{
					Metadata: Metadata{
						HasMore:              true,
						NextPageStartingAfter: "cursor1",
					},
					Data: map[string]interface{}{
						"org_code": "org1",
						"items":    []string{"item1"},
					},
				})
			} else {
				json.NewEncoder(w).Encode(BaseAccountResponse{
					Metadata: Metadata{
						HasMore: false,
					},
					Data: map[string]interface{}{
						"org_code": "org1",
						"items":    []string{"item2"},
					},
				})
			}
		}))
		defer server.Close()

		getToken := func(ctx context.Context) (string, error) {
			return "test-token", nil
		}

		client, err := NewClient(server.URL, getToken)
		require.NoError(t, err)

		type ResultData struct {
			OrgCode string   `json:"org_code"`
			Items   []string `json:"items"`
		}
		var result ResultData
		err = client.CallAccountAPIPaginated(context.Background(), "account_api/v1/test", &result)
		require.NoError(t, err)
		assert.Equal(t, "org1", result.OrgCode)
		assert.Contains(t, result.Items, "item1")
		assert.Contains(t, result.Items, "item2")
		assert.Equal(t, 2, callCount)
	})
}

func TestMergeArrays(t *testing.T) {
	t.Run("merges arrays and removes duplicates", func(t *testing.T) {
		arr1 := []json.RawMessage{
			json.RawMessage(`{"id":"1"}`),
			json.RawMessage(`{"id":"2"}`),
		}
		arr2 := []json.RawMessage{
			json.RawMessage(`{"id":"2"}`),
			json.RawMessage(`{"id":"3"}`),
		}

		result := mergeArrays(arr1, arr2)
		assert.Len(t, result, 3)
	})

	t.Run("handles empty arrays", func(t *testing.T) {
		arr1 := []json.RawMessage{}
		arr2 := []json.RawMessage{
			json.RawMessage(`{"id":"1"}`),
		}

		result := mergeArrays(arr1, arr2)
		assert.Len(t, result, 1)
	})
}

func TestDeepMergeObjects(t *testing.T) {
	t.Run("merges objects", func(t *testing.T) {
		obj1 := map[string]interface{}{
			"key1": "value1",
			"key2": "value2",
		}
		obj2 := map[string]interface{}{
			"key2": "value2-updated",
			"key3": "value3",
		}

		result := deepMergeObjects(obj1, obj2)
		resultMap := result.(map[string]interface{})
		assert.Equal(t, "value1", resultMap["key1"])
		assert.Equal(t, "value2-updated", resultMap["key2"])
		assert.Equal(t, "value3", resultMap["key3"])
	})

	t.Run("merges nested objects", func(t *testing.T) {
		obj1 := map[string]interface{}{
			"nested": map[string]interface{}{
				"key1": "value1",
			},
		}
		obj2 := map[string]interface{}{
			"nested": map[string]interface{}{
				"key2": "value2",
			},
		}

		result := deepMergeObjects(obj1, obj2)
		resultMap := result.(map[string]interface{})
		nested := resultMap["nested"].(map[string]interface{})
		assert.Equal(t, "value1", nested["key1"])
		assert.Equal(t, "value2", nested["key2"])
	})

	t.Run("merges arrays in objects", func(t *testing.T) {
		obj1 := map[string]interface{}{
			"items": []interface{}{"item1", "item2"},
		}
		obj2 := map[string]interface{}{
			"items": []interface{}{"item2", "item3"},
		}

		result := deepMergeObjects(obj1, obj2)
		resultMap := result.(map[string]interface{})
		items := resultMap["items"].([]interface{})
		assert.Len(t, items, 3)
	})
}

