package account_api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Client is the Account API client for making authenticated requests to the Kinde Account API.
// It handles authentication, request formatting, pagination, and response parsing.
//
// The getToken function should return a valid access token string for authentication.
type Client struct {
	// httpClient is the HTTP client used for making requests. Can be customized via WithHTTPClient option.
	httpClient *http.Client
	// baseURL is the base URL for the Kinde Account API (e.g., "https://yourdomain.kinde.com").
	baseURL string
	// getToken is a function that returns an access token for authenticating API requests.
	getToken func(ctx context.Context) (string, error)
}

// ClientOption is a function that configures a Client during initialization.
// Options are passed to NewClient to customize the client's behavior.
type ClientOption func(*Client)

// WithHTTPClient returns a ClientOption that sets a custom HTTP client.
// Use this to configure timeouts, transport settings, or other HTTP client behavior.
//
// Example:
//
//	httpClient := &http.Client{Timeout: 30 * time.Second}
//	client := NewClient(baseURL, getToken, WithHTTPClient(httpClient))
func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = client
	}
}

// NewClient creates a new Account API client for making authenticated requests to the Kinde Account API.
//
// Parameters:
//   - baseURL: The base URL for your Kinde instance (e.g., "https://yourdomain.kinde.com")
//   - getToken: A function that returns a valid access token for authentication. This function
//     is called before each API request to obtain a fresh token.
//   - opts: Optional configuration options (e.g., WithHTTPClient to customize the HTTP client)
//
// Returns an error if the baseURL is empty or if any configuration option fails.
//
// Example:
//
//	client, err := NewClient(
//	    "https://yourdomain.kinde.com",
//	    func(ctx context.Context) (string, error) {
//	        return token.GetAccessToken(), nil
//	    },
//	    WithHTTPClient(&http.Client{Timeout: 30 * time.Second}),
//	)
func NewClient(baseURL string, getToken func(ctx context.Context) (string, error), opts ...ClientOption) (*Client, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("baseURL cannot be empty")
	}
	if getToken == nil {
		return nil, fmt.Errorf("getToken function cannot be nil")
	}

	// Remove trailing slash
	baseURL = strings.TrimSuffix(baseURL, "/")

	client := &Client{
		httpClient: http.DefaultClient,
		baseURL:    baseURL,
		getToken:   getToken,
	}

	for _, opt := range opts {
		opt(client)
	}

	return client, nil
}

// callAPI makes an authenticated HTTP GET request to the Account API.
//
// It obtains an access token using the configured getToken function, constructs the full URL,
// and makes a GET request with the Authorization header. The raw response body is returned
// without parsing or pagination handling.
//
// This is an internal helper method used by CallAccountAPI and CallAccountAPIPaginated.
func (c *Client) callAPI(ctx context.Context, route string) ([]byte, error) {
	accessToken, err := c.getToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	if accessToken == "" {
		return nil, fmt.Errorf("access token is empty")
	}

	// Build URL
	apiURL := fmt.Sprintf("%s/%s", c.baseURL, route)
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set authorization header
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Content-Type", "application/json")

	// Make request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body once (can only be read once)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// Metadata represents pagination metadata in Account API responses.
// It contains the cursor information needed to fetch the next page of results.
type Metadata struct {
	// HasMore indicates whether there are more pages of results available.
	HasMore bool `json:"has_more"`
	// NextPageStartingAfter is the cursor value for the next page of results.
	// Empty if there are no more pages to fetch.
	NextPageStartingAfter string `json:"next_page_starting_after"`
}

// BaseAccountResponse represents the base structure of Account API responses.
// All Account API responses include this metadata for pagination support.
type BaseAccountResponse struct {
	// Metadata contains pagination information, including whether there are more pages
	// and the cursor for the next page.
	Metadata Metadata `json:"metadata"`
	// Data contains the response payload, which varies by endpoint.
	Data interface{} `json:"data"`
}

// CallAccountAPI makes a single authenticated request to the Account API.
//
// This method does NOT handle pagination - it only fetches the first page of results.
// For paginated results, use CallAccountAPIPaginated instead.
//
// Parameters:
//   - ctx: Context for the request
//   - route: The API route path (e.g., "account_api/v1/permissions")
//   - result: Pointer to a struct where the JSON response will be unmarshaled
//
// Returns an error if the request fails or the response cannot be parsed.
func (c *Client) CallAccountAPI(ctx context.Context, route string, result interface{}) error {
	body, err := c.callAPI(ctx, route)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(body, result); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return nil
}

// CallAccountAPIPaginated makes authenticated requests to the Account API with automatic pagination.
//
// This method automatically handles pagination by following the next_page_starting_after cursor
// until all pages have been fetched. It intelligently merges results from multiple pages:
//   - For array responses (permissions, roles, feature_flags): Concatenates arrays and removes duplicates
//   - For object responses (entitlements): Deep merges objects, preserving all unique data
//
// Parameters:
//   - ctx: Context for the requests (all paginated requests share this context)
//   - route: The API route path (e.g., "account_api/v1/permissions")
//   - result: Pointer to a struct where the merged JSON response will be unmarshaled.
//     The struct should match the API response format (without pagination metadata).
//
// Returns an error if any request fails or the response cannot be parsed.
//
// Example:
//
//	type PermissionsResponse struct {
//	    OrgCode     string `json:"org_code"`
//	    Permissions []struct {
//	        ID   string `json:"id"`
//	        Name string `json:"name"`
//	    } `json:"permissions"`
//	}
//	var result PermissionsResponse
//	err := client.CallAccountAPIPaginated(ctx, "account_api/v1/permissions", &result)
func (c *Client) CallAccountAPIPaginated(ctx context.Context, route string, result interface{}) error {
	// First request
	var firstResponse BaseAccountResponse
	if err := c.CallAccountAPI(ctx, route, &firstResponse); err != nil {
		return err
	}

	// If no more pages, return first response data directly
	if !firstResponse.Metadata.HasMore {
		dataBytes, err := json.Marshal(firstResponse.Data)
		if err != nil {
			return fmt.Errorf("failed to marshal response data: %w", err)
		}
		return json.Unmarshal(dataBytes, result)
	}

	// Check if data is an array or object
	dataBytes, err := json.Marshal(firstResponse.Data)
	if err != nil {
		return fmt.Errorf("failed to marshal first response data: %w", err)
	}

	// Try to unmarshal as array first
	var dataArray []json.RawMessage
	if err := json.Unmarshal(dataBytes, &dataArray); err == nil {
		// It's an array - handle array pagination
		return c.paginateArray(ctx, route, firstResponse, dataArray, result)
	}

	// It's an object - handle object pagination
	return c.paginateObject(ctx, route, firstResponse, firstResponse.Data, result)
}

// paginateArray handles pagination for array-type API responses.
//
// This method is used for endpoints that return arrays (e.g., permissions, roles, feature_flags).
// It fetches all pages by following the next_page_starting_after cursor, concatenates the arrays,
// and removes duplicate entries based on JSON comparison.
//
// This is an internal helper method used by CallAccountAPIPaginated.
func (c *Client) paginateArray(ctx context.Context, route string, firstResponse BaseAccountResponse, firstData []json.RawMessage, result interface{}) error {
	allDataItems := make([]json.RawMessage, len(firstData))
	copy(allDataItems, firstData)

	nextPageStartingAfter := firstResponse.Metadata.NextPageStartingAfter
	currentResponse := firstResponse

	for currentResponse.Metadata.HasMore {
		// Build URL with pagination parameter
		// Parse route to preserve existing query parameters
		routeURL, err := url.Parse(route)
		if err != nil {
			return fmt.Errorf("failed to parse route: %w", err)
		}
		q := routeURL.Query()
		q.Set("starting_after", nextPageStartingAfter)
		routeURL.RawQuery = q.Encode()

		// Make request with pagination
		var pageResponse BaseAccountResponse
		pageBody, err := c.callAPI(ctx, routeURL.String())
		if err != nil {
			return err
		}

		if err := json.Unmarshal(pageBody, &pageResponse); err != nil {
			return fmt.Errorf("failed to unmarshal page response: %w", err)
		}

		// Extract page data
		pageDataBytes, err := json.Marshal(pageResponse.Data)
		if err != nil {
			return fmt.Errorf("failed to marshal page response data: %w", err)
		}

		var pageDataItems []json.RawMessage
		if err := json.Unmarshal(pageDataBytes, &pageDataItems); err != nil {
			return fmt.Errorf("failed to unmarshal page data items: %w", err)
		}

		// Merge arrays (deduplicate)
		allDataItems = mergeArrays(allDataItems, pageDataItems)

		// Update for next iteration
		currentResponse = pageResponse
		nextPageStartingAfter = pageResponse.Metadata.NextPageStartingAfter
	}

	// Unmarshal merged results
	return json.Unmarshal(marshalArray(allDataItems), result)
}

// paginateObject handles pagination for object-type API responses.
//
// This method is used for endpoints that return objects (e.g., entitlements).
// It fetches all pages by following the next_page_starting_after cursor and performs
// deep merging of objects to combine data from all pages while preserving all fields.
//
// This is an internal helper method used by CallAccountAPIPaginated.
func (c *Client) paginateObject(ctx context.Context, route string, firstResponse BaseAccountResponse, firstData interface{}, result interface{}) error {
	allData := firstData

	nextPageStartingAfter := firstResponse.Metadata.NextPageStartingAfter
	currentResponse := firstResponse

	for currentResponse.Metadata.HasMore {
		// Build URL with pagination parameter
		// Parse route to preserve existing query parameters
		routeURL, err := url.Parse(route)
		if err != nil {
			return fmt.Errorf("failed to parse route: %w", err)
		}
		q := routeURL.Query()
		q.Set("starting_after", nextPageStartingAfter)
		routeURL.RawQuery = q.Encode()

		// Make request with pagination
		var pageResponse BaseAccountResponse
		pageBody, err := c.callAPI(ctx, routeURL.String())
		if err != nil {
			return err
		}

		if err := json.Unmarshal(pageBody, &pageResponse); err != nil {
			return fmt.Errorf("failed to unmarshal page response: %w", err)
		}

		// Merge objects
		allData = deepMergeObjects(allData, pageResponse.Data)

		// Update for next iteration
		currentResponse = pageResponse
		nextPageStartingAfter = pageResponse.Metadata.NextPageStartingAfter
	}

	// Unmarshal merged result
	resultBytes, err := json.Marshal(allData)
	if err != nil {
		return fmt.Errorf("failed to marshal merged data: %w", err)
	}

	return json.Unmarshal(resultBytes, result)
}

// mergeArrays merges two JSON arrays and removes duplicate entries.
//
// Deduplication is done by comparing the raw JSON bytes of each element.
// This ensures that identical JSON objects are not duplicated even if they
// appear in both arrays.
//
// This is an internal helper used by paginateArray to combine results from multiple pages.
func mergeArrays(arr1, arr2 []json.RawMessage) []json.RawMessage {
	seen := make(map[string]bool)
	result := []json.RawMessage{}

	// Add items from first array
	for _, item := range arr1 {
		key := string(item)
		if !seen[key] {
			seen[key] = true
			result = append(result, item)
		}
	}

	// Add items from second array
	for _, item := range arr2 {
		key := string(item)
		if !seen[key] {
			seen[key] = true
			result = append(result, item)
		}
	}

	return result
}

// marshalArray efficiently converts an array of json.RawMessage to JSON bytes.
//
// This avoids the overhead of marshaling/unmarshaling by directly constructing
// the JSON array syntax with the pre-encoded RawMessage elements.
//
// This is an internal helper used by paginateArray to re-marshal merged results.
func marshalArray(arr []json.RawMessage) []byte {
	if len(arr) == 0 {
		return []byte("[]")
	}

	result := []byte("[")
	for i, item := range arr {
		if i > 0 {
			result = append(result, ',')
		}
		result = append(result, item...)
	}
	result = append(result, ']')
	return result
}

// deepMergeObjects recursively merges two JSON objects.
//
// For each key:
//   - If both values are maps, recursively merges them
//   - If both values are arrays, merges and deduplicates the arrays
//   - Otherwise, the value from obj2 overwrites the value from obj1
//
// This preserves all unique data from both objects while handling nested structures.
//
// This is an internal helper used by paginateObject to combine object results from multiple pages.
func deepMergeObjects(obj1, obj2 interface{}) interface{} {
	obj1Map, ok1 := obj1.(map[string]interface{})
	obj2Map, ok2 := obj2.(map[string]interface{})

	if !ok1 || !ok2 {
		// If either is not a map, return obj2
		return obj2
	}

	merged := make(map[string]interface{})
	for k, v := range obj1Map {
		merged[k] = v
	}

	for k, v := range obj2Map {
		if existing, exists := merged[k]; exists {
			// If both are arrays, merge them
			if arr1, ok1 := existing.([]interface{}); ok1 {
				if arr2, ok2 := v.([]interface{}); ok2 {
					merged[k] = mergeInterfaceArrays(arr1, arr2)
					continue
				}
			}
			// If both are maps, recursively merge
			if map1, ok1 := existing.(map[string]interface{}); ok1 {
				if map2, ok2 := v.(map[string]interface{}); ok2 {
					merged[k] = deepMergeObjects(map1, map2)
					continue
				}
			}
		}
		merged[k] = v
	}

	return merged
}

// mergeInterfaceArrays merges two interface{} arrays and removes duplicate entries.
//
// Deduplication is done by JSON marshaling each element to create a consistent
// comparison key. This ensures reliable deduplication even for complex nested objects,
// maps, and structures, unlike string formatting which can be inconsistent.
//
// If JSON marshaling fails for an item, the item is included in the result without
// deduplication to prevent data loss. This ensures that unmarshalable items are
// not incorrectly dropped from the merged array.
//
// This is an internal helper used by deepMergeObjects when merging arrays within objects.
func mergeInterfaceArrays(arr1, arr2 []interface{}) []interface{} {
	seen := make(map[string]bool)
	result := []interface{}{}

	for _, item := range arr1 {
		keyBytes, err := json.Marshal(item)
		if err != nil {
			// If marshaling fails, include the item without deduplication
			result = append(result, item)
			continue
		}
		key := string(keyBytes)
		if !seen[key] {
			seen[key] = true
			result = append(result, item)
		}
	}

	for _, item := range arr2 {
		keyBytes, err := json.Marshal(item)
		if err != nil {
			// If marshaling fails, include the item without deduplication
			result = append(result, item)
			continue
		}
		key := string(keyBytes)
		if !seen[key] {
			seen[key] = true
			result = append(result, item)
		}
	}

	return result
}
