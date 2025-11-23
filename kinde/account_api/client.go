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

// Client represents an Account API client that uses the user's access token.
// The getToken function should return the access token string.
type Client struct {
	httpClient *http.Client
	baseURL    string
	getToken   func(ctx context.Context) (string, error)
}

// ClientOption is a function that configures a Client.
type ClientOption func(*Client)

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = client
	}
}

// NewClient creates a new Account API client.
// The getToken function should return the access token string.
func NewClient(baseURL string, getToken func(ctx context.Context) (string, error), opts ...ClientOption) (*Client, error) {
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

// callAPI makes an authenticated request to the Account API.
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

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return body, nil
}

// Metadata represents pagination metadata in Account API responses.
type Metadata struct {
	HasMore              bool   `json:"has_more"`
	NextPageStartingAfter string `json:"next_page_starting_after"`
}

// BaseAccountResponse represents the base structure of Account API responses.
type BaseAccountResponse struct {
	Metadata Metadata    `json:"metadata"`
	Data     interface{} `json:"data"`
}

// CallAccountAPI makes a single request to the Account API.
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

// CallAccountAPIPaginated makes paginated requests to the Account API and merges all results.
// It automatically handles pagination by following the next_page_starting_after cursor.
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

// paginateArray handles pagination for array responses (permissions, roles, feature flags).
func (c *Client) paginateArray(ctx context.Context, route string, firstResponse BaseAccountResponse, firstData []json.RawMessage, result interface{}) error {
	allDataItems := make([]json.RawMessage, len(firstData))
	copy(allDataItems, firstData)

	nextPageStartingAfter := firstResponse.Metadata.NextPageStartingAfter
	currentResponse := firstResponse

	for currentResponse.Metadata.HasMore {
		// Build URL with pagination parameter
		u, err := url.Parse(fmt.Sprintf("%s/%s", c.baseURL, route))
		if err != nil {
			return fmt.Errorf("failed to parse URL: %w", err)
		}
		q := u.Query()
		q.Set("starting_after", nextPageStartingAfter)
		u.RawQuery = q.Encode()

		// Make request with pagination
		var pageResponse BaseAccountResponse
		pageBody, err := c.callAPI(ctx, fmt.Sprintf("%s?%s", route, u.RawQuery))
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

// paginateObject handles pagination for object responses (entitlements).
func (c *Client) paginateObject(ctx context.Context, route string, firstResponse BaseAccountResponse, firstData interface{}, result interface{}) error {
	allData := firstData

	nextPageStartingAfter := firstResponse.Metadata.NextPageStartingAfter
	currentResponse := firstResponse

	for currentResponse.Metadata.HasMore {
		// Build URL with pagination parameter
		u, err := url.Parse(fmt.Sprintf("%s/%s", c.baseURL, route))
		if err != nil {
			return fmt.Errorf("failed to parse URL: %w", err)
		}
		q := u.Query()
		q.Set("starting_after", nextPageStartingAfter)
		u.RawQuery = q.Encode()

		// Make request with pagination
		var pageResponse BaseAccountResponse
		pageBody, err := c.callAPI(ctx, fmt.Sprintf("%s?%s", route, u.RawQuery))
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


// mergeArrays merges two arrays and removes duplicates.
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

// marshalArray converts an array of RawMessage to JSON bytes.
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

// deepMergeObjects deeply merges two objects.
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

// mergeInterfaceArrays merges two []interface{} arrays and removes duplicates.
func mergeInterfaceArrays(arr1, arr2 []interface{}) []interface{} {
	seen := make(map[string]bool)
	result := []interface{}{}

	for _, item := range arr1 {
		key := fmt.Sprintf("%v", item)
		if !seen[key] {
			seen[key] = true
			result = append(result, item)
		}
	}

	for _, item := range arr2 {
		key := fmt.Sprintf("%v", item)
		if !seen[key] {
			seen[key] = true
			result = append(result, item)
		}
	}

	return result
}

