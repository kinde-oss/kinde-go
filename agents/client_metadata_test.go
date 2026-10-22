package agents

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildClientMetadataDocument(t *testing.T) {
	t.Parallel()

	valid := ClientMetadataOptions{
		ClientID:     "https://agent.example.com/oauth/client-metadata.json",
		ClientName:   "Example Agent",
		RedirectURIs: []string{"https://agent.example.com/oauth/callback", "http://127.0.0.1/callback", "http://localhost:8080/cb", "http://[::1]/cb"},
	}

	t.Run("builds a public client document", func(t *testing.T) {
		doc, err := BuildClientMetadataDocument(valid)
		require.NoError(t, err)
		assert.Equal(t, valid.ClientID, doc.ClientID)
		assert.Equal(t, []string{"authorization_code", "refresh_token"}, doc.GrantTypes)
		assert.Equal(t, []string{"code"}, doc.ResponseTypes)
		assert.Equal(t, "none", doc.TokenEndpointAuthMethod)
	})

	t.Run("rejects invalid documents", func(t *testing.T) {
		cases := map[string]func(o *ClientMetadataOptions){
			"client_id without a path":   func(o *ClientMetadataOptions) { o.ClientID = "https://agent.example.com" },
			"client_id with root path":   func(o *ClientMetadataOptions) { o.ClientID = "https://agent.example.com/" },
			"client_id over http":        func(o *ClientMetadataOptions) { o.ClientID = "http://agent.example.com/cimd.json" },
			"client_id with a query":     func(o *ClientMetadataOptions) { o.ClientID = "https://agent.example.com/cimd.json?x=1" },
			"client_id with userinfo":    func(o *ClientMetadataOptions) { o.ClientID = "https://u:p@agent.example.com/cimd.json" },
			"empty client_name":          func(o *ClientMetadataOptions) { o.ClientName = " " },
			"no redirect URIs":           func(o *ClientMetadataOptions) { o.RedirectURIs = nil },
			"redirect on another host":   func(o *ClientMetadataOptions) { o.RedirectURIs = []string{"https://evil.example.com/cb"} },
			"custom scheme redirect":     func(o *ClientMetadataOptions) { o.RedirectURIs = []string{"myapp://callback"} },
			"http non-loopback redirect": func(o *ClientMetadataOptions) { o.RedirectURIs = []string{"http://agent.example.com/cb"} },
			"redirect with fragment":     func(o *ClientMetadataOptions) { o.RedirectURIs = []string{"http://127.0.0.1/cb#x"} },
		}
		for name, mutate := range cases {
			opts := valid
			opts.RedirectURIs = append([]string(nil), valid.RedirectURIs...)
			mutate(&opts)
			_, err := BuildClientMetadataDocument(opts)
			assert.Error(t, err, name)
		}
	})
}

func TestClientMetadataHandler(t *testing.T) {
	t.Parallel()
	doc, err := BuildClientMetadataDocument(ClientMetadataOptions{
		ClientID:     "https://agent.example.com/oauth/client-metadata.json",
		ClientName:   "Example Agent",
		RedirectURIs: []string{"http://127.0.0.1/callback"},
	})
	require.NoError(t, err)
	handler, err := ClientMetadataHandler(doc)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/client-metadata.json", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "public, max-age=3600", rec.Header().Get("Cache-Control"))
	assert.JSONEq(t, `{
		"client_id": "https://agent.example.com/oauth/client-metadata.json",
		"client_name": "Example Agent",
		"redirect_uris": ["http://127.0.0.1/callback"],
		"grant_types": ["authorization_code", "refresh_token"],
		"response_types": ["code"],
		"token_endpoint_auth_method": "none"
	}`, rec.Body.String())

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/oauth/client-metadata.json", nil))
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}
