package agents

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithSecureRedirects(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/insecure":
			http.Redirect(w, r, "http://example.com/metadata", http.StatusFound)
		case "/loopback":
			http.Redirect(w, r, "/ok", http.StatusFound)
		case "/ok":
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(server.Close)

	t.Run("refuses a redirect to plain http", func(t *testing.T) {
		_, err := withSecureRedirects(server.Client()).Get(server.URL + "/insecure")
		assert.ErrorContains(t, err, "refusing redirect")
	})

	t.Run("follows a redirect to loopback http", func(t *testing.T) {
		resp, err := withSecureRedirects(server.Client()).Get(server.URL + "/loopback")
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("keeps the caller's own redirect policy", func(t *testing.T) {
		client := server.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		resp, err := withSecureRedirects(client).Get(server.URL + "/loopback")
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusFound, resp.StatusCode)
	})
}
