package gin_kinde

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/kinde-oss/kinde-go/agents"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	agentAppID       = "0123456789abcdef0123456789abcdef"
	agentResourceURL = "https://api.example.com/mcp"
)

// newAgentTestRouter protects /mcp and /docs with an introspection server that accepts activeToken.
func newAgentTestRouter(t *testing.T) (*gin.Engine, string) {
	t.Helper()
	activeToken, err := golangjwt.NewWithClaims(golangjwt.SigningMethodHS256, golangjwt.MapClaims{
		"sub":         "kp_user",
		"permissions": []string{"read:docs"},
		"exp":         time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte("test"))
	require.NoError(t, err)

	kinde := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		active := r.URL.Path == "/oauth2/agents/"+agentAppID+"/introspect" && r.PostForm.Get("token") == activeToken
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"active": active, "aud": []string{agentResourceURL}})
	}))
	t.Cleanup(kinde.Close)

	auth, err := agents.NewKindeAgentAuth(agents.Config{
		Domain:       kinde.URL,
		ClientID:     agentAppID,
		ClientSecret: "secret",
		ResourceURL:  agentResourceURL,
	})
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	MountProtectedResourceMetadata(router, auth)
	router.POST("/mcp", UseKindeAgentAuth(auth), func(c *gin.Context) {
		ac, ok := AgentAuthFromContext(c)
		if !ok {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.String(http.StatusOK, ac.UserID)
	})
	router.GET("/docs", UseKindeAgentAuth(auth), RequireAgentPermission("write:docs"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	return router, activeToken
}

func TestKindeAgentAuth(t *testing.T) {
	t.Parallel()
	router, activeToken := newAgentTestRouter(t)

	do := func(method, path, authorization string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	t.Run("serves protected resource metadata on both paths", func(t *testing.T) {
		for _, path := range []string{"/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"} {
			rec := do(http.MethodGet, path, "")
			require.Equal(t, http.StatusOK, rec.Code, path)
			var prm agents.ProtectedResourceMetadata
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &prm))
			assert.Equal(t, agentResourceURL, prm.Resource)
			assert.Contains(t, prm.ScopesSupported, "offline")
			assert.Equal(t, http.StatusNoContent, do(http.MethodOptions, path, "").Code)
		}
	})

	t.Run("missing token gets a 401 challenge", func(t *testing.T) {
		rec := do(http.MethodPost, "/mcp", "")
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, `Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp"`, rec.Header().Get("WWW-Authenticate"))
	})

	t.Run("inactive token gets invalid_token", func(t *testing.T) {
		rec := do(http.MethodPost, "/mcp", "Bearer "+activeToken+"x")
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
	})

	t.Run("valid token reaches the handler with the auth context", func(t *testing.T) {
		rec := do(http.MethodPost, "/mcp", "Bearer "+activeToken)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "kp_user", rec.Body.String())
	})

	t.Run("missing permission gets a plain 403", func(t *testing.T) {
		rec := do(http.MethodGet, "/docs", "Bearer "+activeToken)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Empty(t, rec.Header().Get("WWW-Authenticate"))
	})
}
