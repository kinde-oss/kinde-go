package agents

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testAppID       = "0123456789abcdef0123456789abcdef"
	testAppSecret   = "app-secret"
	testResourceURL = "https://api.example.com/mcp"
)

// fakeKinde serves the application's introspection endpoint and the domain's JWKS.
type fakeKinde struct {
	server     *httptest.Server
	key        *rsa.PrivateKey
	jwksHits   atomic.Int32
	mu         sync.Mutex
	introspect func(w http.ResponseWriter, r *http.Request)
}

func newFakeKinde(t *testing.T) *fakeKinde {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	f := &fakeKinde{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks", func(w http.ResponseWriter, r *http.Request) {
		f.jwksHits.Add(1)
		writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "kid-1", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/oauth2/agents/"+testAppID+"/introspect", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		handler := f.introspect
		f.mu.Unlock()
		handler(w, r)
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeKinde) setIntrospect(h func(w http.ResponseWriter, r *http.Request)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.introspect = h
}

func (f *fakeKinde) claims() golangjwt.MapClaims {
	return golangjwt.MapClaims{
		"iss":         f.server.URL,
		"aud":         []string{testResourceURL},
		"sub":         "kp_user",
		"azp":         "https://claude.ai/oauth/claude-code-client-metadata",
		"scp":         []string{"offline"},
		"email":       "user@example.com",
		"org_code":    "org_123",
		"permissions": []string{"read:docs"},
		"roles":       []map[string]string{{"id": "r1", "key": "admin", "name": "Admin"}},
		"exp":         time.Now().Add(time.Hour).Unix(),
		"iat":         time.Now().Unix(),
	}
}

func (f *fakeKinde) sign(t *testing.T, claims golangjwt.MapClaims, kid string) string {
	t.Helper()
	token := golangjwt.NewWithClaims(golangjwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(f.key)
	require.NoError(t, err)
	return signed
}

func newTestAuth(t *testing.T, f *fakeKinde, cfg Config) *KindeAgentAuth {
	t.Helper()
	cfg.Domain = f.server.URL
	cfg.ClientID = testAppID
	if cfg.ClientSecret == "" {
		cfg.ClientSecret = testAppSecret
	}
	cfg.ResourceURL = testResourceURL
	auth, err := NewKindeAgentAuth(cfg)
	require.NoError(t, err)
	return auth
}

func serve(auth *KindeAgentAuth, authorization string) (*httptest.ResponseRecorder, *AuthContext) {
	var got *AuthContext
	handler := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = AuthFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec, got
}

func activeIntrospection(aud any) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"active": true, "aud": aud, "exp": time.Now().Add(time.Hour).Unix(), "sub": "kp_user"})
	}
}

func TestNewKindeAgentAuth(t *testing.T) {
	t.Parallel()
	f := newFakeKinde(t)

	t.Run("derives the scoped issuer and metadata URLs", func(t *testing.T) {
		auth, err := NewKindeAgentAuth(Config{Domain: "yourbiz.kinde.com/", ClientID: testAppID, ClientSecret: "s", ResourceURL: testResourceURL})
		require.NoError(t, err)
		assert.Equal(t, "https://yourbiz.kinde.com/oauth2/agents/"+testAppID, auth.Issuer())
		assert.Equal(t, "https://api.example.com/.well-known/oauth-protected-resource/mcp", auth.ProtectedResourceMetadataURL())
		assert.Equal(t, []string{"/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"}, auth.ProtectedResourceMetadataPaths())
	})

	t.Run("root resource serves only the root path", func(t *testing.T) {
		auth, err := NewKindeAgentAuth(Config{Domain: "https://yourbiz.kinde.com", ClientID: testAppID, ClientSecret: "s", ResourceURL: "https://api.example.com/"})
		require.NoError(t, err)
		assert.Equal(t, []string{"/.well-known/oauth-protected-resource"}, auth.ProtectedResourceMetadataPaths())
	})

	t.Run("rejects invalid configuration", func(t *testing.T) {
		for name, cfg := range map[string]Config{
			"no domain":            {ClientID: testAppID, ClientSecret: "s", ResourceURL: testResourceURL},
			"http domain":          {Domain: "http://yourbiz.kinde.com", ClientID: testAppID, ClientSecret: "s", ResourceURL: testResourceURL},
			"no client id":         {Domain: f.server.URL, ClientSecret: "s", ResourceURL: testResourceURL},
			"introspect no secret": {Domain: f.server.URL, ClientID: testAppID, ResourceURL: testResourceURL},
			"http resource":        {Domain: f.server.URL, ClientID: testAppID, ClientSecret: "s", ResourceURL: "http://api.example.com/mcp"},
			"unknown verification": {Domain: f.server.URL, ClientID: testAppID, ClientSecret: "s", ResourceURL: testResourceURL, Verification: "magic"},
		} {
			_, err := NewKindeAgentAuth(cfg)
			assert.Error(t, err, name)
		}
	})

	t.Run("jwt verification needs no secret", func(t *testing.T) {
		_, err := NewKindeAgentAuth(Config{Domain: f.server.URL, ClientID: testAppID, ResourceURL: testResourceURL, Verification: VerificationJWT})
		assert.NoError(t, err)
	})
}

func TestProtectedResourceMetadataHandler(t *testing.T) {
	t.Parallel()
	f := newFakeKinde(t)

	t.Run("serves the exact fields", func(t *testing.T) {
		auth := newTestAuth(t, f, Config{ResourceName: "Docs"})
		rec := httptest.NewRecorder()
		auth.ProtectedResourceMetadataHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/mcp", nil))
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		assert.JSONEq(t, `{
			"resource": "https://api.example.com/mcp",
			"authorization_servers": ["`+f.server.URL+`/oauth2/agents/`+testAppID+`"],
			"bearer_methods_supported": ["header"],
			"scopes_supported": ["offline"],
			"resource_name": "Docs"
		}`, rec.Body.String())
	})

	t.Run("adds offline to custom scopes", func(t *testing.T) {
		auth := newTestAuth(t, f, Config{ScopesSupported: []string{"profile", "email"}})
		assert.Equal(t, []string{"profile", "email", "offline"}, auth.ProtectedResourceMetadata().ScopesSupported)
	})

	t.Run("allows CORS preflight", func(t *testing.T) {
		auth := newTestAuth(t, f, Config{})
		rec := httptest.NewRecorder()
		auth.ProtectedResourceMetadataHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodOptions, "/.well-known/oauth-protected-resource", nil))
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Contains(t, rec.Header().Get("Access-Control-Allow-Methods"), "GET")
	})
}

func TestMiddlewareIntrospection(t *testing.T) {
	t.Parallel()

	t.Run("no Authorization header", func(t *testing.T) {
		f := newFakeKinde(t)
		auth := newTestAuth(t, f, Config{})
		rec, _ := serve(auth, "")
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		challenge := rec.Header().Get("WWW-Authenticate")
		assert.Equal(t, `Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp"`, challenge)
		assert.NotContains(t, challenge, "error=")
	})

	t.Run("non-Bearer Authorization header", func(t *testing.T) {
		f := newFakeKinde(t)
		auth := newTestAuth(t, f, Config{})
		for _, header := range []string{"Basic dXNlcjpwYXNz", "Bearer", "Bearer  two-spaces", "Bearer a b"} {
			rec, _ := serve(auth, header)
			assert.Equal(t, http.StatusUnauthorized, rec.Code, header)
			assert.Equal(t, "invalid_token", bearerParam(rec.Header().Values("WWW-Authenticate"), "error"), header)
			assert.NotEmpty(t, bearerParam(rec.Header().Values("WWW-Authenticate"), "resource_metadata"), header)
		}
	})

	t.Run("active token for this resource", func(t *testing.T) {
		f := newFakeKinde(t)
		var gotUser, gotPass, gotToken string
		var gotOK bool
		f.setIntrospect(func(w http.ResponseWriter, r *http.Request) {
			gotUser, gotPass, gotOK = r.BasicAuth()
			_ = r.ParseForm()
			gotToken = r.PostForm.Get("token")
			activeIntrospection([]string{testResourceURL, "https://other.example.com"})(w, r)
		})
		auth := newTestAuth(t, f, Config{})
		token := f.sign(t, f.claims(), "kid-1")

		rec, ac := serve(auth, "bearer "+token)
		require.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, gotOK)
		assert.Equal(t, testAppID, gotUser, "introspection uses the application's credentials")
		assert.Equal(t, testAppSecret, gotPass)
		assert.Equal(t, token, gotToken)

		require.NotNil(t, ac)
		assert.Equal(t, "kp_user", ac.UserID)
		assert.Equal(t, "user@example.com", ac.Email)
		assert.Equal(t, "org_123", ac.OrgCode)
		assert.Equal(t, []string{"read:docs"}, ac.Permissions)
		assert.Equal(t, []string{"admin"}, ac.Roles)
		assert.Equal(t, []string{"offline"}, ac.Scopes)
		assert.Equal(t, "https://claude.ai/oauth/claude-code-client-metadata", ac.ClientID)
		assert.NotZero(t, ac.ExpiresAt)
		assert.NotContains(t, ac.String(), token, "String must not print the token")
	})

	t.Run("inactive token", func(t *testing.T) {
		f := newFakeKinde(t)
		f.setIntrospect(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{"active": false})
		})
		rec, _ := serve(newTestAuth(t, f, Config{}), "Bearer "+f.sign(t, f.claims(), "kid-1"))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "invalid_token", bearerParam(rec.Header().Values("WWW-Authenticate"), "error"))
	})

	t.Run("audience without the resource URL", func(t *testing.T) {
		f := newFakeKinde(t)
		f.setIntrospect(activeIntrospection("https://other.example.com/mcp"))
		rec, _ := serve(newTestAuth(t, f, Config{}), "Bearer "+f.sign(t, f.claims(), "kid-1"))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("expired according to introspection", func(t *testing.T) {
		f := newFakeKinde(t)
		f.setIntrospect(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{"active": true, "aud": testResourceURL, "exp": time.Now().Add(-time.Hour).Unix()})
		})
		rec, _ := serve(newTestAuth(t, f, Config{}), "Bearer "+f.sign(t, f.claims(), "kid-1"))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("introspection 5xx answers 503, never 401", func(t *testing.T) {
		f := newFakeKinde(t)
		f.setIntrospect(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadGateway) })
		rec, _ := serve(newTestAuth(t, f, Config{}), "Bearer "+f.sign(t, f.claims(), "kid-1"))
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Empty(t, rec.Header().Get("WWW-Authenticate"))
	})

	t.Run("introspection rejecting the app credentials answers 503", func(t *testing.T) {
		f := newFakeKinde(t)
		f.setIntrospect(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
		rec, _ := serve(newTestAuth(t, f, Config{}), "Bearer "+f.sign(t, f.claims(), "kid-1"))
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	})

	t.Run("introspection timeout answers 503", func(t *testing.T) {
		f := newFakeKinde(t)
		f.setIntrospect(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(200 * time.Millisecond)
			activeIntrospection(testResourceURL)(w, r)
		})
		auth := newTestAuth(t, f, Config{HTTPClient: &http.Client{Timeout: 50 * time.Millisecond}})
		rec, _ := serve(auth, "Bearer "+f.sign(t, f.claims(), "kid-1"))
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	})
}

func TestMiddlewareJWT(t *testing.T) {
	t.Parallel()

	jwtAuth := func(t *testing.T, f *fakeKinde) *KindeAgentAuth {
		return newTestAuth(t, f, Config{Verification: VerificationJWT})
	}

	t.Run("iss is the domain and aud contains the resource", func(t *testing.T) {
		f := newFakeKinde(t)
		rec, ac := serve(jwtAuth(t, f), "Bearer "+f.sign(t, f.claims(), "kid-1"))
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "kp_user", ac.UserID)
		assert.Equal(t, []string{"read:docs"}, ac.Permissions)
	})

	t.Run("iss is the scoped issuer", func(t *testing.T) {
		f := newFakeKinde(t)
		claims := f.claims()
		claims["iss"] = f.server.URL + "/oauth2/agents/" + testAppID
		rec, _ := serve(jwtAuth(t, f), "Bearer "+f.sign(t, claims, "kid-1"))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("aud is another resource", func(t *testing.T) {
		f := newFakeKinde(t)
		claims := f.claims()
		claims["aud"] = []string{"https://other.example.com/mcp"}
		rec, _ := serve(jwtAuth(t, f), "Bearer "+f.sign(t, claims, "kid-1"))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("aud array with the resource plus another", func(t *testing.T) {
		f := newFakeKinde(t)
		claims := f.claims()
		claims["aud"] = []string{"https://other.example.com/mcp", testResourceURL}
		rec, _ := serve(jwtAuth(t, f), "Bearer "+f.sign(t, claims, "kid-1"))
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("expired beyond the leeway", func(t *testing.T) {
		f := newFakeKinde(t)
		claims := f.claims()
		claims["exp"] = time.Now().Add(-time.Minute).Unix()
		rec, _ := serve(jwtAuth(t, f), "Bearer "+f.sign(t, claims, "kid-1"))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("missing exp", func(t *testing.T) {
		f := newFakeKinde(t)
		claims := f.claims()
		delete(claims, "exp")
		rec, _ := serve(jwtAuth(t, f), "Bearer "+f.sign(t, claims, "kid-1"))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("alg none and HS256", func(t *testing.T) {
		f := newFakeKinde(t)
		auth := jwtAuth(t, f)
		none, err := golangjwt.NewWithClaims(golangjwt.SigningMethodNone, f.claims()).SignedString(golangjwt.UnsafeAllowNoneSignatureType)
		require.NoError(t, err)
		hs := golangjwt.NewWithClaims(golangjwt.SigningMethodHS256, f.claims())
		hs.Header["kid"] = "kid-1"
		hsSigned, err := hs.SignedString([]byte("secret"))
		require.NoError(t, err)
		for _, token := range []string{none, hsSigned} {
			rec, _ := serve(auth, "Bearer "+token)
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
		}
	})

	t.Run("unknown key refetches the JWKS once, not on every request", func(t *testing.T) {
		f := newFakeKinde(t)
		auth := jwtAuth(t, f)
		other, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		forged := golangjwt.NewWithClaims(golangjwt.SigningMethodRS256, f.claims())
		forged.Header["kid"] = "unknown"
		token, err := forged.SignedString(other)
		require.NoError(t, err)

		initial := f.jwksHits.Load()
		for range 3 {
			rec, _ := serve(auth, "Bearer "+token)
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
		}
		assert.LessOrEqual(t, f.jwksHits.Load()-initial, int32(1))
	})

	t.Run("jwt plus introspection requires both", func(t *testing.T) {
		f := newFakeKinde(t)
		f.setIntrospect(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{"active": false})
		})
		auth := newTestAuth(t, f, Config{Verification: VerificationJWTAndIntrospection})
		rec, _ := serve(auth, "Bearer "+f.sign(t, f.claims(), "kid-1"))
		assert.Equal(t, http.StatusUnauthorized, rec.Code, "revoked token is rejected even though the JWT is valid")

		f.setIntrospect(activeIntrospection(testResourceURL))
		rec, _ = serve(auth, "Bearer "+f.sign(t, f.claims(), "kid-1"))
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestPermissions(t *testing.T) {
	t.Parallel()
	ac := &AuthContext{Permissions: []string{"read:docs"}}

	t.Run("HasPermission", func(t *testing.T) {
		assert.True(t, HasPermission(ac, "read:docs"))
		assert.False(t, HasPermission(ac, "write:docs"))
		assert.False(t, HasPermission(nil, "read:docs"))
	})

	t.Run("RequirePermission answers a plain 403 without insufficient_scope", func(t *testing.T) {
		handler := RequirePermission("read:docs", "write:docs")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest(http.MethodGet, "/docs", nil).WithContext(ContextWithAuth(t.Context(), ac))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Empty(t, rec.Header().Get("WWW-Authenticate"))
		var body map[string]string
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, "forbidden", body["error"])
		assert.False(t, strings.Contains(rec.Body.String(), "insufficient_scope"))
	})

	t.Run("RequirePermission passes when every key is present", func(t *testing.T) {
		handler := RequirePermission("read:docs")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest(http.MethodGet, "/docs", nil).WithContext(ContextWithAuth(t.Context(), ac))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}
