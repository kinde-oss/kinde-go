package agents

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

const testCIMDURL = "https://agent.example.com/oauth/client-metadata.json"

// fakeServer is a protected MCP resource and a Kinde-like scoped authorization server on one origin.
type fakeServer struct {
	t      *testing.T
	server *httptest.Server
	issuer string

	mu                 sync.Mutex
	paths              []string
	omitResourceMeta   bool
	prmResource        string // overrides the PRM resource
	metadata           map[string]any
	registrations      int
	registerAuthMethod string
	authorizations     []url.Values
	browserState       string // overrides the state the fake browser returns
	tokenForms         []url.Values
	tokenBasicAuth     []string
	tokenErrors        []string // returned by the next token calls, in order
	refreshCalls       int
	refreshDelay       time.Duration
	rotateRefresh      bool
	issued             int
	validTokens        map[string]bool
	revocations        []url.Values
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	f := &fakeServer{t: t, validTokens: map[string]bool{}, registerAuthMethod: "client_secret_post"}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	f.issuer = f.server.URL + "/oauth2/agents/" + testAppID
	f.metadata = map[string]any{
		"issuer":                                f.issuer,
		"authorization_endpoint":                f.issuer + "/authorize",
		"token_endpoint":                        f.issuer + "/token",
		"registration_endpoint":                 f.issuer + "/register",
		"revocation_endpoint":                   f.issuer + "/revoke",
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"offline", "profile", "email"},
		"client_id_metadata_document_supported": true,
	}
	return f
}

func (f *fakeServer) resourceURL() string { return f.server.URL + "/mcp" }

func (f *fakeServer) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paths = append(f.paths, r.URL.Path)
	prmURL := f.server.URL + "/.well-known/oauth-protected-resource/mcp"

	switch r.URL.Path {
	case "/mcp", "/mcp/tools":
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if ok && f.validTokens[token] {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ok")
			return
		}
		if !f.omitResourceMeta {
			w.Header().Set("WWW-Authenticate", buildBearerChallenge([2]string{"resource_metadata", prmURL}))
		}
		w.WriteHeader(http.StatusUnauthorized)
	case "/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource":
		resource := f.resourceURL()
		if f.prmResource != "" {
			resource = f.prmResource
		}
		writeJSON(w, http.StatusOK, ProtectedResourceMetadata{Resource: resource, AuthorizationServers: []string{f.issuer}})
	case "/.well-known/oauth-authorization-server/oauth2/agents/" + testAppID:
		writeJSON(w, http.StatusOK, f.metadata)
	case "/oauth2/agents/" + testAppID + "/register":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		assert.Equal(f.t, "none", body["token_endpoint_auth_method"])
		assert.NotContains(f.t, body, "scope")
		f.registrations++
		writeJSON(w, http.StatusCreated, map[string]any{
			"client_id":                  fmt.Sprintf("dcr-client-%d", f.registrations),
			"client_secret":              fmt.Sprintf("dcr-secret-%d", f.registrations),
			"client_secret_expires_at":   time.Now().Add(30 * 24 * time.Hour).Unix(),
			"token_endpoint_auth_method": f.registerAuthMethod,
			"redirect_uris":              body["redirect_uris"],
		})
	case "/oauth2/agents/" + testAppID + "/token":
		f.token(w, r)
	case "/oauth2/agents/" + testAppID + "/revoke":
		_ = r.ParseForm()
		f.revocations = append(f.revocations, r.PostForm)
		w.WriteHeader(http.StatusOK)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeServer) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	form := r.PostForm
	f.tokenForms = append(f.tokenForms, form)
	f.tokenBasicAuth = append(f.tokenBasicAuth, r.Header.Get("Authorization"))
	if len(f.tokenErrors) > 0 {
		code := f.tokenErrors[0]
		f.tokenErrors = f.tokenErrors[1:]
		writeJSON(w, http.StatusBadRequest, oauthErrorBody{Error: code})
		return
	}
	switch form.Get("grant_type") {
	case "authorization_code":
		last := f.authorizations[len(f.authorizations)-1]
		if oauth2.S256ChallengeFromVerifier(form.Get("code_verifier")) != last.Get("code_challenge") {
			writeJSON(w, http.StatusBadRequest, oauthErrorBody{Error: "invalid_grant", ErrorDescription: "PKCE mismatch"})
			return
		}
		if form.Get("redirect_uri") != last.Get("redirect_uri") {
			writeJSON(w, http.StatusBadRequest, oauthErrorBody{Error: "invalid_grant", ErrorDescription: "redirect_uri mismatch"})
			return
		}
		writeJSON(w, http.StatusOK, f.issueLocked("rt-1"))
	case "refresh_token":
		f.refreshCalls++
		delay := f.refreshDelay
		f.mu.Unlock()
		time.Sleep(delay)
		f.mu.Lock()
		resp := f.issueLocked("")
		if f.rotateRefresh {
			resp["refresh_token"] = fmt.Sprintf("rt-rotated-%d", f.refreshCalls)
		}
		writeJSON(w, http.StatusOK, resp)
	default:
		writeJSON(w, http.StatusBadRequest, oauthErrorBody{Error: "unsupported_grant_type"})
	}
}

func (f *fakeServer) issueLocked(refreshToken string) map[string]any {
	f.issued++
	token := fmt.Sprintf("at-%d", f.issued)
	f.validTokens[token] = true
	resp := map[string]any{"access_token": token, "token_type": "bearer", "expires_in": 86400, "scope": "offline"}
	if refreshToken != "" {
		resp["refresh_token"] = refreshToken
	}
	return resp
}

// browser plays the user's browser: it records the authorize request and follows the redirect.
func (f *fakeServer) browser(authURL string) error {
	u, err := url.Parse(authURL)
	if err != nil {
		return err
	}
	q := u.Query()
	f.mu.Lock()
	f.authorizations = append(f.authorizations, q)
	state := q.Get("state")
	if f.browserState != "" {
		state = f.browserState
	}
	f.mu.Unlock()

	redirect, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		return err
	}
	redirect.RawQuery = url.Values{"code": {"code-1"}, "state": {state}, "iss": {f.issuer}}.Encode()
	resp, err := http.Get(redirect.String())
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func (f *fakeServer) newClient(t *testing.T, cfg AgentClientConfig) *KindeAgentClient {
	t.Helper()
	cfg.ResourceURL = f.resourceURL()
	if cfg.OpenBrowser == nil {
		cfg.OpenBrowser = f.browser
	}
	client, err := NewKindeAgentClient(cfg)
	require.NoError(t, err)
	return client
}

func (f *fakeServer) locked(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}

func freeLoopbackRedirect(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return fmt.Sprintf("http://127.0.0.1:%d/callback", port)
}

func TestAgentClientDiscovery(t *testing.T) {
	t.Parallel()

	t.Run("uses resource_metadata and the path-inserted AS metadata URL", func(t *testing.T) {
		f := newFakeServer(t)
		client := f.newClient(t, AgentClientConfig{ClientMetadataURL: testCIMDURL})
		require.NoError(t, client.Connect(t.Context()))
		f.locked(func() {
			assert.Equal(t, []string{
				"/mcp",
				"/.well-known/oauth-protected-resource/mcp",
				"/.well-known/oauth-authorization-server/oauth2/agents/" + testAppID,
			}, f.paths[:3], "no request to <issuer>/.well-known/... first")
			for _, p := range f.paths {
				assert.False(t, strings.HasPrefix(p, "/oauth2/") && !strings.HasPrefix(p, "/oauth2/agents/"), "shared endpoint %s used", p)
			}
		})
	})

	t.Run("falls back to the well-known PRM without resource_metadata", func(t *testing.T) {
		f := newFakeServer(t)
		f.omitResourceMeta = true
		client := f.newClient(t, AgentClientConfig{ClientMetadataURL: testCIMDURL})
		require.NoError(t, client.Connect(t.Context()))
		f.locked(func() { assert.Equal(t, "/.well-known/oauth-protected-resource/mcp", f.paths[1]) })
	})

	t.Run("accepts a PRM for a parent path", func(t *testing.T) {
		f := newFakeServer(t)
		f.prmResource = f.server.URL + "/"
		client := f.newClient(t, AgentClientConfig{ClientMetadataURL: testCIMDURL})
		assert.NoError(t, client.Connect(t.Context()))
	})

	t.Run("aborts on a PRM for another origin or path", func(t *testing.T) {
		for _, resource := range []string{"https://other.example.com/mcp", "SERVER/other"} {
			f := newFakeServer(t)
			f.prmResource = strings.Replace(resource, "SERVER", f.server.URL, 1)
			client := f.newClient(t, AgentClientConfig{ClientMetadataURL: testCIMDURL})
			err := client.Connect(t.Context())
			assert.ErrorContains(t, err, "protected resource metadata is for")
		}
	})

	t.Run("aborts on an issuer mismatch", func(t *testing.T) {
		f := newFakeServer(t)
		f.metadata["issuer"] = f.server.URL
		err := f.newClient(t, AgentClientConfig{ClientMetadataURL: testCIMDURL}).Connect(t.Context())
		assert.ErrorContains(t, err, "does not match")
	})

	t.Run("aborts without S256", func(t *testing.T) {
		f := newFakeServer(t)
		delete(f.metadata, "code_challenge_methods_supported")
		err := f.newClient(t, AgentClientConfig{ClientMetadataURL: testCIMDURL}).Connect(t.Context())
		assert.ErrorContains(t, err, "S256")
	})

	t.Run("refuses an insecure resource URL", func(t *testing.T) {
		_, err := NewKindeAgentClient(AgentClientConfig{ResourceURL: "http://api.example.com/mcp"})
		assert.Error(t, err)
	})
}

func TestAgentClientIdentity(t *testing.T) {
	t.Parallel()

	t.Run("CIMD: no registration, client_id is the URL, no secret", func(t *testing.T) {
		f := newFakeServer(t)
		client := f.newClient(t, AgentClientConfig{ClientMetadataURL: testCIMDURL})
		require.NoError(t, client.Connect(t.Context()))
		f.locked(func() {
			assert.Zero(t, f.registrations)
			assert.Equal(t, testCIMDURL, f.authorizations[0].Get("client_id"))
			assert.Equal(t, testCIMDURL, f.tokenForms[0].Get("client_id"))
			assert.False(t, f.tokenForms[0].Has("client_secret"))
			assert.Empty(t, f.tokenBasicAuth[0])
		})
		info, ok := client.TokenInfo()
		require.True(t, ok)
		assert.Equal(t, testCIMDURL, info.ClientID)
	})

	t.Run("authorize request: PKCE S256, state, resource, offline scope without openid", func(t *testing.T) {
		f := newFakeServer(t)
		client := f.newClient(t, AgentClientConfig{ClientMetadataURL: testCIMDURL, Scopes: []string{"openid", "offline", "profile"}})
		require.NoError(t, client.Connect(t.Context()))
		f.locked(func() {
			q := f.authorizations[0]
			assert.Equal(t, "code", q.Get("response_type"))
			assert.Equal(t, "S256", q.Get("code_challenge_method"))
			assert.NotEmpty(t, q.Get("code_challenge"))
			assert.GreaterOrEqual(t, len(q.Get("state")), 8)
			assert.Equal(t, f.resourceURL(), q.Get("resource"))
			assert.Equal(t, "offline profile", q.Get("scope"))
			assert.Equal(t, f.resourceURL(), f.tokenForms[0].Get("resource"))
		})
	})

	t.Run("default scope is offline", func(t *testing.T) {
		f := newFakeServer(t)
		require.NoError(t, f.newClient(t, AgentClientConfig{ClientMetadataURL: testCIMDURL}).Connect(t.Context()))
		f.locked(func() { assert.Equal(t, "offline", f.authorizations[0].Get("scope")) })
	})

	t.Run("CIMD unsupported by the AS falls back to DCR", func(t *testing.T) {
		f := newFakeServer(t)
		f.metadata["client_id_metadata_document_supported"] = false
		require.NoError(t, f.newClient(t, AgentClientConfig{ClientMetadataURL: testCIMDURL}).Connect(t.Context()))
		f.locked(func() {
			assert.Equal(t, 1, f.registrations)
			assert.Equal(t, "dcr-client-1", f.authorizations[0].Get("client_id"))
		})
	})

	t.Run("DCR asked none, got client_secret_post: secret used at token and refresh", func(t *testing.T) {
		f := newFakeServer(t)
		client := f.newClient(t, AgentClientConfig{})
		require.NoError(t, client.Connect(t.Context()))
		client.now = func() time.Time { return time.Now().Add(25 * time.Hour) }
		resp, err := client.Do(httptestRequest(t, f.resourceURL()))
		require.NoError(t, err)
		resp.Body.Close()
		f.locked(func() {
			require.Len(t, f.tokenForms, 2)
			for _, form := range f.tokenForms {
				assert.Equal(t, "dcr-client-1", form.Get("client_id"))
				assert.Equal(t, "dcr-secret-1", form.Get("client_secret"))
			}
			assert.Equal(t, "refresh_token", f.tokenForms[1].Get("grant_type"))
		})
	})

	t.Run("DCR with client_secret_basic sends a Basic header", func(t *testing.T) {
		f := newFakeServer(t)
		f.registerAuthMethod = "client_secret_basic"
		require.NoError(t, f.newClient(t, AgentClientConfig{}).Connect(t.Context()))
		f.locked(func() {
			assert.True(t, strings.HasPrefix(f.tokenBasicAuth[0], "Basic "))
			assert.False(t, f.tokenForms[0].Has("client_secret"))
		})
	})

	t.Run("stored registration expiring within a day is replaced", func(t *testing.T) {
		f := newFakeServer(t)
		storage := NewMemoryStorage()
		redirect := freeLoopbackRedirect(t)
		reg, _ := json.Marshal(storedRegistration{
			ClientID: "old", ClientSecret: "old-secret", TokenEndpointAuthMethod: "client_secret_post",
			ClientSecretExpiresAt: time.Now().Add(time.Hour).Unix(), RedirectURI: redirect,
		})
		require.NoError(t, storage.SetKey("kinde_agent_registration_"+storageHash(f.issuer), reg))
		require.NoError(t, f.newClient(t, AgentClientConfig{Storage: storage, RedirectURI: redirect}).Connect(t.Context()))
		f.locked(func() {
			assert.Equal(t, 1, f.registrations)
			assert.Equal(t, "dcr-client-1", f.authorizations[0].Get("client_id"))
		})
	})

	t.Run("valid stored registration with the same redirect is reused", func(t *testing.T) {
		f := newFakeServer(t)
		storage := NewMemoryStorage()
		redirect := freeLoopbackRedirect(t)
		reg, _ := json.Marshal(storedRegistration{
			ClientID: "kept", ClientSecret: "kept-secret", TokenEndpointAuthMethod: "client_secret_post",
			ClientSecretExpiresAt: time.Now().Add(10 * 24 * time.Hour).Unix(), RedirectURI: redirect,
		})
		require.NoError(t, storage.SetKey("kinde_agent_registration_"+storageHash(f.issuer), reg))
		require.NoError(t, f.newClient(t, AgentClientConfig{Storage: storage, RedirectURI: redirect}).Connect(t.Context()))
		f.locked(func() {
			assert.Zero(t, f.registrations)
			assert.Equal(t, "kept", f.authorizations[0].Get("client_id"))
		})
	})

	t.Run("token invalid_client re-registers once, then re-authorizes", func(t *testing.T) {
		f := newFakeServer(t)
		f.tokenErrors = []string{"invalid_client"}
		require.NoError(t, f.newClient(t, AgentClientConfig{}).Connect(t.Context()))
		f.locked(func() {
			assert.Equal(t, 2, f.registrations)
			assert.Len(t, f.authorizations, 2)
			assert.Equal(t, "dcr-client-2", f.authorizations[1].Get("client_id"))
		})
	})

	t.Run("token invalid_client twice gives up", func(t *testing.T) {
		f := newFakeServer(t)
		f.tokenErrors = []string{"invalid_client", "invalid_client"}
		err := f.newClient(t, AgentClientConfig{}).Connect(t.Context())
		var oauthErr *OAuthError
		require.ErrorAs(t, err, &oauthErr)
		assert.Equal(t, "invalid_client", oauthErr.Code)
	})

	t.Run("pre-registered client", func(t *testing.T) {
		f := newFakeServer(t)
		f.metadata["client_id_metadata_document_supported"] = false
		require.NoError(t, f.newClient(t, AgentClientConfig{ClientID: "pre", ClientSecret: "pre-secret"}).Connect(t.Context()))
		f.locked(func() {
			assert.Zero(t, f.registrations)
			assert.Equal(t, "pre", f.tokenForms[0].Get("client_id"))
			assert.Equal(t, "pre-secret", f.tokenForms[0].Get("client_secret"))
		})
	})

	t.Run("neither CIMD nor registration", func(t *testing.T) {
		f := newFakeServer(t)
		f.metadata["client_id_metadata_document_supported"] = false
		delete(f.metadata, "registration_endpoint")
		err := f.newClient(t, AgentClientConfig{}).Connect(t.Context())
		assert.ErrorContains(t, err, "configure ClientID")
	})
}

func TestAgentClientCallback(t *testing.T) {
	t.Parallel()

	t.Run("state mismatch aborts", func(t *testing.T) {
		f := newFakeServer(t)
		f.browserState = "attacker-state"
		err := f.newClient(t, AgentClientConfig{ClientMetadataURL: testCIMDURL}).Connect(t.Context())
		assert.ErrorContains(t, err, "state does not match")
		f.locked(func() { assert.Empty(t, f.tokenForms) })
	})

	t.Run("Connect without OpenBrowser needs login", func(t *testing.T) {
		f := newFakeServer(t)
		client := f.newClient(t, AgentClientConfig{ClientMetadataURL: testCIMDURL})
		client.cfg.OpenBrowser = nil
		assert.ErrorIs(t, client.Connect(t.Context()), ErrLoginRequired)
	})
}

func httptestRequest(t *testing.T, target string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader(`{"jsonrpc":"2.0"}`))
	require.NoError(t, err)
	return req
}

func TestAgentClientTokens(t *testing.T) {
	t.Parallel()

	t.Run("Do sends the bearer token", func(t *testing.T) {
		f := newFakeServer(t)
		client := f.newClient(t, AgentClientConfig{ClientMetadataURL: testCIMDURL})
		require.NoError(t, client.Connect(t.Context()))
		resp, err := client.Do(httptestRequest(t, f.resourceURL()))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("Do refuses another origin", func(t *testing.T) {
		f := newFakeServer(t)
		client := f.newClient(t, AgentClientConfig{ClientMetadataURL: testCIMDURL})
		require.NoError(t, client.Connect(t.Context()))
		_, err := client.Do(httptestRequest(t, "https://evil.example.com/mcp"))
		assert.ErrorContains(t, err, "refusing to send the access token")
	})

	t.Run("Do before Connect needs login", func(t *testing.T) {
		f := newFakeServer(t)
		client := f.newClient(t, AgentClientConfig{ClientMetadataURL: testCIMDURL})
		_, err := client.Do(httptestRequest(t, f.resourceURL()))
		assert.ErrorIs(t, err, ErrLoginRequired)
	})

	t.Run("refresh without refresh_token keeps the old one", func(t *testing.T) {
		f := newFakeServer(t)
		client := f.newClient(t, AgentClientConfig{ClientMetadataURL: testCIMDURL})
		require.NoError(t, client.Connect(t.Context()))
		f.locked(func() { f.validTokens = map[string]bool{} })
		resp, err := client.Do(httptestRequest(t, f.resourceURL()))
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode, "401 triggers one refresh and a retry with the body")
		assert.Equal(t, "rt-1", client.tokens.RefreshToken)
		f.locked(func() { assert.Equal(t, "rt-1", f.tokenForms[1].Get("refresh_token")) })
	})

	t.Run("refresh with a new refresh_token replaces it", func(t *testing.T) {
		f := newFakeServer(t)
		f.rotateRefresh = true
		client := f.newClient(t, AgentClientConfig{ClientMetadataURL: testCIMDURL})
		require.NoError(t, client.Connect(t.Context()))
		f.locked(func() { f.validTokens = map[string]bool{} })
		resp, err := client.Do(httptestRequest(t, f.resourceURL()))
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, "rt-rotated-1", client.tokens.RefreshToken)
	})

	t.Run("invalid_grant clears tokens and needs login", func(t *testing.T) {
		f := newFakeServer(t)
		client := f.newClient(t, AgentClientConfig{ClientMetadataURL: testCIMDURL})
		require.NoError(t, client.Connect(t.Context()))
		f.locked(func() {
			f.validTokens = map[string]bool{}
			f.tokenErrors = []string{"invalid_grant"}
		})
		_, err := client.Do(httptestRequest(t, f.resourceURL()))
		assert.ErrorIs(t, err, ErrLoginRequired)
		_, ok := client.TokenInfo()
		assert.False(t, ok)
	})

	t.Run("concurrent 401s make exactly one refresh request", func(t *testing.T) {
		f := newFakeServer(t)
		client := f.newClient(t, AgentClientConfig{ClientMetadataURL: testCIMDURL})
		require.NoError(t, client.Connect(t.Context()))
		f.locked(func() {
			f.validTokens = map[string]bool{}
			f.refreshDelay = 50 * time.Millisecond
		})
		var wg sync.WaitGroup
		for range 5 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := client.Do(httptestRequest(t, f.resourceURL()))
				if assert.NoError(t, err) {
					assert.Equal(t, http.StatusOK, resp.StatusCode)
					resp.Body.Close()
				}
			}()
		}
		wg.Wait()
		f.locked(func() { assert.Equal(t, 1, f.refreshCalls) })
	})

	t.Run("stored tokens are reused by a new client", func(t *testing.T) {
		f := newFakeServer(t)
		storage := NewMemoryStorage()
		require.NoError(t, f.newClient(t, AgentClientConfig{ClientMetadataURL: testCIMDURL, Storage: storage}).Connect(t.Context()))
		second := f.newClient(t, AgentClientConfig{ClientMetadataURL: testCIMDURL, Storage: storage})
		require.NoError(t, second.Connect(t.Context()))
		f.locked(func() { assert.Len(t, f.authorizations, 1) })
	})

	t.Run("Disconnect revokes with the client's auth and clears storage", func(t *testing.T) {
		f := newFakeServer(t)
		storage := NewMemoryStorage()
		client := f.newClient(t, AgentClientConfig{Storage: storage})
		require.NoError(t, client.Connect(t.Context()))
		require.NoError(t, client.Disconnect(t.Context(), false))
		f.locked(func() {
			require.Len(t, f.revocations, 1)
			assert.Equal(t, "rt-1", f.revocations[0].Get("token"))
			assert.Equal(t, "refresh_token", f.revocations[0].Get("token_type_hint"))
			assert.Equal(t, "dcr-client-1", f.revocations[0].Get("client_id"))
			assert.Equal(t, "dcr-secret-1", f.revocations[0].Get("client_secret"))
		})
		_, err := storage.GetKey("kinde_agent_tokens_" + storageHash(f.issuer, f.resourceURL()))
		assert.Error(t, err, "tokens cleared")
		_, err = storage.GetKey("kinde_agent_registration_" + storageHash(f.issuer))
		assert.NoError(t, err, "registration kept without forget")

		require.NoError(t, client.Disconnect(t.Context(), true))
		_, err = storage.GetKey("kinde_agent_registration_" + storageHash(f.issuer))
		assert.Error(t, err, "registration cleared with forget")
	})
}
