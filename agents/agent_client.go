package agents

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

const (
	metadataCacheTTL       = 5 * time.Minute
	refreshBeforeExpiry    = 60 * time.Second
	reregisterBeforeExpiry = 24 * time.Hour
	defaultClientName      = "Kinde Go agent"
	defaultClientTimeout   = 30 * time.Second
)

// ErrLoginRequired is returned when there are no usable tokens; call Connect to sign in again.
var ErrLoginRequired = errors.New("agents: login required")

// AgentClientConfig configures KindeAgentClient.
type AgentClientConfig struct {
	// ResourceURL is the MCP or API URL to call. Required.
	ResourceURL string
	// ClientMetadataURL is the https URL of this agent's client ID metadata document (CIMD).
	// Preferred whenever the agent has somewhere public to host it.
	ClientMetadataURL string
	// ClientID and ClientSecret identify a pre-registered client, as an alternative to CIMD and DCR.
	ClientID     string
	ClientSecret string
	// ClientName is sent when registering dynamically. Defaults to "Kinde Go agent".
	ClientName string
	// RedirectURI is the loopback callback, e.g. "http://127.0.0.1:53682/callback". Defaults to
	// "http://127.0.0.1/callback" on an ephemeral port. Use a fixed port with DCR, or the client
	// re-registers whenever the port changes.
	RedirectURI string
	// Scopes defaults to ["offline"]. openid is dropped when the server doesn't support it.
	Scopes []string
	// Storage persists tokens and the DCR registration. Defaults to memory. frameworks/cli's
	// keyring session implements it.
	Storage Storage
	// HTTPClient is used for every request. Defaults to a client with a 30 second timeout.
	HTTPClient *http.Client
	// OpenBrowser opens authURL in the system browser. Required for Connect to sign in.
	OpenBrowser func(authURL string) error
}

// TokenInfo describes the current tokens without exposing them.
type TokenInfo struct {
	ClientID  string
	Scopes    []string
	ExpiresAt time.Time
}

type clientIdentity struct {
	id         string
	secret     string
	authMethod string // none, client_secret_post or client_secret_basic
	dynamic    bool
}

type storedTokens struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scope        string    `json:"scope,omitempty"`
	ClientID     string    `json:"client_id"`
}

type storedRegistration struct {
	ClientID                string `json:"client_id"`
	ClientSecret            string `json:"client_secret,omitempty"`
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`
	ClientSecretExpiresAt   int64  `json:"client_secret_expires_at"`
	RedirectURI             string `json:"redirect_uri"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
}

// KindeAgentClient signs a user in to an OAuth-protected MCP server or API and calls it with a
// bearer token. It works against any spec-compliant server, with Kinde's quirks handled. It is
// safe for concurrent use; refreshes are serialised.
type KindeAgentClient struct {
	cfg        AgentClientConfig
	resource   *url.URL
	httpClient *http.Client
	// noRedirectClient sends requests that carry the access token or client credentials. A
	// redirect would forward them (the token even to plain http on the same host), so the 3xx
	// is returned to the caller instead.
	noRedirectClient *http.Client
	storage          Storage
	now              func() time.Time

	mu         sync.Mutex
	metadata   *AuthorizationServerMetadata
	metadataAt time.Time
	tokens     *storedTokens
	generation uint64 // incremented whenever tokens change
}

// NewKindeAgentClient validates cfg and applies defaults. It makes no network calls.
func NewKindeAgentClient(cfg AgentClientConfig) (*KindeAgentClient, error) {
	resource, err := parseSecureURL(cfg.ResourceURL)
	if err != nil {
		return nil, fmt.Errorf("resource URL: %w", err)
	}
	if cfg.ClientMetadataURL != "" {
		u, err := url.Parse(cfg.ClientMetadataURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Path == "" || u.Path == "/" {
			return nil, fmt.Errorf("client metadata URL must be an https URL with a path")
		}
	}
	if cfg.ClientSecret != "" && cfg.ClientID == "" {
		return nil, fmt.Errorf("client secret given without a client ID")
	}
	if cfg.RedirectURI == "" {
		cfg.RedirectURI = defaultRedirectURI
	}
	if u, err := url.Parse(cfg.RedirectURI); err != nil || u.Scheme != "http" || !isLoopbackHost(u.Hostname()) {
		return nil, fmt.Errorf("redirect URI %q must be an http loopback URI", cfg.RedirectURI)
	}
	if cfg.ClientName == "" {
		cfg.ClientName = defaultClientName
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"offline"}
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultClientTimeout}
	}
	noRedirectClient := *httpClient
	noRedirectClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	storage := cfg.Storage
	if storage == nil {
		storage = NewMemoryStorage()
	}
	return &KindeAgentClient{
		cfg:              cfg,
		resource:         resource,
		httpClient:       httpClient,
		noRedirectClient: &noRedirectClient,
		storage:          storage,
		now:              time.Now,
	}, nil
}

// Connect discovers the authorization server and makes sure there are usable tokens:
// stored ones, refreshed ones, or a new browser sign-in.
func (c *KindeAgentClient) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureMetadataLocked(ctx); err != nil {
		return err
	}
	if c.loadTokensLocked() {
		if !c.expiringLocked() {
			return nil
		}
		err := c.refreshLocked(ctx)
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrLoginRequired) {
			return err
		}
	}
	return c.loginLocked(ctx)
}

// Do sends req to the resource with the bearer token, refreshing it when it is about to expire.
// On a 401 it refreshes once and retries; a request with a body is retried only when
// req.GetBody is set (http.NewRequest sets it for common body types). If the retry also gets
// a 401, that response is returned and the caller should call Connect.
func (c *KindeAgentClient) Do(req *http.Request) (*http.Response, error) {
	if !sameOrigin(req.URL, c.resource) {
		return nil, fmt.Errorf("refusing to send the access token to %s: only %s is allowed", origin(req.URL), origin(c.resource))
	}
	token, generation, err := c.currentToken(req.Context())
	if err != nil {
		return nil, err
	}
	resp, err := c.send(req, req.Body, token)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
		return resp, nil
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	resp.Body.Close()

	token, err = c.refreshAfter(req.Context(), generation)
	if err != nil {
		return nil, err
	}
	var body io.ReadCloser
	if req.GetBody != nil {
		if body, err = req.GetBody(); err != nil {
			return nil, err
		}
	}
	return c.send(req, body, token)
}

func (c *KindeAgentClient) send(req *http.Request, body io.ReadCloser, token string) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.Body = body
	out.Header.Set("Authorization", "Bearer "+token)
	return c.noRedirectClient.Do(out)
}

// Disconnect revokes the tokens at the authorization server and clears them from storage.
// With forget, the dynamic client registration is cleared too.
func (c *KindeAgentClient) Disconnect(ctx context.Context, forget bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureMetadataLocked(ctx); err != nil {
		return err
	}
	if !c.loadTokensLocked() {
		if stored := c.readTokens(); stored != nil {
			// Clearing them would leave them valid at the authorization server.
			return fmt.Errorf("stored tokens were issued to client %q, not the configured one; disconnect with the configuration used to sign in", stored.ClientID)
		}
	}
	var revokeErr error
	if c.tokens != nil && c.metadata.RevocationEndpoint != "" {
		if identity, ok := c.existingIdentityLocked(); ok {
			form := url.Values{"token": {c.tokens.AccessToken}, "token_type_hint": {"access_token"}}
			if c.tokens.RefreshToken != "" {
				form = url.Values{"token": {c.tokens.RefreshToken}, "token_type_hint": {"refresh_token"}}
			}
			// RFC 7009 answers 200 whatever the token's state, so only transport errors matter.
			if resp, err := c.postForm(ctx, c.metadata.RevocationEndpoint, identity, form); err != nil {
				revokeErr = fmt.Errorf("failed to revoke tokens: %w", err)
			} else {
				resp.Body.Close()
			}
		}
	}
	c.clearTokensLocked()
	if forget {
		_ = c.storage.DeleteKey(c.registrationKey())
	}
	return revokeErr
}

// TokenInfo returns details of the current tokens, if Connect has loaded any.
func (c *KindeAgentClient) TokenInfo() (TokenInfo, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tokens == nil {
		return TokenInfo{}, false
	}
	return TokenInfo{ClientID: c.tokens.ClientID, Scopes: strings.Fields(c.tokens.Scope), ExpiresAt: c.tokens.ExpiresAt}, true
}

func (c *KindeAgentClient) currentToken(ctx context.Context) (string, uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureMetadataLocked(ctx); err != nil {
		return "", 0, err
	}
	if !c.loadTokensLocked() {
		return "", 0, ErrLoginRequired
	}
	if c.expiringLocked() {
		if err := c.refreshLocked(ctx); err != nil {
			return "", 0, err
		}
	}
	return c.tokens.AccessToken, c.generation, nil
}

// refreshAfter refreshes unless another request already did since generation was read.
func (c *KindeAgentClient) refreshAfter(ctx context.Context, generation uint64) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tokens != nil && c.generation != generation {
		return c.tokens.AccessToken, nil
	}
	if !c.loadTokensLocked() {
		return "", ErrLoginRequired
	}
	if err := c.refreshLocked(ctx); err != nil {
		return "", err
	}
	return c.tokens.AccessToken, nil
}

// ensureMetadataLocked discovers the authorization server, caching it for 5 minutes. When a
// re-discovery fails, the previously validated metadata stays in use for another period.
func (c *KindeAgentClient) ensureMetadataLocked(ctx context.Context) error {
	if c.metadata != nil && c.now().Sub(c.metadataAt) < metadataCacheTTL {
		return nil
	}
	metadata, err := c.discoverLocked(ctx)
	if err != nil {
		if c.metadata != nil {
			c.metadataAt = c.now()
			return nil
		}
		return err
	}
	if c.metadata != nil && c.metadata.Issuer != metadata.Issuer {
		c.tokens = nil
	}
	c.metadata, c.metadataAt = metadata, c.now()
	return nil
}

func (c *KindeAgentClient) discoverLocked(ctx context.Context) (*AuthorizationServerMetadata, error) {
	prm, err := discoverProtectedResource(ctx, c.httpClient, c.resource)
	if err != nil {
		return nil, err
	}
	return discoverAuthorizationServer(ctx, c.httpClient, prm.AuthorizationServers[0])
}

func (c *KindeAgentClient) loginLocked(ctx context.Context) error {
	if c.cfg.OpenBrowser == nil {
		return fmt.Errorf("%w: OpenBrowser is required to sign in", ErrLoginRequired)
	}
	for attempt := 0; ; attempt++ {
		identity, err := c.authorizeLocked(ctx)
		var oauthErr *OAuthError
		if err != nil && errors.As(err, &oauthErr) && oauthErr.Code == "invalid_client" {
			if identity.dynamic && attempt == 0 {
				// The registration expired or was removed: register again and re-authorize once.
				_ = c.storage.DeleteKey(c.registrationKey())
				continue
			}
			if identity.id == c.cfg.ClientMetadataURL {
				return fmt.Errorf("%w (is the client metadata host in the application's Trusted agent hosts?)", err)
			}
		}
		return err
	}
}

// authorizeLocked runs one authorization code + PKCE round trip through the loopback redirect.
func (c *KindeAgentClient) authorizeLocked(ctx context.Context) (clientIdentity, error) {
	loopback, err := startLoopback(c.cfg.RedirectURI)
	if err != nil {
		return clientIdentity{}, err
	}
	defer loopback.close()

	identity, err := c.identityForLoginLocked(ctx, loopback.redirectURI)
	if err != nil {
		return identity, err
	}
	state, err := randomString()
	if err != nil {
		return identity, err
	}
	verifier := oauth2.GenerateVerifier()
	authURL, err := c.authorizationURL(identity, loopback.redirectURI, state, verifier)
	if err != nil {
		return identity, err
	}
	if err := c.cfg.OpenBrowser(authURL); err != nil {
		return identity, fmt.Errorf("failed to open the browser: %w", err)
	}
	code, err := loopback.wait(ctx, state, c.metadata.Issuer)
	if err != nil {
		return identity, err
	}
	resp, err := c.tokenRequestLocked(ctx, identity, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {loopback.redirectURI},
		"code_verifier": {verifier},
		"resource":      {c.cfg.ResourceURL},
	})
	if err != nil {
		return identity, err
	}
	return identity, c.saveTokensLocked(identity, resp, "")
}

func (c *KindeAgentClient) authorizationURL(identity clientIdentity, redirectURI, state, verifier string) (string, error) {
	u, err := url.Parse(c.metadata.AuthorizationEndpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", identity.id)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(c.scopesLocked(), " "))
	q.Set("state", state)
	q.Set("code_challenge", oauth2.S256ChallengeFromVerifier(verifier))
	q.Set("code_challenge_method", "S256")
	q.Set("resource", c.cfg.ResourceURL)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// scopesLocked drops openid when the server doesn't list it; Kinde's scoped issuer refuses it.
func (c *KindeAgentClient) scopesLocked() []string {
	supported := c.metadata.ScopesSupported
	if len(supported) == 0 || slices.Contains(supported, "openid") {
		return c.cfg.Scopes
	}
	return slices.DeleteFunc(slices.Clone(c.cfg.Scopes), func(s string) bool { return s == "openid" })
}

func (c *KindeAgentClient) refreshLocked(ctx context.Context) error {
	if c.tokens == nil || c.tokens.RefreshToken == "" {
		return ErrLoginRequired
	}
	identity, ok := c.existingIdentityLocked()
	if !ok {
		return ErrLoginRequired
	}
	resp, err := c.tokenRequestLocked(ctx, identity, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {c.tokens.RefreshToken},
		"resource":      {c.cfg.ResourceURL},
	})
	var oauthErr *OAuthError
	if errors.As(err, &oauthErr) {
		switch oauthErr.Code {
		case "invalid_grant":
			// Revoked, expired, or the application was deleted.
			c.clearTokensLocked()
			return fmt.Errorf("%w: %w", ErrLoginRequired, err)
		case "invalid_client":
			c.clearTokensLocked()
			if identity.dynamic {
				_ = c.storage.DeleteKey(c.registrationKey())
			}
			return fmt.Errorf("%w: %w", ErrLoginRequired, err)
		}
	}
	if err != nil {
		return err
	}
	return c.saveTokensLocked(identity, resp, c.tokens.RefreshToken)
}

// identityForLoginLocked picks CIMD, then a pre-registered client, then DCR.
func (c *KindeAgentClient) identityForLoginLocked(ctx context.Context, redirectURI string) (clientIdentity, error) {
	if identity, ok := c.staticIdentity(); ok {
		return identity, nil
	}
	if c.metadata.RegistrationEndpoint == "" {
		return clientIdentity{}, fmt.Errorf("authorization server supports neither client ID metadata documents nor registration; configure ClientID")
	}
	reg := c.loadRegistration()
	expiring := reg != nil && reg.ClientSecretExpiresAt != 0 &&
		time.Unix(reg.ClientSecretExpiresAt, 0).Before(c.now().Add(reregisterBeforeExpiry))
	if reg == nil || expiring || reg.RedirectURI != redirectURI {
		var err error
		if reg, err = c.registerLocked(ctx, redirectURI); err != nil {
			return clientIdentity{dynamic: true}, err
		}
	}
	return registrationIdentity(reg), nil
}

// existingIdentityLocked returns the identity tokens were issued to, without registering.
func (c *KindeAgentClient) existingIdentityLocked() (clientIdentity, bool) {
	if identity, ok := c.staticIdentity(); ok {
		return identity, true
	}
	if reg := c.loadRegistration(); reg != nil {
		return registrationIdentity(reg), true
	}
	return clientIdentity{}, false
}

func (c *KindeAgentClient) staticIdentity() (clientIdentity, bool) {
	if c.cfg.ClientMetadataURL != "" && c.metadata.ClientIDMetadataDocumentSupported {
		return clientIdentity{id: c.cfg.ClientMetadataURL, authMethod: "none"}, true
	}
	if c.cfg.ClientID != "" {
		identity := clientIdentity{id: c.cfg.ClientID, secret: c.cfg.ClientSecret, authMethod: "none"}
		if c.cfg.ClientSecret != "" {
			identity.authMethod = "client_secret_post"
		}
		return identity, true
	}
	return clientIdentity{}, false
}

func registrationIdentity(reg *storedRegistration) clientIdentity {
	return clientIdentity{id: reg.ClientID, secret: reg.ClientSecret, authMethod: reg.TokenEndpointAuthMethod, dynamic: true}
}

// registerLocked performs RFC 7591 registration. It asks for "none", the right method for a
// public native client, and then honours what comes back: Kinde always issues a secret.
func (c *KindeAgentClient) registerLocked(ctx context.Context, redirectURI string) (*storedRegistration, error) {
	body, err := json.Marshal(map[string]any{
		"redirect_uris":              []string{redirectURI},
		"client_name":                c.cfg.ClientName,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.metadata.RegistrationEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client registration failed: %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		c.clearTokensLocked()
		_ = c.storage.DeleteKey(c.registrationKey())
		return nil, fmt.Errorf("client registration failed: the authorization server no longer exists (was the application deleted?): %w", newOAuthError(resp))
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, fmt.Errorf("client registration failed: too many registrations, try again later: %w", newOAuthError(resp))
	case resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK:
		// invalid_redirect_uri's description names the host to add to Trusted agent hosts.
		return nil, fmt.Errorf("client registration failed: %w", newOAuthError(resp))
	}

	var reg storedRegistration
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&reg); err != nil {
		return nil, fmt.Errorf("invalid client registration response: %w", err)
	}
	if reg.ClientID == "" {
		return nil, fmt.Errorf("client registration response has no client_id")
	}
	if reg.TokenEndpointAuthMethod == "" {
		// RFC 7591 §2: the default is client_secret_basic.
		reg.TokenEndpointAuthMethod = "client_secret_basic"
		if reg.ClientSecret == "" {
			reg.TokenEndpointAuthMethod = "none"
		}
	}
	reg.RedirectURI = redirectURI
	data, err := json.Marshal(reg)
	if err != nil {
		return nil, err
	}
	if err := c.storage.SetKey(c.registrationKey(), data); err != nil {
		return nil, fmt.Errorf("failed to store client registration: %w", err)
	}
	return &reg, nil
}

func (c *KindeAgentClient) loadRegistration() *storedRegistration {
	data, err := c.storage.GetKey(c.registrationKey())
	if err != nil {
		return nil
	}
	var reg storedRegistration
	if json.Unmarshal(data, &reg) != nil || reg.ClientID == "" {
		return nil
	}
	return &reg
}

// postForm sends a form to a token or revocation endpoint with the client's authentication.
func (c *KindeAgentClient) postForm(ctx context.Context, endpoint string, identity clientIdentity, form url.Values) (*http.Response, error) {
	switch identity.authMethod {
	case "client_secret_basic":
	case "client_secret_post":
		form.Set("client_id", identity.id)
		form.Set("client_secret", identity.secret)
	default:
		form.Set("client_id", identity.id)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	if identity.authMethod == "client_secret_basic" {
		req.SetBasicAuth(url.QueryEscape(identity.id), url.QueryEscape(identity.secret))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return c.noRedirectClient.Do(req)
}

func (c *KindeAgentClient) tokenRequestLocked(ctx context.Context, identity clientIdentity, form url.Values) (*tokenResponse, error) {
	resp, err := c.postForm(ctx, c.metadata.TokenEndpoint, identity, form)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, newOAuthError(resp)
	}
	// There is no id_token on Kinde's scoped issuer, and none is expected.
	var tr tokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&tr); err != nil {
		return nil, fmt.Errorf("invalid token response: %w", err)
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("token response has no access_token")
	}
	return &tr, nil
}

// saveTokensLocked stores resp, keeping previousRefresh when the server didn't rotate it.
func (c *KindeAgentClient) saveTokensLocked(identity clientIdentity, resp *tokenResponse, previousRefresh string) error {
	tokens := &storedTokens{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		Scope:        resp.Scope,
		ClientID:     identity.id,
	}
	if tokens.RefreshToken == "" {
		tokens.RefreshToken = previousRefresh
	}
	if resp.ExpiresIn > 0 {
		tokens.ExpiresAt = c.now().Add(time.Duration(resp.ExpiresIn) * time.Second)
	}
	data, err := json.Marshal(tokens)
	if err != nil {
		return err
	}
	if err := c.storage.SetKey(c.tokenKey(), data); err != nil {
		return fmt.Errorf("failed to store tokens: %w", err)
	}
	c.tokens = tokens
	c.generation++
	return nil
}

// loadTokensLocked loads stored tokens, discarding ones issued to a different client.
func (c *KindeAgentClient) loadTokensLocked() bool {
	if c.tokens != nil {
		return true
	}
	tokens := c.readTokens()
	if tokens == nil {
		return false
	}
	if identity, ok := c.existingIdentityLocked(); !ok || identity.id != tokens.ClientID {
		return false
	}
	c.tokens = tokens
	c.generation++
	return true
}

// readTokens returns the stored tokens for this issuer and resource, whichever client they were issued to.
func (c *KindeAgentClient) readTokens() *storedTokens {
	data, err := c.storage.GetKey(c.tokenKey())
	if err != nil {
		return nil
	}
	var tokens storedTokens
	if json.Unmarshal(data, &tokens) != nil || tokens.AccessToken == "" {
		return nil
	}
	return &tokens
}

func (c *KindeAgentClient) clearTokensLocked() {
	c.tokens = nil
	c.generation++
	_ = c.storage.DeleteKey(c.tokenKey())
}

func (c *KindeAgentClient) expiringLocked() bool {
	return !c.tokens.ExpiresAt.IsZero() && c.now().Add(refreshBeforeExpiry).After(c.tokens.ExpiresAt)
}

// Tokens are keyed by (issuer, resource); the registration by issuer, with its redirect URI
// checked on login. Keys are hashed so they're safe for any keyring backend.
func (c *KindeAgentClient) tokenKey() string {
	return "kinde_agent_tokens_" + storageHash(c.metadata.Issuer, c.cfg.ResourceURL)
}

func (c *KindeAgentClient) registrationKey() string {
	return "kinde_agent_registration_" + storageHash(c.metadata.Issuer)
}

func storageHash(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:16])
}

func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
