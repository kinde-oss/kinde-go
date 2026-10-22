package agents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/kinde-oss/kinde-go/jwt"
)

// Verification selects how KindeAgentAuth verifies access tokens.
type Verification string

const (
	// VerificationIntrospection calls the application's introspection endpoint. Revocation takes
	// effect immediately. This is the default.
	VerificationIntrospection Verification = "introspection"
	// VerificationJWT verifies the token locally against the domain's JWKS. It needs no client
	// secret, but a revoked token stays valid until it expires (24 hours by default).
	VerificationJWT Verification = "jwt"
	// VerificationJWTAndIntrospection verifies the token locally first, then introspects it.
	VerificationJWTAndIntrospection Verification = "jwt+introspection"
)

const (
	defaultClockTolerance = 30 * time.Second
	defaultHTTPTimeout    = 5 * time.Second
	prmWellKnown          = "oauth-protected-resource"
)

var (
	// ErrMissingToken is returned when the request has no Authorization header.
	ErrMissingToken = errors.New("agents: missing bearer token")
	// ErrInvalidToken is returned when the token is malformed, inactive, expired or not for this resource.
	ErrInvalidToken = errors.New("agents: invalid token")
	// ErrUnavailable is returned when Kinde can't be reached or rejects the application's credentials.
	ErrUnavailable = errors.New("agents: authorization server unavailable")
)

// authError carries a client-safe description alongside the sentinel kind and the cause.
type authError struct {
	kind        error
	description string
	cause       error
}

func (e *authError) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%v: %s: %v", e.kind, e.description, e.cause)
	}
	return fmt.Sprintf("%v: %s", e.kind, e.description)
}

func (e *authError) Unwrap() []error {
	if e.cause != nil {
		return []error{e.kind, e.cause}
	}
	return []error{e.kind}
}

func invalidToken(description string, cause error) error {
	return &authError{kind: ErrInvalidToken, description: description, cause: cause}
}

func unavailable(description string, cause error) error {
	return &authError{kind: ErrUnavailable, description: description, cause: cause}
}

// Config configures KindeAgentAuth. Use the AI agents and MCP application's credentials,
// not those of the SDK's normal login application.
type Config struct {
	// Domain is the Kinde domain, e.g. "https://yourbiz.kinde.com" or a custom domain.
	Domain string
	// ClientID is the AI agents and MCP application's client ID.
	ClientID string
	// ClientSecret is the application's client secret. Required for introspection.
	ClientSecret string
	// ResourceURL must equal the Resource URL configured in Kinde, byte for byte.
	ResourceURL string
	// Verification defaults to VerificationIntrospection.
	Verification Verification
	// ScopesSupported is advertised in the protected resource metadata. "offline" is always added.
	ScopesSupported []string
	// ResourceName is advertised in the protected resource metadata.
	ResourceName string
	// ClockTolerance is the leeway for exp and nbf. Defaults to 30 seconds.
	ClockTolerance time.Duration
	// HTTPClient is used to call Kinde. Defaults to a client with a 5 second timeout.
	HTTPClient *http.Client
}

// KindeAgentAuth protects an MCP server or HTTP API with tokens issued through a Kinde
// AI agents and MCP application. Create it once and share it; it is safe for concurrent use.
type KindeAgentAuth struct {
	domain         string
	clientID       string
	clientSecret   string
	resourceURL    string
	issuer         string
	prmPath        string
	prmURL         string
	verification   Verification
	metadata       ProtectedResourceMetadata
	clockTolerance time.Duration
	httpClient     *http.Client
	jwtOptions     []func(*jwt.Token)
	now            func() time.Time
}

// ProtectedResourceMetadata is the RFC 9728 protected resource metadata document.
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	ResourceName           string   `json:"resource_name,omitempty"`
}

// AuthContext describes the verified caller. Its Token field is the raw access token; never log it.
type AuthContext struct {
	Token       string
	UserID      string
	Email       string
	OrgCode     string
	Permissions []string
	Roles       []string
	Scopes      []string
	// ClientID identifies the agent: a CIMD URL or a DCR registrant ID.
	ClientID  string
	ExpiresAt int64
	Claims    map[string]any
}

// String redacts the raw token so an AuthContext can be printed safely.
func (a AuthContext) String() string {
	return fmt.Sprintf("AuthContext{UserID:%q ClientID:%q OrgCode:%q Permissions:%v Roles:%v Scopes:%v ExpiresAt:%d}",
		a.UserID, a.ClientID, a.OrgCode, a.Permissions, a.Roles, a.Scopes, a.ExpiresAt)
}

// NewKindeAgentAuth validates the configuration and derives the scoped issuer and metadata URLs.
func NewKindeAgentAuth(cfg Config) (*KindeAgentAuth, error) {
	domain, err := normalizeDomain(cfg.Domain)
	if err != nil {
		return nil, err
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("client ID is required")
	}
	resource, err := parseSecureURL(cfg.ResourceURL)
	if err != nil {
		return nil, fmt.Errorf("resource URL: %w", err)
	}
	if resource.User != nil || resource.Fragment != "" {
		return nil, fmt.Errorf("resource URL must not contain userinfo or a fragment")
	}

	verification := cfg.Verification
	if verification == "" {
		verification = VerificationIntrospection
	}
	switch verification {
	case VerificationIntrospection, VerificationJWTAndIntrospection:
		if cfg.ClientSecret == "" {
			return nil, fmt.Errorf("client secret is required for %s verification", verification)
		}
	case VerificationJWT:
	default:
		return nil, fmt.Errorf("unknown verification %q", verification)
	}

	scopes := slices.Clone(cfg.ScopesSupported)
	if !slices.Contains(scopes, "offline") {
		scopes = append(scopes, "offline")
	}

	tolerance := cfg.ClockTolerance
	if tolerance == 0 {
		tolerance = defaultClockTolerance
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}

	issuer := domain + "/oauth2/agents/" + url.PathEscape(cfg.ClientID)
	prmURL := wellKnownURL(resource, prmWellKnown)
	a := &KindeAgentAuth{
		domain:       domain,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		resourceURL:  cfg.ResourceURL,
		issuer:       issuer,
		prmPath:      strings.TrimPrefix(prmURL, origin(resource)),
		prmURL:       prmURL,
		verification: verification,
		metadata: ProtectedResourceMetadata{
			Resource:               cfg.ResourceURL,
			AuthorizationServers:   []string{issuer},
			BearerMethodsSupported: []string{"header"},
			ScopesSupported:        scopes,
			ResourceName:           cfg.ResourceName,
		},
		clockTolerance: tolerance,
		httpClient:     httpClient,
		now:            time.Now,
	}

	if verification != VerificationIntrospection {
		// Unlike jwt.WillValidateWithJWKSUrl, this doesn't fail permanently when Kinde is
		// unreachable at startup: keys are refetched hourly and on an unknown kid (rate-limited).
		keys, err := keyfunc.NewDefaultOverrideCtx(context.Background(), []string{domain + "/.well-known/jwks"}, keyfunc.Override{
			Client:      httpClient,
			HTTPTimeout: defaultHTTPTimeout,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create JWKS client: %w", err)
		}
		a.jwtOptions = []func(*jwt.Token){
			jwt.WillValidateWithKeyFunc(keys.Keyfunc),
			jwt.WillValidateAlgorithm("RS256"),
			// Access tokens carry the domain as iss, not the scoped issuer.
			jwt.WillValidateIssuer(domain),
			jwt.WillValidateAudience(cfg.ResourceURL),
			jwt.WillValidateWithClockSkew(tolerance),
			jwt.WillValidateClaims(func(claims golangjwt.MapClaims) (bool, error) {
				if exp, err := claims.GetExpirationTime(); err != nil || exp == nil {
					return false, fmt.Errorf("token has no exp claim")
				}
				return true, nil
			}),
		}
	}
	return a, nil
}

// Issuer returns the application's scoped issuer, https://<domain>/oauth2/agents/<client_id>.
func (a *KindeAgentAuth) Issuer() string { return a.issuer }

// ProtectedResourceMetadataURL returns the URL advertised in the 401 challenge.
func (a *KindeAgentAuth) ProtectedResourceMetadataURL() string { return a.prmURL }

// ProtectedResourceMetadataPaths returns the paths to serve ProtectedResourceMetadataHandler on:
// the path-suffixed form for the resource, and the root form for older clients.
func (a *KindeAgentAuth) ProtectedResourceMetadataPaths() []string {
	root := "/.well-known/" + prmWellKnown
	if a.prmPath == root {
		return []string{root}
	}
	return []string{a.prmPath, root}
}

// ProtectedResourceMetadata returns the RFC 9728 document this resource serves.
func (a *KindeAgentAuth) ProtectedResourceMetadata() ProtectedResourceMetadata {
	m := a.metadata
	m.AuthorizationServers = slices.Clone(m.AuthorizationServers)
	m.BearerMethodsSupported = slices.Clone(m.BearerMethodsSupported)
	m.ScopesSupported = slices.Clone(m.ScopesSupported)
	return m
}

// ProtectedResourceMetadataHandler serves the protected resource metadata, with permissive CORS
// because browser-based MCP clients fetch it.
func (a *KindeAgentAuth) ProtectedResourceMetadataHandler() http.Handler {
	body, _ := json.Marshal(a.metadata)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		switch r.Method {
		case http.MethodOptions:
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "*")
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet, http.MethodHead:
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "max-age=3600")
			_, _ = w.Write(body)
		default:
			w.Header().Set("Allow", "GET, OPTIONS")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
}

// Authenticate extracts the bearer token from r and verifies it.
func (a *KindeAgentAuth) Authenticate(r *http.Request) (*AuthContext, error) {
	token, err := bearerToken(r)
	if err != nil {
		return nil, err
	}
	return a.VerifyAccessToken(r.Context(), token)
}

// bearerToken accepts only "Authorization: Bearer <token>"; the scheme is case-insensitive.
func bearerToken(r *http.Request) (string, error) {
	values := r.Header.Values("Authorization")
	if len(values) == 0 {
		return "", ErrMissingToken
	}
	if len(values) > 1 {
		return "", invalidToken("multiple Authorization headers", nil)
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t") {
		return "", invalidToken("expected a Bearer token", nil)
	}
	return token, nil
}

// VerifyAccessToken verifies token with the configured strategy.
func (a *KindeAgentAuth) VerifyAccessToken(ctx context.Context, token string) (*AuthContext, error) {
	var (
		claims golangjwt.MapClaims
		err    error
	)
	switch a.verification {
	case VerificationJWT:
		claims, err = a.verifyJWT(token)
	case VerificationJWTAndIntrospection:
		if claims, err = a.verifyJWT(token); err == nil {
			_, err = a.introspect(ctx, token)
		}
	default:
		claims, err = a.introspect(ctx, token)
	}
	if err != nil {
		return nil, err
	}
	return newAuthContext(token, claims), nil
}

func (a *KindeAgentAuth) verifyJWT(token string) (golangjwt.MapClaims, error) {
	parsed, err := jwt.ParseFromString(token, a.jwtOptions...)
	if err != nil {
		return nil, invalidToken("token verification failed", err)
	}
	if !parsed.IsValid() {
		return nil, invalidToken("token verification failed", nil)
	}
	return parsed.GetClaims(), nil
}

type introspectionResponse struct {
	Active bool            `json:"active"`
	Aud    json.RawMessage `json:"aud"`
	Exp    *int64          `json:"exp"`
}

// introspect calls <issuer>/introspect with the application's Basic credentials. The shared
// /oauth2/introspect endpoint can't resolve CIMD clients, so it's never used.
func (a *KindeAgentAuth) introspect(ctx context.Context, token string) (golangjwt.MapClaims, error) {
	form := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.issuer+"/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, unavailable("failed to build introspection request", err)
	}
	req.SetBasicAuth(url.QueryEscape(a.clientID), url.QueryEscape(a.clientSecret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, unavailable("introspection request failed", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, unavailable("introspection rejected the application credentials; check the client ID and secret", nil)
	case resp.StatusCode != http.StatusOK:
		return nil, unavailable(fmt.Sprintf("introspection returned status %d", resp.StatusCode), nil)
	}

	var data introspectionResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&data); err != nil {
		return nil, unavailable("invalid introspection response", err)
	}
	if !data.Active {
		return nil, invalidToken("token is not active", nil)
	}
	if !slices.Contains(parseAudience(data.Aud), a.resourceURL) {
		return nil, invalidToken("token audience does not include this resource", nil)
	}
	if data.Exp != nil && time.Unix(*data.Exp, 0).Add(a.clockTolerance).Before(a.now()) {
		return nil, invalidToken("token is expired", nil)
	}
	// Kinde has just confirmed the token, so its payload can be decoded without a signature check.
	claims, err := jwt.ParseIDTokenUnverified(token)
	if err != nil {
		return nil, invalidToken("token is not a JWT", err)
	}
	return claims, nil
}

func parseAudience(raw json.RawMessage) []string {
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}
	}
	return nil
}

func newAuthContext(token string, claims golangjwt.MapClaims) *AuthContext {
	ac := &AuthContext{
		Token:       token,
		Email:       stringClaim(claims, "email"),
		OrgCode:     stringClaim(claims, "org_code"),
		Permissions: stringsClaim(claims["permissions"]),
		Roles:       roleKeys(claims["roles"]),
		ClientID:    stringClaim(claims, "azp"),
		Claims:      claims,
	}
	ac.UserID, _ = claims.GetSubject()
	if ac.ClientID == "" {
		ac.ClientID = stringClaim(claims, "client_id")
	}
	if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
		ac.ExpiresAt = exp.Unix()
	}
	if scp, ok := claims["scp"]; ok {
		ac.Scopes = stringsClaim(scp)
	} else if scope := stringClaim(claims, "scope"); scope != "" {
		ac.Scopes = strings.Fields(scope)
	}
	return ac
}

func stringClaim(claims golangjwt.MapClaims, key string) string {
	s, _ := claims[key].(string)
	return s
}

// stringsClaim reads a claim that is an array of strings or a space-separated string.
func stringsClaim(v any) []string {
	switch v := v.(type) {
	case string:
		return strings.Fields(v)
	case []any:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return []string{}
}

// roleKeys reads Kinde's roles claim, an array of {id, key, name} objects, as role keys.
func roleKeys(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return []string{}
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		switch r := item.(type) {
		case string:
			result = append(result, r)
		case map[string]any:
			if key, ok := r["key"].(string); ok {
				result = append(result, key)
			}
		}
	}
	return result
}

// WriteError answers a failed Authenticate call: 401 with an RFC 6750 / RFC 9728 challenge for a
// missing or invalid token, and 503 when Kinde is unavailable, so agents don't restart login in a loop.
func (a *KindeAgentAuth) WriteError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrUnavailable) {
		log.Printf("kinde agents: %v", err)
		writeJSON(w, http.StatusServiceUnavailable, oauthErrorBody{Error: "temporarily_unavailable", ErrorDescription: "authorization server unavailable"})
		return
	}
	if errors.Is(err, ErrMissingToken) {
		w.Header().Set("WWW-Authenticate", buildBearerChallenge([2]string{"resource_metadata", a.prmURL}))
		writeJSON(w, http.StatusUnauthorized, oauthErrorBody{Error: "unauthorized", ErrorDescription: "bearer token required"})
		return
	}
	description := "invalid token"
	var ae *authError
	if errors.As(err, &ae) {
		description = ae.description
	}
	w.Header().Set("WWW-Authenticate", buildBearerChallenge(
		[2]string{"error", "invalid_token"},
		[2]string{"error_description", description},
		[2]string{"resource_metadata", a.prmURL},
	))
	writeJSON(w, http.StatusUnauthorized, oauthErrorBody{Error: "invalid_token", ErrorDescription: description})
}

type authContextKey struct{}

// ContextWithAuth returns a copy of ctx carrying auth.
func ContextWithAuth(ctx context.Context, auth *AuthContext) context.Context {
	return context.WithValue(ctx, authContextKey{}, auth)
}

// AuthFromContext returns the AuthContext stored by Middleware.
func AuthFromContext(ctx context.Context) (*AuthContext, bool) {
	auth, ok := ctx.Value(authContextKey{}).(*AuthContext)
	return auth, ok && auth != nil
}

// Middleware requires a valid agent token and stores the AuthContext in the request context.
func (a *KindeAgentAuth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, err := a.Authenticate(r)
		if err != nil {
			a.WriteError(w, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(ContextWithAuth(r.Context(), auth)))
	})
}

// HasPermission reports whether auth carries the Kinde permission key. Use it inside each MCP
// tool and return a tool error (isError: true) on failure. Don't answer 403 insufficient_scope:
// permissions aren't OAuth scopes, and MCP clients would loop the user through login.
func HasPermission(auth *AuthContext, key string) bool {
	return auth != nil && slices.Contains(auth.Permissions, key)
}

// RequirePermission is middleware for plain REST routes behind Middleware. It answers a plain
// 403 with a JSON body, without an insufficient_scope challenge, unless every key is present.
func RequirePermission(keys ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth, _ := AuthFromContext(r.Context())
			for _, key := range keys {
				if !HasPermission(auth, key) {
					WriteForbidden(w)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// WriteForbidden writes the plain 403 response used by RequirePermission.
func WriteForbidden(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, oauthErrorBody{Error: "forbidden", ErrorDescription: "missing required permission"})
}
