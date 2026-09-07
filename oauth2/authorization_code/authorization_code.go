package authorization_code

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/kinde-oss/kinde-go/jwt"
	"golang.org/x/oauth2"
)

type (
	contextKey string

	// ISessionHooks defines the interface for session management in the authorization code flow.
	ISessionHooks interface {
		// SetRawToken stores the raw token in the session.
		SetRawToken(token *oauth2.Token) error
		// GetRawToken retrieves the raw token from the session.
		GetRawToken() (*oauth2.Token, error)
		// GetState retrieves the state from the session.
		GetState() (string, error)
		// SetState sets the state in the session.
		SetState(state string) error
		// SetPostAuthRedirect sets the post-authentication redirect URL in the session.
		SetPostAuthRedirect(redirect string) error
		// GetPostAuthRedirect retrieves the post-authentication redirect URL from the session.
		GetPostAuthRedirect() (string, error)
		// SetCodeVerifier stores the PKCE code verifier in the session.
		SetCodeVerifier(codeVerifier string) error
		// GetCodeVerifier retrieves the PKCE code verifier from the session.
		GetCodeVerifier() (string, error)
	}

	// IAuthorizationCodeFlow represents the interface for the authorization code flow.
	IAuthorizationCodeFlow interface {
		// Returns the URL to redirect the user to start authentication pipeline.
		GetAuthURL() string
		// GetAuthURLWithInvitation returns the URL to redirect the user to start authentication pipeline
		// with invitation code support. If invitationCode is provided, it will include both
		// invitation_code and is_invitation parameters in the auth URL.
		GetAuthURLWithInvitation(invitationCode string) string
		// SwitchOrg returns the URL to redirect the user to in order to re-authenticate
		// into the organization identified by orgCode.
		SwitchOrg(orgCode string) string
		// Exchanges the authorization code for a token and establishes KindeContext.
		ExchangeCode(ctx context.Context, authorizationCode string, receivedState string) error
		// Returns http client to call external services, will refresh token behind the scenes if offline is requested.
		GetClient(ctx context.Context) (*http.Client, error)
		// Check if user is authenticated.
		IsAuthenticated(context.Context) (bool, error)
		// Clears local tokens and logs user out.
		Logout() error
		// A helper handler middleware for the code exchanger
		AuthorizationCodeReceivedHandler(w http.ResponseWriter, r *http.Request)
		// InjectTokenMiddleware that injects the token into the request context
		InjectTokenMiddleware(next http.Handler) http.Handler
		// GetToken returns the validated JWT token.
		GetToken(context.Context) (*jwt.Token, error)
		// SwitchOrg returns the URL to re-authenticate the user into a different organization.
		SwitchOrg(orgCode string) (string, error)
	}

	// IDeviceAuthorizationFlow represents the interface for the device authorization flow.
	IDeviceAuthorizationFlow interface {
		// StartDeviceAuth starts the device authorization flow.
		StartDeviceAuth(ctx context.Context) (*oauth2.DeviceAuthResponse, error)
		// Exchanges the device code to access token.
		ExchangeDeviceAccessToken(ctx context.Context, da *oauth2.DeviceAuthResponse, opts ...oauth2.AuthCodeOption) error
		// Returns http client to call external services, will refresh token behind the scenes if offline is requested.
		GetClient(ctx context.Context) (*http.Client, error)
		// Checks if the user is authenticated.
		IsAuthenticated(context.Context) (bool, error)
		// Clears local tokens and logs user out.
		Logout() error
		// Returns the token for the current session.
		GetToken(context.Context) (*jwt.Token, error)
	}

	// AuthorizationCodeFlow represents the authorization code flow.
	AuthorizationCodeFlow struct {
		config         oauth2.Config
		authURLOptions url.Values
		JWKS_URL       string
		tokenOptions   []func(*jwt.Token)
		sessionHooks   ISessionHooks
		stateGenerator func(from *AuthorizationCodeFlow) string
		stateVerifier  func(flow *AuthorizationCodeFlow, receivedState string) bool
		// PKCE support fields
		usePKCE         bool
		codeChallenge   string
		challengeMethod string
	}
)

func (flow *AuthorizationCodeFlow) Logout() error {
	if err := flow.sessionHooks.SetRawToken(nil); err != nil {
		return fmt.Errorf("failed to clear raw token: %w", err)
	}
	return nil
}

func (flow *AuthorizationCodeFlow) GetToken(ctx context.Context) (*jwt.Token, error) {

	tokenSource, err := flow.getTokenSource(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get token source: %w", err)
	}
	return tokenSource.getValidatedToken(ctx)
}

func (flow *AuthorizationCodeFlow) IsAuthenticated(ctx context.Context) (bool, error) {
	_, err := flow.GetToken(ctx)
	if err != nil {
		return false, err
	}
	return true, nil
}

// NewAuthorizationCodeFlow creates a new AuthorizationCodeFlow for authenticating backend applications.
//
// This function initializes an OAuth2 authorization code flow with the provided configuration.
// The flow handles the complete OAuth2 authorization code exchange process, including
// generating authorization URLs, handling callbacks, and exchanging codes for tokens.
//
// Default scopes (openid, profile, email) are automatically prepended to any scopes
// specified in the options.
//
// Parameters:
//   - baseURL: The base URL of your Kinde instance (e.g., "https://yourdomain.kinde.com")
//   - clientID: Your OAuth2 client ID
//   - clientSecret: Your OAuth2 client secret
//   - callbackURL: The redirect URI registered with your OAuth2 application
//   - options: Optional configuration functions to customize the flow behavior
//
// Returns an IAuthorizationCodeFlow interface and an error if initialization fails.
//
// Example:
//
//	flow, err := NewAuthorizationCodeFlow(
//	    "https://yourdomain.kinde.com",
//	    "your-client-id",
//	    "your-client-secret",
//	    "https://yourapp.com/callback",
//	    WithScopes("openid", "profile", "email"),
//	    WithPKCE(),
//	)
func NewAuthorizationCodeFlow(baseURL string, clientID string, clientSecret string, callbackURL string,
	options ...Option) (IAuthorizationCodeFlow, error) {
	options = append([]Option{WithScopes("openid", "profile", "email")}, options...) // prepending default openid scopes when nothing requested
	return newAuthorizationCodeFlow(baseURL, clientID, clientSecret, callbackURL, options...)
}

// NewDeviceAuthorizationFlow creates a new device authorization flow for OAuth2 device code grant.
//
// The device authorization flow is designed for devices that lack a browser or have limited
// input capabilities. It allows users to authorize applications by entering a code on
// a separate device (e.g., a smartphone or computer).
//
// Unlike the authorization code flow, this flow does not require a client secret or callback URL,
// making it suitable for public clients and constrained devices.
//
// Parameters:
//   - baseURL: The base URL of your Kinde instance (e.g., "https://yourdomain.kinde.com")
//   - options: Optional configuration functions to customize the flow behavior
//
// Returns an IDeviceAuthorizationFlow interface and an error if initialization fails.
//
// Example:
//
//	flow, err := NewDeviceAuthorizationFlow(
//	    "https://yourdomain.kinde.com",
//	    WithScopes("openid", "profile", "email"),
//	)
func NewDeviceAuthorizationFlow(baseURL string, options ...Option) (IDeviceAuthorizationFlow, error) {
	return newAuthorizationCodeFlow(baseURL, "", "", "", options...)
}

// StartDeviceAuth retrieves the device authorization response.
// It returns the device authorization response or an error if the request fails.
// This is used for the device authorization flow.
func (flow *AuthorizationCodeFlow) StartDeviceAuth(ctx context.Context) (*oauth2.DeviceAuthResponse, error) {
	return flow.config.DeviceAuth(ctx)
}

// GetAuthURL returns the authorization URL to redirect users to for authentication.
//
// This method generates the complete OAuth2 authorization URL with all configured parameters,
// including scopes, PKCE challenges (if enabled), custom auth parameters, and state.
// The URL should be used to redirect the user's browser to the authorization server.
//
// The state parameter is automatically generated using the configured state generator
// (or a random value by default) to prevent CSRF attacks.
//
// Returns the complete authorization URL as a string.
//
// Example:
//
//	authURL := flow.GetAuthURL()
//	http.Redirect(w, r, authURL, http.StatusFound)
func (flow *AuthorizationCodeFlow) GetAuthURL() string {
	return flow.GetAuthURLWithInvitation("")
}

// GetAuthURLWithInvitation returns the URL to redirect the user to start authentication pipeline
// with invitation code support. If invitationCode is provided, it will include both
// invitation_code and is_invitation parameters in the auth URL.
func (flow *AuthorizationCodeFlow) GetAuthURLWithInvitation(invitationCode string) string {
	state := flow.stateGenerator(flow)
	url, _ := url.Parse(flow.config.AuthCodeURL(state))
	query := url.Query()
	for k, v := range flow.authURLOptions {
		if query.Get(k) == "" {
			query[k] = v
		}
	}

	// Add invitation code parameters if provided
	invitationCode = strings.TrimSpace(invitationCode)
	if invitationCode != "" {
		query.Set("invitation_code", invitationCode)
		query.Set("is_invitation", "true")
	}

	// Add PKCE parameters if enabled
	if flow.usePKCE {
		query.Set("code_challenge", flow.codeChallenge)
		query.Set("code_challenge_method", flow.challengeMethod)
	}

	url.RawQuery = query.Encode()
	return url.String()
}

// SwitchOrg returns the authorization URL that re-authenticates the user into the
// organization identified by orgCode, using org_code and prompt=login.
func (flow *AuthorizationCodeFlow) SwitchOrg(orgCode string) (string, error) {
	orgCode = strings.TrimSpace(orgCode)
	if orgCode == "" {
		return "", fmt.Errorf("org code cannot be empty")
	}

	authURL, err := url.Parse(flow.GetAuthURL())
	if err != nil {
		return "", fmt.Errorf("failed to parse auth URL: %w", err)
	}

	query := authURL.Query()
	query.Set("org_code", orgCode)
	query.Set("prompt", "login")
	authURL.RawQuery = query.Encode()

	return authURL.String(), nil
}

// AuthorizationCodeReceivedHandler handles the OAuth2 callback from the authorization server.
//
// This method processes the authorization callback, validates the state parameter to prevent
// CSRF attacks, exchanges the authorization code for tokens, and stores the tokens using
// the configured session hooks.
//
// The handler expects the callback request to contain:
//   - "code": The authorization code from the authorization server
//   - "state": The state parameter that was sent in the authorization request
//
// If successful, the tokens are stored and the user is authenticated. If an error occurs,
// an HTTP error response is written to the response writer.
//
// Parameters:
//   - w: The HTTP response writer
//   - r: The HTTP request containing the authorization callback
//
// Example:
//
//	http.HandleFunc("/callback", flow.AuthorizationCodeReceivedHandler)
func (flow *AuthorizationCodeFlow) AuthorizationCodeReceivedHandler(w http.ResponseWriter, r *http.Request) {
	receivedState := r.URL.Query().Get("state")
	if !flow.stateVerifier(flow, receivedState) {
		http.Error(w, "invalid state parameter", http.StatusBadRequest)
		return
	}
	// Use ExchangeCode to properly handle PKCE code verifier if enabled
	if err := flow.ExchangeCode(r.Context(), r.URL.Query().Get("code"), receivedState); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func newAuthorizationCodeFlow(baseURL string, clientID string, clientSecret string, callbackURL string,
	options ...Option) (*AuthorizationCodeFlow, error) {
	asURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	host := asURL.Hostname()

	if asURL.Port() != "" {
		host = fmt.Sprintf("%v:%v", host, asURL.Port())
	}

	flow := &AuthorizationCodeFlow{
		JWKS_URL: fmt.Sprintf("%v://%v/.well-known/jwks", asURL.Scheme, host),
		config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  callbackURL,
			Scopes:       []string{},
			Endpoint: oauth2.Endpoint{
				TokenURL:      fmt.Sprintf("%v://%v/oauth2/token", asURL.Scheme, host),
				AuthURL:       fmt.Sprintf("%v://%v/oauth2/auth", asURL.Scheme, host),
				DeviceAuthURL: fmt.Sprintf("%v://%v/oauth2/device/auth", asURL.Scheme, host),
				AuthStyle:     oauth2.AuthStyleInParams,
			},
		},
		authURLOptions: url.Values{},
		stateGenerator: func(flow *AuthorizationCodeFlow) string {
			state := fmt.Sprintf("ks_%v", strings.ReplaceAll(uuid.NewString(), "-", ""))
			flow.sessionHooks.SetState(state)
			return state
		},
		stateVerifier: func(flow *AuthorizationCodeFlow, receivedState string) bool {
			state, err := flow.sessionHooks.GetState()
			if err != nil {
				return false
			}
			return state == receivedState
		},
		// Initialize PKCE fields
		usePKCE:         false,
		codeChallenge:   "",
		challengeMethod: "S256",
	}

	for _, o := range options {
		o(flow)
	}

	if flow.sessionHooks == nil {
		return nil, fmt.Errorf("session hooks are not set, please connect your session management with WithSessionHooks")
	}

	return flow, nil
}

// Exchanges the authorization code for a token and established KindeContext
func (flow *AuthorizationCodeFlow) ExchangeCode(ctx context.Context, authorizationCode string, receivedState string) error {
	storedState, err := flow.sessionHooks.GetState()
	if err != nil {
		return fmt.Errorf("failed to get state from session: %w", err)
	}

	if storedState == "" {
		return fmt.Errorf("state not found in session")
	}

	if storedState != receivedState {
		return fmt.Errorf("state mismatch: expected %s, got %s", storedState, receivedState)
	}

	var token *oauth2.Token
	if flow.usePKCE {
		// Get code verifier from session hooks
		codeVerifier, err := flow.sessionHooks.GetCodeVerifier()
		if err != nil {
			return fmt.Errorf("failed to get code verifier from session: %w", err)
		}
		if codeVerifier == "" {
			return fmt.Errorf("code verifier not found in session")
		}

		// Exchange with PKCE code verifier
		token, err = flow.config.Exchange(ctx, authorizationCode, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	} else {
		// Standard exchange without PKCE
		token, err = flow.config.Exchange(ctx, authorizationCode)
	}

	if err != nil {
		return err
	}

	err = flow.sessionHooks.SetRawToken(token)

	return err
}

// ExchangeDeviceAccessToken retrieves the access token for the device authorization flow.
func (flow *AuthorizationCodeFlow) ExchangeDeviceAccessToken(ctx context.Context, da *oauth2.DeviceAuthResponse, opts ...oauth2.AuthCodeOption) error {

	token, err := flow.config.DeviceAccessToken(ctx, da, opts...)

	if err != nil {
		return err
	}

	err = flow.sessionHooks.SetRawToken(token)

	return err
}

// Returns the client to make requests to the backend, will refresh token if offline is requested.
func (flow *AuthorizationCodeFlow) GetClient(ctx context.Context) (*http.Client, error) {
	tokenSource, err := flow.getTokenSource(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get token source: %w", err)
	}
	return oauth2.NewClient(ctx, tokenSource), nil
}

// InjectTokenMiddleware injects the token into the request context for downstream handlers
func (flow *AuthorizationCodeFlow) InjectTokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the token from the session
		token, err := flow.GetToken(r.Context())
		if err != nil {
			// If token retrieval fails, continue without token in context
			// This allows downstream handlers to handle authentication as needed
			next.ServeHTTP(w, r)
			return
		}

		// Create a new context with the token
		ctx := context.WithValue(r.Context(), contextKey("kinde_token"), token)

		// Create a new request with the updated context
		newReq := r.WithContext(ctx)

		// Call the next handler with the updated request
		next.ServeHTTP(w, newReq)
	})
}

func (flow *AuthorizationCodeFlow) getTokenSource(_ context.Context) (sessionTokenSource, error) {
	return sessionTokenSource{flow: flow}, nil
}

// PKCE utility functions
func generateCodeVerifier() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func generateCodeChallenge(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// TokenFromContext extracts the Kinde JWT token from the request context.
//
// This helper function retrieves the parsed and validated JWT token that was previously
// stored in the request context by middleware (e.g., InjectTokenMiddleware). It provides
// a convenient way for downstream handlers to access the authenticated user's token.
//
// Parameters:
//   - ctx: The request context that may contain a Kinde token
//
// Returns the JWT token and true if a token was found in the context, or nil and false otherwise.
//
// Example:
//
//	func myHandler(w http.ResponseWriter, r *http.Request) {
//	    token, ok := TokenFromContext(r.Context())
//	    if !ok {
//	        http.Error(w, "Unauthorized", http.StatusUnauthorized)
//	        return
//	    }
//	    userID := token.GetSubject()
//	    // Use token...
//	}
func TokenFromContext(ctx context.Context) (*jwt.Token, bool) {
	token, ok := ctx.Value(contextKey("kinde_token")).(*jwt.Token)
	return token, ok
}
