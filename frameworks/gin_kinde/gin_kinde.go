package gin_kinde

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/kinde-oss/kinde-go/oauth2/authorization_code"
	"golang.org/x/oauth2"
)

// SessionStorage implements the authorization_code.ISessionHooks interface
// for storing and retrieving OAuth2 session data using Gin's session middleware.
//
// It provides methods for managing:
//   - OAuth2 tokens (access, refresh, ID tokens)
//   - PKCE code verifiers
//   - Authentication state
//   - Post-authentication redirect URLs
//   - Custom session items
//
// This storage backend is designed to work seamlessly with Gin's sessions package
// and is used by the UseKindeAuth middleware to manage authentication state.
type SessionStorage struct {
	session sessions.Session
}

// GetCodeVerifier retrieves the PKCE code verifier from the session.
//
// This method implements authorization_code.ISessionHooks and is used during
// the OAuth2 authorization code exchange with PKCE flow. The code verifier
// is required to complete the token exchange after the user authorizes the application.
//
// Returns the code verifier string if found, or an error if:
//   - The code verifier is not found in the session
//   - The stored value is not a valid string type
//
// This method implements authorization_code.ISessionHooks.
func (storage *SessionStorage) GetCodeVerifier() (string, error) {
	v := storage.session.Get("code_verifier")
	if v == nil {
		return "", fmt.Errorf("code_verifier not found in session")
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("invalid code_verifier type in session")
	}
	return s, nil
}

// SetCodeVerifier stores the PKCE code verifier in the session.
//
// This method implements authorization_code.ISessionHooks and is used to store
// the PKCE code verifier during the OAuth2 authorization flow. The code verifier
// must be stored securely in the session so it can be retrieved later during
// the token exchange process.
//
// Parameters:
//   - codeVerifier: The PKCE code verifier string to store
//
// Returns an error if the session cannot be saved.
//
// This method implements authorization_code.ISessionHooks.
func (storage *SessionStorage) SetCodeVerifier(codeVerifier string) error {
	storage.session.Set("code_verifier", codeVerifier)
	if err := storage.session.Save(); err != nil {
		return fmt.Errorf("failed to save session: %w", err)
	}
	return nil
}

// GetRawToken retrieves the raw OAuth2 token from the session.
//
// This method implements authorization_code.ISessionHooks and retrieves the
// complete OAuth2 token (including access token, refresh token, expiry, etc.)
// that was previously stored in the session. The token is deserialized from
// JSON format for compatibility with session storage.
//
// Returns the OAuth2 token if found, or an error if:
//   - The token is not found in the session
//   - The stored value cannot be deserialized as a valid token
//   - The token data is in an invalid format
//
// This method implements authorization_code.ISessionHooks.
func (storage *SessionStorage) GetRawToken() (*oauth2.Token, error) {
	tokenData := storage.session.Get("kinde_token")
	if tokenData == nil {
		return nil, fmt.Errorf("token not found in session")
	}

	// Handle both JSON string (new format) and direct token (old format for backwards compatibility)
	var tokenBytes []byte
	switch v := tokenData.(type) {
	case string:
		tokenBytes = []byte(v)
	case []byte:
		tokenBytes = v
	default:
		// Try to marshal if it's already a token (backwards compatibility)
		if t, ok := tokenData.(*oauth2.Token); ok {
			return t, nil
		}
		return nil, fmt.Errorf("invalid token type in session")
	}

	var t oauth2.Token
	if err := json.Unmarshal(tokenBytes, &t); err != nil {
		return nil, fmt.Errorf("invalid token type in session")
	}
	return &t, nil
}

// SetRawToken stores the raw OAuth2 token in the session.
//
// This method implements authorization_code.ISessionHooks and stores the complete
// OAuth2 token (including access token, refresh token, expiry, etc.) in the
// session. The token is serialized to JSON format to avoid gob serialization
// issues with the oauth2.Token type.
//
// Parameters:
//   - token: The OAuth2 token to store, or nil to clear the token from the session
//
// Returns an error if:
//   - The token cannot be serialized to JSON
//   - The session cannot be saved
//
// This method implements authorization_code.ISessionHooks.
func (storage *SessionStorage) SetRawToken(token *oauth2.Token) error {
	if token == nil {
		storage.session.Set("kinde_token", nil)
	} else {
		// Serialize token to JSON to avoid gob serialization issues
		tokenBytes, err := json.Marshal(token)
		if err != nil {
			return fmt.Errorf("failed to marshal token: %w", err)
		}
		storage.session.Set("kinde_token", string(tokenBytes))
	}
	if err := storage.session.Save(); err != nil {
		return fmt.Errorf("failed to save session: %w", err)
	}
	return nil
}

// GetPostAuthRedirect retrieves the post-authentication redirect URL from the session.
//
// This method implements authorization_code.SessionHooks and retrieves the URL
// where the user should be redirected after successful authentication. This is
// useful for preserving the user's intended destination before they were redirected
// to the login page.
//
// Returns the redirect URL if found, or an empty string if not set. Returns an
// error if the stored value is not a valid string type.
//
// This method implements authorization_code.SessionHooks.
func (storage *SessionStorage) GetPostAuthRedirect() (string, error) {
	v := storage.session.Get("post_auth_redirect")
	if v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("invalid post_auth_redirect type in session")
	}
	return s, nil
}

// GetState retrieves the OAuth2 state parameter from the session.
//
// This method implements authorization_code.SessionHooks and retrieves the state
// value that was generated during the authorization request. The state parameter
// is used to prevent CSRF attacks by verifying that the authorization response
// corresponds to the original request.
//
// Returns the state string if found, or an empty string if not set. Returns an
// error if the stored value is not a valid string type.
//
// This method implements authorization_code.SessionHooks.
func (storage *SessionStorage) GetState() (string, error) {
	v := storage.session.Get("auth_state")
	if v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("invalid auth_state type in session")
	}
	return s, nil
}

// SetPostAuthRedirect stores the post-authentication redirect URL in the session.
//
// This method implements authorization_code.SessionHooks and stores the URL where
// the user should be redirected after successful authentication. This allows the
// application to remember the user's intended destination before they were
// redirected to the login page.
//
// Parameters:
//   - redirect: The URL to redirect to after authentication
//
// Returns an error if the session cannot be saved.
//
// This method implements authorization_code.SessionHooks.
func (storage *SessionStorage) SetPostAuthRedirect(redirect string) error {
	storage.session.Set("post_auth_redirect", redirect)
	if err := storage.session.Save(); err != nil {
		return fmt.Errorf("failed to save session: %w", err)
	}
	return nil
}

// SetState stores the OAuth2 state parameter in the session.
//
// This method implements authorization_code.SessionHooks and stores the state
// value that will be used during the OAuth2 authorization flow. The state
// parameter is used to prevent CSRF attacks by verifying that the authorization
// response corresponds to the original request.
//
// Parameters:
//   - state: The state string to store
//
// Returns an error if the session cannot be saved.
//
// This method implements authorization_code.SessionHooks.
func (storage *SessionStorage) SetState(state string) error {
	storage.session.Set("auth_state", state)
	if err := storage.session.Save(); err != nil {
		return fmt.Errorf("failed to save session: %w", err)
	}
	return nil
}

// GetItem retrieves a custom string value from the session by key.
//
// Parameters:
//   - key: The session key to retrieve
//
// Returns the string value associated with the key, or an empty string if not found.
func (storage *SessionStorage) GetItem(key string) string {
	value := storage.session.Get(key)
	if value == nil {
		return ""
	}
	if s, ok := value.(string); ok {
		return s
	}
	return ""
}

// SetItem stores a custom string value in the session with the specified key.
//
// Parameters:
//   - key: The session key to store the value under
//   - value: The string value to store
//
// Note: This method does not return an error for backwards compatibility,
// but errors from session.Save() are silently ignored. Consider using
// a method that returns an error for critical session operations.
func (storage *SessionStorage) SetItem(key, value string) {
	storage.session.Set(key, value)
	_ = storage.session.Save() // Error ignored for backwards compatibility
}

// UseKindeAuth sets up Kinde authentication middleware for a Gin router group.
//
// This function configures OAuth2 authorization code flow authentication with Kinde,
// including automatic token validation, session management, and protected route handling.
// It adds three middleware layers:
//  1. Initialization middleware that creates the Kinde client and stores it in context
//  2. Callback handler for processing OAuth2 authorization callbacks
//  3. Authentication middleware that redirects unauthenticated users to login
//
// The middleware automatically:
//   - Validates JWT tokens using JWKS
//   - Manages OAuth2 tokens in session storage
//   - Handles PKCE flow if enabled
//   - Redirects unauthenticated users to the Kinde login page
//   - Processes OAuth2 callbacks and stores tokens
//
// Parameters:
//   - router: The Gin router group to apply authentication to
//   - kindeDomain: Your Kinde domain (e.g., "https://yourdomain.kinde.com" or "yourdomain")
//   - clientID: Your OAuth2 client ID
//   - clientSecret: Your OAuth2 client secret
//   - baseRedirectURL: The base URL for redirects (e.g., "https://yourapp.com")
//   - options: Optional configuration options (e.g., WithPKCE, WithScopes, WithOffline)
//
// Returns an error if the Kinde client cannot be created.
//
// Example:
//
//	router := gin.Default()
//	api := router.Group("/api")
//	err := gin_kinde.UseKindeAuth(
//	    api,
//	    "https://yourdomain.kinde.com",
//	    "your-client-id",
//	    "your-client-secret",
//	    "https://yourapp.com",
//	    authorization_code.WithPKCE(),
//	    authorization_code.WithOffline(),
//	)
func UseKindeAuth(router *gin.RouterGroup, kindeDomain, clientID, clientSecret, baseRedirectURL string, options ...authorization_code.Option) error {
	basePath := router.BasePath()
	if basePath == "/" {
		basePath = ""
	}
	redirectURI := fmt.Sprintf("%s%s%s", baseRedirectURL, basePath, "/kinde/callback")

	router.Use(func(ctx *gin.Context) {
		session := sessions.Default(ctx)
		sessionStorage := &SessionStorage{session: session}

		reqOptions := append(options,
			authorization_code.WithSessionHooks(sessionStorage),
			authorization_code.WithTokenValidation(true),
		)
		kindeClient, err := authorization_code.NewAuthorizationCodeFlow(kindeDomain,
			clientID,
			clientSecret,
			redirectURI,
			reqOptions...,
		)

		if err != nil {
			fmt.Printf("Error creating Kinde client: %v", err)
			ctx.String(500, "Error creating Kinde client")
			ctx.Abort()
			return
		}

		ctx.Set("kinde_client", kindeClient)
	})

	router.GET("/kinde/callback", func(ctx *gin.Context) {
		if client, ok := ctx.Get("kinde_client"); ok {
			if kindeClient, ok := client.(authorization_code.IAuthorizationCodeFlow); ok {
				err := kindeClient.ExchangeCode(context.Background(), ctx.Query("code"), ctx.Query("state"))
				if err != nil {
					ctx.AbortWithError(500, err)
					return
				}
				ctx.Redirect(302, "/")
				return
			}
		}
		ctx.AbortWithError(500, fmt.Errorf("kinde client not found"))
	})

	router.Use(func(ctx *gin.Context) {

		if client, ok := ctx.Get("kinde_client"); ok {
			if kindeClient, ok := client.(authorization_code.IAuthorizationCodeFlow); ok {

				if isAuthenticated, _ := kindeClient.IsAuthenticated(context.Background()); !isAuthenticated {
					// Check for invitation_code query parameter
					invitationCode := ctx.Query("invitation_code")
					authURL := kindeClient.GetAuthURLWithInvitation(invitationCode)
					ctx.Redirect(302, authURL)
					ctx.Abort()
				}
				return
			}
		}

		ctx.AbortWithError(401, fmt.Errorf("unauthorized"))

	})

	return nil
}
