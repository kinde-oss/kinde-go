package authorization_code

import (
	"slices"
	"strings"

	"github.com/kinde-oss/kinde-go/jwt"
)

type (
	Option func(*AuthorizationCodeFlow)
)

// Adds an arbitrary parameter to the list of parameters to request.
func WithAuthParameter(name, value string) Option {
	return func(s *AuthorizationCodeFlow) {
		if val, ok := s.authURLOptions[name]; ok {
			if !slices.Contains(val, value) {
				s.authURLOptions[name] = append(val, value)
			}
		} else {
			s.authURLOptions[name] = []string{value}
		}

	}
}

// Adds an audience to the list of audiences to request.
func WithAudience(audience string) Option {
	return func(s *AuthorizationCodeFlow) {
		WithAuthParameter("audience", audience)(s)
	}
}

// Adds an audience to the list of audiences to request.
func WithPrompt(prompt string) Option {
	return func(s *AuthorizationCodeFlow) {
		WithAuthParameter("prompt", prompt)(s)
	}
}

// Adds the offline scope to the list of scopes to request.
func WithOffline() Option {
	return func(s *AuthorizationCodeFlow) {
		WithAdditionalScope("offline")(s)
	}
}

// Adds the offline scope to the list of scopes to request.
func WithCustomStateGenerator(stateFunc func(*AuthorizationCodeFlow) string) Option {
	return func(s *AuthorizationCodeFlow) {
		s.stateGenerator = stateFunc
	}
}

// Integrates with the session management
func WithSessionHooks(sessionHooks ISessionHooks) Option {
	return func(s *AuthorizationCodeFlow) {
		s.sessionHooks = sessionHooks
	}
}

// Integrates with the session management
func WithClientID(clientID string) Option {
	return func(s *AuthorizationCodeFlow) {
		s.config.ClientID = clientID
	}
}

// Integrates with the session management
func WithClientSecret(clientSecret string) Option {
	return func(s *AuthorizationCodeFlow) {
		s.config.ClientSecret = clientSecret
	}
}

// Adds a scopes to the list of scopes to request, replaces value with the provided.
func WithScopes(scopes ...string) Option {
	return func(s *AuthorizationCodeFlow) {
		s.config.Scopes = scopes
	}
}

// Adds a scopes to the list of scopes to request, adds scope to existing list.
func WithAdditionalScope(scope string) Option {
	return func(s *AuthorizationCodeFlow) {
		s.config.Scopes = append(s.config.Scopes, scope)
	}
}

// Adds options to validate the token.
func WithTokenValidation(isValidateJWKS bool, tokenOptions ...func(*jwt.Token)) Option {
	return func(s *AuthorizationCodeFlow) {

		if isValidateJWKS {
			s.tokenOptions = append(s.tokenOptions, jwt.WillValidateWithJWKSUrl(s.JWKS_URL))
		}

		s.tokenOptions = append(s.tokenOptions, tokenOptions...)
	}
}

// Enables PKCE (Proof Key for Code Exchange) for enhanced security in public clients.
// This is recommended for applications that cannot securely store a client secret.
func WithPKCE() Option {
	return func(s *AuthorizationCodeFlow) {
		s.usePKCE = true
		s.challengeMethod = "S256" // Explicitly set recommended default
		// Generate code verifier and challenge when PKCE is enabled
		if codeVerifier, err := generateCodeVerifier(); err == nil {
			// Store code verifier in session hooks
			if s.sessionHooks != nil {
				_ = s.sessionHooks.SetCodeVerifier(codeVerifier)
			}
			s.codeChallenge = generateCodeChallenge(codeVerifier)
		}
	}
}

func WithPKCEChallengeMethod(method string) Option {
	return func(s *AuthorizationCodeFlow) {
		s.usePKCE = true
		// accept only "S256" or "plain"; default to "S256"
		switch method {
		case "plain":
			s.challengeMethod = "plain"
		case "S256":
			s.challengeMethod = "S256"
		default:
			s.challengeMethod = "S256"
		}
		// Generate code verifier and challenge when PKCE is enabled
		if codeVerifier, err := generateCodeVerifier(); err == nil {
			// Store code verifier in session hooks
			if s.sessionHooks != nil {
				_ = s.sessionHooks.SetCodeVerifier(codeVerifier)
			}
			if s.challengeMethod == "plain" {
				s.codeChallenge = codeVerifier
			} else {
				s.codeChallenge = generateCodeChallenge(codeVerifier)
			}
		}
	}
}

// WithInvitationCode sets the invitation code and is_invitation parameters for team member invitations.
// When an invitation code is provided, is_invitation will be set to "true".
func WithInvitationCode(invitationCode string) Option {
	return func(s *AuthorizationCodeFlow) {
		invitationCode = strings.TrimSpace(invitationCode)
		if invitationCode != "" {
			WithAuthParameter("invitation_code", invitationCode)(s)
			WithAuthParameter("is_invitation", "true")(s)
		}
	}
}
