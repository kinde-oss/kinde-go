package authorization_code

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/kinde-oss/kinde-go/jwt"
)

type (
	Option func(*AuthorizationCodeFlow)
)

const (
	authParamAcrValues = "acr_values"
	authParamMaxAge    = "max_age"
)

// WithAuthParameter adds an arbitrary parameter to the authorization URL.
//
// This option allows you to add custom query parameters to the authorization request URL.
// If the parameter already exists, the new value is appended to the existing values.
//
// Parameters:
//   - name: The parameter name (e.g., "custom_param", "login_hint")
//   - value: The parameter value
//
// Returns an Option that adds the specified parameter to the authorization URL.
//
// Example:
//
//	flow, err := NewAuthorizationCodeFlow(baseURL, clientID, clientSecret, callbackURL,
//	    WithAuthParameter("login_hint", "user@example.com"),
//	)
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

// WithAudience adds an audience parameter to the authorization request.
//
// The audience parameter specifies which API or resource server the token is intended for.
// This is used in OAuth 2.0 flows where tokens are scoped to specific audiences.
//
// Parameters:
//   - audience: The audience identifier (e.g., API endpoint URL or identifier)
//
// Returns an Option that adds the audience parameter to the authorization URL.
//
// Example:
//
//	flow, err := NewAuthorizationCodeFlow(baseURL, clientID, clientSecret, callbackURL,
//	    WithAudience("https://api.example.com"),
//	)
func WithAudience(audience string) Option {
	return func(s *AuthorizationCodeFlow) {
		WithAuthParameter("audience", audience)(s)
	}
}

// WithPrompt adds a prompt parameter to the authorization request.
//
// The prompt parameter controls how the authorization server handles the authentication
// and consent UI. Common values include:
//   - "login": Forces the user to re-authenticate
//   - "consent": Forces the user to see the consent screen
//   - "select_account": Prompts the user to select an account
//   - "none": Prevents any UI from being shown (will fail if user is not authenticated)
//
// Parameters:
//   - prompt: The prompt value to include in the authorization request
//
// Returns an Option that adds the prompt parameter to the authorization URL.
//
// Example:
//
//	flow, err := NewAuthorizationCodeFlow(baseURL, clientID, clientSecret, callbackURL,
//	    WithPrompt("login"),
//	)
func WithPrompt(prompt string) Option {
	return func(s *AuthorizationCodeFlow) {
		WithAuthParameter("prompt", prompt)(s)
	}
}

// WithAcrValues requests an authentication context (RFC 9470) by adding the
// acr_values parameter to the authorization request.
//
// Kinde recognises jwt.AcrMFA (a second factor) and jwt.AcrPHR (phishing-resistant,
// a passkey). When several values are given the highest one applies. If the
// session already meets the context, Kinde issues tokens without prompting;
// otherwise it asks only for the missing factor.
//
// Set on a flow, this applies to every login made with it. To ask for a
// stronger context before a single sensitive action, use StepUp instead.
//
// Nothing is sent when no values are given. A value other than "mfa" or "phr"
// makes NewAuthorizationCodeFlow (or StepUp) return an error, because Kinde
// would silently ignore it.
//
// Parameters:
//   - acrValues: One or more of jwt.AcrMFA and jwt.AcrPHR
//
// Returns an Option that sets the acr_values parameter of the authorization URL.
//
// Example:
//
//	flow, err := NewAuthorizationCodeFlow(baseURL, clientID, clientSecret, callbackURL,
//	    WithAcrValues(jwt.AcrMFA),
//	)
func WithAcrValues(acrValues ...string) Option {
	return func(s *AuthorizationCodeFlow) {
		normalized := []string{}
		for _, value := range strings.Fields(strings.ToLower(strings.Join(acrValues, " "))) {
			if value != jwt.AcrMFA && value != jwt.AcrPHR {
				s.optionErrors = append(s.optionErrors,
					fmt.Errorf("unsupported acr value %q: expected %q or %q", value, jwt.AcrMFA, jwt.AcrPHR))
				return
			}
			if !slices.Contains(normalized, value) {
				normalized = append(normalized, value)
			}
		}
		if len(normalized) == 0 {
			return
		}
		s.authURLOptions[authParamAcrValues] = []string{strings.Join(normalized, " ")}
	}
}

// WithMaxAge sets the maximum age, in seconds, of the user's last authentication
// by adding the max_age parameter to the authorization request.
//
// When the session is older than maxAge, Kinde asks the user to authenticate
// again: with their first factor when used on its own, or with only the factor
// required by WithAcrValues when used together with it. 0 is valid and requires
// re-authentication on every request.
//
// The parameter is only sent when this option is used. A negative value makes
// NewAuthorizationCodeFlow (or StepUp) return an error.
//
// Parameters:
//   - maxAge: The maximum authentication age in seconds (0 or more)
//
// Returns an Option that sets the max_age parameter of the authorization URL.
//
// Example:
//
//	flow, err := NewAuthorizationCodeFlow(baseURL, clientID, clientSecret, callbackURL,
//	    WithAcrValues(jwt.AcrMFA),
//	    WithMaxAge(300),
//	)
func WithMaxAge(maxAge int) Option {
	return func(s *AuthorizationCodeFlow) {
		if maxAge < 0 {
			s.optionErrors = append(s.optionErrors,
				fmt.Errorf("invalid max age %d: expected a non-negative number of seconds", maxAge))
			return
		}
		s.authURLOptions[authParamMaxAge] = []string{strconv.Itoa(maxAge)}
	}
}

// WithCallbackErrorHandler sets a function that receives every error from
// AuthorizationCodeReceivedHandler instead of the default plain-text response.
// The callback route of gin_kinde.UseKindeAuth calls it too; in a Gin app,
// gin_kinde.WithCallbackErrorHandler gives the function the Gin context.
//
// Use it to show your own page when a callback fails. In particular, a step-up
// that the user cannot complete arrives here as an
// *UnmetAuthenticationRequirementsError (check with errors.As). That answer is
// final: show the user why, and do not redirect them back to login.
//
// Parameters:
//   - handler: Writes the response for a failed callback
//
// Returns an Option that configures the callback error handler.
//
// Example:
//
//	flow, err := NewAuthorizationCodeFlow(baseURL, clientID, clientSecret, callbackURL,
//	    WithCallbackErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
//	        var unmet *UnmetAuthenticationRequirementsError
//	        if errors.As(err, &unmet) {
//	            http.Error(w, "Add a passkey or authenticator app to continue.", http.StatusForbidden)
//	            return
//	        }
//	        http.Error(w, "Sign-in failed.", http.StatusInternalServerError)
//	    }),
//	)
func WithCallbackErrorHandler(handler func(w http.ResponseWriter, r *http.Request, err error)) Option {
	return func(s *AuthorizationCodeFlow) {
		s.callbackErrorHandler = handler
	}
}

// WithOffline adds the "offline_access" scope to the authorization request.
//
// The offline_access scope requests a refresh token that can be used to obtain
// new access tokens without requiring user interaction. This is useful for applications
// that need to access resources on behalf of the user when they are not actively using the app.
//
// Returns an Option that adds the offline_access scope to the authorization request.
//
// Example:
//
//	flow, err := NewAuthorizationCodeFlow(baseURL, clientID, clientSecret, callbackURL,
//	    WithOffline(),
//	)
func WithOffline() Option {
	return func(s *AuthorizationCodeFlow) {
		WithAdditionalScope("offline")(s)
	}
}

// WithCustomStateGenerator sets a custom function to generate the OAuth state parameter.
//
// The state parameter is used to prevent CSRF attacks and to maintain state between
// the authorization request and callback. By default, a random state is generated.
//
// This option allows you to provide a custom state generation function, which can be useful
// for maintaining application-specific state or integrating with session management systems.
//
// Parameters:
//   - stateFunc: A function that receives the AuthorizationCodeFlow and returns a state string
//
// Returns an Option that configures the custom state generator.
//
// Example:
//
//	flow, err := NewAuthorizationCodeFlow(baseURL, clientID, clientSecret, callbackURL,
//	    WithCustomStateGenerator(func(flow *AuthorizationCodeFlow) string {
//	        return generateSecureState()
//	    }),
//	)
func WithCustomStateGenerator(stateFunc func(*AuthorizationCodeFlow) string) Option {
	return func(s *AuthorizationCodeFlow) {
		s.stateGenerator = stateFunc
	}
}

// WithSessionHooks integrates the authorization flow with session management.
//
// Session hooks allow you to customize how tokens and session data are stored and retrieved.
// This is essential for integrating with your application's session management system.
//
// The ISessionHooks interface provides methods for:
//   - Storing and retrieving OAuth2 tokens
//   - Managing PKCE code verifiers
//   - Handling session state
//
// Parameters:
//   - sessionHooks: An implementation of ISessionHooks for custom session management
//
// Returns an Option that configures session management hooks.
//
// Example:
//
//	flow, err := NewAuthorizationCodeFlow(baseURL, clientID, clientSecret, callbackURL,
//	    WithSessionHooks(mySessionHooks),
//	)
func WithSessionHooks(sessionHooks ISessionHooks) Option {
	return func(s *AuthorizationCodeFlow) {
		s.sessionHooks = sessionHooks
	}
}

// WithClientID sets the OAuth2 client ID for the authorization flow.
//
// The client ID identifies your application to the authorization server.
// This option allows you to override the client ID that was provided to NewAuthorizationCodeFlow.
//
// Parameters:
//   - clientID: The OAuth2 client ID
//
// Returns an Option that sets the client ID.
func WithClientID(clientID string) Option {
	return func(s *AuthorizationCodeFlow) {
		s.config.ClientID = clientID
	}
}

// WithClientSecret sets the OAuth2 client secret for the authorization flow.
//
// The client secret is used to authenticate your application when exchanging
// authorization codes for tokens. This option allows you to override the client secret
// that was provided to NewAuthorizationCodeFlow.
//
// Parameters:
//   - clientSecret: The OAuth2 client secret
//
// Returns an Option that sets the client secret.
func WithClientSecret(clientSecret string) Option {
	return func(s *AuthorizationCodeFlow) {
		s.config.ClientSecret = clientSecret
	}
}

// WithScopes sets the OAuth2 scopes for the authorization request.
//
// Scopes define the permissions that your application is requesting from the user.
// This option replaces any existing scopes with the provided list. Default scopes
// (openid, profile, email) are automatically prepended if not explicitly included.
//
// Parameters:
//   - scopes: One or more scope strings (e.g., "openid", "profile", "email", "offline_access")
//
// Returns an Option that sets the authorization scopes.
//
// Example:
//
//	flow, err := NewAuthorizationCodeFlow(baseURL, clientID, clientSecret, callbackURL,
//	    WithScopes("openid", "profile", "email", "custom_scope"),
//	)
func WithScopes(scopes ...string) Option {
	return func(s *AuthorizationCodeFlow) {
		s.config.Scopes = scopes
	}
}

// WithAdditionalScope adds a scope to the existing list of authorization scopes.
//
// Unlike WithScopes which replaces all scopes, this option appends a new scope
// to the current scope list. This is useful for incrementally adding scopes.
//
// Parameters:
//   - scope: The scope string to add (e.g., "offline_access", "custom_scope")
//
// Returns an Option that adds the scope to the authorization request.
//
// Example:
//
//	flow, err := NewAuthorizationCodeFlow(baseURL, clientID, clientSecret, callbackURL,
//	    WithScopes("openid", "profile"),
//	    WithAdditionalScope("offline_access"),
//	)
func WithAdditionalScope(scope string) Option {
	return func(s *AuthorizationCodeFlow) {
		s.config.Scopes = append(s.config.Scopes, scope)
	}
}

// WithTokenValidation configures JWT token validation options.
//
// This option allows you to enable JWKS-based token validation and provide additional
// JWT validation options. When isValidateJWKS is true, the flow will automatically
// validate tokens using the JWKS URL from the authorization server.
//
// Parameters:
//   - isValidateJWKS: If true, enables automatic JWKS-based token validation
//   - tokenOptions: Additional JWT validation options (e.g., WillValidateIssuer, WillValidateAudience)
//
// Returns an Option that configures token validation.
//
// Example:
//
//	flow, err := NewAuthorizationCodeFlow(baseURL, clientID, clientSecret, callbackURL,
//	    WithTokenValidation(true,
//	        jwt.WillValidateIssuer("https://yourdomain.kinde.com"),
//	        jwt.WillValidateAudience("your-client-id"),
//	    ),
//	)
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

// WithPKCEChallengeMethod configures the PKCE challenge method for the authorization flow.
//
// PKCE (Proof Key for Code Exchange) uses a code challenge to enhance security.
// This option allows you to specify which challenge method to use:
//   - "S256" (recommended): Uses SHA256 to hash the code verifier. This is the default and recommended method.
//   - "plain": Uses the code verifier directly without hashing. Less secure, only use if the authorization server doesn't support S256.
//
// If an invalid method is provided, it defaults to "S256".
//
// This option automatically enables PKCE and generates the code verifier and challenge
// based on the selected method. The code verifier is stored in session hooks if available.
//
// Parameters:
//   - method: The challenge method to use ("S256" or "plain")
//
// Returns an Option that configures PKCE with the specified challenge method.
//
// Example:
//
//	flow, err := NewAuthorizationCodeFlow(baseURL, clientID, clientSecret, callbackURL,
//	    WithPKCEChallengeMethod("S256"),
//	)
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

// WithSupportsReauth adds the supports_reauth parameter to the authorization request.
//
// The supports_reauth parameter indicates that the authentication instigator supports
// re-authentication on expired flows. This is used to enable re-authentication flows
// when tokens expire, allowing the application to prompt users to re-authenticate
// without losing their session context.
//
// Returns an Option that adds the supports_reauth parameter to the authorization URL.
//
// Example:
//
//	flow, err := NewAuthorizationCodeFlow(baseURL, clientID, clientSecret, callbackURL,
//	    WithSupportsReauth(true),
//	)
func WithSupportsReauth(supportsReauth bool) Option {
	return func(s *AuthorizationCodeFlow) {
		WithAuthParameter("supports_reauth", fmt.Sprintf("%t", supportsReauth))(s)
	}
}

// WithReauthState decodes a Base64-encoded JSON string containing re-authentication
// parameters and merges them into the authorization URL options.
//
// The reauthState parameter is used to preserve authentication parameters during
// re-authentication flows. It should be a Base64-encoded JSON string containing
// login options that will be merged into the authorization request.
//
// This is particularly useful when tokens expire and you need to re-authenticate
// the user while preserving their original authentication context (e.g., org_code,
// audience, scopes, etc.).
//
// Parameters:
//   - reauthState: A Base64-encoded JSON string containing re-authentication parameters
//
// Returns an Option that decodes and merges the reauth state parameters.
//
// Example:
//
//	// reauthState is a Base64-encoded JSON like: {"org_code":"org123","audience":"api.example.com"}
//	flow, err := NewAuthorizationCodeFlow(baseURL, clientID, clientSecret, callbackURL,
//	    WithReauthState(encodedReauthState),
//	)
func WithReauthState(reauthState string) Option {
	return func(s *AuthorizationCodeFlow) {
		if reauthState == "" {
			return
		}

		// Decode Base64
		decodedBytes, err := base64.StdEncoding.DecodeString(reauthState)
		if err != nil {
			// Store error to be checked later - invalid reauthState will be ignored
			// This matches js-utils behavior where invalid reauthState throws an error
			// In Go, we store it and can check it, but for now we'll just skip invalid reauthState
			return
		}

		// Parse JSON
		var reauthParams map[string]interface{}
		if err := json.Unmarshal(decodedBytes, &reauthParams); err != nil {
			// Invalid JSON - skip reauthState (matches js-utils error handling)
			return
		}

		// Convert snake_case keys to the format expected by authURLOptions
		// and merge into authURLOptions
		for key, value := range reauthParams {
			// The reauth state is not written by the app, so like the rest of it an
			// unusable acr_values or max_age is skipped, not reported: never send
			// "<nil>", a rounded fraction, or anything but a non-negative whole number
			switch key {
			case "acrValues", authParamAcrValues:
				if value == nil {
					continue
				}
			case "maxAge", authParamMaxAge:
				if number, ok := value.(float64); ok {
					value = strconv.FormatFloat(number, 'f', -1, 64)
				}
				text, ok := value.(string)
				if !ok {
					continue
				}
				if _, err := parseMaxAge(text); err != nil {
					continue
				}
			}

			// Convert value to string
			var strValue string
			switch v := value.(type) {
			case string:
				strValue = v
			case bool:
				strValue = fmt.Sprintf("%t", v)
			case float64:
				strValue = fmt.Sprintf("%.0f", v)
			case []interface{}:
				// Handle arrays (e.g., audience, scopes)
				strValues := make([]string, 0, len(v))
				for _, item := range v {
					strValues = append(strValues, fmt.Sprintf("%v", item))
				}
				strValue = strings.Join(strValues, " ")
			default:
				strValue = fmt.Sprintf("%v", v)
			}

			// Map common camelCase to snake_case for URL parameters
			urlKey := key
			switch key {
			case "orgCode":
				urlKey = "org_code"
			case "orgName":
				urlKey = "org_name"
			case "loginHint":
				urlKey = "login_hint"
			case "connectionId":
				urlKey = "connection_id"
			case "redirectURL", "redirectUri":
				urlKey = "redirect_uri"
			case "isCreateOrg":
				urlKey = "is_create_org"
			case "hasSuccessPage":
				urlKey = "has_success_page"
			case "workflowDeploymentId":
				urlKey = "workflow_deployment_id"
			case "planInterest":
				urlKey = "plan_interest"
			case "pricingTableKey":
				urlKey = "pricing_table_key"
			case "pagesMode":
				urlKey = "pages_mode"
			case "acrValues":
				urlKey = authParamAcrValues
			case "maxAge":
				urlKey = authParamMaxAge
			}

			// Add to authURLOptions (don't overwrite existing values)
			if _, exists := s.authURLOptions[urlKey]; !exists {
				WithAuthParameter(urlKey, strValue)(s)
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

// validateAuthURLOptions reports the errors recorded by options and makes sure
// acr_values and max_age are only sent with a usable value, whichever option
// set them: an empty value is dropped, and a max_age that is not a non-negative
// whole number is rejected, because Kinde would read it as "re-authenticate".
func (flow *AuthorizationCodeFlow) validateAuthURLOptions() error {
	errs := slices.Clone(flow.optionErrors)

	for _, name := range []string{authParamAcrValues, authParamMaxAge} {
		values, ok := flow.authURLOptions[name]
		if !ok {
			continue
		}
		values = slices.DeleteFunc(slices.Clone(values), func(value string) bool {
			return strings.TrimSpace(value) == ""
		})
		if len(values) == 0 {
			delete(flow.authURLOptions, name)
			continue
		}
		flow.authURLOptions[name] = values
	}

	switch values := flow.authURLOptions[authParamMaxAge]; {
	case len(values) > 1:
		errs = append(errs, fmt.Errorf("invalid max_age: more than one value given (%s)", strings.Join(values, ", ")))
	case len(values) == 1:
		maxAge, err := parseMaxAge(values[0])
		if err != nil {
			errs = append(errs, fmt.Errorf("invalid max_age %q: expected a non-negative whole number of seconds", values[0]))
		} else {
			flow.authURLOptions[authParamMaxAge] = []string{strconv.FormatUint(maxAge, 10)}
		}
	}

	return errors.Join(errs...)
}

// parseMaxAge parses a max_age value: a non-negative whole number of seconds.
func parseMaxAge(value string) (uint64, error) {
	return strconv.ParseUint(strings.TrimSpace(value), 10, 63)
}
