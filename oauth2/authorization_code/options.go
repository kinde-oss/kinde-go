package authorization_code

import (
	"net/http"
	"net/url"
	"slices"

	"github.com/kinde-oss/kinde-go/jwt"
)

// Adds an arbitrary parameter to the list of parameters to request.
func WithAuthParameter(name, value string) func(*AuthorizationCodeFlow) {
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
func WithAudience(audience string) func(*AuthorizationCodeFlow) {
	return func(s *AuthorizationCodeFlow) {
		WithAuthParameter("audience", audience)(s)
	}
}

// Adds the offline scope to the list of scopes to request.
func WithOffline() func(*AuthorizationCodeFlow) {
	return func(s *AuthorizationCodeFlow) {
		WithScope("offline")
	}
}

// Adds the offline scope to the list of scopes to request.
func WithCustomStateGenerator(stateFunc func(*AuthorizationCodeFlow) string) func(*AuthorizationCodeFlow) {
	return func(s *AuthorizationCodeFlow) {
		s.stateGenerator = stateFunc
	}
}

// Integrates with the session management
func WithSessionHooks(sessionHooks SessionHooks) func(*AuthorizationCodeFlow) {
	return func(s *AuthorizationCodeFlow) {
		s.sessionHooks = sessionHooks
	}
}

// Adds a scope to the list of scopes to request.
func WithScope(scope string) func(*AuthorizationCodeFlow) {
	return func(s *AuthorizationCodeFlow) {
		s.config.Scopes = append(s.config.Scopes, scope)
	}
}

func (flow *AuthorizationCodeFlow) AuthorizationCodeReceived(w http.ResponseWriter, r *http.Request) {
	receivedState := r.URL.Query().Get("state")
	if flow.stateVerifier(flow, receivedState) {
		token, err := flow.config.Exchange(r.Context(), receivedState)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		parsedToken, err := jwt.ParseOAuth2Token(token, flow.tokenOptions...)
		if parsedToken.IsValid() {
			stringToken, err := parsedToken.AsString()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			flow.sessionHooks.SetToken(stringToken)
		}
	}
}

// // Checks if the user is authenticated.
// func (flow *AuthorizationCodeFlow) IsAuthenticated() bool {
// 	accessToken := flow.sessionHooks.GetToken()
// 	parsedToken, err := jwt.ParseFromString(accessToken, flow.tokenOptions...)
// 	if err != nil {
// 		return false

// 	}
// 	return parsedToken.IsValid()
// }

// Returns the URL to redirect the user to start authentication pipeline.
func (flow *AuthorizationCodeFlow) GetAuthURL() string {

	state := flow.stateGenerator(flow)
	url, _ := url.Parse(flow.config.AuthCodeURL(state))
	query := url.Query()
	for k, v := range flow.authURLOptions {
		if query.Get(k) == "" {
			query[k] = v
		}
	}
	url.RawQuery = query.Encode()
	return url.String()
}

// Adds options to validate the token.
func WithTokenValidation(isValidateJWKS bool, tokenOptions ...func(*jwt.Token)) func(*AuthorizationCodeFlow) {
	return func(s *AuthorizationCodeFlow) {

		if isValidateJWKS {
			s.tokenOptions = append(s.tokenOptions, jwt.WillValidateWithJWKSUrl(s.JWKS_URL))
		}

		s.tokenOptions = append(s.tokenOptions, tokenOptions...)
	}
}
