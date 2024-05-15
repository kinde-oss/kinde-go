package authorization_code

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	keyfunc "github.com/MicahParks/keyfunc/v3"
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

func WithKindeManagementAPI(kindeDomain string) func(*AuthorizationCodeFlow) {
	return func(s *AuthorizationCodeFlow) {

		asURL, err := url.Parse(kindeDomain)
		if err != nil {
			return
		}

		host := asURL.Hostname()
		if host == "" {
			host = kindeDomain
		}

		host = strings.TrimSuffix(host, ".kinde.com")
		managementApiaudience := fmt.Sprintf("https://%v.kinde.com/api", host)

		WithAuthParameter("audience", managementApiaudience)(s)
	}
}

// Adds the offline scope to the list of scopes to request.
func WithOffline() func(*AuthorizationCodeFlow) {
	return func(s *AuthorizationCodeFlow) {
		WithScope("offline")
	}
}

// Adds the offline scope to the list of scopes to request.
func WithCustomStateGenerator(stateFunc func() string) func(*AuthorizationCodeFlow) {
	return func(s *AuthorizationCodeFlow) {
		s.stateGenerator = stateFunc
	}
}

// Adds a scope to the list of scopes to request.
func WithScope(scope string) func(*AuthorizationCodeFlow) {
	return func(s *AuthorizationCodeFlow) {
		s.config.Scopes = append(s.config.Scopes, scope)
	}
}

// Returns the URL to redirect the user to start authentication pipeline.
func (flow *AuthorizationCodeFlow) GetAuthURL() string {

	state := flow.stateGenerator()
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
			jwks, err := keyfunc.NewDefault([]string{s.JWKS_URL})
			if err != nil {
				return
			}
			s.tokenOptions = append(s.tokenOptions, jwt.WillValidateWithKeyFunc(jwks.Keyfunc))
		}

		s.tokenOptions = append(s.tokenOptions, tokenOptions...)
	}
}
