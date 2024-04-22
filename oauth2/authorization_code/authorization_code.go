package authorization_code

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	keyfunc "github.com/MicahParks/keyfunc/v3"
	"github.com/kinde-oss/kinde-go/jwt"
	"golang.org/x/oauth2"
)

// AuthorizationCodeFlow represents the authorization code flow.
type AuthorizationCodeFlow struct {
	config         oauth2.Config
	authURLOptions url.Values
	JWKS_URL       string
	tokenOptions   []func(*jwt.Token)
}

// Creates a new AuthorizationCodeFlow with the given baseURL, clientID, clientSecret and options to authenticate backend applications.
func NewAuthorizationclientFlow(baseURL string, clientID string, clientSecret string, callbackURL string,
	options ...func(*AuthorizationCodeFlow)) (*AuthorizationCodeFlow, error) {
	return newAuthorizationCodeflow(baseURL, clientID, clientSecret, callbackURL, options...)
}

func newAuthorizationCodeflow(baseURL string, clientID string, clientSecret string, callbackURL string,
	options ...func(*AuthorizationCodeFlow)) (*AuthorizationCodeFlow, error) {
	asURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	host := asURL.Hostname()

	if asURL.Port() != "" {
		host = fmt.Sprintf("%v:%v", host, asURL.Port())
	}

	client := &AuthorizationCodeFlow{
		JWKS_URL: fmt.Sprintf("%v://%v/.well-known/jwks", asURL.Scheme, host),
		config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  callbackURL,
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint: oauth2.Endpoint{
				TokenURL: fmt.Sprintf("%v://%v/oauth2/token", asURL.Scheme, host),
				AuthURL:  fmt.Sprintf("%v://%v/oauth2/auth", asURL.Scheme, host),
			},
		},
		authURLOptions: url.Values{},
	}

	for _, o := range options {
		o(client)
	}

	return client, nil
}

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

// Adds a scope to the list of scopes to request.
func WithScope(scope string) func(*AuthorizationCodeFlow) {
	return func(s *AuthorizationCodeFlow) {
		s.config.Scopes = append(s.config.Scopes, scope)
	}
}

// Returns the URL to redirect the user to authenticate.
func (flow *AuthorizationCodeFlow) GetAuthURL(state string) string {
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
func WithTokenValidation(tokenOptions ...func(*jwt.Token)) func(*AuthorizationCodeFlow) {
	return func(s *AuthorizationCodeFlow) {

		if len(s.tokenOptions) == 0 {
			jwks, err := keyfunc.NewDefault([]string{s.JWKS_URL})
			if err != nil {
				return
			}
			s.tokenOptions = append(s.tokenOptions, jwt.WillValidateSignature(jwks.Keyfunc), jwt.WillValidateAlgorythm())
		}

		s.tokenOptions = append(s.tokenOptions, tokenOptions...)
	}
}

// Exchanges the authorization code for a token.
func (flow *AuthorizationCodeFlow) Exchange(ctx context.Context, authorizationCode string) (*jwt.Token, error) {
	token, err := flow.config.Exchange(ctx, authorizationCode)

	if err != nil {
		return nil, err
	}

	result, err := jwt.ParseJwtToken(token, flow.tokenOptions...)
	return result, err
}

// Returns the client to make requests to the backend.
func (flow *AuthorizationCodeFlow) GetClient(ctx context.Context, token *jwt.Token) *http.Client {
	return flow.config.Client(ctx, token.GetRawToken())
}
