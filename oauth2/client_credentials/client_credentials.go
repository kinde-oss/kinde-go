package client_credentials

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/kinde-oss/kinde-go/jwt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// ClientCredentialsFlow represents the client credentials flow.
type ClientCredentialsFlow struct {
	config       clientcredentials.Config
	tokenOptions []func(*jwt.Token)
	JWKS_URL     string
	tokenSource  oauth2.TokenSource
}

// Creates a new ClientCredentialsFlow with the given baseURL, clientID, clientSecret and options to authenticate backend applications.
func NewClientCredentialsFlow(baseURL string, clientID string, clientSecret string, options ...func(*ClientCredentialsFlow)) (*ClientCredentialsFlow, error) {
	asURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	host := asURL.Hostname()
	if asURL.Port() != "" {
		host = fmt.Sprintf("%v:%v", host, asURL.Port())
	}
	client := &ClientCredentialsFlow{
		config: clientcredentials.Config{
			ClientID:       clientID,
			ClientSecret:   clientSecret,
			TokenURL:       fmt.Sprintf("%v://%v/%v", asURL.Scheme, host, "oauth2/token"),
			EndpointParams: map[string][]string{},
		},
		JWKS_URL: fmt.Sprintf("%v://%v/.well-known/jwks", asURL.Scheme, host),
	}

	for _, o := range options {
		o(client)
	}

	client.tokenSource = client.config.TokenSource(context.Background())

	return client, nil
}

// Adds an arbitrary parameter to the list of parameters to request.
func WithAuthParameter(key, value string) func(*ClientCredentialsFlow) {
	return func(s *ClientCredentialsFlow) {
		if params, ok := s.config.EndpointParams[key]; ok {
			s.config.EndpointParams[key] = append(params, value)
		} else {
			s.config.EndpointParams[key] = []string{value}
		}
	}
}

// Adds an arbitrary parameter to the list of parameters to request.
func WithAudience(audience string) func(*ClientCredentialsFlow) {
	return func(s *ClientCredentialsFlow) {
		WithAuthParameter("audience", audience)(s)
	}
}

// Adds Kinde management API audience to the list of audiences to request.
func WithKindeManagementAPI(kindeDomain string) func(*ClientCredentialsFlow) {
	return func(s *ClientCredentialsFlow) {

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

// Adds options to validate the token.
func WithTokenValidation(isValidateJWKS bool, tokenOptions ...func(*jwt.Token)) func(*ClientCredentialsFlow) {
	return func(s *ClientCredentialsFlow) {

		if isValidateJWKS {
			s.tokenOptions = append(s.tokenOptions, jwt.WillValidateJWKSUrl(s.JWKS_URL))
		}

		s.tokenOptions = append(s.tokenOptions, tokenOptions...)
	}
}

// Returns the http client to be used to make requests.
func (flow *ClientCredentialsFlow) GetClient(ctx context.Context) *http.Client {
	return flow.config.Client(ctx)
}

// Returns the token to be used to make requests.
func (flow *ClientCredentialsFlow) GetToken(ctx context.Context) (*jwt.Token, error) {

	token, err := flow.tokenSource.Token()
	if err != nil {
		return nil, err
	}
	return jwt.ParseOAuth2Token(token, flow.tokenOptions...)
}
