package client_credentials

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/kinde-oss/kinde-go/v1/jwt"
	"golang.org/x/oauth2/clientcredentials"
)

// ClientCredentialsFlow represents the client credentials flow.
type ClientCredentialsFlow struct {
	config clientcredentials.Config
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
	}

	//applying With... options
	for _, o := range options {
		o(client)
	}

	return client, nil
}

// Adds an arbitrary parameter to the list of parameters to request.
func WithAudience(audience string) func(*ClientCredentialsFlow) {
	return func(s *ClientCredentialsFlow) {

		if params, ok := s.config.EndpointParams["audience"]; ok {
			s.config.EndpointParams["audience"] = append(params, audience)
		} else {
			s.config.EndpointParams["audience"] = []string{audience}
		}
	}
}

// Adds Kinde management API audience to the list of audiences to request.
func WithKindeManagementAPI(kindeDomain string) func(*ClientCredentialsFlow) {
	return func(s *ClientCredentialsFlow) {
		managementApiaudience := fmt.Sprintf("https://%v.kinde.com", kindeDomain)
		if params, ok := s.config.EndpointParams["audience"]; ok {
			s.config.EndpointParams["audience"] = append(params, managementApiaudience)
		} else {
			s.config.EndpointParams["audience"] = []string{managementApiaudience}
		}
	}
}

// Returns the http client to be used to make requests.
func (client *ClientCredentialsFlow) GetClient(ctx context.Context) *http.Client {
	return client.config.Client(ctx)
}

// Returns the token to be used to make requests.
func (client *ClientCredentialsFlow) GetToken(ctx context.Context) (*jwt.Token, error) {
	token, err := client.config.Token(ctx)
	if err != nil {
		return nil, err
	}
	return jwt.NewJwtToken(token), nil
}
