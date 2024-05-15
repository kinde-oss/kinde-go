package authorization_code

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/kinde-oss/kinde-go/jwt"
	"golang.org/x/oauth2"
)

// AuthorizationCodeFlow represents the authorization code flow.
type AuthorizationCodeFlow struct {
	config         oauth2.Config
	authURLOptions url.Values
	JWKS_URL       string
	tokenOptions   []func(*jwt.Token)
	stateGenerator func() string
}

// Creates a new AuthorizationCodeFlow with the given baseURL, clientID, clientSecret and options to authenticate backend applications.
func NewAuthorizationCodeFlow(baseURL string, clientID string, clientSecret string, callbackURL string,
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
		stateGenerator: func() string {
			return fmt.Sprintf("ks_%v", strings.ReplaceAll(uuid.NewString(), "-", ""))
		},
	}

	for _, o := range options {
		o(client)
	}

	return client, nil
}

// Exchanges the authorization code for a token and validates it. Please verify the IsValid method of the token.
func (flow *AuthorizationCodeFlow) ExchangeAndValidate(ctx context.Context, authorizationCode string) (*jwt.Token, error) {
	token, err := flow.config.Exchange(ctx, authorizationCode)

	if err != nil {
		return nil, err
	}

	result, err := jwt.ParseOAuth2Token(token, flow.tokenOptions...)
	return result, err
}

// Returns the client to make requests to the backend.
func (flow *AuthorizationCodeFlow) GetClient(ctx context.Context, token *jwt.Token) *http.Client {
	return flow.config.Client(ctx, token.GetRawToken())
}
