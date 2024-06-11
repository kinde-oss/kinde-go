package authorization_code

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/kinde-oss/kinde-go/jwt"
	"github.com/kinde-oss/kinde-go/kinde"
	"golang.org/x/oauth2"
)

type SessionHooks interface {
	GetState() string
	SetState(state string)
	SetToken(token string)
	GetToken() string
	SetPostAuthRedirect(redirect string)
	GetPostAuthRedirect() string
}

// AuthorizationCodeFlow represents the authorization code flow.
type AuthorizationCodeFlow struct {
	config         oauth2.Config
	authURLOptions url.Values
	JWKS_URL       string
	tokenOptions   []func(*jwt.Token)
	sessionHooks   SessionHooks
	stateGenerator func(from *AuthorizationCodeFlow) string
	stateVerifier  func(flow *AuthorizationCodeFlow, receivedState string) bool
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
		stateGenerator: func(flow *AuthorizationCodeFlow) string {
			state := fmt.Sprintf("ks_%v", strings.ReplaceAll(uuid.NewString(), "-", ""))
			flow.sessionHooks.SetState(state)
			return state
		},
		stateVerifier: func(flow *AuthorizationCodeFlow, receivedState string) bool {
			return flow.sessionHooks.GetState() == receivedState
		},
	}

	for _, o := range options {
		o(client)
	}

	if client.sessionHooks == nil {
		panic("please connect your sesion management with WithSessionHooks")
	}

	return client, nil
}

// Exchanges the authorization code for a token and established KindeContext
func (flow *AuthorizationCodeFlow) ExchangeCode(ctx context.Context, authorizationCode string) error {
	token, err := flow.config.Exchange(ctx, authorizationCode)

	if err != nil {
		return err
	}

	flow.sessionHooks.SetToken(token.AccessToken)

	return nil
}

// Returns the client to make requests to the backend, will refreesh token if offline is requested.
func (flow *AuthorizationCodeFlow) GetClient(ctx context.Context, tokenSource oauth2.TokenSource) *http.Client {
	return oauth2.NewClient(ctx, tokenSource)
}

// ProtectAPI is intended to authorize backend API endpoints, which will receive a token via the authoriuization header.
// This method doens't support token refreshing, returns 401 if the token is invalid
// You could use (see [kinde.GetKindeContext]) to get token or HttpClient inside the handler
func (flow *AuthorizationCodeFlow) ProtectAPI(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {

		parsedToken, err := jwt.ParseFromAuthorizationHeader(r, flow.tokenOptions...)
		if err != nil || !parsedToken.IsValid() {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(rw, r.WithContext(kinde.SetKindeContext(r.Context(), oauth2.StaticTokenSource(parsedToken.GetRawToken()), flow.tokenOptions)))
	})
}

func (flow *AuthorizationCodeFlow) CallbackHandler() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		receivedState := r.URL.Query().Get("state")
		if flow.stateVerifier(flow, receivedState) {
			token, err := flow.config.Exchange(r.Context(), receivedState)
			if err != nil {
				http.Error(rw, err.Error(), http.StatusInternalServerError)
			}
			parsedToken, err := jwt.ParseOAuth2Token(token, flow.tokenOptions...)
			if err != nil {
				http.Error(rw, err.Error(), http.StatusInternalServerError)
			}
			if parsedToken.IsValid() {
				stringToken, err := parsedToken.AsString()
				if err != nil {
					http.Error(rw, err.Error(), http.StatusInternalServerError)
				}
				flow.sessionHooks.SetToken(stringToken)

				postAuthRedirect := flow.sessionHooks.GetPostAuthRedirect()
				http.Redirect(rw, r, postAuthRedirect, http.StatusFound)
			}
		} else {
			http.Error(rw, "state parameter is invalid", http.StatusInternalServerError)
		}
	})
}

// ProtectPage protects the page with the given token options, otherwise starts an interactive auth flow
func (flow *AuthorizationCodeFlow) ProtectPage(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {

		token := flow.sessionHooks.GetToken()
		parsedToken, err := jwt.ParseFromSessionStorage(token, flow.tokenOptions...)
		if err != nil || !parsedToken.IsValid() {
			flow.sessionHooks.SetPostAuthRedirect(r.URL.String())
			state := flow.stateGenerator(flow)
			flow.sessionHooks.SetState(state)
			http.Redirect(rw, r, flow.config.AuthCodeURL(state), http.StatusFound)
			return
		}

		tokenSource := flow.config.TokenSource(r.Context(), parsedToken.GetRawToken())

		next.ServeHTTP(rw, r.WithContext(kinde.SetKindeContext(r.Context(), tokenSource, flow.tokenOptions)))
	})
}
