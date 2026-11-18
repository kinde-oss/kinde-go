package authorization_code

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

const (
	stepUpTestKeyID   = "step-up-test-key"
	stepUpTestSubject = "kp_step_up_user"
)

var stepUpTestKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
})

// signStepUpTestToken returns a JWT signed with the test key, issued to the test
// user and client unless the claims say otherwise.
func signStepUpTestToken(t *testing.T, claims golangjwt.MapClaims) string {
	t.Helper()
	all := golangjwt.MapClaims{
		"sub": stepUpTestSubject,
		"iss": "https://testing.kinde.com",
		"azp": "client_id",
		"aud": []string{"https://testing.kinde.com"}, // as in Kinde's ID tokens: the client is in azp
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	for name, value := range claims {
		all[name] = value
	}
	token := golangjwt.NewWithClaims(golangjwt.SigningMethodRS256, all)
	token.Header["kid"] = stepUpTestKeyID
	signed, err := token.SignedString(stepUpTestKey())
	require.NoError(t, err)
	return signed
}

// fakeKinde is a Kinde stand-in serving JWKS, discovery and the token endpoint.
type fakeKinde struct {
	*httptest.Server

	mu sync.Mutex
	// acrValuesSupported is what discovery advertises; nil leaves the field out.
	acrValuesSupported []string
	discoveryStatus    int
	discoveryHits      int
	// tokenResponse is the body of the next token endpoint response; nil answers 400.
	tokenResponse map[string]any
	tokenRequests []url.Values
}

func newFakeKinde(t *testing.T, acrValuesSupported []string) *fakeKinde {
	t.Helper()
	fake := &fakeKinde{acrValuesSupported: acrValuesSupported, discoveryStatus: http.StatusOK}

	publicKey := stepUpTestKey().PublicKey
	jwks, err := json.Marshal(map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "alg": "RS256", "use": "sig", "key_ops": []string{"verify"}, "kid": stepUpTestKeyID,
		"n": base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
	}}})
	require.NoError(t, err)

	fake.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/jwks"):
			w.Write(jwks)
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration"):
			fake.discoveryHits++
			if fake.discoveryStatus != http.StatusOK {
				w.WriteHeader(fake.discoveryStatus)
				return
			}
			document := map[string]any{"issuer": fake.URL}
			if fake.acrValuesSupported != nil {
				document["acr_values_supported"] = fake.acrValuesSupported
			}
			json.NewEncoder(w).Encode(document)
		case strings.HasSuffix(r.URL.Path, "/oauth2/token"):
			r.ParseForm()
			fake.tokenRequests = append(fake.tokenRequests, r.PostForm)
			if fake.tokenResponse == nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":"invalid_grant"}`))
				return
			}
			json.NewEncoder(w).Encode(fake.tokenResponse)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fake.Close)
	return fake
}

func (fake *fakeKinde) setTokenResponse(response map[string]any) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.tokenResponse = response
}

func (fake *fakeKinde) setAcrValuesSupported(acrValuesSupported []string) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.acrValuesSupported = acrValuesSupported
}

func (fake *fakeKinde) setDiscoveryStatus(status int) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.discoveryStatus = status
}

func (fake *fakeKinde) getDiscoveryHits() int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.discoveryHits
}

func (fake *fakeKinde) getTokenRequests() []url.Values {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return append([]url.Values{}, fake.tokenRequests...)
}

// stepUpSessionHooks keeps the session in memory. Unlike a JSON round trip, it
// keeps the ID token that comes with the OAuth2 token.
type stepUpSessionHooks struct {
	token            *oauth2.Token
	state            string
	postAuthRedirect string
	codeVerifier     string
	// full makes the session refuse a new post-auth redirect, like a cookie
	// store that has no room left. Clearing it still works.
	full bool
}

func (h *stepUpSessionHooks) SetRawToken(token *oauth2.Token) error { h.token = token; return nil }
func (h *stepUpSessionHooks) GetRawToken() (*oauth2.Token, error) {
	if h.token == nil {
		return nil, http.ErrNoCookie
	}
	return h.token, nil
}
func (h *stepUpSessionHooks) GetState() (string, error)   { return h.state, nil }
func (h *stepUpSessionHooks) SetState(state string) error { h.state = state; return nil }
func (h *stepUpSessionHooks) SetPostAuthRedirect(redirect string) error {
	if h.full && redirect != "" {
		return errors.New("securecookie: the value is too long")
	}
	h.postAuthRedirect = redirect
	return nil
}
func (h *stepUpSessionHooks) GetPostAuthRedirect() (string, error) { return h.postAuthRedirect, nil }
func (h *stepUpSessionHooks) SetCodeVerifier(codeVerifier string) error {
	h.codeVerifier = codeVerifier
	return nil
}
func (h *stepUpSessionHooks) GetCodeVerifier() (string, error) { return h.codeVerifier, nil }

// newStepUpTestFlow returns a flow that talks to the fake Kinde and validates
// tokens against its JWKS, and the session behind it.
func newStepUpTestFlow(t *testing.T, fake *fakeKinde, options ...Option) (*AuthorizationCodeFlow, *stepUpSessionHooks) {
	t.Helper()
	hooks := &stepUpSessionHooks{}
	options = append([]Option{WithSessionHooks(hooks), WithOffline(), WithTokenValidation(true)}, options...)
	flow, err := NewAuthorizationCodeFlow(fake.URL, "client_id", "client_secret", "https://app.example.com/callback", options...)
	require.NoError(t, err)
	return flow.(*AuthorizationCodeFlow), hooks
}

// pendingStepUp is what a step-up for the "pending_state" request keeps in the
// session until its callback: where to return to and what was asked for.
func pendingStepUp(returnTo string) string {
	return encodeStepUpMarker(stepUpMarker{State: "pending_state", ReturnTo: returnTo, Acr: "mfa"})
}

// storedStepUp decodes what a step-up left in the session's post-auth redirect.
func storedStepUp(t *testing.T, hooks *stepUpSessionHooks) stepUpMarker {
	t.Helper()
	require.True(t, strings.HasPrefix(hooks.postAuthRedirect, stepUpMarkerPrefix), "expected a step-up marker, got %q", hooks.postAuthRedirect)
	flow := &AuthorizationCodeFlow{sessionHooks: hooks}
	marker, ok := flow.readStepUpMarker()
	require.True(t, ok)
	return marker
}
