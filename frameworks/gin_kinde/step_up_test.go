package gin_kinde

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/kinde-oss/kinde-go/jwt"
	"github.com/kinde-oss/kinde-go/oauth2/authorization_code"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	stepUpTestKeyID  = "step-up-test-key"
	unmetDescription = "The requested authentication context could not be met"
)

var stepUpTestKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
})

func signStepUpTestToken(t *testing.T, claims golangjwt.MapClaims) string {
	t.Helper()
	all := golangjwt.MapClaims{
		"sub": "kp_step_up_user",
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

// signStepUpTestTokenOfLength returns a signed token padded to the given length.
func signStepUpTestTokenOfLength(t *testing.T, claims golangjwt.MapClaims, length int) string {
	t.Helper()
	padded := golangjwt.MapClaims{"pad": ""}
	for name, value := range claims {
		padded[name] = value
	}
	missing := length - len(signStepUpTestToken(t, padded))
	require.Positive(t, missing)
	padded["pad"] = strings.Repeat("x", missing*3/4) // base64 turns 3 characters into 4
	token := signStepUpTestToken(t, padded)
	require.InDelta(t, length, len(token), 4)
	return token
}

// fakeKinde is a Kinde stand-in serving JWKS, discovery and the token endpoint.
type fakeKinde struct {
	*httptest.Server

	mu            sync.Mutex
	tokenResponse map[string]any
	tokenRequests []url.Values
}

func newFakeKinde(t *testing.T) *fakeKinde {
	t.Helper()
	fake := &fakeKinde{}

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
			json.NewEncoder(w).Encode(map[string]any{"acr_values_supported": []string{"mfa", "phr"}})
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

func (fake *fakeKinde) getTokenRequests() []url.Values {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return append([]url.Values{}, fake.tokenRequests...)
}

const stepUpTestAppURL = "https://app.example.com"

// stepUpTestApp is a Gin app protected by UseKindeAuth, and the cookies of a browser using it.
type stepUpTestApp struct {
	t       *testing.T
	fake    *fakeKinde
	router  *gin.Engine
	cookies http.CookieJar
	// errors collects what the callback attached to the Gin context.
	errors []error
}

var payoutRequirement = jwt.AuthenticationRequirement{Acr: jwt.AcrMFA, MaxAge: new(300)}

// newStepUpTestApp starts the app. /private/payout requires MFA in the last 5
// minutes; /private/profile only requires a signed-in user.
func newStepUpTestApp(t *testing.T, options ...authorization_code.Option) *stepUpTestApp {
	t.Helper()
	gin.SetMode(gin.TestMode)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	router := gin.New()
	app := &stepUpTestApp{t: t, fake: newFakeKinde(t), router: router, cookies: jar}

	router.Use(sessions.Sessions("kinde-session", cookie.NewStore([]byte("secret"))))
	router.Use(func(ctx *gin.Context) {
		ctx.Next()
		for _, ginError := range ctx.Errors {
			app.errors = append(app.errors, ginError.Err)
		}
	})

	privateGroup := router.Group("/private")
	options = append([]authorization_code.Option{authorization_code.WithOffline()}, options...)
	require.NoError(t, UseKindeAuth(privateGroup, app.fake.URL, "client_id", "client_secret", stepUpTestAppURL, options...))

	privateGroup.GET("/profile", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "profile")
	})
	payout := func(ctx *gin.Context) {
		if met, _ := HasAuthenticationContext(ctx, payoutRequirement); !met {
			if err := StepUp(ctx, payoutRequirement); err != nil {
				ctx.String(http.StatusForbidden, "%s", err.Error())
			}
			return
		}
		authContext, err := GetAuthenticationContext(ctx)
		assert.NoError(t, err)
		ctx.JSON(http.StatusOK, gin.H{"acr": authContext.Acr, "amr": authContext.Amr, "auth_time": authContext.AuthTime.Unix()})
	}
	privateGroup.GET("/payout", payout)
	privateGroup.POST("/payout", payout)

	return app
}

// do sends a request to the app and returns the status, Location header and body.
func (app *stepUpTestApp) do(method, path string, header http.Header) (int, string, string) {
	app.t.Helper()
	request := httptest.NewRequest(method, stepUpTestAppURL+path, nil)
	for name, values := range header {
		request.Header[name] = values
	}
	for _, sessionCookie := range app.cookies.Cookies(request.URL) {
		request.AddCookie(sessionCookie)
	}
	recorder := httptest.NewRecorder()
	app.router.ServeHTTP(recorder, request)
	app.cookies.SetCookies(request.URL, recorder.Result().Cookies())
	return recorder.Code, recorder.Header().Get("Location"), recorder.Body.String()
}

func (app *stepUpTestApp) get(path string) (int, string, string) {
	app.t.Helper()
	return app.do(http.MethodGet, path, nil)
}

// signIn signs the user in with a single factor and returns the tokens they got.
func (app *stepUpTestApp) signIn() map[string]any {
	app.t.Helper()
	return app.signInWith(map[string]any{
		"access_token":  signStepUpTestToken(app.t, golangjwt.MapClaims{"jti": "access-before"}),
		"id_token":      signStepUpTestToken(app.t, golangjwt.MapClaims{"jti": "id-before", "auth_time": time.Now().Add(-time.Hour).Unix()}),
		"refresh_token": "refresh-before",
		"token_type":    "bearer",
		"expires_in":    3600,
	})
}

// signInWith signs the user in with the given token response.
func (app *stepUpTestApp) signInWith(tokens map[string]any) map[string]any {
	app.t.Helper()
	status, location, _ := app.get("/private/profile")
	require.Equal(app.t, http.StatusFound, status)
	state := kindeRedirect(app.t, app.fake, location).Get("state")

	app.fake.setTokenResponse(tokens)
	status, location, _ = app.get("/private/kinde/callback?code=login_code&state=" + state)
	require.Equal(app.t, http.StatusFound, status)
	require.Equal(app.t, "/", location, "a normal login lands on / as before")

	status, _, body := app.get("/private/profile")
	require.Equal(app.t, http.StatusOK, status)
	require.Equal(app.t, "profile", body)
	return tokens
}

// kindeRedirect checks that location is an authorization request to the fake Kinde and returns its query.
func kindeRedirect(t *testing.T, fake *fakeKinde, location string) url.Values {
	t.Helper()
	require.True(t, strings.HasPrefix(location, fake.URL+"/oauth2/auth?"), "expected a redirect to Kinde, got %q", location)
	parsed, err := url.Parse(location)
	require.NoError(t, err)
	return parsed.Query()
}

func steppedUpTokens(t *testing.T, authTime time.Time) map[string]any {
	t.Helper()
	return map[string]any{
		"access_token":  signStepUpTestToken(t, golangjwt.MapClaims{"jti": "access-after", "acr": "mfa", "amr": []string{"pwd", "totp"}}),
		"id_token":      signStepUpTestToken(t, golangjwt.MapClaims{"jti": "id-after", "acr": "mfa", "amr": []string{"pwd", "totp"}, "auth_time": authTime.Unix()}),
		"refresh_token": "refresh-after",
		"token_type":    "bearer",
		"expires_in":    1, // expired straight away, so the next request refreshes
	}
}

func TestStepUp(t *testing.T) {
	t.Parallel()

	t.Run("steps up a signed-in user, replaces their tokens and returns them to where they were", func(t *testing.T) {
		app := newStepUpTestApp(t)
		app.signIn()

		// The sensitive page starts a step-up: an interactive request for the missing context
		status, location, _ := app.get("/private/payout?tab=bank")
		require.Equal(t, http.StatusFound, status)
		stepUp := kindeRedirect(t, app.fake, location)
		assert.Equal(t, "mfa", stepUp.Get("acr_values"))
		assert.Equal(t, "300", stepUp.Get("max_age"))
		assert.False(t, stepUp.Has("prompt"))
		assert.Equal(t, stepUpTestAppURL+"/private/kinde/callback", stepUp.Get("redirect_uri"))

		// The user is still signed in while the step-up is pending
		status, _, _ = app.get("/private/profile")
		assert.Equal(t, http.StatusOK, status)

		// Kinde returns to the callback with the stepped-up tokens
		authTime := time.Now().Truncate(time.Second)
		app.fake.setTokenResponse(steppedUpTokens(t, authTime))
		status, location, _ = app.get("/private/kinde/callback?code=step_up_code&state=" + stepUp.Get("state"))
		assert.Equal(t, http.StatusFound, status)
		assert.Equal(t, "/private/payout?tab=bank", location)

		// Back on the page, the requirement is met; using the tokens refreshes with the new refresh token
		app.fake.setTokenResponse(map[string]any{
			"access_token":  signStepUpTestToken(t, golangjwt.MapClaims{"jti": "access-refreshed", "acr": "mfa", "amr": []string{"pwd", "totp"}}),
			"id_token":      signStepUpTestToken(t, golangjwt.MapClaims{"jti": "id-refreshed", "acr": "mfa", "amr": []string{"pwd", "totp"}, "auth_time": authTime.Unix()}),
			"refresh_token": "refresh-rotated",
			"token_type":    "bearer",
			"expires_in":    3600,
		})
		status, _, body := app.get(location)
		require.Equal(t, http.StatusOK, status)
		var authContext struct {
			Acr      string   `json:"acr"`
			Amr      []string `json:"amr"`
			AuthTime int64    `json:"auth_time"`
		}
		require.NoError(t, json.Unmarshal([]byte(body), &authContext))
		assert.Equal(t, "mfa", authContext.Acr)
		assert.Equal(t, []string{"pwd", "totp"}, authContext.Amr)
		assert.Equal(t, authTime.Unix(), authContext.AuthTime, "auth_time comes from the ID token kept in the session")

		requests := app.fake.getTokenRequests()
		require.Len(t, requests, 3)
		assert.Equal(t, "login_code", requests[0].Get("code"))
		assert.Equal(t, "step_up_code", requests[1].Get("code"))
		assert.Equal(t, "refresh_token", requests[2].Get("grant_type"))
		assert.Equal(t, "refresh-after", requests[2].Get("refresh_token"), "the refresh token from before the step-up is gone")
		assert.Empty(t, app.errors)
	})

	t.Run("a step-up that the session cannot show is stopped instead of looping", func(t *testing.T) {
		app := newStepUpTestApp(t)
		app.signIn()

		status, location, _ := app.get("/private/payout")
		require.Equal(t, http.StatusFound, status)
		stepUp := kindeRedirect(t, app.fake, location)

		// The stepped-up tokens are too big for the cookie session to keep the ID token,
		// and the access token has no auth_time: the max age can never be shown as met
		padding := strings.Repeat("x", 1500)
		app.fake.setTokenResponse(map[string]any{
			"access_token":  signStepUpTestToken(t, golangjwt.MapClaims{"acr": "mfa", "pad": padding[:600]}),
			"id_token":      signStepUpTestToken(t, golangjwt.MapClaims{"acr": "mfa", "auth_time": time.Now().Unix(), "pad": padding}),
			"refresh_token": "refresh-after",
			"token_type":    "bearer",
			"expires_in":    3600,
		})
		status, location, _ = app.get("/private/kinde/callback?code=step_up_code&state=" + stepUp.Get("state"))
		require.Equal(t, http.StatusFound, status)
		require.Equal(t, "/private/payout", location)

		// Back on the page the requirement is still unmet. Asking Kinde again would loop.
		status, location, body := app.get(location)
		assert.Equal(t, http.StatusForbidden, status)
		assert.Empty(t, location)
		assert.Equal(t, authorization_code.ErrStepUpLoop.Error(), body)
		assert.Len(t, app.fake.getTokenRequests(), 2, "the login and one step-up")

		// The user is still signed in
		status, _, _ = app.get("/private/profile")
		assert.Equal(t, http.StatusOK, status)
	})

	t.Run("a session with no room to record the step-up refuses it instead of looping", func(t *testing.T) {
		app := newStepUpTestApp(t)
		// An access token that nearly fills the cookie session on its own
		accessToken := signStepUpTestTokenOfLength(t, golangjwt.MapClaims{"jti": "access-before"}, 1925)
		app.signInWith(map[string]any{"access_token": accessToken, "token_type": "bearer", "expires_in": 3600})

		for range 2 {
			status, location, body := app.get("/private/payout")

			assert.Equal(t, http.StatusForbidden, status)
			assert.Empty(t, location, "no redirect to Kinde that could not be followed up")
			assert.Contains(t, body, "could not be recorded in the session")
		}
		assert.Len(t, app.fake.getTokenRequests(), 1, "only the login")

		// The session itself is unharmed
		status, _, body := app.get("/private/profile")
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, "profile", body)
	})

	t.Run("an error writes nothing and does not abort", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/private/payout", nil)

		err := StepUp(ctx, payoutRequirement)

		assert.EqualError(t, err, "kinde client not found")
		assert.False(t, ctx.IsAborted())
		assert.Empty(t, recorder.Header().Get("Location"))
	})
}

func TestCallback_UnmetAuthenticationRequirements(t *testing.T) {
	t.Parallel()

	// startStepUp signs in, starts a step-up and returns the callback Kinde answers it with.
	startStepUp := func(app *stepUpTestApp, errorCode string) string {
		app.signIn()
		status, location, _ := app.get("/private/payout")
		require.Equal(app.t, http.StatusFound, status)
		state := kindeRedirect(app.t, app.fake, location).Get("state")
		return "/private/kinde/callback?error=" + errorCode + "&error_description=" + url.QueryEscape(unmetDescription) + "&state=" + state
	}

	// assertFinal checks that the error was a final answer: nothing was exchanged or
	// retried, and the user is still signed in with the tokens they had.
	assertFinal := func(app *stepUpTestApp, location string) {
		assert.Empty(app.t, location, "the error must not become a redirect")
		assert.Len(app.t, app.fake.getTokenRequests(), 1, "only the original login reached the token endpoint")
		status, _, body := app.get("/private/profile")
		assert.Equal(app.t, http.StatusOK, status)
		assert.Equal(app.t, "profile", body)
	}

	t.Run("reaches the callback error handler", func(t *testing.T) {
		var received error
		app := newStepUpTestApp(t, WithCallbackErrorHandler(func(ctx *gin.Context, err error) {
			received = err
			ctx.String(http.StatusForbidden, "Add an authenticator app to continue.")
		}))
		callback := startStepUp(app, "unmet_authentication_requirements")

		status, location, body := app.get(callback)

		var unmet *authorization_code.UnmetAuthenticationRequirementsError
		require.True(t, errors.As(received, &unmet), "expected UnmetAuthenticationRequirementsError, got %T", received)
		assert.Equal(t, unmetDescription, unmet.ErrorDescription)
		assert.NotEmpty(t, unmet.State)
		assert.Contains(t, callback, "state="+unmet.State)
		assert.Equal(t, http.StatusForbidden, status)
		assert.Equal(t, "Add an authenticator app to continue.", body)
		assertFinal(app, location)
	})

	t.Run("reaches a handler set with the core option", func(t *testing.T) {
		var received error
		app := newStepUpTestApp(t, authorization_code.WithCallbackErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
			received = err
			http.Error(w, "Add an authenticator app to continue.", http.StatusForbidden)
		}))
		callback := startStepUp(app, "unmet_authentication_requirements")

		status, location, body := app.get(callback)

		var unmet *authorization_code.UnmetAuthenticationRequirementsError
		require.True(t, errors.As(received, &unmet), "expected UnmetAuthenticationRequirementsError, got %T", received)
		assert.Equal(t, http.StatusForbidden, status)
		assert.Contains(t, body, "Add an authenticator app to continue.")
		assertFinal(app, location)
	})

	t.Run("without a handler it is shown to the user and attached to the Gin context", func(t *testing.T) {
		app := newStepUpTestApp(t)
		callback := startStepUp(app, "unmet_authentication_requirements")

		status, location, body := app.get(callback)

		assert.Equal(t, http.StatusForbidden, status)
		assert.Contains(t, body, "the extra verification could not be completed")
		assert.Contains(t, body, unmetDescription)
		require.Len(t, app.errors, 1)
		var unmet *authorization_code.UnmetAuthenticationRequirementsError
		assert.True(t, errors.As(app.errors[0], &unmet))
		assertFinal(app, location)
	})

	t.Run("the state is validated before the error is reported", func(t *testing.T) {
		var received error
		app := newStepUpTestApp(t, WithCallbackErrorHandler(func(ctx *gin.Context, err error) {
			received = err
			ctx.Status(http.StatusBadRequest)
		}))
		callback := startStepUp(app, "unmet_authentication_requirements")

		status, location, _ := app.get(callback + "_forged")

		require.Error(t, received)
		var unmet *authorization_code.UnmetAuthenticationRequirementsError
		assert.False(t, errors.As(received, &unmet))
		assert.Contains(t, received.Error(), "state mismatch")
		assert.Equal(t, http.StatusBadRequest, status)
		assertFinal(app, location)
	})

	t.Run("a cancelled sign-in is reported, not exchanged", func(t *testing.T) {
		app := newStepUpTestApp(t)
		callback := startStepUp(app, "access_denied")

		status, location, body := app.get(callback)

		assert.Equal(t, http.StatusForbidden, status)
		assert.Contains(t, body, "access_denied")
		assertFinal(app, location)
	})

	t.Run("other callback errors are answered as before without a handler", func(t *testing.T) {
		app := newStepUpTestApp(t)
		callback := startStepUp(app, "unmet_authentication_requirements")

		status, location, body := app.get(callback + "_forged")

		assert.Equal(t, http.StatusInternalServerError, status)
		assert.Empty(t, body)
		assert.Empty(t, location)
		require.Len(t, app.errors, 1)
		assert.Contains(t, app.errors[0].Error(), "state mismatch")
	})
}

func TestUseKindeAuth_ReportsInvalidOptionsAtSetup(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	testCases := []struct {
		name    string
		option  authorization_code.Option
		message string
	}{
		{"negative max age", authorization_code.WithMaxAge(-1), "invalid max age -1"},
		{"invalid max_age parameter", authorization_code.WithAuthParameter("max_age", "soon"), `invalid max_age "soon"`},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			router := gin.New()
			router.Use(sessions.Sessions("kinde-session", cookie.NewStore([]byte("secret"))))

			err := UseKindeAuth(router.Group("/private"), "https://test.kinde.com", "client_id", "client_secret", stepUpTestAppURL, tc.option)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.message)
		})
	}
}

func TestWithCallbackErrorHandler_OutsideTheGinRoute(t *testing.T) {
	flow, err := authorization_code.NewAuthorizationCodeFlow("https://testing.kinde.com", "client_id", "client_secret", "https://app.example.com/callback",
		authorization_code.WithSessionHooks(&SessionStorage{}),
		WithCallbackErrorHandler(func(*gin.Context, error) { t.Error("there is no Gin context to call it with") }),
	)
	require.NoError(t, err)

	// Without a Gin context the error is answered with its own status, not a 500
	recorder := httptest.NewRecorder()
	handled := flow.(*authorization_code.AuthorizationCodeFlow).HandleCallbackError(recorder,
		httptest.NewRequest(http.MethodGet, "/callback", nil), &authorization_code.UnmetAuthenticationRequirementsError{})

	assert.True(t, handled)
	assert.Equal(t, http.StatusForbidden, recorder.Code)
}
