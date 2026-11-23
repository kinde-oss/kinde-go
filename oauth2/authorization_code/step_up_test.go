package authorization_code

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/kinde-oss/kinde-go/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestGetStepUpURL(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		flowOptions []Option
		requirement jwt.AuthenticationRequirement
		options     []Option
		acrValues   string // "" when acr_values must be absent
		maxAge      string // "" when max_age must be absent
	}{
		{name: "mfa", requirement: jwt.AuthenticationRequirement{Acr: jwt.AcrMFA}, acrValues: "mfa"},
		{name: "mfa in the last 5 minutes", requirement: jwt.AuthenticationRequirement{Acr: jwt.AcrMFA, MaxAge: new(300)}, acrValues: "mfa", maxAge: "300"},
		{name: "max age only", requirement: jwt.AuthenticationRequirement{MaxAge: new(300)}, maxAge: "300"},
		{
			name:        "the requirement replaces the flow's own acr_values and max_age",
			flowOptions: []Option{WithAcrValues(jwt.AcrMFA), WithMaxAge(3600)},
			requirement: jwt.AuthenticationRequirement{Acr: jwt.AcrPHR, MaxAge: new(0)},
			acrValues:   "phr", maxAge: "0",
		},
		{
			name:        "a stronger acr on the flow is not weakened",
			flowOptions: []Option{WithAcrValues(jwt.AcrPHR)},
			requirement: jwt.AuthenticationRequirement{Acr: jwt.AcrMFA, MaxAge: new(300)},
			acrValues:   "phr", maxAge: "300",
		},
		{
			name:        "an option does not weaken the flow's acr either",
			flowOptions: []Option{WithAcrValues(jwt.AcrPHR)},
			options:     []Option{WithAcrValues(jwt.AcrMFA)},
			requirement: jwt.AuthenticationRequirement{Acr: " MFA "},
			acrValues:   "phr",
		},
		{
			name:        "an option can raise the acr, however the requirement is written",
			flowOptions: []Option{WithAcrValues(jwt.AcrMFA)},
			options:     []Option{WithAcrValues(jwt.AcrPHR)},
			requirement: jwt.AuthenticationRequirement{Acr: " MFA "},
			acrValues:   "phr",
		},
		{name: "prompt=login is still interactive", options: []Option{WithPrompt("login")}, requirement: jwt.AuthenticationRequirement{Acr: jwt.AcrMFA}, acrValues: "mfa"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeKinde(t, []string{"mfa", "phr"})
			flow, hooks := newStepUpTestFlow(t, fake, tc.flowOptions...)
			loginURLBefore := queryOf(t, flow.GetAuthURL())

			stepUpURL, err := flow.GetStepUpURL(context.Background(), tc.requirement, tc.options...)

			require.NoError(t, err)
			assert.True(t, strings.HasPrefix(stepUpURL, fake.URL+"/oauth2/auth?"), "a step-up is a normal authorization request: %s", stepUpURL)
			query := queryOf(t, stepUpURL)
			assert.Equal(t, tc.acrValues, query.Get("acr_values"))
			assert.Equal(t, tc.acrValues != "", query.Has("acr_values"))
			assert.Equal(t, tc.maxAge, query.Get("max_age"))
			assert.Equal(t, tc.maxAge != "", query.Has("max_age"))
			assert.NotContains(t, query.Get("prompt"), "none", "a step-up is interactive")

			// The rest is the SDK's usual login request
			assert.Equal(t, "code", query.Get("response_type"))
			assert.Equal(t, "client_id", query.Get("client_id"))
			assert.Equal(t, "https://app.example.com/callback", query.Get("redirect_uri"))
			assert.Equal(t, "openid profile email offline", query.Get("scope"))
			assert.NotEmpty(t, query.Get("state"))
			assert.Equal(t, hooks.state, query.Get("state"), "the state is stored for the callback")

			// The options only applied to this request
			loginURLAfter := queryOf(t, flow.GetAuthURL())
			loginURLBefore.Del("state")
			loginURLAfter.Del("state")
			assert.Equal(t, loginURLBefore, loginURLAfter)
		})
	}

	t.Run("keeps the flow's parameters and PKCE challenge", func(t *testing.T) {
		fake := newFakeKinde(t, []string{"mfa", "phr"})
		flow, _ := newStepUpTestFlow(t, fake, WithAudience("https://api.example.com"), WithAuthParameter("org_code", "org_123"), WithPKCE())

		stepUpURL, err := flow.GetStepUpURL(context.Background(), jwt.AuthenticationRequirement{Acr: jwt.AcrMFA}, WithAuthParameter("login_hint", "jo@example.com"))

		require.NoError(t, err)
		query := queryOf(t, stepUpURL)
		assert.Equal(t, "https://api.example.com", query.Get("audience"))
		assert.Equal(t, "org_123", query.Get("org_code"))
		assert.Equal(t, "jo@example.com", query.Get("login_hint"))
		assert.Equal(t, queryOf(t, flow.GetAuthURL()).Get("code_challenge"), query.Get("code_challenge"))
		assert.Equal(t, "S256", query.Get("code_challenge_method"))
	})

	t.Run("a refused request leaves the session's code verifier alone", func(t *testing.T) {
		fake := newFakeKinde(t, []string{"mfa", "phr"})
		flow, hooks := newStepUpTestFlow(t, fake, WithPKCE())
		verifier := hooks.codeVerifier
		require.NotEmpty(t, verifier)

		_, err := flow.GetStepUpURL(context.Background(), jwt.AuthenticationRequirement{Acr: jwt.AcrMFA}, WithPKCE())

		require.ErrorContains(t, err, "cannot set PKCE for one request")
		assert.Equal(t, verifier, hooks.codeVerifier, "a login already in progress can still complete")
	})

	t.Run("keeps the current tokens until the callback replaces them", func(t *testing.T) {
		fake := newFakeKinde(t, []string{"mfa", "phr"})
		flow, hooks := newStepUpTestFlow(t, fake)
		before := signedInSession(t, hooks)

		_, err := flow.GetStepUpURL(context.Background(), jwt.AuthenticationRequirement{Acr: jwt.AcrMFA})

		require.NoError(t, err)
		assert.Same(t, before, hooks.token)
		assert.Empty(t, fake.getTokenRequests(), "a step-up is never attempted by refreshing")
	})
}

func TestGetStepUpURL_RejectsInvalidRequests(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		flowOptions []Option
		requirement jwt.AuthenticationRequirement
		options     []Option
		message     string
	}{
		// prompt=none, however it is set
		{name: "prompt=none on the flow", flowOptions: []Option{WithPrompt("none")}, requirement: jwt.AuthenticationRequirement{Acr: jwt.AcrMFA}, message: "prompt=none"},
		{name: "prompt=none as an option", requirement: jwt.AuthenticationRequirement{Acr: jwt.AcrMFA}, options: []Option{WithPrompt("none")}, message: "prompt=none"},
		{name: "prompt=none through WithAuthParameter", requirement: jwt.AuthenticationRequirement{Acr: jwt.AcrMFA}, options: []Option{WithAuthParameter("prompt", "none")}, message: "prompt=none"},
		{name: "prompt with none among other values", requirement: jwt.AuthenticationRequirement{Acr: jwt.AcrMFA}, options: []Option{WithPrompt("login none")}, message: "prompt=none"},

		// Nothing to step up to
		{name: "PKCE for this request only", requirement: jwt.AuthenticationRequirement{Acr: jwt.AcrMFA}, options: []Option{WithPKCE()}, message: "cannot set PKCE for one request"},
		{name: "no acr and no max age", message: "requires an acr"},

		// Invalid values
		{name: "unknown acr", requirement: jwt.AuthenticationRequirement{Acr: "gold"}, message: `unsupported acr "gold"`},
		{name: "negative max age", requirement: jwt.AuthenticationRequirement{Acr: jwt.AcrMFA, MaxAge: new(-1)}, message: "invalid max age -1"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeKinde(t, []string{"mfa", "phr"})
			flow, hooks := newStepUpTestFlow(t, fake, tc.flowOptions...)
			hooks.state = "state_of_a_login_in_progress"

			stepUpURL, err := flow.GetStepUpURL(context.Background(), tc.requirement, tc.options...)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.message)
			assert.Empty(t, stepUpURL)
			assert.Equal(t, "state_of_a_login_in_progress", hooks.state, "a rejected step-up does not start a request")
		})
	}
}

func TestGetStepUpURL_RespectsDiscovery(t *testing.T) {
	t.Parallel()

	t.Run("an environment without step-up support is an error", func(t *testing.T) {
		for _, requirement := range []jwt.AuthenticationRequirement{
			{Acr: jwt.AcrMFA},
			{Acr: jwt.AcrPHR, MaxAge: new(300)},
			// Not a prompt=login fallback: the tokens could never show the max age was met,
			// so a gate would send the user to sign in again on every request
			{MaxAge: new(300)},
		} {
			fake := newFakeKinde(t, nil)
			flow, hooks := newStepUpTestFlow(t, fake)

			stepUpURL, err := flow.GetStepUpURL(context.Background(), requirement)

			assert.ErrorIs(t, err, ErrStepUpNotSupported)
			assert.Empty(t, stepUpURL)
			assert.Empty(t, hooks.state, "no request is started")
		}
	})

	t.Run("it does not guess when discovery cannot be fetched", func(t *testing.T) {
		fake := newFakeKinde(t, []string{"mfa", "phr"})
		fake.setDiscoveryStatus(http.StatusServiceUnavailable)
		flow, _ := newStepUpTestFlow(t, fake)

		stepUpURL, err := flow.GetStepUpURL(context.Background(), jwt.AuthenticationRequirement{Acr: jwt.AcrMFA})

		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrStepUpNotSupported)
		assert.Empty(t, stepUpURL)
	})
}

func TestStepUp(t *testing.T) {
	t.Parallel()

	requirement := jwt.AuthenticationRequirement{Acr: jwt.AcrMFA, MaxAge: new(300)}

	testCases := []struct {
		name             string
		method           string
		target           string
		referer          string
		postAuthRedirect string
	}{
		{"GET returns to the requested URL", http.MethodGet, "https://app.example.com/settings/payout?tab=bank", "", "/settings/payout?tab=bank"},
		{"POST returns to the page that sent it", http.MethodPost, "https://app.example.com/settings/payout/save", "https://app.example.com/settings/payout?tab=bank", "/settings/payout?tab=bank"},
		{"POST from another site has no return path", http.MethodPost, "https://app.example.com/settings/payout/save", "https://evil.example.com/form", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeKinde(t, []string{"mfa", "phr"})
			flow, hooks := newStepUpTestFlow(t, fake)
			hooks.postAuthRedirect = "/left/over"
			request := httptest.NewRequest(tc.method, tc.target, nil)
			if tc.referer != "" {
				request.Header.Set("Referer", tc.referer)
			}
			recorder := httptest.NewRecorder()

			err := flow.StepUp(recorder, request, requirement)

			require.NoError(t, err)
			assert.Equal(t, http.StatusFound, recorder.Code)
			location := recorder.Header().Get("Location")
			assert.True(t, strings.HasPrefix(location, fake.URL+"/oauth2/auth?"), location)
			query := queryOf(t, location)
			assert.Equal(t, "mfa", query.Get("acr_values"))
			assert.Equal(t, "300", query.Get("max_age"))
			assert.False(t, query.Has("prompt"))
			assert.Equal(t, hooks.state, query.Get("state"))
			pending := storedStepUp(t, hooks)
			assert.Equal(t, tc.postAuthRedirect, pending.ReturnTo)
			assert.Equal(t, hooks.state, pending.State, "the return path belongs to this request only")
		})
	}

	t.Run("the user lands back where they started", func(t *testing.T) {
		fake := newFakeKinde(t, []string{"mfa", "phr"})
		flow, hooks := newStepUpTestFlow(t, fake)
		signedInSession(t, hooks)

		stepUp := httptest.NewRecorder()
		require.NoError(t, flow.StepUp(stepUp, httptest.NewRequest(http.MethodGet, "https://app.example.com/settings/payout", nil), requirement))
		state := queryOf(t, stepUp.Header().Get("Location")).Get("state")

		fake.setTokenResponse(steppedUpTokenResponse(t, 3600))
		callback := httptest.NewRecorder()
		flow.AuthorizationCodeReceivedHandler(callback, httptest.NewRequest(http.MethodGet, "https://app.example.com/callback?code=code&state="+state, nil))

		assert.Equal(t, http.StatusFound, callback.Code)
		assert.Equal(t, "/settings/payout", callback.Header().Get("Location"))
		met, err := flow.HasAuthenticationContext(context.Background(), requirement)
		require.NoError(t, err)
		assert.True(t, met)
	})

	t.Run("a session with a key for step-ups leaves the app's post-auth redirect alone", func(t *testing.T) {
		fake := newFakeKinde(t, []string{"mfa", "phr"})
		base := &stepUpSessionHooks{postAuthRedirect: "/the-apps-own-page"}
		hooks := &stepUpRecordHooks{stepUpSessionHooks: base}
		created, err := NewAuthorizationCodeFlow(fake.URL, "client_id", "client_secret", "https://app.example.com/callback",
			WithSessionHooks(hooks), WithOffline(), WithTokenValidation(true))
		require.NoError(t, err)
		flow := created.(*AuthorizationCodeFlow)
		signedInSession(t, base)

		recorder := httptest.NewRecorder()
		require.NoError(t, flow.StepUp(recorder, httptest.NewRequest(http.MethodGet, "https://app.example.com/settings/payout", nil), requirement))
		assert.Equal(t, "/the-apps-own-page", base.postAuthRedirect)
		assert.NotEmpty(t, hooks.record)

		fake.setTokenResponse(steppedUpTokenResponse(t, 3600))
		returnTo, err := flow.HandleCallback(context.Background(), url.Values{"code": {"code"}, "state": {queryOf(t, recorder.Header().Get("Location")).Get("state")}})
		require.NoError(t, err)
		assert.Equal(t, "/settings/payout", returnTo)
		assert.Equal(t, "/the-apps-own-page", base.postAuthRedirect)
		assert.Empty(t, hooks.record)
	})

	t.Run("an error writes nothing", func(t *testing.T) {
		fake := newFakeKinde(t, []string{"mfa", "phr"})
		flow, hooks := newStepUpTestFlow(t, fake)
		hooks.postAuthRedirect = "/left/over"
		recorder := httptest.NewRecorder()

		err := flow.StepUp(recorder, httptest.NewRequest(http.MethodGet, "https://app.example.com/settings", nil), requirement, WithPrompt("none"))

		require.Error(t, err)
		assert.Empty(t, recorder.Header().Get("Location"))
		assert.Empty(t, recorder.Body.String())
		assert.Equal(t, "/left/over", hooks.postAuthRedirect)
	})
}

// sessionWithClaims puts tokens with the given claims in the session. A nil idClaims leaves out the ID token.
func sessionWithClaims(t *testing.T, hooks *stepUpSessionHooks, accessClaims, idClaims golangjwt.MapClaims) {
	t.Helper()
	token := &oauth2.Token{AccessToken: signStepUpTestToken(t, accessClaims), Expiry: time.Now().Add(time.Hour)}
	if idClaims != nil {
		token = token.WithExtra(map[string]interface{}{"id_token": signStepUpTestToken(t, idClaims)})
	}
	hooks.token = token
}

func TestGetAuthenticationContext(t *testing.T) {
	t.Parallel()

	idAuthTime := time.Now().Add(-2 * time.Minute).Truncate(time.Second)
	accessAuthTime := time.Now().Add(-2 * time.Hour).Truncate(time.Second)

	testCases := []struct {
		name               string
		acrValuesSupported []string
		accessClaims       golangjwt.MapClaims
		idClaims           golangjwt.MapClaims
		expected           jwt.AuthenticationContext
	}{
		{
			name:               "after an mfa step-up",
			acrValuesSupported: []string{"mfa", "phr"},
			accessClaims:       golangjwt.MapClaims{"acr": "mfa", "amr": []string{"pwd", "totp"}},
			idClaims:           golangjwt.MapClaims{"acr": "mfa", "amr": []string{"pwd", "totp"}, "auth_time": idAuthTime.Unix()},
			expected:           jwt.AuthenticationContext{Acr: jwt.AcrMFA, Amr: []string{"pwd", "totp"}, AuthTime: idAuthTime},
		},
		{
			name:               "auth_time differs between the tokens: the ID token is used",
			acrValuesSupported: []string{"mfa", "phr"},
			accessClaims:       golangjwt.MapClaims{"acr": "phr", "auth_time": accessAuthTime.Unix()},
			idClaims:           golangjwt.MapClaims{"acr": "phr", "auth_time": idAuthTime.Unix()},
			expected:           jwt.AuthenticationContext{Acr: jwt.AcrPHR, Amr: []string{}, AuthTime: idAuthTime},
		},
		{
			name:         "environment without step-up support: auth_time is not reliable",
			accessClaims: golangjwt.MapClaims{},
			idClaims:     golangjwt.MapClaims{"auth_time": idAuthTime.Unix()},
			expected:     jwt.AuthenticationContext{Amr: []string{}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeKinde(t, tc.acrValuesSupported)
			flow, hooks := newStepUpTestFlow(t, fake)
			sessionWithClaims(t, hooks, tc.accessClaims, tc.idClaims)

			authContext, err := flow.GetAuthenticationContext(context.Background())

			require.NoError(t, err)
			assert.Equal(t, tc.expected.Acr, authContext.Acr)
			assert.NotNil(t, authContext.Amr)
			assert.Equal(t, tc.expected.Amr, authContext.Amr)
			assert.True(t, tc.expected.AuthTime.Equal(authContext.AuthTime), "expected auth time %v, got %v", tc.expected.AuthTime, authContext.AuthTime)
		})
	}

	t.Run("no session", func(t *testing.T) {
		fake := newFakeKinde(t, []string{"mfa", "phr"})
		flow, _ := newStepUpTestFlow(t, fake)

		_, err := flow.GetAuthenticationContext(context.Background())

		assert.Error(t, err)
	})
}

func TestFlowHasAuthenticationContext(t *testing.T) {
	t.Parallel()

	recent := time.Now().Add(-time.Minute).Unix()
	stale := time.Now().Add(-time.Hour).Unix()

	testCases := []struct {
		name               string
		acrValuesSupported []string
		accessClaims       golangjwt.MapClaims
		idClaims           golangjwt.MapClaims
		requirement        jwt.AuthenticationRequirement
		expected           bool
	}{
		{"single factor, mfa required", []string{"mfa", "phr"}, golangjwt.MapClaims{}, golangjwt.MapClaims{"auth_time": recent}, jwt.AuthenticationRequirement{Acr: jwt.AcrMFA}, false},
		{"phr, mfa required", []string{"mfa", "phr"}, golangjwt.MapClaims{"acr": "phr"}, golangjwt.MapClaims{"auth_time": recent}, jwt.AuthenticationRequirement{Acr: jwt.AcrMFA}, true},
		{"mfa in the last 5 minutes, met", []string{"mfa", "phr"}, golangjwt.MapClaims{"acr": "mfa"}, golangjwt.MapClaims{"auth_time": recent}, jwt.AuthenticationRequirement{Acr: jwt.AcrMFA, MaxAge: new(300)}, true},
		{"mfa in the last 5 minutes, too old", []string{"mfa", "phr"}, golangjwt.MapClaims{"acr": "mfa"}, golangjwt.MapClaims{"auth_time": stale}, jwt.AuthenticationRequirement{Acr: jwt.AcrMFA, MaxAge: new(300)}, false},
		{"recency uses the ID token's auth_time", []string{"mfa", "phr"}, golangjwt.MapClaims{"acr": "mfa", "auth_time": recent}, golangjwt.MapClaims{"auth_time": stale}, jwt.AuthenticationRequirement{MaxAge: new(300)}, false},
		{"max age set, auth_time missing", []string{"mfa", "phr"}, golangjwt.MapClaims{"acr": "phr"}, golangjwt.MapClaims{}, jwt.AuthenticationRequirement{MaxAge: new(300)}, false},
		{"no step-up support: auth_time is not used for recency", nil, golangjwt.MapClaims{}, golangjwt.MapClaims{"auth_time": recent}, jwt.AuthenticationRequirement{MaxAge: new(300)}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeKinde(t, tc.acrValuesSupported)
			flow, hooks := newStepUpTestFlow(t, fake)
			sessionWithClaims(t, hooks, tc.accessClaims, tc.idClaims)

			met, err := flow.HasAuthenticationContext(context.Background(), tc.requirement)

			require.NoError(t, err)
			assert.Equal(t, tc.expected, met)
			assert.Empty(t, fake.getTokenRequests(), "checking never refreshes to satisfy a requirement")
		})
	}

	t.Run("a forged ID token in the session does not meet a requirement", func(t *testing.T) {
		fake := newFakeKinde(t, []string{"mfa", "phr"})
		flow, hooks := newStepUpTestFlow(t, fake)
		forged, err := golangjwt.NewWithClaims(golangjwt.SigningMethodNone, golangjwt.MapClaims{
			"sub": stepUpTestSubject, "iss": "https://testing.kinde.com", "aud": []string{"client_id"},
			"acr": "phr", "auth_time": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		}).SignedString(golangjwt.UnsafeAllowNoneSignatureType)
		require.NoError(t, err)
		// A genuine single-factor access token, next to an ID token nobody signed
		hooks.token = (&oauth2.Token{AccessToken: signStepUpTestToken(t, golangjwt.MapClaims{}), Expiry: time.Now().Add(time.Hour)}).
			WithExtra(map[string]interface{}{"id_token": forged})

		for _, requirement := range []jwt.AuthenticationRequirement{{Acr: jwt.AcrPHR, MaxAge: new(300)}, {Acr: jwt.AcrMFA}, {MaxAge: new(300)}} {
			met, err := flow.HasAuthenticationContext(context.Background(), requirement)
			require.NoError(t, err)
			assert.False(t, met)
		}
	})

	t.Run("no session", func(t *testing.T) {
		fake := newFakeKinde(t, []string{"mfa", "phr"})
		flow, _ := newStepUpTestFlow(t, fake)

		met, err := flow.HasAuthenticationContext(context.Background(), jwt.AuthenticationRequirement{Acr: jwt.AcrMFA})

		assert.Error(t, err)
		assert.False(t, met)
	})
}
