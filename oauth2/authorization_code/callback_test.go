package authorization_code

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/kinde-oss/kinde-go/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

const unmetDescription = "The requested authentication context could not be met"

// signedInSession puts single-factor tokens in the session, as after a first login.
func signedInSession(t *testing.T, hooks *stepUpSessionHooks) *oauth2.Token {
	t.Helper()
	token := (&oauth2.Token{
		AccessToken:  signStepUpTestToken(t, golangjwt.MapClaims{"jti": "access-before"}),
		RefreshToken: "refresh-before",
		Expiry:       time.Now().Add(time.Hour),
	}).WithExtra(map[string]interface{}{
		"id_token": signStepUpTestToken(t, golangjwt.MapClaims{"jti": "id-before", "auth_time": time.Now().Add(-time.Hour).Unix()}),
	})
	hooks.token = token
	return token
}

// steppedUpTokenResponse is what the token endpoint returns after a step-up.
func steppedUpTokenResponse(t *testing.T, expiresIn int) map[string]any {
	t.Helper()
	return map[string]any{
		"access_token":  signStepUpTestToken(t, golangjwt.MapClaims{"jti": "access-after", "acr": "mfa", "amr": []string{"pwd", "totp"}}),
		"id_token":      signStepUpTestToken(t, golangjwt.MapClaims{"jti": "id-after", "acr": "mfa", "amr": []string{"pwd", "totp"}, "auth_time": time.Now().Unix()}),
		"refresh_token": "refresh-after",
		"token_type":    "bearer",
		"expires_in":    expiresIn,
	}
}

func TestHandleCallback_StepUpErrors(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		errorCode string
		assertErr func(t *testing.T, err error)
	}{
		{
			name:      "unmet_authentication_requirements",
			errorCode: "unmet_authentication_requirements",
			assertErr: func(t *testing.T, err error) {
				var unmet *UnmetAuthenticationRequirementsError
				require.True(t, errors.As(err, &unmet), "expected UnmetAuthenticationRequirementsError, got %T", err)
				assert.Equal(t, unmetDescription, unmet.ErrorDescription)
				assert.Equal(t, "pending_state", unmet.State)
				assert.Contains(t, err.Error(), unmetDescription)

				var loginRequired *LoginRequiredError
				assert.False(t, errors.As(err, &loginRequired))
			},
		},
		{
			name:      "login_required",
			errorCode: "login_required",
			assertErr: func(t *testing.T, err error) {
				var loginRequired *LoginRequiredError
				require.True(t, errors.As(err, &loginRequired), "expected LoginRequiredError, got %T", err)
				assert.Equal(t, unmetDescription, loginRequired.ErrorDescription)
				assert.Equal(t, "pending_state", loginRequired.State)

				var unmet *UnmetAuthenticationRequirementsError
				assert.False(t, errors.As(err, &unmet))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeKinde(t, []string{"mfa", "phr"})
			flow, hooks := newStepUpTestFlow(t, fake)
			before := signedInSession(t, hooks)
			hooks.state = "pending_state"
			hooks.postAuthRedirect = pendingStepUp("/settings/payout")

			postAuthRedirect, err := flow.HandleCallback(context.Background(), url.Values{
				"error":             {tc.errorCode},
				"error_description": {unmetDescription},
				"state":             {"pending_state"},
			})

			tc.assertErr(t, err)
			assert.Empty(t, postAuthRedirect)
			assert.Empty(t, fake.getTokenRequests(), "the error must not be retried or exchanged")
			assert.Same(t, before, hooks.token, "the user stays signed in with the tokens they had")
			assert.Empty(t, hooks.postAuthRedirect, "the step-up is over, so its return path is cleared")
		})
	}
}

func TestHandleCallback_ValidatesStateBeforeReportingStepUpErrors(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		storedState   string
		receivedState string
		message       string
	}{
		{"state mismatch", "pending_state", "forged_state", "state mismatch"},
		{"no request in progress", "", "pending_state", "state not found in session"},
	}

	for _, errorCode := range []string{"unmet_authentication_requirements", "login_required"} {
		for _, tc := range testCases {
			t.Run(errorCode+"/"+tc.name, func(t *testing.T) {
				fake := newFakeKinde(t, []string{"mfa", "phr"})
				flow, hooks := newStepUpTestFlow(t, fake)
				hooks.state = tc.storedState
				pending := pendingStepUp("/settings/payout")
				hooks.postAuthRedirect = pending

				query := url.Values{"error": {errorCode}, "error_description": {unmetDescription}}
				if tc.receivedState != "" {
					query.Set("state", tc.receivedState)
				}
				_, err := flow.HandleCallback(context.Background(), query)

				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.message)
				var unmet *UnmetAuthenticationRequirementsError
				var loginRequired *LoginRequiredError
				assert.False(t, errors.As(err, &unmet))
				assert.False(t, errors.As(err, &loginRequired))
				assert.Equal(t, pending, hooks.postAuthRedirect, "a forged callback changes nothing")
			})
		}
	}
}

func TestHandleCallback_OtherErrorsAreReported(t *testing.T) {
	t.Parallel()

	fake := newFakeKinde(t, []string{"mfa", "phr"})
	flow, hooks := newStepUpTestFlow(t, fake)
	before := signedInSession(t, hooks)
	hooks.state = "pending_state"
	hooks.postAuthRedirect = pendingStepUp("/settings/payout")
	cancelled := url.Values{"error": {"access_denied"}, "error_description": {"User cancelled"}, "state": {"pending_state"}}

	// The user cancelled: there is no code, so nothing is sent to the token endpoint
	_, err := flow.HandleCallback(context.Background(), cancelled)

	var reported *CallbackError
	require.ErrorAs(t, err, &reported)
	assert.Equal(t, "access_denied", reported.Code)
	assert.Equal(t, "User cancelled", reported.ErrorDescription)
	assert.Equal(t, "pending_state", reported.State)
	assert.Empty(t, fake.getTokenRequests())
	assert.Same(t, before, hooks.token, "the user stays signed in")
	assert.Empty(t, hooks.postAuthRedirect, "the step-up it belonged to is over")

	// The built-in handler says so instead of answering with a server error
	hooks.state = "pending_state"
	recorder := httptest.NewRecorder()
	flow.AuthorizationCodeReceivedHandler(recorder, httptest.NewRequest(http.MethodGet, "/callback?"+cancelled.Encode(), nil))
	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "access_denied")

	// The state is still checked first
	_, err = flow.HandleCallback(context.Background(), url.Values{"error": {"access_denied"}, "state": {"forged"}})
	require.Error(t, err)
	assert.False(t, errors.As(err, &reported))
}

func TestHandleCallback_StepUpReplacesTokensOfSignedInUser(t *testing.T) {
	t.Parallel()

	fake := newFakeKinde(t, []string{"mfa", "phr"})
	flow, hooks := newStepUpTestFlow(t, fake)
	before := signedInSession(t, hooks)
	hooks.state = "pending_state"
	hooks.postAuthRedirect = pendingStepUp("/settings/payout?tab=bank")
	response := steppedUpTokenResponse(t, 3600)
	fake.setTokenResponse(response)

	postAuthRedirect, err := flow.HandleCallback(context.Background(), url.Values{"code": {"step_up_code"}, "state": {"pending_state"}})

	require.NoError(t, err)
	assert.Equal(t, "/settings/payout?tab=bank", postAuthRedirect, "the user goes back to where they were")
	assert.Empty(t, hooks.postAuthRedirect, "the return path is used once")

	requests := fake.getTokenRequests()
	require.Len(t, requests, 1)
	assert.Equal(t, "authorization_code", requests[0].Get("grant_type"))
	assert.Equal(t, "step_up_code", requests[0].Get("code"))

	// All three tokens are the ones from the step-up callback
	after := hooks.token
	require.NotSame(t, before, after)
	assert.Equal(t, response["access_token"], after.AccessToken)
	assert.NotEqual(t, before.AccessToken, after.AccessToken)
	assert.Equal(t, "refresh-after", after.RefreshToken)
	assert.Equal(t, response["id_token"], after.Extra("id_token"))
	assert.NotEqual(t, before.Extra("id_token"), after.Extra("id_token"))
}

func TestHandleCallback_PostAuthRedirectMustBeALocalPath(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		stored   string
		expected string
	}{
		{"/settings/payout?tab=bank#iban", "/settings/payout?tab=bank#iban"},
		{"https://evil.example.com/", ""},
		{"//evil.example.com/", ""},
		{"/\\evil.example.com", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.stored, func(t *testing.T) {
			fake := newFakeKinde(t, []string{"mfa", "phr"})
			flow, hooks := newStepUpTestFlow(t, fake)
			hooks.state = "pending_state"
			hooks.postAuthRedirect = pendingStepUp(tc.stored)
			fake.setTokenResponse(steppedUpTokenResponse(t, 3600))

			postAuthRedirect, err := flow.HandleCallback(context.Background(), url.Values{"code": {"code"}, "state": {"pending_state"}})

			require.NoError(t, err)
			assert.Equal(t, tc.expected, postAuthRedirect)
		})
	}
}

func TestHandleCallback_OnlyActsOnItsOwnStepUp(t *testing.T) {
	t.Parallel()

	callbacks := []struct {
		name  string
		query url.Values
	}{
		{"successful login", url.Values{"code": {"code"}, "state": {"pending_state"}}},
		{"step-up error", url.Values{"error": {"unmet_authentication_requirements"}, "state": {"pending_state"}}},
	}

	for _, callback := range callbacks {
		t.Run("a post-auth redirect of the app is left alone/"+callback.name, func(t *testing.T) {
			for _, stored := range []string{"https://other.example/after", "/dashboard"} {
				fake := newFakeKinde(t, []string{"mfa", "phr"})
				flow, hooks := newStepUpTestFlow(t, fake)
				hooks.state = "pending_state"
				hooks.postAuthRedirect = stored
				fake.setTokenResponse(steppedUpTokenResponse(t, 3600))

				postAuthRedirect, _ := flow.HandleCallback(context.Background(), callback.query)

				assert.Empty(t, postAuthRedirect, "the SDK only returns what StepUp stored")
				assert.Equal(t, stored, hooks.postAuthRedirect)

				recorder := httptest.NewRecorder()
				flow.AuthorizationCodeReceivedHandler(recorder, httptest.NewRequest(http.MethodGet, "/callback?"+callback.query.Encode(), nil))
				assert.Empty(t, recorder.Header().Get("Location"), "and the handler does not redirect, as before")
				assert.Equal(t, stored, hooks.postAuthRedirect)
			}
		})

		t.Run("an abandoned step-up does not redirect a later login/"+callback.name, func(t *testing.T) {
			fake := newFakeKinde(t, []string{"mfa", "phr"})
			flow, hooks := newStepUpTestFlow(t, fake)
			// A step-up from /settings/payout was started and never finished
			hooks.postAuthRedirect = encodeStepUpMarker(stepUpMarker{State: "abandoned_state", ReturnTo: "/settings/payout", Acr: "mfa"})
			// ... and this callback belongs to a later, ordinary login
			hooks.state = "pending_state"
			fake.setTokenResponse(steppedUpTokenResponse(t, 3600))

			postAuthRedirect, _ := flow.HandleCallback(context.Background(), callback.query)

			assert.Empty(t, postAuthRedirect)
			assert.Empty(t, hooks.postAuthRedirect, "the leftover is cleared")
		})
	}
}

func TestStepUpLoopIsStopped(t *testing.T) {
	t.Parallel()

	requirement := jwt.AuthenticationRequirement{Acr: jwt.AcrMFA, MaxAge: new(300)}
	// The step-up "succeeds", but the tokens that end up in the session cannot
	// show it: no auth_time on the access token, and no ID token
	tokensWithoutAuthTime := func(t *testing.T) map[string]any {
		return map[string]any{
			"access_token": signStepUpTestToken(t, golangjwt.MapClaims{"acr": "mfa"}),
			"token_type":   "bearer",
			"expires_in":   3600,
		}
	}
	// completeStepUp starts the step-up and handles its callback.
	completeStepUp := func(t *testing.T, flow *AuthorizationCodeFlow, fake *fakeKinde, tokens map[string]any) {
		t.Helper()
		stepUpURL, err := flow.GetStepUpURL(context.Background(), requirement)
		require.NoError(t, err)
		fake.setTokenResponse(tokens)
		_, err = flow.HandleCallback(context.Background(), url.Values{"code": {"code"}, "state": {queryOf(t, stepUpURL).Get("state")}})
		require.NoError(t, err)
	}

	t.Run("the same step-up is refused right after it did not help", func(t *testing.T) {
		fake := newFakeKinde(t, []string{"mfa", "phr"})
		flow, hooks := newStepUpTestFlow(t, fake)
		signedInSession(t, hooks)

		completeStepUp(t, flow, fake, tokensWithoutAuthTime(t))

		// Back in the app the requirement is still unmet, so it asks again
		met, err := flow.HasAuthenticationContext(context.Background(), requirement)
		require.NoError(t, err)
		require.False(t, met)
		state := hooks.state

		stepUpURL, err := flow.GetStepUpURL(context.Background(), requirement)
		assert.ErrorIs(t, err, ErrStepUpLoop)
		assert.Empty(t, stepUpURL)
		assert.Equal(t, state, hooks.state, "no new request is started")

		recorder := httptest.NewRecorder()
		err = flow.StepUp(recorder, httptest.NewRequest(http.MethodGet, "https://app.example.com/settings/payout", nil), requirement)
		assert.ErrorIs(t, err, ErrStepUpLoop)
		assert.Empty(t, recorder.Header().Get("Location"))

		// A different requirement is a different question
		_, err = flow.GetStepUpURL(context.Background(), jwt.AuthenticationRequirement{Acr: jwt.AcrPHR, MaxAge: new(300)})
		assert.NoError(t, err)
	})

	t.Run("it can be tried again later", func(t *testing.T) {
		fake := newFakeKinde(t, []string{"mfa", "phr"})
		flow, hooks := newStepUpTestFlow(t, fake)
		signedInSession(t, hooks)
		completeStepUp(t, flow, fake, tokensWithoutAuthTime(t))

		marker := storedStepUp(t, hooks)
		marker.UnmetAt = time.Now().Add(-2 * stepUpLoopWindow).Unix()
		hooks.postAuthRedirect = encodeStepUpMarker(marker)

		_, err := flow.GetStepUpURL(context.Background(), requirement)
		assert.NoError(t, err)
	})

	t.Run("a step-up that worked can be repeated", func(t *testing.T) {
		for _, repeated := range []jwt.AuthenticationRequirement{requirement, {Acr: jwt.AcrMFA, MaxAge: new(0)}} {
			fake := newFakeKinde(t, []string{"mfa", "phr"})
			flow, hooks := newStepUpTestFlow(t, fake)
			signedInSession(t, hooks)

			for range 2 {
				stepUpURL, err := flow.GetStepUpURL(context.Background(), repeated)
				require.NoError(t, err)
				fake.setTokenResponse(steppedUpTokenResponse(t, 3600))
				_, err = flow.HandleCallback(context.Background(), url.Values{"code": {"code"}, "state": {queryOf(t, stepUpURL).Get("state")}})
				require.NoError(t, err)
				assert.Empty(t, hooks.postAuthRedirect)
			}
		}
	})

	t.Run("a step-up whose state cannot be stored is not started", func(t *testing.T) {
		fake := newFakeKinde(t, []string{"mfa", "phr"})
		flow, hooks := newStepUpTestFlow(t, fake)
		signedInSession(t, hooks)
		hooks.stateFull = true

		stepUpURL, err := flow.GetStepUpURL(context.Background(), requirement)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not store its state")
		assert.Empty(t, stepUpURL)
		assert.Empty(t, hooks.postAuthRedirect)
	})

	t.Run("a step-up the session cannot record is not started", func(t *testing.T) {
		fake := newFakeKinde(t, []string{"mfa", "phr"})
		flow, hooks := newStepUpTestFlow(t, fake)
		signedInSession(t, hooks)
		hooks.state = "state_of_a_login_in_progress"
		hooks.full = true

		stepUpURL, err := flow.GetStepUpURL(context.Background(), requirement)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not be recorded in the session")
		assert.Contains(t, err.Error(), "too long", "the session's own error is kept")
		assert.Empty(t, stepUpURL)
		assert.Equal(t, "state_of_a_login_in_progress", hooks.state, "no new request is started")

		recorder := httptest.NewRecorder()
		err = flow.StepUp(recorder, httptest.NewRequest(http.MethodGet, "https://app.example.com/settings/payout", nil), requirement)
		require.Error(t, err)
		assert.Empty(t, recorder.Header().Get("Location"), "without a record there is no return path and no loop check")
		assert.Empty(t, recorder.Body.String())
	})
}

func TestRefreshAfterStepUpUsesNewRefreshToken(t *testing.T) {
	t.Parallel()

	fake := newFakeKinde(t, []string{"mfa", "phr"})
	flow, hooks := newStepUpTestFlow(t, fake)
	signedInSession(t, hooks)
	hooks.state = "pending_state"

	// The stepped-up access token expires straight away, so the next use refreshes it
	fake.setTokenResponse(steppedUpTokenResponse(t, 1))
	_, err := flow.HandleCallback(context.Background(), url.Values{"code": {"step_up_code"}, "state": {"pending_state"}})
	require.NoError(t, err)

	fake.setTokenResponse(map[string]any{
		"access_token":  signStepUpTestToken(t, golangjwt.MapClaims{"jti": "access-refreshed", "acr": "mfa"}),
		"refresh_token": "refresh-rotated",
		"token_type":    "bearer",
		"expires_in":    3600,
	})
	token, err := flow.GetToken(context.Background())
	require.NoError(t, err)

	requests := fake.getTokenRequests()
	require.Len(t, requests, 2)
	assert.Equal(t, "refresh_token", requests[1].Get("grant_type"))
	assert.Equal(t, "refresh-after", requests[1].Get("refresh_token"), "the refresh token from the step-up callback is used")
	for _, request := range requests {
		assert.NotEqual(t, "refresh-before", request.Get("refresh_token"), "the refresh token from before the step-up is never used")
	}
	assert.Equal(t, "mfa", token.GetAuthenticationContext().Acr)
	assert.Equal(t, "refresh-rotated", hooks.token.RefreshToken)
	assert.False(t, token.GetAuthenticationContext().AuthTime.IsZero(), "the ID token is kept when the refresh response has none")
}

func TestAuthorizationCodeReceivedHandler_StepUp(t *testing.T) {
	t.Parallel()

	unmetCallback := "/callback?error=unmet_authentication_requirements&error_description=" + url.QueryEscape(unmetDescription) + "&state=pending_state"

	t.Run("an unmet step-up is shown to the user, not turned into a login redirect", func(t *testing.T) {
		fake := newFakeKinde(t, []string{"mfa", "phr"})
		flow, hooks := newStepUpTestFlow(t, fake)
		before := signedInSession(t, hooks)
		hooks.state = "pending_state"

		recorder := httptest.NewRecorder()
		flow.AuthorizationCodeReceivedHandler(recorder, httptest.NewRequest(http.MethodGet, unmetCallback, nil))

		assert.Equal(t, http.StatusForbidden, recorder.Code)
		assert.Contains(t, recorder.Body.String(), "the extra verification could not be completed")
		assert.Contains(t, recorder.Body.String(), unmetDescription)
		assert.Empty(t, recorder.Header().Get("Location"))
		assert.Empty(t, fake.getTokenRequests())
		assert.Same(t, before, hooks.token)
	})

	t.Run("the error reaches the callback error handler", func(t *testing.T) {
		fake := newFakeKinde(t, []string{"mfa", "phr"})
		var received error
		flow, hooks := newStepUpTestFlow(t, fake, WithCallbackErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
			received = err
			http.Error(w, "add a passkey to continue", http.StatusForbidden)
		}))
		hooks.state = "pending_state"

		recorder := httptest.NewRecorder()
		flow.AuthorizationCodeReceivedHandler(recorder, httptest.NewRequest(http.MethodGet, unmetCallback, nil))

		var unmet *UnmetAuthenticationRequirementsError
		require.True(t, errors.As(received, &unmet), "expected UnmetAuthenticationRequirementsError, got %T", received)
		assert.Equal(t, unmetDescription, unmet.ErrorDescription)
		assert.Equal(t, "pending_state", unmet.State)
		assert.Equal(t, http.StatusForbidden, recorder.Code)
		assert.Contains(t, recorder.Body.String(), "add a passkey to continue")
		assert.Empty(t, recorder.Header().Get("Location"))
	})

	t.Run("without a handler other errors are answered as before", func(t *testing.T) {
		fake := newFakeKinde(t, []string{"mfa", "phr"})
		flow, hooks := newStepUpTestFlow(t, fake)
		hooks.state = "pending_state"

		forged := httptest.NewRecorder()
		flow.AuthorizationCodeReceivedHandler(forged, httptest.NewRequest(http.MethodGet, unmetCallback+"_forged", nil))
		assert.Equal(t, http.StatusBadRequest, forged.Code)
		assert.Contains(t, forged.Body.String(), "invalid state parameter")

		failed := httptest.NewRecorder()
		flow.AuthorizationCodeReceivedHandler(failed, httptest.NewRequest(http.MethodGet, "/callback?code=bad_code&state=pending_state", nil))
		assert.Equal(t, http.StatusInternalServerError, failed.Code)
	})

	t.Run("after a step-up the user is sent back to where they were", func(t *testing.T) {
		fake := newFakeKinde(t, []string{"mfa", "phr"})
		flow, hooks := newStepUpTestFlow(t, fake)
		hooks.state = "pending_state"
		hooks.postAuthRedirect = pendingStepUp("/settings/payout")
		fake.setTokenResponse(steppedUpTokenResponse(t, 3600))

		recorder := httptest.NewRecorder()
		flow.AuthorizationCodeReceivedHandler(recorder, httptest.NewRequest(http.MethodGet, "/callback?code=code&state=pending_state", nil))

		assert.Equal(t, http.StatusFound, recorder.Code)
		assert.Equal(t, "/settings/payout", recorder.Header().Get("Location"))
	})

	t.Run("a normal login writes nothing, as before", func(t *testing.T) {
		fake := newFakeKinde(t, []string{"mfa", "phr"})
		flow, hooks := newStepUpTestFlow(t, fake)
		hooks.state = "pending_state"
		fake.setTokenResponse(steppedUpTokenResponse(t, 3600))

		recorder := httptest.NewRecorder()
		flow.AuthorizationCodeReceivedHandler(recorder, httptest.NewRequest(http.MethodGet, "/callback?code=code&state=pending_state", nil))

		assert.Equal(t, http.StatusOK, recorder.Code)
		assert.Empty(t, recorder.Body.String())
		assert.Empty(t, recorder.Header().Get("Location"))
		assert.NotNil(t, hooks.token)
	})
}
