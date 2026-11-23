package authorization_code

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/kinde-oss/kinde-go/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorizationCodeFlowWithPKCE(t *testing.T) {
	assert := assert.New(t)

	testBackendServerURL := "https://api.com"
	testKindeServerURL := "https://mytest.kinde.com"

	callbackURL := fmt.Sprintf("%v/callback", testBackendServerURL)

	// Create session hooks first
	sessionHooks := newTestSessionHooks()

	kindeAuthFlow, err := NewAuthorizationCodeFlow(
		testKindeServerURL, "b9da18c441b44d81bab3e8232de2e18d", "", callbackURL, // No client secret for public client
		WithSessionHooks(sessionHooks),
		WithCustomStateGenerator(func(*AuthorizationCodeFlow) string { return "test_state" }),
		WithOffline(),
		WithAudience("http://my.api.com/api"),
		WithPKCE(), // Enable PKCE
		WithTokenValidation(
			true,
			jwt.WillValidateAlgorithm(),
			jwt.WillValidateAudience("http://my.api.com/api"),
		),
	)

	assert.Nil(err, "could not create kinde client with PKCE")

	// Verify PKCE fields are set
	flow := kindeAuthFlow.(*AuthorizationCodeFlow)
	assert.True(flow.usePKCE, "PKCE should be enabled")
	assert.NotEmpty(flow.codeChallenge, "code_challenge should be generated")
	assert.Equal("S256", flow.challengeMethod, "challenge method should be S256")

	// Verify code verifier is stored in session hooks
	codeVerifier, err := sessionHooks.GetCodeVerifier()
	assert.Nil(err, "should be able to get code verifier from session hooks")
	assert.NotEmpty(codeVerifier, "code_verifier should be stored in session hooks")

	authURL := kindeAuthFlow.GetAuthURL()
	assert.NotEmpty(authURL, "AuthURL cannot be empty")
	assert.Contains(authURL, "code_challenge=", "AuthURL should contain code_challenge parameter")
	assert.Contains(authURL, "code_challenge_method=S256", "AuthURL should contain code_challenge_method parameter")
}

func TestAuthorizationCodeFlowWithPKCEPlain(t *testing.T) {
	assert := assert.New(t)

	testBackendServerURL := "https://api.com"
	testKindeServerURL := "https://mytest.kinde.com"

	callbackURL := fmt.Sprintf("%v/callback", testBackendServerURL)

	// Create session hooks first
	sessionHooks := newTestSessionHooks()

	kindeAuthFlow, err := NewAuthorizationCodeFlow(
		testKindeServerURL, "b9da18c441b44d81bab3e8232de2e18d", "", callbackURL,
		WithSessionHooks(sessionHooks),
		WithCustomStateGenerator(func(*AuthorizationCodeFlow) string { return "test_state" }),
		WithPKCEChallengeMethod("plain"), // Use plain challenge method
	)

	assert.Nil(err, "could not create kinde client with PKCE plain method")

	flow := kindeAuthFlow.(*AuthorizationCodeFlow)
	assert.True(flow.usePKCE, "PKCE should be enabled")
	assert.Equal("plain", flow.challengeMethod, "challenge method should be plain")

	// Verify code verifier is stored in session hooks and challenge equals verifier for plain method
	codeVerifier, err := sessionHooks.GetCodeVerifier()
	assert.Nil(err, "should be able to get code verifier from session hooks")
	assert.NotEmpty(codeVerifier, "code_verifier should be stored in session hooks")
	assert.Equal(flow.codeChallenge, codeVerifier, "code_challenge should equal code_verifier for plain method")

	authURL := kindeAuthFlow.GetAuthURL()
	assert.Contains(authURL, "code_challenge_method=plain", "AuthURL should contain plain challenge method")
}

func TestAuthorizationCodeFlowPKCEExchange(t *testing.T) {
	testAuthorizationServer := getTestAuthorizationServer()
	defer testAuthorizationServer.Close()

	testBackendServerURL := testAuthorizationServer.URL
	callbackURL := fmt.Sprintf("%v/callback", testBackendServerURL)

	// Create session hooks first
	sessionHooks := newTestSessionHooks()

	kindeClient, err := NewAuthorizationCodeFlow(
		testBackendServerURL, "b9da18c441b44d81bab3e8232de2e18d", "", callbackURL,
		WithSessionHooks(sessionHooks),
		WithCustomStateGenerator(func(flow *AuthorizationCodeFlow) string {
			state := "test_state"
			flow.sessionHooks.SetState(state)
			return state
		}),
		WithPKCE(), // Enable PKCE
		WithTokenValidation(
			true,
			jwt.WillValidateAlgorithm(),
			jwt.WillValidateAudience("http://my.api.com/api"),
		),
	)

	assert.Nil(t, err, "could not create kinde client with PKCE")

	flow := kindeClient.(*AuthorizationCodeFlow)
	assert.True(t, flow.usePKCE, "PKCE should be enabled")

	// Verify code verifier is stored in session hooks
	codeVerifier, err := sessionHooks.GetCodeVerifier()
	assert.Nil(t, err, "should be able to get code verifier from session hooks")
	assert.NotEmpty(t, codeVerifier, "code_verifier should be stored in session hooks")

	authURL := kindeClient.GetAuthURL()
	assert.Contains(t, authURL, "code_challenge=", "AuthURL should contain PKCE parameters")

	ctx := context.Background()
	err = kindeClient.ExchangeCode(ctx, "code", "test_state")
	assert.Nil(t, err, "could not exchange token with PKCE")
}

func TestPKCEUtilityFunctions(t *testing.T) {
	assert := assert.New(t)

	// Test code verifier generation
	codeVerifier, err := generateCodeVerifier()
	assert.Nil(err, "should generate code verifier without error")
	assert.NotEmpty(codeVerifier, "code verifier should not be empty")
	assert.Len(codeVerifier, 43, "code verifier should be 43 characters (32 bytes base64url encoded)")

	// Test code challenge generation
	codeChallenge := generateCodeChallenge(codeVerifier)
	assert.NotEmpty(codeChallenge, "code challenge should not be empty")
	assert.Len(codeChallenge, 43, "code challenge should be 43 characters")
	assert.NotEqual(codeVerifier, codeChallenge, "code challenge should be different from code verifier")

	// Test that challenge is deterministic
	codeChallenge2 := generateCodeChallenge(codeVerifier)
	assert.Equal(codeChallenge, codeChallenge2, "code challenge should be deterministic for same verifier")
}

func TestExchangeCode_PKCEFailureKeepsTokens(t *testing.T) {
	t.Parallel()

	fake := newFakeKinde(t, []string{"mfa", "phr"})
	hooks := &stepUpSessionHooks{}
	created, err := NewAuthorizationCodeFlow(fake.URL, "client_id", "client_secret", "https://app.example.com/callback",
		WithSessionHooks(hooks), WithPKCE(), WithTokenValidation(true))
	require.NoError(t, err)
	flow := created.(*AuthorizationCodeFlow)
	before := signedInSession(t, hooks)
	hooks.state = "pending_state"

	// The token endpoint rejects the code
	_, err = flow.HandleCallback(context.Background(), url.Values{"code": {"bad_code"}, "state": {"pending_state"}})

	assert.Error(t, err, "a failed exchange is not a successful callback")
	assert.Same(t, before, hooks.token, "a failed step-up leaves the user signed in with the tokens they had")
}
