package authorization_code

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kinde-oss/kinde-go/jwt"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func TestAutorizationCodeFlowOnline(t *testing.T) {

	assert := assert.New(t)

	testBackendServerURL := "https://api.com"
	testKindeServerURL := "https://mytest.kinde.com"

	callbackURL := fmt.Sprintf("%v/callback", testBackendServerURL)
	kindeAuthFlow, _ := NewAuthorizationCodeFlow(
		testKindeServerURL, "b9da18c441b44d81bab3e8232de2e18d", "client_secret", callbackURL,
		WithSessionHooks(newTestSessionHooks()),
		WithCustomStateGenerator(func(*AuthorizationCodeFlow) string { return "test_state" }), //custom state generator for testing
		WithOffline(),                         //offline scope
		WithAudience("http://my.api.com/api"), //custom API audience
		WithTokenValidation(
			true,
			jwt.WillValidateAlgorithm(),
			jwt.WillValidateAudience("http://my.api.com/api"),
		),
	)

	authURL := kindeAuthFlow.GetAuthURL()
	assert.NotEmpty(authURL, "AuthURL cannot be empty")
	assert.Equal("https://mytest.kinde.com/oauth2/auth?audience=http%3A%2F%2Fmy.api.com%2Fapi&client_id=b9da18c441b44d81bab3e8232de2e18d&redirect_uri=https%3A%2F%2Fapi.com%2Fcallback&response_type=code&scope=openid+profile+email+offline&state=test_state", authURL, "AuthURL is not correct")

}

func TestAutorizationCodeFlowClient(t *testing.T) {

	testAuthorizationServer := getTestAuthorizationServer()
	defer testAuthorizationServer.Close()

	testBackendServerURL := testAuthorizationServer.URL
	callbackURL := fmt.Sprintf("%v/callback", testBackendServerURL)
	kindeClient, err := NewAuthorizationCodeFlow(
		testBackendServerURL, "b9da18c441b44d81bab3e8232de2e18d", "client_secret", callbackURL,
		WithSessionHooks(newTestSessionHooks()),
		WithCustomStateGenerator(func(flow *AuthorizationCodeFlow) string {
			state := "test_state"
			flow.sessionHooks.SetState(state) //we need to save the state to sessino for later verification after callback
			return state
		}), //custom state generator for testing
		WithOffline(),                         //offline scope
		WithAudience("http://my.api.com/api"), //custom API audience
		WithTokenValidation(
			true,
			jwt.WillValidateAlgorithm(),
			jwt.WillValidateAudience("http://my.api.com/api"),
			jwt.WillValidateWithTimeFunc(func() time.Time {
				return time.Unix(1168335720000-1, 0)
			}),
		),
	)

	flow := kindeClient.(*AuthorizationCodeFlow)

	assert.Nil(t, err, "could not create kinde client")
	assert.Equal(t, flow.config.ClientID, "b9da18c441b44d81bab3e8232de2e18d")
	assert.Equal(t, flow.config.ClientSecret, "client_secret")
	assert.Equal(t, flow.config.RedirectURL, callbackURL)
	assert.Contains(t, flow.authURLOptions["audience"], "http://my.api.com/api")

	authURL := kindeClient.GetAuthURL()
	assert.NotNil(t, authURL, "AuthURL cannot be null")
	assert.Contains(t, authURL, "test_state", "state parameter is missing")

	ctx := context.Background()

	err = kindeClient.ExchangeCode(ctx, "code", "test_state")
	assert.Nil(t, err, "could not exchange token")

}

func TestGetAuthURLWithInvitation(t *testing.T) {
	assert := assert.New(t)

	testBackendServerURL := "https://api.com"
	testKindeServerURL := "https://mytest.kinde.com"

	callbackURL := fmt.Sprintf("%v/callback", testBackendServerURL)
	kindeAuthFlow, _ := NewAuthorizationCodeFlow(
		testKindeServerURL, "b9da18c441b44d81bab3e8232de2e18d", "client_secret", callbackURL,
		WithSessionHooks(newTestSessionHooks()),
		WithCustomStateGenerator(func(*AuthorizationCodeFlow) string { return "test_state" }),
	)

	// Test with invitation code
	invitationCode := "inv_123456789"
	authURL := kindeAuthFlow.GetAuthURLWithInvitation(invitationCode)
	assert.NotEmpty(authURL, "AuthURL cannot be empty")
	assert.Contains(authURL, "invitation_code=inv_123456789", "AuthURL should contain invitation_code parameter")
	assert.Contains(authURL, "is_invitation=true", "AuthURL should contain is_invitation parameter")

	// Test without invitation code (empty string)
	authURLNoInvitation := kindeAuthFlow.GetAuthURLWithInvitation("")
	assert.NotEmpty(authURLNoInvitation, "AuthURL cannot be empty")
	assert.NotContains(authURLNoInvitation, "invitation_code", "AuthURL should not contain invitation_code when empty")
	assert.NotContains(authURLNoInvitation, "is_invitation", "AuthURL should not contain is_invitation when empty")
}

func TestSwitchOrg(t *testing.T) {
	assert := assert.New(t)

	testBackendServerURL := "https://api.com"
	testKindeServerURL := "https://mytest.kinde.com"

	callbackURL := fmt.Sprintf("%v/callback", testBackendServerURL)
	kindeAuthFlow, _ := NewAuthorizationCodeFlow(
		testKindeServerURL, "b9da18c441b44d81bab3e8232de2e18d", "client_secret", callbackURL,
		WithSessionHooks(newTestSessionHooks()),
		WithCustomStateGenerator(func(*AuthorizationCodeFlow) string { return "test_state" }),
		WithAudience("http://my.api.com/api"),
	)

	authURL := kindeAuthFlow.SwitchOrg("org_123456789")
	assert.NotEmpty(authURL, "AuthURL cannot be empty")
	assert.Contains(authURL, "org_code=org_123456789", "AuthURL should contain org_code parameter")
	assert.Contains(authURL, "prompt=login", "AuthURL should force re-authentication via prompt=login")
	assert.Contains(authURL, "audience=", "AuthURL should keep other configured options")
}

func TestSwitchOrgOverridesExistingPrompt(t *testing.T) {
	assert := assert.New(t)

	testBackendServerURL := "https://api.com"
	testKindeServerURL := "https://mytest.kinde.com"

	callbackURL := fmt.Sprintf("%v/callback", testBackendServerURL)
	kindeAuthFlow, _ := NewAuthorizationCodeFlow(
		testKindeServerURL, "b9da18c441b44d81bab3e8232de2e18d", "client_secret", callbackURL,
		WithSessionHooks(newTestSessionHooks()),
		WithCustomStateGenerator(func(*AuthorizationCodeFlow) string { return "test_state" }),
		WithPrompt("none"),
	)

	authURL := kindeAuthFlow.SwitchOrg("org_987654321")
	assert.Contains(authURL, "org_code=org_987654321", "AuthURL should contain org_code parameter")
	assert.Contains(authURL, "prompt=login", "AuthURL should force prompt=login even if another prompt was configured")
	assert.NotContains(authURL, "prompt=none", "AuthURL should not keep the previously configured prompt")
}

func TestWithInvitationCodeOption(t *testing.T) {
	assert := assert.New(t)

	testBackendServerURL := "https://api.com"
	testKindeServerURL := "https://mytest.kinde.com"

	callbackURL := fmt.Sprintf("%v/callback", testBackendServerURL)
	invitationCode := "inv_987654321"
	kindeAuthFlow, _ := NewAuthorizationCodeFlow(
		testKindeServerURL, "b9da18c441b44d81bab3e8232de2e18d", "client_secret", callbackURL,
		WithSessionHooks(newTestSessionHooks()),
		WithCustomStateGenerator(func(*AuthorizationCodeFlow) string { return "test_state" }),
		WithInvitationCode(invitationCode),
	)

	flow := kindeAuthFlow.(*AuthorizationCodeFlow)
	invitationCodeValues, hasInvitationCode := flow.authURLOptions["invitation_code"]
	assert.True(hasInvitationCode, "invitation_code should be set in authURLOptions")
	if hasInvitationCode {
		assert.Contains(invitationCodeValues, invitationCode, "invitation_code should contain the provided value")
	}

	isInvitationValues, hasIsInvitation := flow.authURLOptions["is_invitation"]
	assert.True(hasIsInvitation, "is_invitation should be set in authURLOptions")
	if hasIsInvitation {
		assert.Contains(isInvitationValues, "true", "is_invitation should be set to 'true'")
	}

	authURL := kindeAuthFlow.GetAuthURL()
	assert.Contains(authURL, "invitation_code=inv_987654321", "AuthURL should contain invitation_code parameter")
	assert.Contains(authURL, "is_invitation=true", "AuthURL should contain is_invitation parameter")
}

func TestWithInvitationCodeOptionEmpty(t *testing.T) {
	assert := assert.New(t)

	testBackendServerURL := "https://api.com"
	testKindeServerURL := "https://mytest.kinde.com"

	callbackURL := fmt.Sprintf("%v/callback", testBackendServerURL)
	kindeAuthFlow, _ := NewAuthorizationCodeFlow(
		testKindeServerURL, "b9da18c441b44d81bab3e8232de2e18d", "client_secret", callbackURL,
		WithSessionHooks(newTestSessionHooks()),
		WithCustomStateGenerator(func(*AuthorizationCodeFlow) string { return "test_state" }),
		WithInvitationCode(""), // Empty invitation code should not add parameters
	)

	flow := kindeAuthFlow.(*AuthorizationCodeFlow)
	_, hasInvitationCode := flow.authURLOptions["invitation_code"]
	_, hasIsInvitation := flow.authURLOptions["is_invitation"]
	assert.False(hasInvitationCode, "invitation_code should not be set when empty")
	assert.False(hasIsInvitation, "is_invitation should not be set when empty")
}

func TestWithInvitationCodeOptionWhitespace(t *testing.T) {
	assert := assert.New(t)

	testBackendServerURL := "https://api.com"
	testKindeServerURL := "https://mytest.kinde.com"

	callbackURL := fmt.Sprintf("%v/callback", testBackendServerURL)
	testCases := []string{" ", "  ", "\t", "\n", "   \t\n   "}

	for _, whitespaceCode := range testCases {
		t.Run(fmt.Sprintf("whitespace_%q", whitespaceCode), func(t *testing.T) {
			kindeAuthFlow, _ := NewAuthorizationCodeFlow(
				testKindeServerURL, "b9da18c441b44d81bab3e8232de2e18d", "client_secret", callbackURL,
				WithSessionHooks(newTestSessionHooks()),
				WithCustomStateGenerator(func(*AuthorizationCodeFlow) string { return "test_state" }),
				WithInvitationCode(whitespaceCode), // Whitespace-only invitation code should not add parameters
			)

			flow := kindeAuthFlow.(*AuthorizationCodeFlow)
			_, hasInvitationCode := flow.authURLOptions["invitation_code"]
			_, hasIsInvitation := flow.authURLOptions["is_invitation"]
			assert.False(hasInvitationCode, "invitation_code should not be set when whitespace-only")
			assert.False(hasIsInvitation, "is_invitation should not be set when whitespace-only")
		})
	}
}

// TestGetAuthURLWithInvitationParameterPrecedence tests that invitation code parameter
// takes precedence over option when both are provided
func TestGetAuthURLWithInvitationParameterPrecedence(t *testing.T) {
	assert := assert.New(t)

	testBackendServerURL := "https://api.com"
	testKindeServerURL := "https://mytest.kinde.com"

	callbackURL := fmt.Sprintf("%v/callback", testBackendServerURL)
	optionInvitationCode := "inv_from_option"
	parameterInvitationCode := "inv_from_parameter"
	kindeAuthFlow, _ := NewAuthorizationCodeFlow(
		testKindeServerURL, "b9da18c441b44d81bab3e8232de2e18d", "client_secret", callbackURL,
		WithSessionHooks(newTestSessionHooks()),
		WithCustomStateGenerator(func(*AuthorizationCodeFlow) string { return "test_state" }),
		WithInvitationCode(optionInvitationCode),
	)

	// When GetAuthURLWithInvitation is called with a parameter, it should override the option
	authURL := kindeAuthFlow.GetAuthURLWithInvitation(parameterInvitationCode)
	assert.Contains(authURL, fmt.Sprintf("invitation_code=%s", parameterInvitationCode), "Parameter invitation code should take precedence")
	assert.Contains(authURL, "is_invitation=true", "is_invitation should be set when parameter is provided")
	assert.NotContains(authURL, optionInvitationCode, "Option invitation code should not appear when parameter is provided")
}

// TestGetAuthURLWithInvitationWithOtherOptions tests that invitation code works
// correctly when combined with other options like PKCE, audience, etc.
func TestGetAuthURLWithInvitationWithOtherOptions(t *testing.T) {
	assert := assert.New(t)

	testBackendServerURL := "https://api.com"
	testKindeServerURL := "https://mytest.kinde.com"

	callbackURL := fmt.Sprintf("%v/callback", testBackendServerURL)
	invitationCode := "inv_combined_test"
	kindeAuthFlow, _ := NewAuthorizationCodeFlow(
		testKindeServerURL, "b9da18c441b44d81bab3e8232de2e18d", "client_secret", callbackURL,
		WithSessionHooks(newTestSessionHooks()),
		WithCustomStateGenerator(func(*AuthorizationCodeFlow) string { return "test_state" }),
		WithInvitationCode(invitationCode),
		WithAudience("http://my.api.com/api"),
		WithPKCE(),
	)

	authURL := kindeAuthFlow.GetAuthURLWithInvitation(invitationCode)
	assert.Contains(authURL, fmt.Sprintf("invitation_code=%s", invitationCode), "Should contain invitation_code")
	assert.Contains(authURL, "is_invitation=true", "Should contain is_invitation")
	assert.Contains(authURL, "audience=http%3A%2F%2Fmy.api.com%2Fapi", "Should contain audience parameter")
	assert.Contains(authURL, "code_challenge=", "Should contain PKCE code_challenge")
	assert.Contains(authURL, "code_challenge_method=S256", "Should contain PKCE method")
}

// TestGetAuthURLWithInvitationSpecialCharacters tests URL encoding of invitation codes
// with special characters
func TestGetAuthURLWithInvitationSpecialCharacters(t *testing.T) {
	assert := assert.New(t)

	testBackendServerURL := "https://api.com"
	testKindeServerURL := "https://mytest.kinde.com"

	callbackURL := fmt.Sprintf("%v/callback", testBackendServerURL)
	kindeAuthFlow, _ := NewAuthorizationCodeFlow(
		testKindeServerURL, "b9da18c441b44d81bab3e8232de2e18d", "client_secret", callbackURL,
		WithSessionHooks(newTestSessionHooks()),
		WithCustomStateGenerator(func(*AuthorizationCodeFlow) string { return "test_state" }),
	)

	testCases := []struct {
		name           string
		invitationCode string
		expectedInURL  string
	}{
		{
			name:           "invitation code with spaces",
			invitationCode: "inv code with spaces",
			expectedInURL:  "invitation_code=inv+code+with+spaces",
		},
		{
			name:           "invitation code with special chars",
			invitationCode: "inv_123-456@789",
			expectedInURL:  "invitation_code=inv_123-456%40789",
		},
		{
			name:           "invitation code with unicode",
			invitationCode: "inv_测试_123",
			expectedInURL:  "invitation_code=inv_%E6%B5%8B%E8%AF%95_123",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			authURL := kindeAuthFlow.GetAuthURLWithInvitation(tc.invitationCode)
			assert.Contains(authURL, tc.expectedInURL, "URL should contain properly encoded invitation code")
			assert.Contains(authURL, "is_invitation=true", "Should contain is_invitation parameter")
		})
	}
}

// TestGetAuthURLWithInvitationMultipleCalls tests that multiple calls with different
// invitation codes work correctly
func TestGetAuthURLWithInvitationMultipleCalls(t *testing.T) {
	assert := assert.New(t)

	testBackendServerURL := "https://api.com"
	testKindeServerURL := "https://mytest.kinde.com"

	callbackURL := fmt.Sprintf("%v/callback", testBackendServerURL)
	kindeAuthFlow, _ := NewAuthorizationCodeFlow(
		testKindeServerURL, "b9da18c441b44d81bab3e8232de2e18d", "client_secret", callbackURL,
		WithSessionHooks(newTestSessionHooks()),
		WithCustomStateGenerator(func(*AuthorizationCodeFlow) string { return "test_state" }),
	)

	// First call with invitation code
	invitationCode1 := "inv_first"
	authURL1 := kindeAuthFlow.GetAuthURLWithInvitation(invitationCode1)
	assert.Contains(authURL1, fmt.Sprintf("invitation_code=%s", invitationCode1), "First URL should contain first invitation code")
	assert.Contains(authURL1, "is_invitation=true", "First URL should contain is_invitation")

	// Second call with different invitation code
	invitationCode2 := "inv_second"
	authURL2 := kindeAuthFlow.GetAuthURLWithInvitation(invitationCode2)
	assert.Contains(authURL2, fmt.Sprintf("invitation_code=%s", invitationCode2), "Second URL should contain second invitation code")
	assert.Contains(authURL2, "is_invitation=true", "Second URL should contain is_invitation")
	assert.NotContains(authURL2, invitationCode1, "Second URL should not contain first invitation code")

	// Third call without invitation code
	authURL3 := kindeAuthFlow.GetAuthURLWithInvitation("")
	assert.NotContains(authURL3, "invitation_code", "Third URL should not contain invitation_code")
	assert.NotContains(authURL3, "is_invitation", "Third URL should not contain is_invitation")
}

// TestGetAuthURLWithInvitationOptionAndEmptyParameter tests that when option is set
// but empty parameter is passed, the option values are still used (since empty parameter
// doesn't override the option values in authURLOptions)
func TestGetAuthURLWithInvitationOptionAndEmptyParameter(t *testing.T) {
	assert := assert.New(t)

	testBackendServerURL := "https://api.com"
	testKindeServerURL := "https://mytest.kinde.com"

	callbackURL := fmt.Sprintf("%v/callback", testBackendServerURL)
	optionInvitationCode := "inv_from_option"
	kindeAuthFlow, _ := NewAuthorizationCodeFlow(
		testKindeServerURL, "b9da18c441b44d81bab3e8232de2e18d", "client_secret", callbackURL,
		WithSessionHooks(newTestSessionHooks()),
		WithCustomStateGenerator(func(*AuthorizationCodeFlow) string { return "test_state" }),
		WithInvitationCode(optionInvitationCode),
	)

	// When empty parameter is passed, it doesn't override option values
	// The option values are already in authURLOptions and will be included
	authURL := kindeAuthFlow.GetAuthURLWithInvitation("")
	assert.Contains(authURL, fmt.Sprintf("invitation_code=%s", optionInvitationCode), "Should use invitation code from option when parameter is empty")
	assert.Contains(authURL, "is_invitation=true", "Should contain is_invitation from option")
}

// TestGetAuthURLWithInvitationWhitespaceOnly tests that whitespace-only invitation codes
// are treated as empty
func TestGetAuthURLWithInvitationWhitespaceOnly(t *testing.T) {
	assert := assert.New(t)

	testBackendServerURL := "https://api.com"
	testKindeServerURL := "https://mytest.kinde.com"

	callbackURL := fmt.Sprintf("%v/callback", testBackendServerURL)
	kindeAuthFlow, _ := NewAuthorizationCodeFlow(
		testKindeServerURL, "b9da18c441b44d81bab3e8232de2e18d", "client_secret", callbackURL,
		WithSessionHooks(newTestSessionHooks()),
		WithCustomStateGenerator(func(*AuthorizationCodeFlow) string { return "test_state" }),
	)

	testCases := []string{" ", "  ", "\t", "\n", "   \t\n   "}

	for _, whitespaceCode := range testCases {
		t.Run(fmt.Sprintf("whitespace_%q", whitespaceCode), func(t *testing.T) {
			authURL := kindeAuthFlow.GetAuthURLWithInvitation(whitespaceCode)
			// Whitespace-only codes should be trimmed and treated as empty
			assert.NotContains(authURL, "invitation_code=", "AuthURL should not contain invitation_code parameter for whitespace-only codes")
			assert.NotContains(authURL, "is_invitation=", "AuthURL should not contain is_invitation parameter for whitespace-only codes")
		})
	}
}

// TestGetAuthURLIncludesInvitationCodeFromOption tests that GetAuthURL() includes
// invitation code when set via option
func TestGetAuthURLIncludesInvitationCodeFromOption(t *testing.T) {
	assert := assert.New(t)

	testBackendServerURL := "https://api.com"
	testKindeServerURL := "https://mytest.kinde.com"

	callbackURL := fmt.Sprintf("%v/callback", testBackendServerURL)
	invitationCode := "inv_via_option"
	kindeAuthFlow, _ := NewAuthorizationCodeFlow(
		testKindeServerURL, "b9da18c441b44d81bab3e8232de2e18d", "client_secret", callbackURL,
		WithSessionHooks(newTestSessionHooks()),
		WithCustomStateGenerator(func(*AuthorizationCodeFlow) string { return "test_state" }),
		WithInvitationCode(invitationCode),
	)

	// GetAuthURL() should include invitation code from option
	authURL := kindeAuthFlow.GetAuthURL()
	assert.Contains(authURL, fmt.Sprintf("invitation_code=%s", invitationCode), "GetAuthURL should include invitation code from option")
	assert.Contains(authURL, "is_invitation=true", "GetAuthURL should include is_invitation from option")
}

func getTestAuthorizationServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if strings.Contains(r.URL.Path, "/.well-known/jwks") {
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			w.Write(testJWKSPublicKeys())
			return
		}

		if strings.Contains(r.URL.Path, "/oauth2/auth") {
			callbackURL := r.URL.Query().Get("redirect_uri")
			http.Redirect(w, r, fmt.Sprintf("%v?code=authorization_code&state=%v", callbackURL, r.URL.Query().Get("state")), http.StatusFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token": "%v","token_type":"bearer"}`, testJwtToken())
	}))
}

func testJwtToken() string {
	// {
	//   "aud": ["http://my.api.com/api", "https://my_kinde_tenant.kinde.com/api"],
	//   "azp": "b9da18c441b44d81bab3e8232de2e18d",
	//   "exp": 1168335720000,
	//   "iat": 1516239022,
	//   "iss": "https://testing.kinde.com",
	//   "jti": "27daa125-2fb2-4e14-9270-742cd56e764b",
	//   "org_code": "org_123456789",
	//   "permissions": [
	//     "read:users",
	//     "read:competitions"
	//   ],
	//   "scp": [
	//     "openid",
	//     "profile",
	//     "email",
	//     "offline"
	//   ],
	//   "sub": "kp_cfcb1ae5b9254ad99521214014c54f43"
	// }
	return `eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjU2ZWVkZGMwNTUwM2YyMzBlYWNmNmQxMmMxOGViNDQwIn0.eyJhdWQiOlsiaHR0cDovL215LmFwaS5jb20vYXBpIiwiaHR0cHM6Ly9teV9raW5kZV90ZW5hbnQua2luZGUuY29tL2FwaSJdLCJhenAiOiJiOWRhMThjNDQxYjQ0ZDgxYmFiM2U4MjMyZGUyZTE4ZCIsImV4cCI6MTE2ODMzNTcyMDAwMCwiaWF0IjoxNTE2MjM5MDIyLCJpc3MiOiJodHRwczovL3Rlc3Rpbmcua2luZGUuY29tIiwianRpIjoiMjdkYWExMjUtMmZiMi00ZTE0LTkyNzAtNzQyY2Q1NmU3NjRiIiwib3JnX2NvZGUiOiJvcmdfMTIzNDU2Nzg5IiwicGVybWlzc2lvbnMiOlsicmVhZDp1c2VycyIsInJlYWQ6Y29tcGV0aXRpb25zIl0sInNjcCI6WyJvcGVuaWQiLCJwcm9maWxlIiwiZW1haWwiLCJvZmZsaW5lIl0sInN1YiI6ImtwX2NmY2IxYWU1YjkyNTRhZDk5NTIxMjE0MDE0YzU0ZjQzIn0.nozeVFfLZxK2vvlFvmPZl5sce0D1IkNsPYuDxx5dCEuQ-gM36TI1pqVVL57UEH-IRNGqhwxG3mBXVcucz_hZF3HvOVe8CkWhBoFmlB_wLqYBsUS2Mzt4vQJd4Ob5MszsHwLDYtPo643ber1lfI8KccEouPZDT1XHNExUkvhiD7jU-f3QZQRFjmxEaGOYlPScNxnGMZMgBgasIxfHnQHSdoyASh1puXauNFFQnqEwlMk77L-UXV6sd5hYFNcapiOazB6yhRfq6xivupOSJXtfY96NTgRBvgyWRN32Ba_aF1NIik0NMxmrXUzLAsUKsYUfyDgiV-zzvsd5WPEmmNwRqg`
}

func testJWKSPublicKeys() []byte {
	key := `{"keys":
  [
    {
      "alg": "RS256",
      "e": "AQAB",
      "key_ops": [
        "verify"
      ],
      "kty": "RSA",
      "n": "uOaDKcdR8JR7PiVEHjRO1dQVbLFoMRSiBio-rRlq-ljouBFJtehghnkIk0sSJlmoJY8329RdF9122IL0NYxO-QTFJmAamSdUcmSgg4D3qI3Nc82H7L7ocad2OfhhXmBwz-O_8cxK-xYAnvKGmHf_tSmqVWJVbvBFG1r7sU3WBfLZPoivofFKjnhPG5jFbC2AziTFqKiQ7i2T2F0APIPTJ5Bf05zI2BpIYwyZyaP1F5EWmBEOvOP02Mr0L3Rj0lOJGQJ8gJh9uacGCt_RZAlx0ZMiK93fk3vfszfKv0UhOpYKBcElR_5U1gJfXuDF6j10vG-8rwoorIPzCwu3wKZPew",
      "use": "sig",
      "kid": "56eeddc05503f230eacf6d12c18eb440"
    }
  ]}`

	return []byte(key)
}

// func testPublicPEM() *rsa.PublicKey {
// 	publicKey := `-----BEGIN PUBLIC KEY-----
// MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuOaDKcdR8JR7PiVEHjRO
// 1dQVbLFoMRSiBio+rRlq+ljouBFJtehghnkIk0sSJlmoJY8329RdF9122IL0NYxO
// +QTFJmAamSdUcmSgg4D3qI3Nc82H7L7ocad2OfhhXmBwz+O/8cxK+xYAnvKGmHf/
// tSmqVWJVbvBFG1r7sU3WBfLZPoivofFKjnhPG5jFbC2AziTFqKiQ7i2T2F0APIPT
// J5Bf05zI2BpIYwyZyaP1F5EWmBEOvOP02Mr0L3Rj0lOJGQJ8gJh9uacGCt/RZAlx
// 0ZMiK93fk3vfszfKv0UhOpYKBcElR/5U1gJfXuDF6j10vG+8rwoorIPzCwu3wKZP
// ewIDAQAB
// -----END PUBLIC KEY-----`
// 	block, _ := pem.Decode([]byte(publicKey))
// 	pemKey, _ := x509.ParsePKIXPublicKey(block.Bytes)
// 	return pemKey.(*rsa.PublicKey)
// }

// func testJWKSPrivateKey() string {
// 	return `{
//     "alg": "RS256",
//     "d": "R-dsrnySwuobG0nGubBB0CnPwxsil6OcdqVLBmnSDlUw-xPOBG2_y8uZqB4TitJm72RIprZpFXTMWNpkOca8l15hhNDuxwxibLHxMfKfXO74LMaKy2haYIhtE5Ih21_Jvy6kYFW_-vDNgQJzkStpR3xSfy3kZ2YMmdzB8GuChYEH_nRvG5xd7O9rf_C-6-M81U4160c9krP4SQoZv5hZ6APm9SmCk5KIHTAEmv5kVx9uiHC7IWiQWDj44I24UZ82IfJwK4LC6-bKszwBWgdTgB-1ngZ5mWoIyuQJskw7d88J4YJr87wNv2y0oLjPRnnPcWdfqjTEkf9s7r5b4Q-H4Q",
//     "dp": "YbZw8_lD4JI2p-n6BgdiDyKAaMKssayhgBME7_Y8GCG-wtYxq-vA4csyYkksvRosPvLcSea-TMefUkGbFEst3JCAlm3H0UtRtyFqIflw6ObyT_gO-xX_M92sYwPbdd9Sza9kwNSkzcol6OVVLMlM1atG0erW_qlm2dwl6ri35As",
//     "dq": "vXO-K5h75qEjuKFZZah1QCTeprgsK6AYDY4ylLLXeSoXtUeeTJR8IiijiJO3v-neEdlLgazzn1aLCRVT20iDekENKTQ9OU8JlW9oI464pqMROH0oivrvDkO9bDxLPSl6QiAY1FtLvTXssoQR4RjdZJqH2zuDi--nETsco8gOzik",
//     "e": "AQAB",
//     "key_ops": [
//       "sign"
//     ],
//     "kty": "RSA",
//     "n": "uOaDKcdR8JR7PiVEHjRO1dQVbLFoMRSiBio-rRlq-ljouBFJtehghnkIk0sSJlmoJY8329RdF9122IL0NYxO-QTFJmAamSdUcmSgg4D3qI3Nc82H7L7ocad2OfhhXmBwz-O_8cxK-xYAnvKGmHf_tSmqVWJVbvBFG1r7sU3WBfLZPoivofFKjnhPG5jFbC2AziTFqKiQ7i2T2F0APIPTJ5Bf05zI2BpIYwyZyaP1F5EWmBEOvOP02Mr0L3Rj0lOJGQJ8gJh9uacGCt_RZAlx0ZMiK93fk3vfszfKv0UhOpYKBcElR_5U1gJfXuDF6j10vG-8rwoorIPzCwu3wKZPew",
//     "p": "2wfOtQqjJBEeudxqOmo_FTz_z0X_6l3f-gPy9kzBfnHEIaGqwJeyS4e6j2cBkdtt2qyKJEtEwcUtif6O5cKslD4kksWSu_MIS7_hxNKx_txG_AByNMW7LSmaI23UviuX6stsg_K0hKCMQ2E4A2tES_fg8a5Qci6c4lEqmw6r9SM",
//     "q": "2Bv2iGwT-dZ5Lem9JkCmJrHhNV74hI2D6bH_QWLzeYfLfWfrzp_HowT8FHCgbPFoOYfZupbe7P8mjfR7QCbrpRFskS095xNIx2k9cg8x_Kgpb-aNj9hDYJVW-RQv3KjfctCJVIy3EKQW56S6lEHZqOgB6jngKAJ5FhaZbTg4vck",
//     "qi": "LlP6px0kjGp8nnqucE_qlKn-KrfT9PUEw_LJURL30iSZIaxrWxThpaKV6jaGGKy6CpTYZ-gePrw4oq7IZ9gqSAFBmHWfhCRqvhZDlensKLtQ-4d-dNlE6Xe3yuuENT1wKQMXYbCQS71hHFiTahJW-27picZfQdIF7jY96BjebL4",
//     "use": "sig",
//     "kid": "56eeddc05503f230eacf6d12c18eb440"
//   }`
// }

type testSessionHooks struct {
	sessionState map[string]string
}

// GetRawToken implements ISessionHooks.
func (t *testSessionHooks) GetRawToken() (*oauth2.Token, error) {
	tokenData, ok := t.sessionState["token"]
	if !ok {
		return nil, fmt.Errorf("no token found in session state")
	}
	var token oauth2.Token
	if err := json.Unmarshal([]byte(tokenData), &token); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}
	return &token, nil
}

// SetRawToken implements ISessionHooks.
func (t *testSessionHooks) SetRawToken(token *oauth2.Token) error {
	tData, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}
	t.sessionState["token"] = string(tData)
	return nil
}

// GetCodeVerifier implements ISessionHooks.
func (t *testSessionHooks) GetCodeVerifier() (string, error) {
	return t.sessionState["code_verifier"], nil
}

// SetCodeVerifier implements ISessionHooks.
func (t *testSessionHooks) SetCodeVerifier(codeVerifier string) error {
	t.sessionState["code_verifier"] = codeVerifier
	return nil
}

func newTestSessionHooks() *testSessionHooks {
	return &testSessionHooks{
		sessionState: make(map[string]string),
	}
}

// GetPostAuthRedirect implements SessionHooks.
func (t *testSessionHooks) GetPostAuthRedirect() (string, error) {
	return t.sessionState["post_auth_redirect"], nil
}

// SetPostAuthRedirect implements SessionHooks.
func (t *testSessionHooks) SetPostAuthRedirect(redirect string) error {
	t.sessionState["post_auth_redirect"] = redirect
	return nil
}

// GetState implements SessionHooks.
func (t *testSessionHooks) GetState() (string, error) {
	return t.sessionState["state"], nil
}

// SetState implements SessionHooks.
func (t *testSessionHooks) SetState(state string) error {
	t.sessionState["state"] = state
	return nil
}

func TestSwitchOrg(t *testing.T) {
	assert := assert.New(t)

	callbackURL := "https://api.com/callback"
	kindeAuthFlow, _ := NewAuthorizationCodeFlow(
		"https://mytest.kinde.com", "b9da18c441b44d81bab3e8232de2e18d", "client_secret", callbackURL,
		WithSessionHooks(newTestSessionHooks()),
		WithCustomStateGenerator(func(*AuthorizationCodeFlow) string { return "test_state" }),
	)

	switchURL, err := kindeAuthFlow.SwitchOrg("  org_1234  ")
	assert.Nil(err, "SwitchOrg should not fail for a valid org code")
	assert.Contains(switchURL, "org_code=org_1234", "URL should contain the trimmed org_code")
	assert.Contains(switchURL, "prompt=login", "URL should force re-authentication")
	assert.Contains(switchURL, "state=test_state", "URL should contain the state parameter")
	assert.Contains(switchURL, "https://mytest.kinde.com/oauth2/auth?", "URL should point at the auth endpoint")
}

func TestSwitchOrgEmptyOrgCode(t *testing.T) {
	assert := assert.New(t)

	kindeAuthFlow, _ := NewAuthorizationCodeFlow(
		"https://mytest.kinde.com", "b9da18c441b44d81bab3e8232de2e18d", "client_secret", "https://api.com/callback",
		WithSessionHooks(newTestSessionHooks()),
	)

	switchURL, err := kindeAuthFlow.SwitchOrg("   ")
	assert.NotNil(err, "SwitchOrg should fail for an empty org code")
	assert.Empty(switchURL, "URL should be empty when org code is invalid")
}

func TestSwitchOrgOverridesConfiguredOrgCode(t *testing.T) {
	assert := assert.New(t)

	kindeAuthFlow, _ := NewAuthorizationCodeFlow(
		"https://mytest.kinde.com", "b9da18c441b44d81bab3e8232de2e18d", "client_secret", "https://api.com/callback",
		WithSessionHooks(newTestSessionHooks()),
		WithCustomStateGenerator(func(*AuthorizationCodeFlow) string { return "test_state" }),
		WithAuthParameter("org_code", "org_original"),
	)

	switchURL, err := kindeAuthFlow.SwitchOrg("org_new")
	assert.Nil(err, "SwitchOrg should not fail for a valid org code")
	assert.Contains(switchURL, "org_code=org_new", "URL should contain the requested org_code")
	assert.NotContains(switchURL, "org_original", "URL should not contain the previously configured org_code")
}

func TestSwitchOrgStoresFreshState(t *testing.T) {
	assert := assert.New(t)

	sessionHooks := newTestSessionHooks()
	kindeAuthFlow, _ := NewAuthorizationCodeFlow(
		"https://mytest.kinde.com", "b9da18c441b44d81bab3e8232de2e18d", "client_secret", "https://api.com/callback",
		WithSessionHooks(sessionHooks),
	)

	switchURL, err := kindeAuthFlow.SwitchOrg("org_1234")
	assert.Nil(err, "SwitchOrg should not fail for a valid org code")

	state, err := sessionHooks.GetState()
	assert.Nil(err, "state should be readable from the session")
	assert.NotEmpty(state, "state should be stored in the session")
	assert.Contains(switchURL, fmt.Sprintf("state=%v", state), "URL state should match the stored state")
}
