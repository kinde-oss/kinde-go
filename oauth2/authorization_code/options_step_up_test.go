package authorization_code

import (
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/kinde-oss/kinde-go/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The authorization URL of a flow without step-up options, as it was before they existed.
const authURLWithoutStepUpOptions = "https://mytest.kinde.com/oauth2/auth?audience=http%3A%2F%2Fmy.api.com%2Fapi&client_id=b9da18c441b44d81bab3e8232de2e18d&redirect_uri=https%3A%2F%2Fapi.com%2Fcallback&response_type=code&scope=openid+profile+email+offline&state=test_state"

func newOptionsTestFlow(options ...Option) (IAuthorizationCodeFlow, error) {
	options = append([]Option{
		WithSessionHooks(newTestSessionHooks()),
		WithCustomStateGenerator(func(*AuthorizationCodeFlow) string { return "test_state" }),
		WithOffline(),
		WithAudience("http://my.api.com/api"),
	}, options...)
	return NewAuthorizationCodeFlow("https://mytest.kinde.com", "b9da18c441b44d81bab3e8232de2e18d", "client_secret", "https://api.com/callback", options...)
}

func reauthState(json string) string {
	return base64.StdEncoding.EncodeToString([]byte(json))
}

// queryOf returns the query parameters of a URL.
func queryOf(t *testing.T, rawURL string) url.Values {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	require.NoError(t, err)
	return parsed.Query()
}

func TestAuthURLUnchangedWithoutStepUpOptions(t *testing.T) {
	t.Parallel()

	// Unset values must leave the parameters out entirely, through every way of setting them.
	// The reauth state comes from outside the app: what is unusable in it is skipped, as before.
	testCases := []struct {
		name    string
		options []Option
	}{
		{"no options", nil},
		{"WithAcrValues without values", []Option{WithAcrValues()}},
		{"WithAuthParameter with an empty max_age", []Option{WithAuthParameter("max_age", "")}},
		{"WithReauthState with a null max_age", []Option{WithReauthState(reauthState(`{"max_age":null}`))}},
		{"WithReauthState with a text max_age", []Option{WithReauthState(reauthState(`{"max_age":"x"}`))}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			flow, err := newOptionsTestFlow(tc.options...)
			require.NoError(t, err)

			authURL := flow.GetAuthURL()
			assert.Equal(t, authURLWithoutStepUpOptions, authURL)
			assert.NotContains(t, authURL, "max_age")
			assert.NotContains(t, authURL, "acr_values")
		})
	}
}

func TestWithAcrValuesAndWithMaxAge(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		options     []Option
		expectedURL string // part of the raw URL, when the encoding matters
		acrValues   string
		maxAge      string // "-" when max_age must be absent
	}{
		{"acr mfa", []Option{WithAcrValues(jwt.AcrMFA)}, "acr_values=mfa&", "mfa", "-"},
		{"acr mfa and phr", []Option{WithAcrValues(jwt.AcrMFA, jwt.AcrPHR)}, "acr_values=mfa+phr&", "mfa phr", "-"},
		{"max age zero", []Option{WithMaxAge(0)}, "max_age=0&", "", "0"},
		{"max age", []Option{WithMaxAge(300)}, "max_age=300&", "", "300"},
		{"both", []Option{WithAcrValues(jwt.AcrPHR), WithMaxAge(0)}, "", "phr", "0"},
		{"WithAuthParameter max_age is normalized", []Option{WithAuthParameter("max_age", " 0300 ")}, "max_age=300&", "", "300"},
		{"WithReauthState snake_case", []Option{WithReauthState(reauthState(`{"acr_values":"mfa","max_age":300}`))}, "", "mfa", "300"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			flow, err := newOptionsTestFlow(tc.options...)
			require.NoError(t, err)

			authURL := flow.GetAuthURL()
			query := queryOf(t, authURL)

			assert.Contains(t, authURL, tc.expectedURL)
			assert.Equal(t, tc.acrValues, query.Get("acr_values"))
			if tc.maxAge == "-" {
				assert.False(t, query.Has("max_age"), "max_age must not be sent")
			} else {
				assert.Equal(t, []string{tc.maxAge}, query["max_age"])
			}
			if tc.acrValues == "" {
				assert.False(t, query.Has("acr_values"), "acr_values must not be sent")
			}
			assert.False(t, query.Has("prompt"), "the options must not add a prompt")
		})
	}
}

func TestInvalidAcrValuesAndMaxAgeAreRejected(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		options []Option
		message string
	}{
		{"negative WithMaxAge", []Option{WithMaxAge(-1)}, "invalid max age -1"},
		{"fractional max_age", []Option{WithAuthParameter("max_age", "1.5")}, `invalid max_age "1.5"`},
		{"text max_age", []Option{WithAuthParameter("max_age", "five")}, "invalid max_age"},
		{"two max_age values", []Option{WithAuthParameter("max_age", "1"), WithAuthParameter("max_age", "2")}, "more than one value"},
		{"unknown acr value", []Option{WithAcrValues("gold")}, `unsupported acr value "gold"`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			flow, err := newOptionsTestFlow(tc.options...)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.message)
			assert.Nil(t, flow, "no flow, so no URL can be built")
		})
	}
}
