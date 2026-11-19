package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"sync"
	"testing"
	"time"

	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestHasAuthenticationContext(t *testing.T) {
	t.Parallel()

	now := time.Unix(1716800000, 0)
	minutesAgo := func(minutes int) time.Time { return now.Add(-time.Duration(minutes) * time.Minute) }

	testCases := []struct {
		name        string
		authContext AuthenticationContext
		requirement AuthenticationRequirement
		expected    bool
	}{
		// The table every SDK must satisfy
		{"absent acr, nothing required", AuthenticationContext{}, AuthenticationRequirement{}, true},
		{"absent acr, mfa required", AuthenticationContext{}, AuthenticationRequirement{Acr: AcrMFA}, false},
		{"mfa, mfa required", AuthenticationContext{Acr: AcrMFA}, AuthenticationRequirement{Acr: AcrMFA}, true},
		{"mfa, phr required", AuthenticationContext{Acr: AcrMFA}, AuthenticationRequirement{Acr: AcrPHR}, false},
		{"phr, mfa required", AuthenticationContext{Acr: AcrPHR}, AuthenticationRequirement{Acr: AcrMFA}, true},
		{"max age set, auth_time missing", AuthenticationContext{Acr: AcrPHR}, AuthenticationRequirement{MaxAge: new(300)}, false},

		// amr is informational
		{"amr does not meet mfa", AuthenticationContext{Amr: []string{"pwd", "totp", "mfa"}}, AuthenticationRequirement{Acr: AcrMFA}, false},

		// Recency
		{"within max age", AuthenticationContext{AuthTime: minutesAgo(4)}, AuthenticationRequirement{MaxAge: new(300)}, true},
		{"older than max age", AuthenticationContext{AuthTime: minutesAgo(10)}, AuthenticationRequirement{MaxAge: new(300)}, false},
		{"auth_time far in the future is invalid", AuthenticationContext{AuthTime: now.Add(time.Hour)}, AuthenticationRequirement{MaxAge: new(300)}, false},

		// Both
		{"mfa but stale", AuthenticationContext{Acr: AcrMFA, AuthTime: minutesAgo(10)}, AuthenticationRequirement{Acr: AcrMFA, MaxAge: new(300)}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, HasAuthenticationContext(tc.authContext, tc.requirement, now))
		})
	}
}

func TestAuthenticationRequirement_Validate(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		requirement AuthenticationRequirement
		valid       bool
	}{
		{"mfa", AuthenticationRequirement{Acr: AcrMFA}, true},
		{"unknown acr", AuthenticationRequirement{Acr: "gold"}, false},
		{"negative max age", AuthenticationRequirement{MaxAge: new(-1)}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.valid {
				assert.NoError(t, tc.requirement.Validate())
			} else {
				assert.Error(t, tc.requirement.Validate())
			}
		})
	}
}

const (
	authContextTestSubject = "kp_user"
	authContextTestIssuer  = "https://testing.kinde.com"
	authContextTestClient  = "client_id"
)

var (
	authContextTestKey      = sync.OnceValue(func() *rsa.PrivateKey { return mustGenerateKey() })
	authContextTestOtherKey = sync.OnceValue(func() *rsa.PrivateKey { return mustGenerateKey() })
)

func mustGenerateKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
}

// authContextTestClaims returns the claims of a token Kinde would issue for the
// test user and client, with the given claims added or replaced (nil removes
// one). As in Kinde's tokens, the client is named in azp, and aud is the Kinde
// domain (ID token) or an API (access token).
func authContextTestClaims(claims golangjwt.MapClaims) golangjwt.MapClaims {
	all := golangjwt.MapClaims{
		"sub": authContextTestSubject,
		"iss": authContextTestIssuer,
		"azp": authContextTestClient,
		"aud": []string{authContextTestIssuer},
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	for name, value := range claims {
		if value == nil {
			delete(all, name)
		} else {
			all[name] = value
		}
	}
	return all
}

func signAuthContextTestToken(t *testing.T, key *rsa.PrivateKey, claims golangjwt.MapClaims) string {
	t.Helper()
	signed, err := golangjwt.NewWithClaims(golangjwt.SigningMethodRS256, authContextTestClaims(claims)).SignedString(key)
	require.NoError(t, err)
	return signed
}

// parseAuthContextTestToken parses the tokens as the SDK does, validating them
// with the test key. idToken may be empty.
func parseAuthContextTestToken(t *testing.T, accessToken, idToken string) (*Token, error) {
	t.Helper()
	rawToken := &oauth2.Token{AccessToken: accessToken}
	if idToken != "" {
		rawToken = rawToken.WithExtra(map[string]interface{}{"id_token": idToken})
	}
	return ParseOAuth2Token(rawToken,
		WillValidateWithPublicKey(func(string) (*rsa.PublicKey, error) { return &authContextTestKey().PublicKey, nil }),
		WillValidateAlgorithm(),
	)
}

func TestToken_GetAuthenticationContext(t *testing.T) {
	t.Parallel()

	idAuthTime := time.Unix(1716800000, 0)
	accessAuthTime := time.Unix(1716700000, 0)
	unsigned := func(claims golangjwt.MapClaims) func(*testing.T) string {
		return func(t *testing.T) string {
			token, err := golangjwt.NewWithClaims(golangjwt.SigningMethodNone, authContextTestClaims(claims)).SignedString(golangjwt.UnsafeAllowNoneSignatureType)
			require.NoError(t, err)
			return token
		}
	}
	signedWith := func(key func() *rsa.PrivateKey, claims golangjwt.MapClaims) func(*testing.T) string {
		return func(t *testing.T) string { return signAuthContextTestToken(t, key(), claims) }
	}
	signed := func(claims golangjwt.MapClaims) func(*testing.T) string {
		return signedWith(authContextTestKey, claims)
	}
	forgedContext := golangjwt.MapClaims{"acr": "phr", "amr": []string{"passkey"}, "auth_time": idAuthTime.Unix()}
	with := func(claims golangjwt.MapClaims, name string, value any) golangjwt.MapClaims {
		all := golangjwt.MapClaims{name: value}
		for n, v := range claims {
			if _, replaced := all[n]; !replaced {
				all[n] = v
			}
		}
		return all
	}

	testCases := []struct {
		name         string
		accessClaims golangjwt.MapClaims
		idToken      func(*testing.T) string // nil: no ID token
		expected     AuthenticationContext
	}{
		{
			name:         "no acr or amr",
			accessClaims: golangjwt.MapClaims{},
			idToken:      signed(golangjwt.MapClaims{"auth_time": idAuthTime.Unix()}),
			expected:     AuthenticationContext{Acr: "", Amr: []string{}, AuthTime: idAuthTime},
		},
		{
			name:         "mfa with methods",
			accessClaims: golangjwt.MapClaims{"acr": "mfa", "amr": []string{"pwd", "totp"}},
			idToken:      signed(golangjwt.MapClaims{"acr": "mfa", "amr": []string{"pwd", "totp"}, "auth_time": idAuthTime.Unix()}),
			expected:     AuthenticationContext{Acr: AcrMFA, Amr: []string{"pwd", "totp"}, AuthTime: idAuthTime},
		},
		{
			name:         "auth_time differs: the ID token wins",
			accessClaims: golangjwt.MapClaims{"auth_time": accessAuthTime.Unix()},
			idToken:      signed(golangjwt.MapClaims{"auth_time": idAuthTime.Unix()}),
			expected:     AuthenticationContext{Amr: []string{}, AuthTime: idAuthTime},
		},
		{
			name:         "no ID token: auth_time from the access token",
			accessClaims: golangjwt.MapClaims{"acr": "phr", "auth_time": accessAuthTime.Unix()},
			expected:     AuthenticationContext{Acr: AcrPHR, Amr: []string{}, AuthTime: accessAuthTime},
		},
		{
			name:         "acr and amr are only read from the access token",
			accessClaims: golangjwt.MapClaims{},
			idToken:      signed(forgedContext),
			expected:     AuthenticationContext{Amr: []string{}, AuthTime: idAuthTime},
		},

		// An ID token that cannot be tied to the verified access token is not read
		{
			name:         "unsigned ID token",
			accessClaims: golangjwt.MapClaims{"auth_time": accessAuthTime.Unix()},
			idToken:      unsigned(forgedContext),
			expected:     AuthenticationContext{Amr: []string{}, AuthTime: accessAuthTime},
		},
		{
			name:         "ID token signed with another key",
			accessClaims: golangjwt.MapClaims{},
			idToken:      signedWith(authContextTestOtherKey, forgedContext),
			expected:     AuthenticationContext{Amr: []string{}},
		},
		{
			name:         "expired ID token: when the user authenticated is still read",
			accessClaims: golangjwt.MapClaims{"auth_time": accessAuthTime.Unix()},
			idToken:      signed(with(forgedContext, "exp", time.Now().Add(-time.Hour).Unix())),
			expected:     AuthenticationContext{Amr: []string{}, AuthTime: idAuthTime},
		},
		{
			name:         "ID token of another user",
			accessClaims: golangjwt.MapClaims{},
			idToken:      signed(with(forgedContext, "sub", "kp_someone_else")),
			expected:     AuthenticationContext{Amr: []string{}},
		},
		{
			name:         "ID token of another issuer",
			accessClaims: golangjwt.MapClaims{},
			idToken:      signed(with(forgedContext, "iss", "https://other.kinde.com")),
			expected:     AuthenticationContext{Amr: []string{}},
		},
		{
			name:         "ID token issued to another client",
			accessClaims: golangjwt.MapClaims{},
			idToken:      signed(with(forgedContext, "azp", "another_client")),
			expected:     AuthenticationContext{Amr: []string{}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			idToken := ""
			if tc.idToken != nil {
				idToken = tc.idToken(t)
			}
			token, err := parseAuthContextTestToken(t, signAuthContextTestToken(t, authContextTestKey(), tc.accessClaims), idToken)
			require.NoError(t, err)

			authContext := token.GetAuthenticationContext()

			assert.Equal(t, tc.expected.Acr, authContext.Acr)
			assert.NotNil(t, authContext.Amr, "Amr is empty, never nil")
			assert.Equal(t, tc.expected.Amr, authContext.Amr)
			assert.True(t, tc.expected.AuthTime.Equal(authContext.AuthTime), "expected auth time %v, got %v", tc.expected.AuthTime, authContext.AuthTime)
		})
	}
}

func TestToken_HasAuthenticationContext(t *testing.T) {
	t.Parallel()

	steppedUp := golangjwt.MapClaims{"acr": "phr", "auth_time": time.Now().Add(-time.Minute).Unix()}
	requirement := AuthenticationRequirement{Acr: AcrPHR, MaxAge: new(300)}

	t.Run("valid token", func(t *testing.T) {
		token, err := parseAuthContextTestToken(t, signAuthContextTestToken(t, authContextTestKey(), steppedUp), "")
		require.NoError(t, err)

		assert.True(t, token.HasAuthenticationContext(requirement))
		assert.True(t, token.HasAuthenticationContext(AuthenticationRequirement{Acr: AcrMFA}))
		assert.False(t, token.HasAuthenticationContext(AuthenticationRequirement{Acr: AcrPHR, MaxAge: new(30)}))
	})

	// The parse functions return the token together with the validation error,
	// so a token that failed validation must never meet a requirement
	invalidTokens := []struct {
		name  string
		token func(t *testing.T) string
	}{
		{"signed with the wrong key", func(t *testing.T) string {
			return signAuthContextTestToken(t, authContextTestOtherKey(), steppedUp)
		}},
		{"expired", func(t *testing.T) string {
			return signAuthContextTestToken(t, authContextTestKey(), golangjwt.MapClaims{"acr": "phr", "auth_time": time.Now().Unix(), "exp": time.Now().Add(-time.Minute).Unix()})
		}},
		{"unsigned", func(t *testing.T) string {
			token, err := golangjwt.NewWithClaims(golangjwt.SigningMethodNone, authContextTestClaims(steppedUp)).SignedString(golangjwt.UnsafeAllowNoneSignatureType)
			require.NoError(t, err)
			return token
		}},
	}
	for _, tc := range invalidTokens {
		t.Run(tc.name, func(t *testing.T) {
			token, err := parseAuthContextTestToken(t, tc.token(t), "")

			require.Error(t, err)
			require.NotNil(t, token)
			assert.False(t, token.IsValid())
			assert.False(t, token.HasAuthenticationContext(requirement))
			assert.False(t, token.HasAuthenticationContext(AuthenticationRequirement{}), "not even an empty requirement")
			assert.Equal(t, AuthenticationContext{Amr: []string{}}, token.GetAuthenticationContext())
		})
	}
}
