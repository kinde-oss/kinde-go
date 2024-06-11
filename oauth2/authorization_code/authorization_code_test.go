package authorization_code

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kinde-oss/kinde-go/jwt"
	"github.com/kinde-oss/kinde-go/kinde"
	"github.com/stretchr/testify/assert"
)

func TestAutorizationCodeFlowOnline(t *testing.T) {

	testAuthorizationServer := getTestAuthorizationServer()
	defer testAuthorizationServer.Close()

	mux := http.NewServeMux()
	testBackendServer := httptest.NewServer(mux)
	defer testBackendServer.Close()

	callbackURL := fmt.Sprintf("%v/callback", testBackendServer.URL)
	kindeAuthFlow, _ := NewAuthorizationCodeFlow(
		testAuthorizationServer.URL, "b9da18c441b44d81bab3e8232de2e18d", "client_secret", callbackURL,
		WithSessionHooks(newTestSessionHooks()),
		WithCustomStateGenerator(func(*AuthorizationCodeFlow) string { return "test_state" }), //custom state generator for testing
		WithOffline(),                         //offline scope
		WithAudience("http://my.api.com/api"), //custom API audience
		WithTokenValidation(
			true,
			jwt.WillValidateAlgorythm(),
			jwt.WillValidateAudience("http://my.api.com/api"),
		),
	)
	apiCalled := false
	mux.Handle("/test_protected_api_call", kindeAuthFlow.ProtectAPI(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		sub := kinde.GetKindeContext(r.Context()).GetAccessToken().GetSubject()
		assert.Equal(t, "kp_cfcb1ae5b9254ad99521214014c54f43", sub)
		w.Write([]byte(fmt.Sprintf("hello %v", sub)))
		apiCalled = true
	}))

	mux.Handle("/callback", kindeAuthFlow.CallbackHandler())

	mux.Handle("/user_profile", kindeAuthFlow.ProtectPage(func(w http.ResponseWriter, r *http.Request) {
		kindecontext := kinde.GetKindeContext(r.Context())
		client := kindecontext.GetHttpClient(context.Background())
		resp, err := client.Get(fmt.Sprintf("%v/test_protected_api_call", testBackendServer.URL))
		assert.Nil(t, err, "could not make request")

		response, err := io.ReadAll(resp.Body)
		assert.Nil(t, err, "could not make request")
		assert.Equal(t, `hello kp_cfcb1ae5b9254ad99521214014c54f43`, string(response), "incorrect test server response")

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello, authenticated world"))
	}))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		panic("this is catch-all endpoint should never be called")
	})

	resp, err := http.Get(fmt.Sprintf("%v/user_profile", testBackendServer.URL))
	assert.Nil(t, err, "could not make request")
	response, err := io.ReadAll(resp.Body)
	assert.Nil(t, err, "could not read response")
	assert.Equal(t, `hello, authenticated world`, string(response), "incorrect test server response")

	assert.True(t, apiCalled, "API was not called")

}

func TestAutorizationCodeFlowClient(t *testing.T) {

	testAuthorizationServer := getTestAuthorizationServer()
	defer testAuthorizationServer.Close()

	testBackendServerURL := testAuthorizationServer.URL
	callbackURL := fmt.Sprintf("%v/callback", testBackendServerURL)
	kindeClient, err := NewAuthorizationCodeFlow(
		testBackendServerURL, "b9da18c441b44d81bab3e8232de2e18d", "client_secret", callbackURL,
		WithSessionHooks(newTestSessionHooks()),
		WithCustomStateGenerator(func(*AuthorizationCodeFlow) string { return "test_state" }), //custom state generator for testing
		WithOffline(),                         //offline scope
		WithAudience("http://my.api.com/api"), //custom API audience
		WithTokenValidation(
			true,
			jwt.WillValidateAlgorythm(),
			jwt.WillValidateAudience("http://my.api.com/api"),
			jwt.WillValidateWithTimeFunc(func() time.Time {
				return time.Unix(1168335720000-1, 0)
			}),
		),
	)

	assert.Nil(t, err, "could not create kinde client")
	assert.Equal(t, kindeClient.config.ClientID, "b9da18c441b44d81bab3e8232de2e18d")
	assert.Equal(t, kindeClient.config.ClientSecret, "client_secret")
	assert.Equal(t, kindeClient.config.RedirectURL, callbackURL)
	assert.Contains(t, kindeClient.authURLOptions["audience"], "http://my.api.com/api")

	authURL := kindeClient.GetAuthURL()
	assert.NotNil(t, authURL, "AuthURL cannot be null")
	assert.Contains(t, authURL, "test_state", "state parameter is missing")

	ctx := context.Background()

	err = kindeClient.ExchangeCode(ctx, "code")
	assert.Nil(t, err, "could not exchange token")

	kindeContext := kinde.GetKindeContext(ctx)

	client := kindeContext.GetHttpClient(ctx)
	assert.NotNil(t, client, "client cannot be null")
	// response, err := client.Get(fmt.Sprintf("%v/test_protected_api_call", testBackendServerURL))
	// assert.Nil(t, err, "could not make request")

	// testClientResponse, _ := io.ReadAll(response.Body)
	// assert.Equal(t, `hello world`, string(testClientResponse), "incorrect test server response")
	// assert.Equal(t, `hello world`, string(testClientResponse), "incorrect test server response") //second call to test token caching

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
		w.Write([]byte(fmt.Sprintf(`{"access_token": "%v","token_type":"bearer"}`, testJwtToken())))
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

func testPublicPEM() *rsa.PublicKey {
	publicKey := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuOaDKcdR8JR7PiVEHjRO
1dQVbLFoMRSiBio+rRlq+ljouBFJtehghnkIk0sSJlmoJY8329RdF9122IL0NYxO
+QTFJmAamSdUcmSgg4D3qI3Nc82H7L7ocad2OfhhXmBwz+O/8cxK+xYAnvKGmHf/
tSmqVWJVbvBFG1r7sU3WBfLZPoivofFKjnhPG5jFbC2AziTFqKiQ7i2T2F0APIPT
J5Bf05zI2BpIYwyZyaP1F5EWmBEOvOP02Mr0L3Rj0lOJGQJ8gJh9uacGCt/RZAlx
0ZMiK93fk3vfszfKv0UhOpYKBcElR/5U1gJfXuDF6j10vG+8rwoorIPzCwu3wKZP
ewIDAQAB
-----END PUBLIC KEY-----`
	block, _ := pem.Decode([]byte(publicKey))
	pemKey, _ := x509.ParsePKIXPublicKey(block.Bytes)
	return pemKey.(*rsa.PublicKey)
}

func testJWKSPrivateKey() string {
	return `{
    "alg": "RS256",
    "d": "R-dsrnySwuobG0nGubBB0CnPwxsil6OcdqVLBmnSDlUw-xPOBG2_y8uZqB4TitJm72RIprZpFXTMWNpkOca8l15hhNDuxwxibLHxMfKfXO74LMaKy2haYIhtE5Ih21_Jvy6kYFW_-vDNgQJzkStpR3xSfy3kZ2YMmdzB8GuChYEH_nRvG5xd7O9rf_C-6-M81U4160c9krP4SQoZv5hZ6APm9SmCk5KIHTAEmv5kVx9uiHC7IWiQWDj44I24UZ82IfJwK4LC6-bKszwBWgdTgB-1ngZ5mWoIyuQJskw7d88J4YJr87wNv2y0oLjPRnnPcWdfqjTEkf9s7r5b4Q-H4Q",
    "dp": "YbZw8_lD4JI2p-n6BgdiDyKAaMKssayhgBME7_Y8GCG-wtYxq-vA4csyYkksvRosPvLcSea-TMefUkGbFEst3JCAlm3H0UtRtyFqIflw6ObyT_gO-xX_M92sYwPbdd9Sza9kwNSkzcol6OVVLMlM1atG0erW_qlm2dwl6ri35As",
    "dq": "vXO-K5h75qEjuKFZZah1QCTeprgsK6AYDY4ylLLXeSoXtUeeTJR8IiijiJO3v-neEdlLgazzn1aLCRVT20iDekENKTQ9OU8JlW9oI464pqMROH0oivrvDkO9bDxLPSl6QiAY1FtLvTXssoQR4RjdZJqH2zuDi--nETsco8gOzik",
    "e": "AQAB",
    "key_ops": [
      "sign"
    ],
    "kty": "RSA",
    "n": "uOaDKcdR8JR7PiVEHjRO1dQVbLFoMRSiBio-rRlq-ljouBFJtehghnkIk0sSJlmoJY8329RdF9122IL0NYxO-QTFJmAamSdUcmSgg4D3qI3Nc82H7L7ocad2OfhhXmBwz-O_8cxK-xYAnvKGmHf_tSmqVWJVbvBFG1r7sU3WBfLZPoivofFKjnhPG5jFbC2AziTFqKiQ7i2T2F0APIPTJ5Bf05zI2BpIYwyZyaP1F5EWmBEOvOP02Mr0L3Rj0lOJGQJ8gJh9uacGCt_RZAlx0ZMiK93fk3vfszfKv0UhOpYKBcElR_5U1gJfXuDF6j10vG-8rwoorIPzCwu3wKZPew",
    "p": "2wfOtQqjJBEeudxqOmo_FTz_z0X_6l3f-gPy9kzBfnHEIaGqwJeyS4e6j2cBkdtt2qyKJEtEwcUtif6O5cKslD4kksWSu_MIS7_hxNKx_txG_AByNMW7LSmaI23UviuX6stsg_K0hKCMQ2E4A2tES_fg8a5Qci6c4lEqmw6r9SM",
    "q": "2Bv2iGwT-dZ5Lem9JkCmJrHhNV74hI2D6bH_QWLzeYfLfWfrzp_HowT8FHCgbPFoOYfZupbe7P8mjfR7QCbrpRFskS095xNIx2k9cg8x_Kgpb-aNj9hDYJVW-RQv3KjfctCJVIy3EKQW56S6lEHZqOgB6jngKAJ5FhaZbTg4vck",
    "qi": "LlP6px0kjGp8nnqucE_qlKn-KrfT9PUEw_LJURL30iSZIaxrWxThpaKV6jaGGKy6CpTYZ-gePrw4oq7IZ9gqSAFBmHWfhCRqvhZDlensKLtQ-4d-dNlE6Xe3yuuENT1wKQMXYbCQS71hHFiTahJW-27picZfQdIF7jY96BjebL4",
    "use": "sig",
    "kid": "56eeddc05503f230eacf6d12c18eb440"
  }`
}

type testSessionHooks struct {
	sessionState map[string]string
}

// GetPostAuthRedirect implements SessionHooks.
func (t *testSessionHooks) GetPostAuthRedirect() string {
	return t.sessionState["post_auth_redirect"]
}

// SetPostAuthRedirect implements SessionHooks.
func (t *testSessionHooks) SetPostAuthRedirect(redirect string) {
	t.sessionState["post_auth_redirect"] = redirect
}

func newTestSessionHooks() *testSessionHooks {
	return &testSessionHooks{
		sessionState: make(map[string]string),
	}
}

// GetState implements SessionHooks.
func (t *testSessionHooks) GetState() string {
	return t.sessionState["state"]
}

// GetToken implements SessionHooks.
func (t *testSessionHooks) GetToken() string {
	return t.sessionState["token"]
}

// SetState implements SessionHooks.
func (t *testSessionHooks) SetState(state string) {
	t.sessionState["state"] = state
}

// SetToken implements SessionHooks.
func (t *testSessionHooks) SetToken(token string) {
	t.sessionState["token"] = token
}
