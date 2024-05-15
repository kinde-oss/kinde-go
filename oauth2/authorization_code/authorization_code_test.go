package authorization_code

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kinde-oss/kinde-go/jwt"
	"github.com/stretchr/testify/assert"
)

func TestAutorizationCodeFlowOnline(t *testing.T) {

	callCount := 0
	testAuthorizationServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if strings.Contains(r.URL.Path, "/.well-known/jwks") {
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			w.Write(testJWKSPublicKeys())
			return
		}

		callCount++

		assert.LessOrEqual(t, callCount, 2, "token should only be called once")

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(fmt.Sprintf(`{"access_token": "%v","token_type":"bearer"}`, testJwtToken())))
	}))
	defer testAuthorizationServer.Close()

	testApiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headerAuth := r.Header.Get("Authorization")
		assert.Equal(t, headerAuth, "Bearer "+testJwtToken(), "incorrect authorization header")

		parsedToken, err := jwt.ParseFromAuthorizationHeader(r,
			jwt.WillValidateJWKSUrl(fmt.Sprintf("%v/.well-known/jwks", testAuthorizationServer.URL)),
			jwt.WillValidateAudience("http://my.api.com/api"),
			jwt.WillValidateAlgorythm(),
		)
		assert.Nil(t, err, "error parsing token")
		assert.True(t, parsedToken.IsValid(), "token is not valid")

		w.Write([]byte(`hello world`))
	}))
	defer testApiServer.Close()

	callbackURL := fmt.Sprintf("%v/callback", testApiServer.URL)
	kindeClient, err := NewAuthorizationCodeFlow(
		testAuthorizationServer.URL, "b9da18c441b44d81bab3e8232de2e18d", "client_secret", callbackURL,
		WithCustomStateGenerator(func() string { return "test_state" }), //custom state generator for testing
		WithOffline(),                                               //offline scope
		WithAudience("http://my.api.com/api"),                       //custom API audience
		WithKindeManagementAPI("my_kinde_tenant"),                   //we need kinde tenant domain to generate correct management API audience
		WithKindeManagementAPI("https://my_kinde_tenant.kinde.com"), //verifying that just domain and domain with subdomain adds correct audience
		WithTokenValidation(
			true,
			jwt.WillValidateAlgorythm(),
			jwt.WillValidateAudience("http://my.api.com/api"),
			jwt.WillValidateAudience("https://my_kinde_tenant.kinde.com/api"),
		),
	)

	assert.Nil(t, err, "could not create kinde client")
	assert.Equal(t, kindeClient.config.ClientID, "b9da18c441b44d81bab3e8232de2e18d")
	assert.Equal(t, kindeClient.config.ClientSecret, "client_secret")
	assert.Equal(t, kindeClient.config.RedirectURL, callbackURL)
	assert.Contains(t, kindeClient.authURLOptions["audience"], "http://my.api.com/api")
	assert.Contains(t, kindeClient.authURLOptions["audience"], "https://my_kinde_tenant.kinde.com/api")

	authURL := kindeClient.GetAuthURL()
	assert.NotNil(t, authURL, "AuthURL cannot be null")
	assert.Contains(t, authURL, "test_state", "state parameter is missing")

	token, err := kindeClient.ExchangeAndValidate(context.Background(), "code")
	assert.Nil(t, err, "could not exchange token")
	assert.True(t, token.IsValid(), "token is not valid")

	client := kindeClient.GetClient(context.Background(), token)
	assert.NotNil(t, client, "client cannot be null")
	response, err := client.Get(fmt.Sprintf("%v/test_call", testApiServer.URL))
	assert.Nil(t, err, "could not make request")

	testClientResponse, _ := io.ReadAll(response.Body)
	assert.Equal(t, `hello world`, string(testClientResponse), "incorrect test server response")
	assert.Equal(t, `hello world`, string(testClientResponse), "incorrect test server response") //second call to test token caching

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
