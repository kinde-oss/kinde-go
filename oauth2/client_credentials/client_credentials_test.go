package client_credentials

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

func TestClientCredentials(t *testing.T) {
	callCount := 0
	authorizationServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if strings.Contains(r.URL.Path, "/.well-known/jwks") {
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			w.Write(testJWKSPublicKeys())
			return
		}

		callCount++

		assert.LessOrEqual(t, callCount, 2, "token should only be called once")

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(fmt.Sprintf(`{"access_token": "%v","token_type":"bearer"}`, testclientCredentialsToken())))
	}))
	defer authorizationServer.Close()

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headerAuth := r.Header.Get("Authorization")
		assert.Equal(t, headerAuth, "Bearer "+testclientCredentialsToken(), "incorrect authorization header")
		w.Write([]byte(`hello world`))
	}))
	defer testServer.Close()

	kindeClient, err := NewClientCredentialsFlow(authorizationServer.URL, "b9da18c441b44d81bab3e8232de2e18d", "client_secret",
		WithAudience("http://my.api.com/api"),
		WithKindeManagementAPI("my_kinde_tenant"),
		WithKindeManagementAPI("https://my_kinde_tenant.kinde.com"),
		WithTokenValidation(
			true,
			jwt.WillValidateAlgorythm(),
			jwt.WillValidateAudience("http://my.api.com/api"),
			jwt.WillValidateAudience("https://my_kinde_tenant.kinde.com/api"),
		),
	)

	assert.Nil(t, err, "error creating client credentials flow")
	assert.Equal(t, "b9da18c441b44d81bab3e8232de2e18d", kindeClient.config.ClientID)
	assert.Equal(t, "client_secret", kindeClient.config.ClientSecret)
	assert.Contains(t, kindeClient.config.EndpointParams["audience"], "http://my.api.com/api")
	assert.Contains(t, kindeClient.config.EndpointParams["audience"], "https://my_kinde_tenant.kinde.com/api")
	assert.Equal(t, fmt.Sprintf("%v/oauth2/token", authorizationServer.URL), kindeClient.config.TokenURL)

	client := kindeClient.GetClient(context.Background())
	assert.NotNil(t, client, "client cannot be null")
	response, err := client.Get(fmt.Sprintf("%v/test_call", testServer.URL))
	assert.Nil(t, err, "error calling test server")

	testClientResponse, _ := io.ReadAll(response.Body)
	assert.Equal(t, `hello world`, string(testClientResponse), "incorrect test server response")
	assert.Equal(t, `hello world`, string(testClientResponse), "incorrect test server response") //second call to test token caching

	token, err := kindeClient.GetToken(context.Background())
	assert.Nil(t, err, "error getting token")
	assert.Equal(t, testclientCredentialsToken(), token.GetRawToken().AccessToken, "incorrect token")
}

func testclientCredentialsToken() string {
	// {
	//   "aud": [
	//      "http://my.api.com/api", "https://my_kinde_tenant.kinde.com/api"
	//    ],
	//    "azp": "b9da18c441b44d81bab3e8232de2e18d",
	//    "exp": 1168335720000,
	//    "gty": [
	//      "client_credentials"
	//    ],
	//    "iat": 1516239022,
	//    "iss": "https://monitoringcheckireland.kinde.com",
	//    "jti": "da6eb340-8c11-4601-9b19-d71d3b337c3d",
	//    "scp": []
	//  }
	return `eyJ0eXAiOiJqd3QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjNiOTYxNWNhZGRhM2NhMTM3YmE4ODRhMWEwMTNmZTk4In0.eyJhdWQiOlsiaHR0cDovL215LmFwaS5jb20vYXBpIiwiaHR0cHM6Ly9teV9raW5kZV90ZW5hbnQua2luZGUuY29tL2FwaSJdLCJhenAiOiJiOWRhMThjNDQxYjQ0ZDgxYmFiM2U4MjMyZGUyZTE4ZCIsImV4cCI6MTE2ODMzNTcyMDAwMCwiZ3R5IjpbImNsaWVudF9jcmVkZW50aWFscyJdLCJpYXQiOjE1MTYyMzkwMjIsImlzcyI6Imh0dHBzOi8vbW9uaXRvcmluZ2NoZWNraXJlbGFuZC5raW5kZS5jb20iLCJqdGkiOiJkYTZlYjM0MC04YzExLTQ2MDEtOWIxOS1kNzFkM2IzMzdjM2QiLCJzY3AiOltdfQ.JrXRSX8aRL3MH81dLFxyuGqggVmz6IZWHGnJMMB2WBpTeEpcANvpVvE8SmoDIUHEBJSLKyGcwR_1UESgJGcP3scIcuSgcSF903IqdNlAPEh_b_qwvTj1LANI_zTqiX0NUpnEJjmjT0_ppNV8yjFOOj6XkoMlHikH5pv8VfI6f6fXuFoQ3tP1R52wY4BVLkn0xyDwyUi6PwbyL9ZkAx6rtgSuePOP0rvTl_1FQ3inZ3eHYBAivpt-8AvN7DbBQSSxUd5WoFG8AohPFbIKufGJl-SOHbeSQwfMIbugNqRE-V1kVo2upYLXy0qulB7uullp2GoWou6qKzDospo-0E-Yvw`
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
      "n": "xtfAkNnm9Ah2eoFSttWQtwI4k4K8gKNhUM8vcWK8-QyAOOwcDI-qpDQPrbgGfqLBCorUe-oPLpH0uwcjuk7QERhm5Lel0ONNgON-bWjUzyhOzeKBYSNreRkACPUM73tnZQJeeekfdV3cs2mvkLX0U21DxN0LxD1ka6LT8pVkZIiPldE-GRhd-qf9IAbmXoyMd-HJPF-qxdIz6hc5XK1WTGaUQ85Kj6SKWxg8olt73TytuTJipQMiDa2Hb9FrqiL7fa4YXcyYo0FuBPKHiZD0d1BnX-4Mv4Qz4A-cJbgGKD3qB2NOCJo-3maz-Aa2BgyfYhe43HvK-eR3mQ6wcIGJBw",
      "use": "sig",
      "kid": "3b9615cadda3ca137ba884a1a013fe98"
    }
  ]}`

	return []byte(key)

}

func testJWKSPrivateKey() string {
	return `{
    "alg": "RS256",
    "d": "JPCJ7p78f9Nep02FH0A3nTgFaKn9-OvhNVD4IFlWf_HplCmQ4GiEK_McAorQchAsSpgV91s5LM6ip2ghJAhmMPbWjqDrZg4EJPCeWRcDieSUFz2ACZq56YpSbleP6qGDSMmS4ZUEahpg2NfGbNzQofsHfvgNqow5LqHWPBeyydYc9e66YuRpZVwXdgQtUGjDV_T_5S8R0lGTgubWBfjf8HCYcKRcftKU7r2GzZKepoxtBlDGqDwfhkpeVHRhqnslwgAcO-Uad0DioJSczpuisORDVA9UVwH367jJU_Gs-3HYRFnChcro8up7rvsbj1MPNGBMynXOBb8f-J_mnHNQsQ",
    "dp": "1-URqOGAyspCmHXy36B-ws_jeb2h06-ycMg2sHQ3WwQlXclyV9xF0drg20kEonflYcVGxl7g8Ji5wVMDaLda9gvF-7Vxe8PvdapW4YQRt985SDDAWlxJq2Qcl6E1d5ieeTDP7VFVI_c0AK7W4S0C0R054FuYjdRr2VCwYlyLeJM",
    "dq": "wcfPixKrHKBgU8cSR2GrXJtLQFilMsnAu1mdpwaU5rVNRAhI4Lk3TovhCHTO8csLf9A0N3faz_t0-b4VFovWw0dd3UGOuV9rggrB1gJ6RJSAgI6nXEFbqWFKeNzWFkiK2vCbFFeOqK3QyorRU5k867PQOHb-U2xkC9lIK-hq88E",
    "e": "AQAB",
    "key_ops": [
      "sign"
    ],
    "kty": "RSA",
    "n": "xtfAkNnm9Ah2eoFSttWQtwI4k4K8gKNhUM8vcWK8-QyAOOwcDI-qpDQPrbgGfqLBCorUe-oPLpH0uwcjuk7QERhm5Lel0ONNgON-bWjUzyhOzeKBYSNreRkACPUM73tnZQJeeekfdV3cs2mvkLX0U21DxN0LxD1ka6LT8pVkZIiPldE-GRhd-qf9IAbmXoyMd-HJPF-qxdIz6hc5XK1WTGaUQ85Kj6SKWxg8olt73TytuTJipQMiDa2Hb9FrqiL7fa4YXcyYo0FuBPKHiZD0d1BnX-4Mv4Qz4A-cJbgGKD3qB2NOCJo-3maz-Aa2BgyfYhe43HvK-eR3mQ6wcIGJBw",
    "p": "5kPbaYwHTOZYoFE866Me2yk753UY7Gmp2n2GcQ68KsJ83mtyVpe7O73vfGO0eR8qqiIj2k-pvbCCsZMbbMc-HHuvn6iZJ30pY7NHFk46xJ-JYLOdeWScB-gRvzTgscWS2FBlP1GhTtAzfmBphXjKVfcjcsn0rqac7ld9IKvFel8",
    "q": "3RDeQK2kKdUitKJN2hYdcFyU2npyDvfaF26pMi2KxZ2f7iDtLnX2-sYRRhPaqympj_g_EA97axVykMBJ9TzpyU4dChYVuUNK6AkkwhiHNwB8cJPo8plUJTRi7_RfoE9utSa06ITFyQM3C2yI4zTe50xOxOOwVXbaf2ZeNZ6iwlk",
    "qi": "wR89SIJiXCfVmGKGuA7MCaosP09HRToUJdhVqzhOfavlktEJe4MMXGy8f3cs_hqPz3tNAfjK07tuH3XB6IimI9s1Yz5HyofTObaTY3E0PCgVBwQ1jeqAU9ugXD0HdqAgS6oB19af23DUGi1lHtedCV9ZVQAqqwURyK8xbae2ezc",
    "use": "sig",
    "kid": "3b9615cadda3ca137ba884a1a013fe98"
  }`
}
