package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTokenNeedsKeyFuncToWork(t *testing.T) {
	parsedToken, err := ParseFromString(testJwtToken())
	assert.NotNil(t, err, "expecting error validating a token")
	assert.False(t, parsedToken.IsValid(), "token should be not valid")
}

func TestTokenParsedAndValidated(t *testing.T) {
	parsedToken, err := ParseFromString(testJwtToken(),
		WillValidateWithKeys(func(rawToken string) (*rsa.PublicKey, error) { return testPublicPEM(), nil }),
		WillValidateAlgorythm(),
		WillValidateAudience("http://my.api.com/api"),
	)
	assert.Nil(t, err, "unexpected error")
	assert.True(t, parsedToken.IsValid(), "token should be valid")
}

func TestTokenWithInvalidAudience(t *testing.T) {
	parsedToken, err := ParseFromString(testJwtToken(),
		WillValidateWithKeys(func(rawToken string) (*rsa.PublicKey, error) { return testPublicPEM(), nil }),
		WillValidateAlgorythm(),
		WillValidateAudience("incorrect audience"),
	)
	assert.NotNil(t, err, "expecting error validating a token")
	assert.False(t, parsedToken.IsValid(), "token should be not valid")
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
