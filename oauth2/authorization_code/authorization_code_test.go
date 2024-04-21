package authorization_code

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAutorizationCodeFlowOnline(t *testing.T) {

  callCount := 0
	authorizationServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++

		assert.LessOrEqual(t, callCount, 2, "token should only be called once")

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"sample_access_token","token_type":"bearer"}`))
	}))
	defer authorizationServer.Close()

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headerAuth := r.Header.Get("Authorization")
		assert.Equal(t, headerAuth, "Bearer sample_access_token", "incorrect authorization header")
		w.Write([]byte(`hello world`))
	}))
	defer testServer.Close()

	kindeClient, err := NewAuthorizationclientFlow(authorizationServer.URL, "client_id", "client_secret", WithAudience("test"), WithAudience("test2"))
	assert.Nil(t, err, "could not create kinde client")
	assert.Equal(t, kindeClient.config.ClientID, "client_id")
	assert.Equal(t, kindeClient.config.ClientSecret, "client_secret")
	authURL := kindeClient.GetAuthURL("testState")
	assert.NotNil(t, authURL, "AuthURL cannot be null")

  token, err := kindeClient.Exchange(context.Background(), "code")
	assert.Nil(t, err, "could not exchange token")

  client := kindeClient.GetClient(context.Background(), token)
	assert.NotNil(t, client, "client cannot be null")
	response, err := client.Get(fmt.Sprintf("%v/test_call", testServer.URL))
	assert.Nil(t, err, "could not make request")

  testClientResponse, _ := io.ReadAll(response.Body)
	assert.Equal(t, `hello world`, string(testClientResponse), "incorrect test server response")
	assert.Equal(t, `hello world`, string(testClientResponse), "incorrect test server response") //second call to test token caching

}
