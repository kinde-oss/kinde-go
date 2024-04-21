package client_credentials

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientCredentials(t *testing.T) {
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

	kindeClient, err := NewClientCredentialsFlow(authorizationServer.URL, "client_id", "client_secret", WithAudience("test"), WithKindeManagementAPI("test2"))
	assert.Nil(t, err, "error creating client credentials flow")
	assert.Equal(t, "client_id", kindeClient.config.ClientID)
	assert.Equal(t, "client_secret", kindeClient.config.ClientSecret)
	assert.Equal(t, fmt.Sprintf("%v/oauth2/token", authorizationServer.URL), kindeClient.config.TokenURL)
	client := kindeClient.GetClient(context.Background())
	assert.NotNil(t, client, "client cannot be null")
	response, err := client.Get(fmt.Sprintf("%v/test_call", testServer.URL))
	assert.Nil(t, err, "unexpected error")
	testClientResponse, _ := io.ReadAll(response.Body)
	assert.Equal(t, `hello world`, string(testClientResponse), "incorrect test server response")
	assert.Equal(t, `hello world`, string(testClientResponse), "incorrect test server response") //second call to test token caching

	token, err := kindeClient.GetToken(context.Background())
	assert.Nil(t, err, "error getting token")
	assert.Equal(t, "sample_access_token", token.GetRawToken().AccessToken, "incorrect token")
}
