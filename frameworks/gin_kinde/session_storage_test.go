package gin_kinde

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestSessionStorage_IDToken(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	newStorage := func() *SessionStorage {
		router := gin.New()
		router.Use(sessions.Sessions("test", cookie.NewStore([]byte("secret"))))
		var session sessions.Session
		router.GET("/", func(ctx *gin.Context) { session = sessions.Default(ctx) })
		router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		return &SessionStorage{session: session}
	}
	tokenWithIDToken := func(idToken string) *oauth2.Token {
		return (&oauth2.Token{AccessToken: "access", RefreshToken: "refresh", Expiry: time.Now().Add(time.Hour)}).
			WithExtra(map[string]interface{}{"id_token": idToken})
	}

	t.Run("the ID token is kept with the token", func(t *testing.T) {
		storage := newStorage()

		require.NoError(t, storage.SetRawToken(tokenWithIDToken("the.id.token")))
		token, err := storage.GetRawToken()

		require.NoError(t, err)
		assert.Equal(t, "access", token.AccessToken)
		assert.Equal(t, "refresh", token.RefreshToken)
		assert.Equal(t, "the.id.token", token.Extra("id_token"))
	})

	t.Run("a token stored before ID tokens were kept still loads", func(t *testing.T) {
		storage := newStorage()
		storage.session.Set("kinde_token", `{"access_token":"access","refresh_token":"refresh"}`)

		token, err := storage.GetRawToken()

		require.NoError(t, err)
		assert.Equal(t, "access", token.AccessToken)
		assert.Nil(t, token.Extra("id_token"))
	})

}

// Not parallel: it replaces the package's report function.
func TestSessionStorage_ReportsADroppedIDToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	reported := 0
	report := idTokenDropped
	idTokenDropped = func() { reported++ }
	t.Cleanup(func() { idTokenDropped = report })

	router := gin.New()
	router.Use(sessions.Sessions("test", cookie.NewStore([]byte("secret"))))
	var session sessions.Session
	router.GET("/", func(ctx *gin.Context) { session = sessions.Default(ctx) })
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	storage := &SessionStorage{session: session}

	// A token that fits is not reported
	small := (&oauth2.Token{AccessToken: "access"}).WithExtra(map[string]interface{}{"id_token": "the.id.token"})
	require.NoError(t, storage.SetRawToken(small))
	assert.Equal(t, 0, reported)

	// An ID token too big for the cookie is left out, as before, and that is reported
	big := (&oauth2.Token{AccessToken: "access"}).WithExtra(map[string]interface{}{"id_token": strings.Repeat("x", 8000)})
	require.NoError(t, storage.SetRawToken(big))
	token, err := storage.GetRawToken()

	require.NoError(t, err)
	assert.Equal(t, "access", token.AccessToken)
	assert.Nil(t, token.Extra("id_token"))
	assert.Equal(t, 1, reported)
}
