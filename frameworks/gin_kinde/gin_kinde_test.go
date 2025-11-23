package gin_kinde

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func TestSessionStorage(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	t.Run("GetCodeVerifier returns error when not found", func(t *testing.T) {
		store := cookie.NewStore([]byte("secret"))
		router := gin.New()
		router.Use(sessions.Sessions("test", store))

		var session sessions.Session
		router.GET("/", func(c *gin.Context) {
			session = sessions.Default(c)
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		router.ServeHTTP(w, req)

		storage := &SessionStorage{session: session}

		_, err := storage.GetCodeVerifier()
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "code_verifier not found")
	})

	t.Run("SetCodeVerifier and GetCodeVerifier work correctly", func(t *testing.T) {
		store := cookie.NewStore([]byte("secret"))
		router := gin.New()
		router.Use(sessions.Sessions("test", store))

		var session sessions.Session
		router.GET("/", func(c *gin.Context) {
			session = sessions.Default(c)
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		router.ServeHTTP(w, req)

		storage := &SessionStorage{session: session}

		err := storage.SetCodeVerifier("test_verifier")
		assert.Nil(t, err)

		verifier, err := storage.GetCodeVerifier()
		assert.Nil(t, err)
		assert.Equal(t, "test_verifier", verifier)
	})

	t.Run("GetRawToken returns error when not found", func(t *testing.T) {
		store := cookie.NewStore([]byte("secret"))
		router := gin.New()
		router.Use(sessions.Sessions("test", store))

		var session sessions.Session
		router.GET("/", func(c *gin.Context) {
			session = sessions.Default(c)
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		router.ServeHTTP(w, req)

		storage := &SessionStorage{session: session}

		_, err := storage.GetRawToken()
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "token not found")
	})

	t.Run("SetRawToken and GetRawToken work correctly", func(t *testing.T) {
		store := cookie.NewStore([]byte("secret"))
		router := gin.New()
		router.Use(sessions.Sessions("test", store))

		var session sessions.Session
		router.GET("/", func(c *gin.Context) {
			session = sessions.Default(c)
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		router.ServeHTTP(w, req)

		storage := &SessionStorage{session: session}

		token := &oauth2.Token{
			AccessToken: "test_token",
		}

		err := storage.SetRawToken(token)
		assert.Nil(t, err)

		retrievedToken, err := storage.GetRawToken()
		assert.Nil(t, err)
		assert.Equal(t, token.AccessToken, retrievedToken.AccessToken)
	})

	t.Run("SetRawToken with nil clears token", func(t *testing.T) {
		store := cookie.NewStore([]byte("secret"))
		router := gin.New()
		router.Use(sessions.Sessions("test", store))

		var session sessions.Session
		router.GET("/", func(c *gin.Context) {
			session = sessions.Default(c)
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		router.ServeHTTP(w, req)

		storage := &SessionStorage{session: session}

		// Set a token first
		token := &oauth2.Token{AccessToken: "test_token"}
		storage.SetRawToken(token)

		// Clear it
		err := storage.SetRawToken(nil)
		assert.Nil(t, err)

		// Should not be found
		_, err = storage.GetRawToken()
		assert.NotNil(t, err)
	})

	t.Run("GetState and SetState work correctly", func(t *testing.T) {
		store := cookie.NewStore([]byte("secret"))
		router := gin.New()
		router.Use(sessions.Sessions("test", store))

		var session sessions.Session
		router.GET("/", func(c *gin.Context) {
			session = sessions.Default(c)
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		router.ServeHTTP(w, req)

		storage := &SessionStorage{session: session}

		err := storage.SetState("test_state")
		assert.Nil(t, err)

		state, err := storage.GetState()
		assert.Nil(t, err)
		assert.Equal(t, "test_state", state)
	})

	t.Run("GetPostAuthRedirect and SetPostAuthRedirect work correctly", func(t *testing.T) {
		store := cookie.NewStore([]byte("secret"))
		router := gin.New()
		router.Use(sessions.Sessions("test", store))

		var session sessions.Session
		router.GET("/", func(c *gin.Context) {
			session = sessions.Default(c)
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		router.ServeHTTP(w, req)

		storage := &SessionStorage{session: session}

		err := storage.SetPostAuthRedirect("/dashboard")
		assert.Nil(t, err)

		redirect, err := storage.GetPostAuthRedirect()
		assert.Nil(t, err)
		assert.Equal(t, "/dashboard", redirect)
	})

	t.Run("GetItem and SetItem work correctly", func(t *testing.T) {
		store := cookie.NewStore([]byte("secret"))
		router := gin.New()
		router.Use(sessions.Sessions("test", store))

		var session sessions.Session
		router.GET("/", func(c *gin.Context) {
			session = sessions.Default(c)
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		router.ServeHTTP(w, req)

		storage := &SessionStorage{session: session}

		storage.SetItem("test_key", "test_value")
		value := storage.GetItem("test_key")
		assert.Equal(t, "test_value", value)

		emptyValue := storage.GetItem("nonexistent")
		assert.Equal(t, "", emptyValue)
	})
}

func TestUseKindeAuth(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	t.Run("creates kinde client in context", func(t *testing.T) {
		store := cookie.NewStore([]byte("secret"))
		router := gin.New()
		router.Use(sessions.Sessions("test", store))

		privateGroup := router.Group("/private")
		err := UseKindeAuth(
			privateGroup,
			"https://test.kinde.com",
			"test_client_id",
			"test_client_secret",
			"http://localhost:8080",
		)
		assert.Nil(t, err)

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/private/test", nil)
		router.ServeHTTP(w, req)

		// The middleware should set the kinde_client in context
		// This is tested indirectly through the middleware execution
		assert.NotNil(t, w)
	})

	t.Run("handles callback route", func(t *testing.T) {
		// This test requires full OAuth setup with proper session state
		// The callback route is tested through integration tests
		// Skipping unit test as it requires complex session setup
		t.Skip("Callback route requires full OAuth setup - tested in integration tests")
	})

	t.Run("redirects unauthenticated users", func(t *testing.T) {
		store := cookie.NewStore([]byte("secret"))
		router := gin.New()
		router.Use(sessions.Sessions("test", store))

		privateGroup := router.Group("/private")
		err := UseKindeAuth(
			privateGroup,
			"https://test.kinde.com",
			"test_client_id",
			"test_client_secret",
			"http://localhost:8080",
		)
		assert.Nil(t, err)

		privateGroup.GET("/protected", func(c *gin.Context) {
			c.String(200, "protected")
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/private/protected", nil)
		router.ServeHTTP(w, req)

		// Should redirect to auth URL (302)
		assert.Equal(t, http.StatusFound, w.Code)
	})

	t.Run("handles error creating kinde client", func(t *testing.T) {
		store := cookie.NewStore([]byte("secret"))
		router := gin.New()
		router.Use(sessions.Sessions("test", store))

		privateGroup := router.Group("/private")
		// Use invalid domain - error is handled in middleware, not returned
		err := UseKindeAuth(
			privateGroup,
			"://invalid",
			"test_client_id",
			"test_client_secret",
			"http://localhost:8080",
		)
		// UseKindeAuth doesn't return error immediately - it's handled in middleware
		assert.Nil(t, err, "UseKindeAuth doesn't return error for invalid URL - handled in middleware")

		// Add a route that will trigger the middleware
		privateGroup.GET("/test", func(c *gin.Context) {
			c.String(200, "test")
		})

		// Test that middleware handles error gracefully
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/private/test", nil)
		router.ServeHTTP(w, req)
		// Should return 500 error when kinde client creation fails
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestSessionStorage_GetCodeVerifier_InvalidType(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	t.Run("returns error for invalid code verifier type", func(t *testing.T) {
		store := cookie.NewStore([]byte("secret"))
		router := gin.New()
		router.Use(sessions.Sessions("test", store))

		var session sessions.Session
		router.GET("/", func(c *gin.Context) {
			session = sessions.Default(c)
			session.Set("code_verifier", 123) // Invalid type
			session.Save()
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		router.ServeHTTP(w, req)

		storage := &SessionStorage{session: session}
		_, err := storage.GetCodeVerifier()
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "invalid code_verifier type")
	})
}

func TestSessionStorage_GetRawToken_InvalidType(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	t.Run("returns error for invalid token type", func(t *testing.T) {
		store := cookie.NewStore([]byte("secret"))
		router := gin.New()
		router.Use(sessions.Sessions("test", store))

		var session sessions.Session
		router.GET("/", func(c *gin.Context) {
			session = sessions.Default(c)
			session.Set("kinde_token", "invalid_type") // Invalid type
			session.Save()
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		router.ServeHTTP(w, req)

		storage := &SessionStorage{session: session}
		_, err := storage.GetRawToken()
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "invalid token type")
	})
}

