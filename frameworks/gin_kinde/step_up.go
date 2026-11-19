package gin_kinde

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/kinde-oss/kinde-go/jwt"
	"github.com/kinde-oss/kinde-go/oauth2/authorization_code"
)

// ginContextKey is the request context key under which the callback route
// passes the Gin context to the callback error handler.
type ginContextKey struct{}

// WithCallbackErrorHandler sets the function called when the Kinde callback
// (/kinde/callback) fails, instead of the default response. Pass it to
// UseKindeAuth with the other options.
//
// Use it to show your own page. In particular, a step-up that the user cannot
// complete arrives as an *authorization_code.UnmetAuthenticationRequirementsError
// (check with errors.As). That answer is final: show the user why, and do not
// redirect them back to login. The user stays signed in with their current tokens.
//
// It is authorization_code.WithCallbackErrorHandler with the Gin context. A
// handler set with that option directly is called as well, with the response
// writer and request.
//
// Example:
//
//	gin_kinde.UseKindeAuth(privateGroup, kindeDomain, clientID, clientSecret, baseRedirectURL,
//	    gin_kinde.WithCallbackErrorHandler(func(ctx *gin.Context, err error) {
//	        var unmet *authorization_code.UnmetAuthenticationRequirementsError
//	        if errors.As(err, &unmet) {
//	            ctx.String(http.StatusForbidden, "Add a passkey or authenticator app to continue.")
//	            return
//	        }
//	        ctx.String(http.StatusInternalServerError, "Sign-in failed.")
//	    }),
//	)
func WithCallbackErrorHandler(handler func(ctx *gin.Context, err error)) authorization_code.Option {
	return authorization_code.WithCallbackErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
		if ctx, ok := r.Context().Value(ginContextKey{}).(*gin.Context); ok {
			handler(ctx, err)
			return
		}
		// Not the Gin callback route, so there is no Gin context to hand over
		status, ok := authorization_code.CallbackErrorStatus(err)
		if !ok {
			status = http.StatusInternalServerError
		}
		http.Error(w, err.Error(), status)
	})
}

// StepUp redirects the user to Kinde to step up their authentication (RFC 9470)
// and aborts the request. After the callback the user is returned to where
// they were. See authorization_code.AuthorizationCodeFlow.StepUp.
//
// Call it from a route protected by UseKindeAuth. When it returns an error
// nothing has been written, and the protected action must not run.
//
// Example ("require MFA in the last 5 minutes"):
//
//	requirement := jwt.AuthenticationRequirement{Acr: jwt.AcrMFA, MaxAge: new(300)}
//	if ok, _ := gin_kinde.HasAuthenticationContext(ctx, requirement); !ok {
//	    if err := gin_kinde.StepUp(ctx, requirement); err != nil {
//	        ctx.AbortWithStatus(http.StatusForbidden)
//	    }
//	    return
//	}
func StepUp(ctx *gin.Context, requirement jwt.AuthenticationRequirement, options ...authorization_code.Option) error {
	kindeClient, err := kindeClientFromContext(ctx)
	if err != nil {
		return err
	}
	if err := kindeClient.StepUp(ctx.Writer, ctx.Request, requirement, options...); err != nil {
		return err
	}
	ctx.Abort()
	return nil
}

// HasAuthenticationContext reports whether the signed-in user meets the
// requirement. See authorization_code.AuthorizationCodeFlow.HasAuthenticationContext.
func HasAuthenticationContext(ctx *gin.Context, requirement jwt.AuthenticationRequirement) (bool, error) {
	kindeClient, err := kindeClientFromContext(ctx)
	if err != nil {
		return false, err
	}
	return kindeClient.HasAuthenticationContext(ctx.Request.Context(), requirement)
}

// GetAuthenticationContext returns the acr, amr and auth_time of the signed-in
// user. See authorization_code.AuthorizationCodeFlow.GetAuthenticationContext.
func GetAuthenticationContext(ctx *gin.Context) (jwt.AuthenticationContext, error) {
	kindeClient, err := kindeClientFromContext(ctx)
	if err != nil {
		return jwt.AuthenticationContext{}, err
	}
	return kindeClient.GetAuthenticationContext(ctx.Request.Context())
}

// kindeClientFromContext returns the Kinde client that UseKindeAuth stored in the context.
func kindeClientFromContext(ctx *gin.Context) (authorization_code.IAuthorizationCodeFlow, error) {
	if client, ok := ctx.Get("kinde_client"); ok {
		if kindeClient, ok := client.(authorization_code.IAuthorizationCodeFlow); ok {
			return kindeClient, nil
		}
	}
	return nil, fmt.Errorf("kinde client not found")
}

// handleCallbackError hands a callback error to the app. A step-up error is a
// final answer from Kinde: it is never retried or turned into a login redirect.
func handleCallbackError(ctx *gin.Context, kindeClient authorization_code.IAuthorizationCodeFlow, err error) {
	// The handler set on the flow, with either WithCallbackErrorHandler
	if flow, ok := kindeClient.(interface {
		HandleCallbackError(w http.ResponseWriter, r *http.Request, err error) bool
	}); ok {
		request := ctx.Request.WithContext(context.WithValue(ctx.Request.Context(), ginContextKey{}, ctx))
		if flow.HandleCallbackError(ctx.Writer, request, err) {
			ctx.Abort()
			return
		}
	}

	if status, ok := authorization_code.CallbackErrorStatus(err); ok {
		// What Kinde reported, such as an unmet step-up or a cancelled sign-in
		_ = ctx.Error(err)
		ctx.String(status, "%s", err.Error())
		ctx.Abort()
		return
	}
	ctx.AbortWithError(500, err)
}
