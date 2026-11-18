package authorization_code

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

const (
	callbackErrorUnmetAuthenticationRequirements = "unmet_authentication_requirements"
	callbackErrorLoginRequired                   = "login_required"
)

type (
	// UnmetAuthenticationRequirementsError is returned from the callback when the
	// user cannot meet the requested authentication context, for example because
	// they have no passkey or no enrolled MFA factor.
	//
	// It is a final answer: asking again gives the same result. Show the user why
	// (for example "add a passkey to continue"). Do not retry and do not redirect
	// to login. The session's tokens are left as they were.
	UnmetAuthenticationRequirementsError struct {
		// ErrorDescription is the error_description sent by Kinde.
		ErrorDescription string
		// State is the state parameter of the callback. It has been validated.
		State string
	}

	// LoginRequiredError is returned from the callback when a request made with
	// prompt=none needs the user to sign in. Start an interactive login (one
	// without prompt=none) if the user should continue.
	LoginRequiredError struct {
		// ErrorDescription is the error_description sent by Kinde.
		ErrorDescription string
		// State is the state parameter of the callback. It has been validated.
		State string
	}
)

func (e *UnmetAuthenticationRequirementsError) Error() string {
	if e.ErrorDescription == "" {
		return "the extra verification could not be completed"
	}
	return "the extra verification could not be completed: " + e.ErrorDescription
}

func (e *LoginRequiredError) Error() string {
	if e.ErrorDescription == "" {
		return "sign-in is required to continue"
	}
	return "sign-in is required to continue: " + e.ErrorDescription
}

// HandleCallback processes the query of the OAuth2 callback.
//
// The state is validated first. Then:
//   - error=unmet_authentication_requirements returns an *UnmetAuthenticationRequirementsError;
//   - error=login_required returns a *LoginRequiredError;
//   - anything else is passed to ExchangeCode, which exchanges the code and replaces
//     the access, ID and refresh tokens in the session, also when the user is
//     already signed in (as after a step-up).
//
// Both errors carry the error description and state, and can be matched with
// errors.As. They leave the session's tokens untouched and are never retried.
//
// On success it returns the path StepUp stored to send the user back to, or an
// empty string when the callback does not belong to a StepUp. A post-auth
// redirect your app stored itself is never read or cleared.
//
// Example:
//
//	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
//	    returnTo, err := flow.HandleCallback(r.Context(), r.URL.Query())
//	    var unmet *UnmetAuthenticationRequirementsError
//	    if errors.As(err, &unmet) {
//	        http.Error(w, "Add a passkey or authenticator app to continue.", http.StatusForbidden)
//	        return
//	    }
//	    // handle other errors, then redirect to returnTo
//	})
func (flow *AuthorizationCodeFlow) HandleCallback(ctx context.Context, query url.Values) (string, error) {
	receivedState := query.Get("state")

	switch errorCode := query.Get("error"); errorCode {
	case callbackErrorUnmetAuthenticationRequirements, callbackErrorLoginRequired:
		if err := flow.validateState(receivedState); err != nil {
			return "", err
		}
		// The request it belonged to is over
		flow.finishStepUp(receivedState, false)
		if errorCode == callbackErrorLoginRequired {
			return "", &LoginRequiredError{ErrorDescription: query.Get("error_description"), State: receivedState}
		}
		return "", &UnmetAuthenticationRequirementsError{ErrorDescription: query.Get("error_description"), State: receivedState}
	}

	if err := flow.ExchangeCode(ctx, query.Get("code"), receivedState); err != nil {
		return "", err
	}
	return flow.finishStepUp(receivedState, true), nil
}

// HandleCallbackError passes a callback error to the function set with
// WithCallbackErrorHandler. It reports false, and does nothing, when none is set.
//
// AuthorizationCodeReceivedHandler calls it for you. It is exported for
// callback routes of framework integrations, such as gin_kinde, so that the
// handler set on the flow is honoured there too.
func (flow *AuthorizationCodeFlow) HandleCallbackError(w http.ResponseWriter, r *http.Request, err error) bool {
	if flow.callbackErrorHandler == nil {
		return false
	}
	flow.callbackErrorHandler(w, r, err)
	return true
}

// isLocalPath reports whether target is an absolute path on this site, and not
// a URL that would take the user elsewhere.
func isLocalPath(target string) bool {
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") || strings.ContainsAny(target, "\\\r\n") {
		return false
	}
	parsed, err := url.Parse(target)
	return err == nil && parsed.Scheme == "" && parsed.Host == ""
}

// stepUpCallbackErrorStatus returns the HTTP status for the default response to
// a step-up callback error, and false for any other error.
func stepUpCallbackErrorStatus(err error) (int, bool) {
	var unmet *UnmetAuthenticationRequirementsError
	if errors.As(err, &unmet) {
		return http.StatusForbidden, true
	}
	var loginRequired *LoginRequiredError
	if errors.As(err, &loginRequired) {
		return http.StatusUnauthorized, true
	}
	return 0, false
}
