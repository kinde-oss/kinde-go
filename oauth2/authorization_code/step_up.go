package authorization_code

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kinde-oss/kinde-go/jwt"
)

const (
	authParamPrompt = "prompt"

	// stepUpMarkerPrefix tags what StepUp keeps in the session's post-auth
	// redirect, so that a value the app stored there itself is left alone.
	stepUpMarkerPrefix = "kinde-step-up:"
	// stepUpLoopWindow is how long after a step-up that did not help the same
	// step-up is refused.
	stepUpLoopWindow = time.Minute
	// stepUpCallbackAllowance is added to the max age when the tokens of a
	// step-up callback are checked: Kinde issues them for a session up to max
	// age old, and the round trip takes time.
	stepUpCallbackAllowance = 60
)

// acrAliases are values from other providers that Kinde reads as mfa. The SDK
// never sends them itself, but they can arrive through WithAuthParameter.
var acrAliases = map[string]string{
	"http://schemas.openid.net/pape/policies/2007/06/multi-factor": jwt.AcrMFA,
	"urn:okta:loa:2fa:any": jwt.AcrMFA,
}

// ErrStepUpNotSupported is returned by GetStepUpURL and StepUp when the Kinde
// environment does not advertise acr_values_supported. Kinde would ignore
// acr_values and max_age there, and no token could show the requirement was
// met. To only force a fresh sign-in on such an environment, use GetAuthURL on
// a flow created with WithPrompt("login").
var ErrStepUpNotSupported = errors.New("step-up authentication is not supported on this Kinde environment")

// ErrStepUpLoop is returned by GetStepUpURL and StepUp when the same step-up
// completed less than a minute ago and the session's tokens still do not meet
// it. Asking Kinde again would give the same tokens and send the user round in
// a loop. The usual cause is a session that does not keep the ID token (see
// ISessionHooks), so that auth_time is missing.
var ErrStepUpLoop = errors.New("step-up authentication just completed but the session still does not meet the requirement")

// IStepUpSessionHooks can be implemented by an ISessionHooks to keep the record
// of a step-up in progress under a session key of its own. Without it the
// record is kept in the post-auth redirect, replacing a value the app stored
// there. gin_kinde's SessionStorage implements it.
type IStepUpSessionHooks interface {
	// SetStepUpRecord stores the record; an empty record clears it.
	SetStepUpRecord(record string) error
	// GetStepUpRecord returns the stored record, or an empty string.
	GetStepUpRecord() (string, error)
}

// stepUpMarker is what a step-up keeps in the session (see IStepUpSessionHooks).
// While the request is pending it holds the state of the request, where to
// return the user to, and what was asked for. After a callback whose tokens
// did not meet what was asked for, it holds when that happened.
type stepUpMarker struct {
	State    string `json:"state,omitempty"`
	ReturnTo string `json:"return_to,omitempty"`
	Acr      string `json:"acr,omitempty"`
	MaxAge   *int   `json:"max_age,omitempty"`
	UnmetAt  int64  `json:"unmet_at,omitempty"`
}

// GetStepUpURL returns the URL to redirect the user to for a step-up (RFC 9470):
// an interactive login that asks Kinde for a stronger or more recent
// authentication. Kinde collects only what is missing and the user keeps their
// session. The current tokens stay in place until the callback replaces them.
//
// The requirement needs an Acr, a MaxAge, or both. Any of the usual authorization
// URL options (for example WithAuthParameter) can be added for this request only.
//
// It returns an error, and no URL, when:
//   - the requirement or an option is invalid, or neither an acr nor a max age is requested;
//   - prompt=none is set on the flow or in the options, because Kinde cannot collect a
//     factor without showing a screen;
//   - IsStepUpSupported is false (ErrStepUpNotSupported);
//   - the same step-up just completed and the session still does not meet it (ErrStepUpLoop);
//   - PKCE is enabled for this request only (create the flow with WithPKCE instead);
//   - the state or the request cannot be stored in the session;
//   - the discovery document cannot be fetched.
//
// Each call stores a new state, replacing any login in progress, so call it when
// you redirect and not to render a link. It also records the request in the
// session: under a key of its own when the session implements
// IStepUpSessionHooks, otherwise in the post-auth redirect, replacing what is
// there. That is how a step-up that keeps coming back without the tokens
// meeting it is stopped with ErrStepUpLoop.
//
// An acr the flow already asks for is kept when it is stronger than the
// requirement's: a flow created with WithAcrValues(jwt.AcrPHR) still asks for
// phr when the requirement is mfa.
//
// Example:
//
//	stepUpURL, err := flow.GetStepUpURL(ctx, jwt.AuthenticationRequirement{Acr: jwt.AcrMFA, MaxAge: new(300)})
func (flow *AuthorizationCodeFlow) GetStepUpURL(ctx context.Context, requirement jwt.AuthenticationRequirement, options ...Option) (string, error) {
	return flow.startStepUp(ctx, requirement, "", options)
}

// startStepUp builds the step-up URL and records the request in the session.
func (flow *AuthorizationCodeFlow) startStepUp(ctx context.Context, requirement jwt.AuthenticationRequirement, returnTo string, options []Option) (string, error) {
	if err := requirement.Validate(); err != nil {
		return "", err
	}

	// Apply the options to a copy, so they only affect this request
	stepUp := flow.clone()
	for _, option := range options {
		if option != nil {
			option(stepUp)
		}
	}
	// The callback is handled by the flow itself, which would not send the code
	// verifier of a PKCE challenge that only this request carries
	if stepUp.usePKCE && !flow.usePKCE {
		return "", fmt.Errorf("step-up authentication cannot enable PKCE for one request: create the flow with WithPKCE")
	}
	// The requirement never weakens what the flow already asks for: a flow that
	// always requires phr keeps asking for phr when a step-up needs mfa
	if requirement.Acr != "" && !meetsAcr(requestedAcr(stepUp.authURLOptions[authParamAcrValues]), requirement.Acr) {
		WithAcrValues(requirement.Acr)(stepUp)
	}
	if requirement.MaxAge != nil {
		WithMaxAge(*requirement.MaxAge)(stepUp)
	}
	if err := stepUp.validateAuthURLOptions(); err != nil {
		return "", err
	}

	// Check what will be sent, including parameters set on the flow itself
	if hasPromptNone(stepUp.authURLOptions[authParamPrompt]) {
		return "", fmt.Errorf("step-up authentication cannot use prompt=none: Kinde cannot collect a factor without showing a screen")
	}
	request := stepUpMarker{Acr: requestedAcr(stepUp.authURLOptions[authParamAcrValues]), ReturnTo: returnTo}
	if values := stepUp.authURLOptions[authParamMaxAge]; len(values) == 1 {
		if maxAge, err := strconv.Atoi(values[0]); err == nil {
			request.MaxAge = &maxAge
		}
	}
	if request.Acr == "" && request.MaxAge == nil {
		return "", fmt.Errorf("step-up authentication requires an acr (%q or %q), a max age, or both", jwt.AcrMFA, jwt.AcrPHR)
	}

	// Without support Kinde ignores acr_values and max_age, and its tokens can
	// never show that the requirement was met: don't send them and assume it worked
	supported, err := flow.IsStepUpSupported(ctx)
	if err != nil {
		return "", err
	}
	if !supported {
		return "", ErrStepUpNotSupported
	}

	// The same step-up just completed without the tokens meeting it: stop the loop
	if last, ok := flow.readStepUpMarker(); ok && last.UnmetAt != 0 &&
		time.Since(time.Unix(last.UnmetAt, 0)) < stepUpLoopWindow && last.sameRequirement(request) {
		return "", ErrStepUpLoop
	}

	previousState, _ := flow.sessionHooks.GetState()
	stepUpURL := stepUp.GetAuthURL()
	if parsed, err := url.Parse(stepUpURL); err == nil {
		request.State = parsed.Query().Get("state")
	}
	// The state generator does not report a failed write, and without the state
	// in the session the callback would be refused after the user authenticated
	if err := flow.sessionHooks.SetState(request.State); err != nil {
		_ = flow.sessionHooks.SetState(previousState)
		return "", fmt.Errorf("step-up authentication could not store its state in the session: %w", err)
	}
	// Without the marker the user would not come back to where they were, and
	// nothing would stop a step-up that keeps returning unmet: don't start
	if err := flow.writeStepUpMarker(request); err != nil {
		_ = flow.sessionHooks.SetState(previousState)
		return "", fmt.Errorf("step-up authentication could not be recorded in the session "+
			"(a cookie session store may be full: use a server-side store): %w", err)
	}

	return stepUpURL, nil
}

// StepUp redirects the user to Kinde for a step-up (see GetStepUpURL) and
// remembers where to bring them back to (see GetStepUpURL for where that is kept).
//
// Handle the callback with HandleCallback (or AuthorizationCodeReceivedHandler,
// or gin_kinde), not with ExchangeCode alone: that is where the return path
// and the loop check are settled.
//
// For a GET request the user returns to the URL they requested. For other
// methods the request is not replayed: they return to the page that sent it
// (a same-host Referer), so they can confirm the action again. After a
// successful callback for this request, HandleCallback returns that path.
//
// When it returns an error nothing has been written to w, and the protected
// action must not run. On success the response is a redirect: return from the
// handler without writing anything else.
//
// Example ("require MFA in the last 5 minutes"):
//
//	requirement := jwt.AuthenticationRequirement{Acr: jwt.AcrMFA, MaxAge: new(300)}
//	if ok, _ := flow.HasAuthenticationContext(r.Context(), requirement); !ok {
//	    if err := flow.StepUp(w, r, requirement); err != nil {
//	        http.Error(w, "Extra verification is not available.", http.StatusForbidden)
//	    }
//	    return
//	}
func (flow *AuthorizationCodeFlow) StepUp(w http.ResponseWriter, r *http.Request, requirement jwt.AuthenticationRequirement, options ...Option) error {
	stepUpURL, err := flow.startStepUp(r.Context(), requirement, stepUpReturnPath(r), options)
	if err != nil {
		return err
	}

	http.Redirect(w, r, stepUpURL, http.StatusFound)
	return nil
}

// GetAuthenticationContext returns how and when the user of the current session
// last authenticated: the acr, amr and auth_time claims of the session's tokens.
//
// Acr is empty for a single-factor sign-in. AuthTime is read from the ID token
// when the session has one. When IsStepUpSupported is false, AuthTime is
// returned as the zero time, because the claim can then be the time the token
// was issued and says nothing about recency.
//
// It returns an error when there is no valid session, or when the discovery
// document is needed and cannot be fetched.
func (flow *AuthorizationCodeFlow) GetAuthenticationContext(ctx context.Context) (jwt.AuthenticationContext, error) {
	return flow.authenticationContext(ctx, true)
}

// HasAuthenticationContext reports whether the current session meets the
// requirement: jwt.AcrPHR also meets jwt.AcrMFA, a session without an acr meets
// neither, and a MaxAge is only met when auth_time is known and recent enough.
//
// It returns false and an error when the requirement is invalid or there is no
// valid session. A false result is the cue to call StepUp; refreshing the
// tokens never changes it.
//
// A MaxAge of 0 is almost never met, so checking it sends the user to Kinde on
// every request. Check a short window such as 60 seconds instead.
func (flow *AuthorizationCodeFlow) HasAuthenticationContext(ctx context.Context, requirement jwt.AuthenticationRequirement) (bool, error) {
	if err := requirement.Validate(); err != nil {
		return false, err
	}
	authContext, err := flow.authenticationContext(ctx, requirement.MaxAge != nil)
	if err != nil {
		return false, err
	}
	return jwt.HasAuthenticationContext(authContext, requirement, time.Now()), nil
}

// authenticationContext reads the authentication context of the session's tokens.
// With needsAuthTime it drops an auth_time that discovery says cannot be relied on.
func (flow *AuthorizationCodeFlow) authenticationContext(ctx context.Context, needsAuthTime bool) (jwt.AuthenticationContext, error) {
	token, err := flow.GetToken(ctx)
	if err != nil {
		return jwt.AuthenticationContext{}, err
	}

	authContext := token.GetAuthenticationContext()
	if needsAuthTime && !authContext.AuthTime.IsZero() {
		supported, err := flow.IsStepUpSupported(ctx)
		if err != nil {
			return jwt.AuthenticationContext{}, err
		}
		if !supported {
			authContext.AuthTime = time.Time{}
		}
	}
	return authContext, nil
}

// clone returns a copy of the flow whose options can be changed without
// affecting the original.
func (flow *AuthorizationCodeFlow) clone() *AuthorizationCodeFlow {
	clone := *flow
	clone.authURLOptions = url.Values{}
	for name, values := range flow.authURLOptions {
		clone.authURLOptions[name] = slices.Clone(values)
	}
	clone.config.Scopes = slices.Clone(flow.config.Scopes)
	clone.tokenOptions = slices.Clone(flow.tokenOptions)
	clone.optionErrors = slices.Clone(flow.optionErrors)
	return &clone
}

// stepUpReturnPath returns the path to bring the user back to after a step-up
// started by this request, or an empty string when there is none.
func stepUpReturnPath(r *http.Request) string {
	returnPath := ""
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		returnPath = r.URL.RequestURI()
	} else if referer, err := url.Parse(r.Referer()); err == nil && referer.Host != "" && referer.Host == r.Host {
		// Never replay a non-GET request: go back to the page that sent it
		returnPath = referer.RequestURI()
	}
	if !isLocalPath(returnPath) {
		return ""
	}
	return returnPath
}

// hasPromptNone reports whether any of the prompt values contains "none".
func hasPromptNone(prompts []string) bool {
	for _, prompt := range prompts {
		if slices.Contains(strings.Fields(strings.ToLower(prompt)), "none") {
			return true
		}
	}
	return false
}

// requestedAcr returns the strongest context in acr_values that Kinde acts on,
// or an empty string. Kinde silently ignores the rest, which would skip the step-up.
func requestedAcr(acrValues []string) string {
	strongest := ""
	for _, value := range strings.Fields(strings.ToLower(strings.Join(acrValues, " "))) {
		if alias, ok := acrAliases[value]; ok {
			value = alias
		}
		if value == jwt.AcrPHR || (value == jwt.AcrMFA && strongest == "") {
			strongest = value
		}
	}
	return strongest
}

// meetsAcr reports whether the requested context is at least as strong as the required one.
func meetsAcr(requested, required string) bool {
	return requested == strings.ToLower(required) || (requested == jwt.AcrPHR && strings.EqualFold(required, jwt.AcrMFA))
}

func (marker stepUpMarker) sameRequirement(other stepUpMarker) bool {
	if marker.Acr != other.Acr || (marker.MaxAge == nil) != (other.MaxAge == nil) {
		return false
	}
	return marker.MaxAge == nil || *marker.MaxAge == *other.MaxAge
}

// readStepUpMarker returns the step-up marker in the session's post-auth
// redirect. Anything else stored there is not ours: it reports false.
func (flow *AuthorizationCodeFlow) readStepUpMarker() (stepUpMarker, bool) {
	var marker stepUpMarker
	stored, err := flow.loadStepUpRecord()
	if err != nil || !strings.HasPrefix(stored, stepUpMarkerPrefix) {
		return marker, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(stored, stepUpMarkerPrefix))
	if err != nil || json.Unmarshal(decoded, &marker) != nil {
		// Ours, but unreadable: treat it as an empty marker so it gets cleared
		return stepUpMarker{}, true
	}
	return marker, true
}

func (flow *AuthorizationCodeFlow) writeStepUpMarker(marker stepUpMarker) error {
	return flow.storeStepUpRecord(encodeStepUpMarker(marker))
}

// storeStepUpRecord keeps the step-up marker in the session; an empty record
// clears it. Sessions that implement IStepUpSessionHooks keep it under a key
// of its own. Others keep it in the post-auth redirect, which every
// ISessionHooks has.
func (flow *AuthorizationCodeFlow) storeStepUpRecord(record string) error {
	if hooks, ok := flow.sessionHooks.(IStepUpSessionHooks); ok {
		return hooks.SetStepUpRecord(record)
	}
	return flow.sessionHooks.SetPostAuthRedirect(record)
}

func (flow *AuthorizationCodeFlow) loadStepUpRecord() (string, error) {
	if hooks, ok := flow.sessionHooks.(IStepUpSessionHooks); ok {
		return hooks.GetStepUpRecord()
	}
	return flow.sessionHooks.GetPostAuthRedirect()
}

func encodeStepUpMarker(marker stepUpMarker) string {
	encoded, _ := json.Marshal(marker)
	return stepUpMarkerPrefix + base64.RawURLEncoding.EncodeToString(encoded)
}

// finishStepUp settles the step-up marker when a callback for receivedState has
// been handled, and returns where to send the user back to.
//
// Only the marker of that very request counts: one left behind by an abandoned
// step-up is cleared without effect. When the callback succeeded but the stored
// tokens do not meet what was asked for, that is recorded, so that asking for
// the same again is refused instead of looping.
func (flow *AuthorizationCodeFlow) finishStepUp(receivedState string, succeeded bool) string {
	marker, ok := flow.readStepUpMarker()
	if !ok {
		return ""
	}
	if marker.State == "" || marker.State != receivedState {
		_ = flow.storeStepUpRecord("")
		return ""
	}

	if succeeded && !flow.stepUpWasMet(marker) {
		// Smaller than the marker it replaces, so a session that held that one holds this
		_ = flow.writeStepUpMarker(stepUpMarker{Acr: marker.Acr, MaxAge: marker.MaxAge, UnmetAt: time.Now().Unix()})
	} else {
		_ = flow.storeStepUpRecord("")
	}

	if !succeeded || !isLocalPath(marker.ReturnTo) {
		return ""
	}
	return marker.ReturnTo
}

// stepUpWasMet reports whether the tokens now in the session meet what the
// step-up asked for. It reads them back through the session hooks, because
// that is what the app's next check will see.
func (flow *AuthorizationCodeFlow) stepUpWasMet(marker stepUpMarker) bool {
	rawToken, err := flow.sessionHooks.GetRawToken()
	if err != nil || rawToken == nil {
		return true // nothing to judge: the app's own sign-in check handles it
	}
	token, err := jwt.ParseOAuth2Token(rawToken, flow.tokenOptions...)
	if err != nil {
		return true
	}

	requirement := jwt.AuthenticationRequirement{Acr: marker.Acr}
	if marker.MaxAge != nil && *marker.MaxAge <= math.MaxInt32 {
		requirement.MaxAge = new(*marker.MaxAge + stepUpCallbackAllowance)
	}
	return token.HasAuthenticationContext(requirement)
}
