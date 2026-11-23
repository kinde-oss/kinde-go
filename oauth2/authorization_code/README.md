# Authorization Code Flow

The `authorization_code` package provides OAuth2 authorization code flow implementations for Go applications. This package is imported as `github.com/kinde-oss/kinde-go/oauth2/authorization_code`.

## Overview

The authorization code flow is a backend authorization flow that requires a client secret. It is designed to be used as a server-side auth flow and does not expose tokens to the browser. User sessions need to be managed by other means, for example via session cookies.

## Go Imports

```go
import (
    "github.com/kinde-oss/kinde-go/oauth2/authorization_code" // required
    "github.com/kinde-oss/kinde-go/jwt" // optional - for JWT token validation
)
```

## Standard Authorization Code Flow

### Basic Usage

```go
kindeAuthFlow, err := authorization_code.NewAuthorizationCodeFlow(
  "<issuer URL>",                                       // Kinde subdomain or any auth provider conforming to the spec
  "<client_id>", "<client_secret>", "<callback URL>",
  authorization_code.WithSessionHooks(<ISessionHooks implementation>),     // example of storage for gin framework is gin_kinde.UseKindeAuth(...)
  authorization_code.WithOffline(),                                        // adds offline scope and starts managing refresh tokens
  authorization_code.WithAudience("<your API audience>"),                  // requesting an API audience
  authorization_code.WithTokenValidation(
    true,                                               // will validate token signature via JWKS
    jwt.WillValidateAlgorithm(),                        // will validate the token alg is RS256
    jwt.WillValidateAudience("<your API audience>"),    // will confirm that received token includes correct audience
  ),
)
```

### Available Methods

| Method | Description | Parameters | Returns |
| --- | --- | --- | --- |
| `GetAuthURL` | Returns the URL to redirect the user to start the authentication pipeline. | none | `string` |
| `ExchangeCode` | Exchanges the authorization code for a token and establishes KindeContext. | ctx `context.Context`, authorizationCode `string`, receivedState `string` | `error` |
| `GetClient` | Returns an HTTP client for calling external services, automatically refreshing tokens if offline is requested. | ctx `context.Context` | `(*http.Client, error)` |
| `IsAuthenticated` | Checks if the user is authenticated. | ctx `context.Context` | `(bool, error)` |
| `Logout` | Clears local tokens and logs the user out. | none | `error` |
| `AuthorizationCodeReceivedHandler` | Helper handler middleware for the code exchanger. | w `http.ResponseWriter`, r `*http.Request` | none |
| `HandleCallback` | Processes the callback query: validates the state, returns typed step-up errors, exchanges the code. Returns where to send the user back to after a `StepUp`. | ctx `context.Context`, query `url.Values` | `(string, error)` |
| `StepUp` | Redirects the user to Kinde for a stronger or more recent authentication. See [Step-up authentication](#step-up-authentication). | w `http.ResponseWriter`, r `*http.Request`, requirement `jwt.AuthenticationRequirement`, options `...Option` | `error` |
| `GetStepUpURL` | Returns the step-up URL without redirecting. | ctx `context.Context`, requirement `jwt.AuthenticationRequirement`, options `...Option` | `(string, error)` |
| `GetAuthenticationContext` | Returns the `acr`, `amr` and `auth_time` of the current session. | ctx `context.Context` | `(jwt.AuthenticationContext, error)` |
| `HasAuthenticationContext` | Checks if the current session meets a requirement. | ctx `context.Context`, requirement `jwt.AuthenticationRequirement` | `(bool, error)` |
| `IsStepUpSupported` | Checks if the Kinde environment supports step-up authentication. | ctx `context.Context` | `(bool, error)` |

## Device Authorization Flow

The device authorization flow is an extension of the authorization code flow that separates token requester and receiver. It is best used for devices and environments with limited input capabilities, such as CLIs, TVs, etc.

### Basic Usage

```go
deviceFlow, err := authorization_code.NewDeviceAuthorizationFlow(
  "<issuer_domain>",                                    // Kinde subdomain or any auth provider conforming to the spec
  authorization_code.WithClientID("<your-client-id>"),  // optional, when business provides a default device application, otherwise required
  authorization_code.WithClientSecret("<your-client-secret>"), // optional (used when device flow is used against backend application with a secret)
  authorization_code.WithSessionHooks(<ISessionHooks implementation>),      // used for storing/retrieving tokens
  authorization_code.WithOffline(),                     // optional - include if you'd like to maintain refresh tokens and a long session
  authorization_code.WithTokenValidation(
    true,                                               // will validate token signature via JWKS
    jwt.WillValidateAlgorithm(),                        // will validate the token alg is RS256
  ),
)
```

### Available Methods

| Method | Description | Parameters | Returns |
| --- | --- | --- | --- |
| `StartDeviceAuth` | Starts the device authorization flow and returns the device authorization response. | ctx `context.Context` | `(*oauth2.DeviceAuthResponse, error)` |
| `ExchangeDeviceAccessToken` | Exchanges the device code for an access token. | ctx `context.Context`, da `*oauth2.DeviceAuthResponse`, opts `...oauth2.AuthCodeOption` | `error` |
| `GetClient` | Returns an HTTP client for calling external services, automatically refreshing tokens if offline is requested. | ctx `context.Context` | `(*http.Client, error)` |
| `IsAuthenticated` | Checks if the user is authenticated. | ctx `context.Context` | `(bool, error)` |
| `Logout` | Clears local tokens and logs the user out. | none | `error` |
| `GetToken` | Returns the token for the current session. | ctx `context.Context` | `(*jwt.Token, error)` |
| `InjectTokenMiddleware` | Middleware that injects the auth token into request context. | next `http.Handler` | `http.Handler` |

## Middleware

The authorization code flow package provides several middleware options to simplify integration with popular Go web frameworks and HTTP handlers.

### Built-in HTTP Handler Middleware

The `AuthorizationCodeReceivedHandler` method provides a built-in HTTP handler for processing OAuth2 callbacks:

```go
// Set up your callback route
http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
    kindeAuthFlow.AuthorizationCodeReceivedHandler(w, r)
})
```

This handler automatically:

- Extracts the authorization code and state from the request
- Validates the state parameter
- Exchanges the code for tokens
- Stores the tokens using your session hooks

### Gin Framework Middleware

For Gin applications, use the `gin_kinde` package which provides a complete middleware solution:

```go
import "github.com/kinde-oss/kinde-go/frameworks/gin_kinde"

func main() {
    router := gin.Default()

    // Set up session middleware
    store := sessions.NewStore(...)
    router.Use(sessions.Sessions("kinde-session", store))

    // Create a protected route group
    privateGroup := router.Group("/")

    // Apply Kinde authentication middleware
    gin_kinde.UseKindeAuth(privateGroup,
        "https://your-tenant.kinde.com",    // Kinde domain
        "your-client-id",                  // Client ID
        "your-client-secret",              // Client secret
        "http://localhost:8080",           // Base redirect URL
        authorization_code.WithPrompt("login"),
        authorization_code.WithOffline(),
    )

    // All routes in privateGroup are now protected
    privateGroup.GET("/profile", func(c *gin.Context) {
        // User is authenticated here
        c.JSON(200, gin.H{"message": "Authenticated!"})
    })

    router.Run(":8080")
}
```

The `gin_kinde.UseKindeAuth` middleware:

1. **Initializes the auth flow** for each request
2. **Handles the callback** at `/kinde/callback` automatically
3. **Protects all routes** in the group by checking authentication
4. **Redirects unauthenticated users** to the authorization URL
5. **Provides the Kinde client** in the Gin context for additional operations

### Custom Middleware Implementation

You can create custom middleware for other frameworks or specific use cases:

```go
func AuthMiddleware(kindeFlow *authorization_code.AuthorizationCodeFlow) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Check if user is authenticated
            isAuthenticated, err := kindeFlow.IsAuthenticated(r.Context())
            if err != nil || !isAuthenticated {
                // Redirect to authorization URL
                http.Redirect(w, r, kindeFlow.GetAuthURL(), http.StatusFound)
                return
            }

            // User is authenticated, continue to next handler
            next.ServeHTTP(w, r)
        })
    }
}

// Usage with standard http package
func main() {
    kindeFlow, _ := authorization_code.NewAuthorizationCodeFlow(...)

    mux := http.NewServeMux()
    mux.HandleFunc("/protected", protectedHandler)

    // Apply middleware
    handler := AuthMiddleware(kindeFlow)(mux)

    http.ListenAndServe(":8080", handler)
}
```

### Middleware Features

All middleware implementations provide:

- **Automatic authentication checking** on protected routes
- **Seamless redirects** to the authorization server
- **Session management** integration
- **Token validation** and refresh handling
- **Error handling** with appropriate HTTP status codes

### Middleware Configuration Options

When setting up middleware, you can pass the same options used in the authorization flow:

```go
gin_kinde.UseKindeAuth(privateGroup,
    kindeDomain,
    clientID,
    clientSecret,
    baseRedirectURL,
    authorization_code.WithOffline(),                    // Enable refresh tokens
    authorization_code.WithAudience("your-api"),        // Request specific audience
    authorization_code.WithPKCE(),                      // Enable PKCE for public clients
    authorization_code.WithTokenValidation(true),       // Enable token validation
)
```

These options are automatically applied to the authorization flow created by the middleware.

## Step-up authentication

Before a sensitive action, your app can ask Kinde for a stronger or more recent authentication ([RFC 9470](https://www.rfc-editor.org/rfc/rfc9470)), for example "MFA in the last 5 minutes before changing payout details". Kinde asks the user only for what is missing, and the user keeps their session. Nothing needs to be registered in Kinde, and nothing changes for existing logins: everything here is opt-in.

| What | API |
| --- | --- |
| Authentication contexts | `jwt.AcrMFA` (a second factor), `jwt.AcrPHR` (phishing-resistant: a passkey). `phr` also meets an `mfa` requirement. |
| A requirement | `jwt.AuthenticationRequirement{Acr: jwt.AcrMFA, MaxAge: new(300)}`. `MaxAge` is in seconds; `nil` means no recency requirement and `0` is valid. |
| Check it | `HasAuthenticationContext(ctx, requirement)` |
| Ask for it | `StepUp(w, r, requirement)` or `GetStepUpURL(ctx, requirement)` |
| Read the claims | `GetAuthenticationContext(ctx)` returns `Acr`, `Amr` and `AuthTime` |
| Handle the callback | `HandleCallback(ctx, query)`, `*UnmetAuthenticationRequirementsError`, `*LoginRequiredError` |
| Is it available? | `IsStepUpSupported(ctx)`, `ErrStepUpNotSupported`, `ErrStepUpLoop` |
| On every login | `WithAcrValues(...)` and `WithMaxAge(...)` options |

`new(300)` is Go 1.26 syntax for a pointer to `300`.

> **Upgrading:** `IAuthorizationCodeFlow` has new methods (`HandleCallback`, `StepUp`, `GetStepUpURL`, `GetAuthenticationContext`, `HasAuthenticationContext`, `IsStepUpSupported`). If you implement or mock that interface yourself, add them. Nothing else changes for existing code.

### Require MFA in the last 5 minutes: net/http

```go
var requirement = jwt.AuthenticationRequirement{Acr: jwt.AcrMFA, MaxAge: new(300)}

// kindeFlow(r) returns your AuthorizationCodeFlow for the session of this request.

mux.HandleFunc("/settings/payout", func(w http.ResponseWriter, r *http.Request) {
    flow := kindeFlow(r)

    if signedIn, _ := flow.IsAuthenticated(r.Context()); !signedIn {
        http.Redirect(w, r, flow.GetAuthURL(), http.StatusFound)
        return
    }
    met, err := flow.HasAuthenticationContext(r.Context(), requirement)
    if err != nil {
        // The check could not be made. Don't treat it as "not signed in".
        http.Error(w, "We could not check your sign-in. Please try again.", http.StatusServiceUnavailable)
        return
    }
    if !met {
        // Redirects to Kinde, and brings the user back to this page afterwards
        if err := flow.StepUp(w, r, requirement); err != nil {
            // Nothing was written. Not supported, or the step-up would loop: deny the action.
            http.Error(w, "Extra verification is not available.", http.StatusForbidden)
        }
        return
    }

    // ... the sensitive action
})

mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
    returnTo, err := kindeFlow(r).HandleCallback(r.Context(), r.URL.Query())

    var unmet *authorization_code.UnmetAuthenticationRequirementsError
    switch {
    case errors.As(err, &unmet):
        // The user cannot meet the requirement. This is final: don't retry, don't redirect to login.
        http.Error(w, "Add an authenticator app or a passkey to your account to continue.", http.StatusForbidden)
    case err != nil:
        http.Error(w, "Sign-in failed.", http.StatusInternalServerError)
    case returnTo != "":
        http.Redirect(w, r, returnTo, http.StatusFound) // back to /settings/payout
    default:
        http.Redirect(w, r, "/", http.StatusFound)
    }
})
```

If you use `AuthorizationCodeReceivedHandler` as your callback, it does the same: it redirects back after a step-up, and passes errors to the function you set with `WithCallbackErrorHandler(func(w, r, err))`. Without one it answers an unmet step-up or a cancelled sign-in with a plain-text `403`.

### Require MFA in the last 5 minutes: Gin

```go
privateGroup := router.Group("/")

err := gin_kinde.UseKindeAuth(privateGroup, kindeDomain, clientID, clientSecret, baseRedirectURL,
    // Optional: your own page when the callback fails
    gin_kinde.WithCallbackErrorHandler(func(ctx *gin.Context, err error) {
        var unmet *authorization_code.UnmetAuthenticationRequirementsError
        if errors.As(err, &unmet) {
            ctx.String(http.StatusForbidden, "Add an authenticator app or a passkey to your account to continue.")
            return
        }
        ctx.String(http.StatusInternalServerError, "Sign-in failed.")
    }),
)
if err != nil {
    log.Fatal(err) // an invalid option, for example WithMaxAge(-1)
}

privateGroup.GET("/settings/payout", func(ctx *gin.Context) {
    requirement := jwt.AuthenticationRequirement{Acr: jwt.AcrMFA, MaxAge: new(300)}

    if met, _ := gin_kinde.HasAuthenticationContext(ctx, requirement); !met {
        // Redirects to Kinde; the callback brings the user back to this page
        if err := gin_kinde.StepUp(ctx, requirement); err != nil {
            ctx.String(http.StatusForbidden, "Extra verification is not available.")
        }
        return
    }

    // ... the sensitive action
})
```

`gin_kinde.GetAuthenticationContext(ctx)` reads the claims. Without a callback error handler, the callback answers an unmet step-up with a plain-text `403` and adds the error to `ctx.Errors`. A handler set with `authorization_code.WithCallbackErrorHandler` is called too, with the response writer and request.

### What to know

- **An unmet step-up is final.** `*UnmetAuthenticationRequirementsError` means the user has no passkey or no enrolled MFA factor (a step-up verifies a factor, it never enrols one). Asking again gives the same answer. Tell the user why, for example "add a passkey to continue". Don't retry and don't send them to login. They stay signed in with the tokens they had. The error has `ErrorDescription` and `State`.
- **Use `HandleCallback` in your own callback route.** `StepUp` needs it (or `AuthorizationCodeReceivedHandler`, or `gin_kinde`). `ExchangeCode` only sees the code and the state: it cannot report these errors, return the user to where they were, or stop a loop, and it leaves the step-up's record in the session. Any other error Kinde sends to the callback, such as `access_denied` when the user cancels, comes back as a `*CallbackError` with the error code; nothing is exchanged and the user stays signed in. `AuthorizationCodeReceivedHandler` and `gin_kinde` answer it with a `403` (`400` for other codes).
- **A step-up replaces all three tokens.** The access, ID and refresh tokens from the callback replace the session's, also when the user was already signed in. Refreshing never upgrades a token, and the SDK never tries to. An `http.Client` from `GetClient` made before the step-up keeps its access token until it expires, so get a new one after a step-up.
- **A step-up never weakens the flow.** The strongest `acr` among the flow's, the options' and the requirement's is sent: if the flow was created with `WithAcrValues(jwt.AcrPHR)`, a step-up that needs `mfa` still asks for `phr`. PKCE is configured on the flow: a PKCE option on a single `StepUp` is refused, without touching the session, because the callback uses the flow's code verifier.
- **`StepUp` is interactive.** It returns an error if `prompt=none` is set, on the flow or for the request, because Kinde cannot collect a factor without showing a screen. A `prompt=none` login that needs the user comes back as `*LoginRequiredError`.
- **Where the user returns to.** For a GET that is the requested URL. Other requests are not replayed: the user returns to the page that sent the request (a same-host `Referer`) and confirms the action again. Only paths on your own site are used. `StepUp` keeps this in the session, tied to that one request, so an abandoned step-up does not redirect a later login. A session that implements `IStepUpSessionHooks` (`gin_kinde` does) keeps it under a key of its own. Otherwise it goes in `ISessionHooks.SetPostAuthRedirect` as a tagged value and replaces what is there; the callback never reads or clears a redirect your app stored there itself.
- **A step-up that does not help is stopped.** If a step-up completes and the tokens in the session still do not meet what was asked for, asking for the same step-up again within a minute returns `authorization_code.ErrStepUpLoop` instead of sending the user to Kinde in a loop. Deny the action. The usual cause is a session that does not keep the ID token (see below).
- **A step-up the session cannot record is not started.** `StepUp` and `GetStepUpURL` return an error, before anything is sent, when the state or the step-up's record cannot be stored. On a cookie session store that happens when the tokens leave no room, which is one more reason to use a server-side store.
- **`GetStepUpURL` starts a request.** Each call stores a new state, replacing any login in progress. Call it when you redirect, not to render a link.
- **Don't check `MaxAge: new(0)`.** `StepUp` with a max age of 0 forces a fresh verification, but `HasAuthenticationContext` with 0 is almost never met, so the user would be sent to Kinde on every request. Check a short window such as 60 seconds.
- **`max_age` is never sent empty.** It is only sent when set. `WithMaxAge(-1)`, or a `max_age` that is not a non-negative whole number given through `WithAuthParameter`, makes `NewAuthorizationCodeFlow` return an error (`gin_kinde.UseKindeAuth` returns it at setup). Kinde would read such a value as "re-authenticate", which hides the mistake. In `WithReauthState`, which decodes input your app did not write, such a value is left out.
- **`WithAcrValues` and `WithMaxAge` apply to every login** made with that flow. For a single sensitive action use `StepUp`, which takes the same options for one request only.
- **Keep the ID token in your session.** `auth_time` is read from the ID token (Kinde only adds it to the access token when it can establish it). `json.Marshal` of an `oauth2.Token` drops the ID token, so an `ISessionHooks` implementation has to store `token.Extra("id_token")` itself and put it back with `token.WithExtra`. `gin_kinde` does this. A cookie session store is usually too small for both tokens; `gin_kinde` then stores the token without the ID token and logs that once, so use a server-side store (Redis, memstore) when you check `MaxAge`.
- **Only verified claims count.** `Acr` and `Amr` come from the access token, which the SDK validates. The ID token is verified before `auth_time` is read from it: same keys as the access token, and issued by the same issuer for the same user and client (its `azp` must equal the access token's `azp`). Otherwise it is ignored and `auth_time` is read from the access token. An expired ID token is still read, because it usually expires before the access token and when the user authenticated stays true; a refresh that returns no ID token keeps the one in the session. A token that failed validation never meets a requirement.
- **`mfa` does not mean two independent factors.** `acr: "mfa"` says two factors were accepted under your environment's MFA policy. A user who signs in with a social provider and then gets a one-time code at the same mailbox has proven one channel twice. `phr` is stronger, because a phishing site cannot use a passkey, but it does not assert independence either. For payments and regulated workloads, assess factor independence, enrolment and recovery against your own configuration instead of relying on `acr` alone. See the [Kinde step-up documentation](https://docs.kinde.com/developer-tools/about/using-kinde-without-an-sdk/#step-up-authentication).
- **`Amr` is informational.** Decide on `Acr` only.
- **These checks are for your web app's own session.** An API must check the claims of the verified access token on every request (`token.HasAuthenticationContext(requirement)` on a `jwt.Token`), and must not trust the client to have asked for the context. A `RequireAuthenticationContext` middleware that answers with the RFC 9470 challenge will follow.

### Environments without step-up support

`IsStepUpSupported` reads `acr_values_supported` from `https://<your domain>/.well-known/openid-configuration`. The document is fetched once per Kinde domain and cached in memory for an hour. If it cannot be refreshed after that, the cached document keeps being used and the fetch is retried a minute later. A failed first fetch is an error, remembered for ten seconds. When the field is missing, Kinde ignores `acr_values` and `max_age`, tokens have no `acr`, and `auth_time` can be the time a token was issued. The SDK then behaves like this:

- `StepUp` and `GetStepUpURL` return `authorization_code.ErrStepUpNotSupported`, for an `Acr` and for a `MaxAge`. No token will ever meet the requirement, so deny the action. Don't treat a sign-in as MFA.
- `GetAuthenticationContext` returns a zero `AuthTime`, and `HasAuthenticationContext` with a `MaxAge` returns `false`.
- To only force a fresh sign-in there, redirect to `GetAuthURL()` of a flow created with `WithPrompt("login")`. The tokens cannot prove it afterwards, so remember it in your own session if you need to.

### Differences from other Kinde SDKs

The behaviour above follows Kinde's step-up guidance for SDKs. Where Go differs:

- **Go types.** `Acr` is an empty string and `AuthTime` a zero `time.Time` where other SDKs return null. `Amr` is an empty slice, never `nil`.
- **Login options belong to the flow.** This SDK configures a login when the flow is created, so `WithAcrValues` and `WithMaxAge` are flow options. `StepUp` and `GetStepUpURL` accept options for a single request.
- **`acr_values` with two values is sent as `mfa+phr`**, Go's form encoding of a space, where other SDKs send `mfa%20phr`. They are the same value.
- **The errors don't carry the requested `acr` and max age.** The SDK does not store them between the request and the callback.
- **`jwt.Token.GetAuthenticationContext()` returns `auth_time` as it is.** It makes no discovery request, so on an environment without step-up support don't use it for recency. The flow's `GetAuthenticationContext` does check.
- **Clock tolerance is zero** for the max-age comparison. An `auth_time` up to 60 seconds in the future is treated as clock skew; further ahead it is invalid and the requirement is not met.
- **No `prompt=login` fallback.** On an environment without step-up support, a step-up for a max age alone returns `ErrStepUpNotSupported` like one for an `acr`. After a fallback sign-in the tokens could not show that the max age was met, so a "check, else step up" gate would ask the user to sign in on every request.

## Session Management

Both flows require session hooks to be implemented for token storage and retrieval. The session hooks interface allows you to customize how tokens are stored and retrieved based on your application's needs.

## Token Validation

Both flows support comprehensive token validation options:

- **Signature Validation**: Validates token signatures using JWKS
- **Algorithm Validation**: Ensures tokens use the expected algorithm (e.g., RS256)
- **Audience Validation**: Confirms tokens include the correct API audience
- **Custom Validation**: Additional validation rules can be implemented

## Offline Support

When using `WithOffline()`, the flows will:

- Request offline scope from the authorization server
- Manage refresh tokens automatically
- Maintain long-term sessions
- Automatically refresh expired access tokens

## Examples

For complete examples demonstrating these flows, see the `examples/` directory in the main repository:

- **Gin Chat Example**: Shows how to integrate authorization code flow with a Gin web application
- **CLI Example**: Demonstrates device authorization flow with secure token storage

## Security Considerations

- Always use HTTPS in production
- Implement proper session management
- Store tokens securely using the provided session hooks
- Validate tokens on each request
- Implement proper logout procedures
- Use appropriate scopes and audiences for your application

## Dependencies

This package requires Go 1.24+ and depends on the following packages:

- `github.com/kinde-oss/kinde-go/jwt` - For JWT token handling and validation
- Standard Go packages: `context`, `net/http`, `oauth2`
