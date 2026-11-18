# Agents: AI agents and MCP

The `agents` package implements Kinde's **AI agents and MCP** login flow:

- **Resource server** (`KindeAgentAuth`): protect your own MCP server or HTTP API with tokens Kinde issues to agents such as Claude, ChatGPT, Cursor, or your own.
- **Agent client** (`KindeAgentClient`): let a Go program (typically a CLI) sign a user in to such a server and call it.

It doesn't use the `authorization_code` package, because that package always adds the `openid` scope, which this flow refuses.

## Set up Kinde

1. Create an application of type **AI agents and MCP**. Testing needs the `dcr_application` feature flag enabled on your business.
2. Set its **Resource URL** to your server's URL, for example `https://mcp.example.com/mcp`. It must match `ResourceURL` byte for byte.
3. The application has no callback URLs on purpose. Agents bring their own.
4. **Trusted agent hosts**: add the domain that serves your own agent's client ID metadata document. Bare domains only, up to 10. Vendor agents (Claude, ChatGPT) are already trusted.

Each application gets a scoped issuer, `https://<domain>/oauth2/agents/<client_id>`, which the package derives for you. Access tokens carry `iss = https://<domain>` and an `aud` containing the Resource URL.

## Protect a server

```go
auth, err := agents.NewKindeAgentAuth(agents.Config{
    Domain:       "https://yourbiz.kinde.com",
    ClientID:     os.Getenv("KINDE_AGENTS_CLIENT_ID"),     // the AI agents and MCP application
    ClientSecret: os.Getenv("KINDE_AGENTS_CLIENT_SECRET"), // used for introspection
    ResourceURL:  "https://mcp.example.com/mcp",
})

mux := http.NewServeMux()
for _, path := range auth.ProtectedResourceMetadataPaths() {
    mux.Handle(path, auth.ProtectedResourceMetadataHandler())
}
mux.Handle("/mcp", auth.Middleware(mcpHandler))
```

Inside a tool, check a Kinde permission and return a tool error (`isError: true`) when it's missing:

```go
caller, _ := agents.AuthFromContext(r.Context())
if !agents.HasPermission(caller, "read:docs") {
    // return an MCP tool result with isError: true
}
```

Don't answer `403 insufficient_scope` for a missing permission: MCP clients respond by signing the user in again, which can't grant a permission. For plain REST routes, `agents.RequirePermission("read:docs")` answers a plain `403`.

Requests without a token get `401` with `WWW-Authenticate: Bearer resource_metadata="…"`. Invalid tokens add `error="invalid_token"`. If Kinde can't be reached, the response is `503`, so agents don't restart login.

### Verification

| `Verification` | Behaviour |
|---|---|
| `VerificationIntrospection` (default) | Calls `<issuer>/introspect` with the application's credentials. Revocation takes effect immediately. |
| `VerificationJWT` | Verifies RS256 locally against `<domain>/.well-known/jwks`, with `iss` = domain and `aud` containing the Resource URL. Needs no secret, but a revoked token stays valid until it expires (24 hours by default). |
| `VerificationJWTAndIntrospection` | Both. |

### Gin

```go
router := gin.Default()
gin_kinde.MountProtectedResourceMetadata(router, auth)
router.POST("/mcp", gin_kinde.UseKindeAgentAuth(auth), mcpHandler)
router.GET("/docs", gin_kinde.UseKindeAgentAuth(auth), gin_kinde.RequireAgentPermission("read:docs"), docsHandler)
```

Read the caller with `gin_kinde.AgentAuthFromContext(c)`.

## Build an agent

```go
client, err := agents.NewKindeAgentClient(agents.AgentClientConfig{
    ResourceURL:       "https://mcp.example.com/mcp",
    ClientMetadataURL: "https://agent.example.com/oauth/client-metadata.json", // CIMD, preferred
    OpenBrowser:       openSystemBrowser,
})
if err := client.Connect(ctx); err != nil { ... } // discovery, then sign-in if needed
resp, err := client.Do(req)                       // adds the bearer token, refreshes, retries once on 401
err = client.Disconnect(ctx, false)               // revokes and clears tokens
```

The client picks its identity in this order: CIMD (when the server advertises `client_id_metadata_document_supported`), a pre-registered `ClientID`, then dynamic client registration. It always uses PKCE (S256), never sends `openid`, and signs in through a loopback redirect on `127.0.0.1`. With DCR, set a fixed-port `RedirectURI` (for example `http://127.0.0.1:53682/callback`) so the registration can be reused.

Tokens and registrations go to `Storage`. The default is in memory; `frameworks/cli.NewCliSession` stores them in the OS keychain. See [examples/agent-cli](../examples/agent-cli).

### Publish a client ID metadata document

```go
doc, err := agents.BuildClientMetadataDocument(agents.ClientMetadataOptions{
    ClientID:     "https://agent.example.com/oauth/client-metadata.json",
    ClientName:   "Example Agent",
    RedirectURIs: []string{"http://127.0.0.1/callback"},
})
handler, err := agents.ClientMetadataHandler(doc)
mux.Handle("/oauth/client-metadata.json", handler)
```

Serve it at exactly the `ClientID` URL, on a public host (Kinde refuses private addresses, so `localhost` can't work; use a tunnel with a real domain for local testing), and add that host to **Trusted agent hosts**. Loopback redirect URIs match any port.
