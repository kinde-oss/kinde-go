package gin_kinde

import (
	"github.com/gin-gonic/gin"
	"github.com/kinde-oss/kinde-go/agents"
)

// MountProtectedResourceMetadata serves the agent auth protected resource metadata (RFC 9728)
// on the engine's root, at both the path-suffixed and the root well-known paths.
//
// Example:
//
//	auth, _ := agents.NewKindeAgentAuth(agents.Config{...})
//	router := gin.Default()
//	gin_kinde.MountProtectedResourceMetadata(router, auth)
//	router.POST("/mcp", gin_kinde.UseKindeAgentAuth(auth), mcpHandler)
func MountProtectedResourceMetadata(router *gin.Engine, auth *agents.KindeAgentAuth) {
	handler := gin.WrapH(auth.ProtectedResourceMetadataHandler())
	for _, path := range auth.ProtectedResourceMetadataPaths() {
		router.GET(path, handler)
		router.OPTIONS(path, handler)
	}
}

// UseKindeAgentAuth returns middleware that requires a valid agent token. Unauthenticated
// requests get a 401 with a WWW-Authenticate challenge, and a Kinde outage gets a 503.
// Read the caller with AgentAuthFromContext.
func UseKindeAgentAuth(auth *agents.KindeAgentAuth) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		authContext, err := auth.Authenticate(ctx.Request)
		if err != nil {
			auth.WriteError(ctx.Writer, err)
			ctx.Abort()
			return
		}
		ctx.Request = ctx.Request.WithContext(agents.ContextWithAuth(ctx.Request.Context(), authContext))
		ctx.Next()
	}
}

// AgentAuthFromContext returns the caller verified by UseKindeAgentAuth.
func AgentAuthFromContext(ctx *gin.Context) (*agents.AuthContext, bool) {
	return agents.AuthFromContext(ctx.Request.Context())
}

// RequireAgentPermission is middleware for plain REST routes behind UseKindeAgentAuth. It answers
// a plain 403 unless every permission key is present. In MCP tools use agents.HasPermission instead.
func RequireAgentPermission(keys ...string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		authContext, _ := AgentAuthFromContext(ctx)
		for _, key := range keys {
			if !agents.HasPermission(authContext, key) {
				agents.WriteForbidden(ctx.Writer)
				ctx.Abort()
				return
			}
		}
		ctx.Next()
	}
}
