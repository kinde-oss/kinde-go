package agents

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildBearerChallenge(t *testing.T) {
	t.Parallel()

	t.Run("quotes and escapes values", func(t *testing.T) {
		got := buildBearerChallenge(
			[2]string{"error", "invalid_token"},
			[2]string{"error_description", `bad "token" \ here`},
			[2]string{"resource_metadata", "https://api.example.com/.well-known/oauth-protected-resource/mcp"},
		)
		assert.Equal(t, `Bearer error="invalid_token", error_description="bad \"token\" \\ here", resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp"`, got)
	})

	t.Run("skips empty values", func(t *testing.T) {
		got := buildBearerChallenge([2]string{"error", ""}, [2]string{"resource_metadata", "https://x/y"})
		assert.Equal(t, `Bearer resource_metadata="https://x/y"`, got)
	})

	t.Run("round trips through the parser", func(t *testing.T) {
		description := `a, "quoted" \ value`
		header := buildBearerChallenge([2]string{"error_description", description})
		assert.Equal(t, description, bearerParam([]string{header}, "error_description"))
	})
}

func TestParseChallenges(t *testing.T) {
	t.Parallel()

	t.Run("several challenges with commas inside quotes", func(t *testing.T) {
		header := `Basic realm="a, b", Bearer error="invalid_token", resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp", scope="a b"`
		challenges := parseChallenges([]string{header})
		assert.Len(t, challenges, 2)
		assert.Equal(t, "basic", challenges[0].scheme)
		assert.Equal(t, "a, b", challenges[0].params["realm"])
		assert.Equal(t, "bearer", challenges[1].scheme)
		assert.Equal(t, "invalid_token", challenges[1].params["error"])
		assert.Equal(t, "https://api.example.com/.well-known/oauth-protected-resource/mcp", challenges[1].params["resource_metadata"])
		assert.Equal(t, "a b", challenges[1].params["scope"])
	})

	t.Run("case-insensitive scheme and parameter names, escaped quotes", func(t *testing.T) {
		header := `BEARER Resource_Metadata="https://x/\"y\"", Error=invalid_token`
		assert.Equal(t, `https://x/"y"`, bearerParam([]string{header}, "resource_metadata"))
		assert.Equal(t, "invalid_token", bearerParam([]string{header}, "error"))
	})

	t.Run("bearer challenge in a second header value", func(t *testing.T) {
		headers := []string{`Negotiate abc==`, `Bearer resource_metadata="https://x/y"`}
		assert.Equal(t, "https://x/y", bearerParam(headers, "resource_metadata"))
	})

	t.Run("bare scheme and garbage don't loop or panic", func(t *testing.T) {
		assert.Equal(t, "", bearerParam([]string{"Bearer"}, "resource_metadata"))
		assert.NotPanics(t, func() { parseChallenges([]string{`="",,= "x`, `Bearer a="unterminated`}) })
		assert.Equal(t, "unterminated", bearerParam([]string{`Bearer a="unterminated`}, "a"))
	})
}
