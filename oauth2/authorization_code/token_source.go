package authorization_code

import (
	"context"
	"fmt"

	"github.com/kinde-oss/kinde-go/jwt"
	"golang.org/x/oauth2"
)

type (
	sessionTokenSource struct {
		flow *AuthorizationCodeFlow
	}
)

func (t sessionTokenSource) getValidatedToken(_ context.Context) (*jwt.Token, error) {
	token, err := t.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	return t.validateToken(context.Background(), token)

}

func (t sessionTokenSource) validateToken(_ context.Context, token *oauth2.Token) (*jwt.Token, error) {
	parsedToken, err := jwt.ParseOAuth2Token(token, t.flow.tokenOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT token: %w", err)
	}
	return parsedToken, nil
}

// Token implements oauth2.TokenSource.
func (t sessionTokenSource) Token() (*oauth2.Token, error) {
	token, err := t.flow.sessionHooks.GetRawToken()
	if err != nil {
		return nil, fmt.Errorf("session hook: %w", err)
	}
	ts := t.flow.config.TokenSource(context.Background(), token)

	possiblyNewToken, err := ts.Token()
	if err != nil {
		return nil, fmt.Errorf("token source: %w", err)
	}

	// A refresh response does not have to carry an ID token. Refreshing never
	// changes how or when the user authenticated, so keep the one we have:
	// without it auth_time would be lost.
	if possiblyNewToken != token && token != nil {
		if _, refreshed := possiblyNewToken.Extra("id_token").(string); !refreshed {
			if idToken, ok := token.Extra("id_token").(string); ok && idToken != "" {
				// WithExtra replaces every extra field, so carry over the other
				// fields of a token response next to the ID token
				extra := map[string]interface{}{"id_token": idToken}
				for _, field := range []string{"access_token", "token_type", "expires_in", "refresh_token", "scope"} {
					if value := possiblyNewToken.Extra(field); value != nil {
						extra[field] = value
					}
				}
				possiblyNewToken = possiblyNewToken.WithExtra(extra)
			}
		}
	}

	if _, err := t.validateToken(context.Background(), possiblyNewToken); err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	err = t.flow.sessionHooks.SetRawToken(possiblyNewToken)
	return possiblyNewToken, err
}
