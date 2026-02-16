package authorization_code

import (
	"context"
	"fmt"

	"github.com/kinde-oss/kinde-go/kinde/account_api"
)

// GetAccountAPIClient returns an Account API client that uses the current user's access token.
// The client uses the token's issuer claim as the base URL.
func (flow *AuthorizationCodeFlow) GetAccountAPIClient(ctx context.Context) (*account_api.Client, error) {
	// Get token to extract issuer
	token, err := flow.GetToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	issuer := token.GetIssuer()
	if issuer == "" {
		return nil, fmt.Errorf("issuer claim not found in token")
	}

	// Create getToken function that returns access token string
	getTokenFunc := func(ctx context.Context) (string, error) {
		token, err := flow.GetToken(ctx)
		if err != nil {
			return "", err
		}
		accessToken, ok := token.GetAccessToken()
		if !ok {
			return "", fmt.Errorf("access token not found")
		}
		return accessToken, nil
	}

	return account_api.NewClient(issuer, getTokenFunc)
}

