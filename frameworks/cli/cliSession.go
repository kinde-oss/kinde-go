package cli

import (
	"encoding/json"
	"fmt"

	"github.com/99designs/keyring"
	"github.com/kinde-oss/kinde-go/oauth2/authorization_code"
	"golang.org/x/oauth2"
)

const (
	keyPrefix = "kinde"
)

type (
	cliSession struct {
		keyring keyring.Keyring
	}
)

// GetRawToken implements authorization_code.ISessionHooks.
func (c *cliSession) GetRawToken() (*oauth2.Token, error) {
	key := fmt.Sprintf("%s_token", keyPrefix)
	countKey := fmt.Sprintf("%s_chunk_count", key)

	// Try to get chunk count
	countItem, err := c.keyring.Get(countKey)
	if err != nil {
		// fallback to single token (old format)
		token, err := c.keyring.Get(key)
		if err != nil {
			return nil, fmt.Errorf("failed to get token: %w", err)
		}
		var t oauth2.Token
		if err := json.Unmarshal(token.Data, &t); err != nil {
			return nil, fmt.Errorf("failed to unmarshal token: %w", err)
		}
		return &t, nil
	}

	var chunks int
	if _, err := fmt.Sscanf(string(countItem.Data), "%d", &chunks); err != nil {
		return nil, fmt.Errorf("failed to parse chunk count: %w", err)
	}

	var tokenData []byte
	for i := 0; i < chunks; i++ {
		chunkKey := fmt.Sprintf("%s_chunk_%d", key, i)
		chunkItem, err := c.keyring.Get(chunkKey)
		if err != nil {
			return nil, fmt.Errorf("failed to get token chunk %d: %w", i, err)
		}
		tokenData = append(tokenData, chunkItem.Data...)
	}

	var t oauth2.Token
	if err := json.Unmarshal(tokenData, &t); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}
	return &t, nil
}

// SetRawToken implements authorization_code.ISessionHooks.
func (c *cliSession) SetRawToken(token *oauth2.Token) error {
	key := fmt.Sprintf("%s_token", keyPrefix)

	if token == nil {
		// Remove legacy single-key entry
		_ = c.keyring.Remove(key)
		// Remove chunked keys and chunk count
		for i := 0; ; i++ {
			chunkKey := fmt.Sprintf("%s_chunk_%d", key, i)
			if err := c.keyring.Remove(chunkKey); err != nil {
				break
			}
		}
		countKey := fmt.Sprintf("%s_chunk_count", key)
		_ = c.keyring.Remove(countKey)
		return nil
	}

	t, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	const chunkSize = 1024
	chunks := (len(t) + chunkSize - 1) / chunkSize

	// Remove any existing chunks
	for i := 0; ; i++ {
		chunkKey := fmt.Sprintf("%s_chunk_%d", key, i)
		if err := c.keyring.Remove(chunkKey); err != nil {
			break
		}
	}

	// Save chunks
	for i := range chunks {
		start := i * chunkSize
		end := min(start+chunkSize, len(t))
		chunkKey := fmt.Sprintf("%s_chunk_%d", key, i)
		if err := c.keyring.Set(keyring.Item{
			Key:  chunkKey,
			Data: t[start:end],
		}); err != nil {
			return fmt.Errorf("failed to save token chunk %d: %w", i, err)
		}
	}

	// Save chunk count
	countKey := fmt.Sprintf("%s_chunk_count", key)
	countData := fmt.Appendf(nil, "%d", chunks)
	if err := c.keyring.Set(keyring.Item{
		Key:  countKey,
		Data: countData,
	}); err != nil {
		return fmt.Errorf("failed to save chunk count: %w", err)
	}

	return nil
}

// GetPostAuthRedirect implements authorization_code.SessionHooks.
func (c *cliSession) GetPostAuthRedirect() (string, error) {
	return "", fmt.Errorf("not supported in CLI session")
}

// GetState implements authorization_code.SessionHooks.
func (c *cliSession) GetState() (string, error) {
	return "", fmt.Errorf("not supported in CLI session")
}

// SetPostAuthRedirect implements authorization_code.SessionHooks.
func (c *cliSession) SetPostAuthRedirect(redirect string) error {
	return fmt.Errorf("not supported in CLI session")
}

// SetState implements authorization_code.SessionHooks.
func (c *cliSession) SetState(state string) error {
	return fmt.Errorf("not supported in CLI session")
}

func NewCliSession(serviceName string) (authorization_code.ISessionHooks, error) {
	ring, err := keyring.Open(keyring.Config{
		KeychainTrustApplication: true,
		ServiceName:              serviceName,
	})

	if err != nil {
		return nil, err
	}

	return &cliSession{
		keyring: ring,
	}, nil
}
