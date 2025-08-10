package cli

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/99designs/keyring"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func TestNewCliSession(t *testing.T) {

	assert := assert.New(t)

	session, err := NewCliSession("test-cli")
	assert.Nil(err)
	assert.NotNil(session)

}

// mockKeyring implements keyring.Keyring for testing
type mockKeyring struct {
	items   map[string]keyring.Item
	getErrs map[string]error
}

func (m *mockKeyring) Get(key string) (keyring.Item, error) {
	if err, ok := m.getErrs[key]; ok {
		return keyring.Item{}, err
	}
	item, ok := m.items[key]
	if !ok {
		return keyring.Item{}, keyring.ErrKeyNotFound
	}
	return item, nil
}
func (m *mockKeyring) Set(item keyring.Item) error { m.items[item.Key] = item; return nil }
func (m *mockKeyring) Remove(key string) error     { delete(m.items, key); return nil }
func (m *mockKeyring) Keys() ([]string, error)     { return nil, nil }
func (m *mockKeyring) Reset() error                { m.items = map[string]keyring.Item{}; return nil }

// GetMetadata implements keyring.Keyring for testing.
func (m *mockKeyring) GetMetadata(key string) (keyring.Metadata, error) {
	return keyring.Metadata{}, nil
}

func TestCliSession_GetRawToken_SingleToken(t *testing.T) {
	assert := assert.New(t)
	token := &oauth2.Token{AccessToken: "abc", TokenType: "Bearer"}
	data, _ := json.Marshal(token)
	mk := &mockKeyring{
		items: map[string]keyring.Item{
			"kinde_token": {Key: "kinde_token", Data: data},
		},
		getErrs: map[string]error{
			"kinde_chunk_count": keyring.ErrKeyNotFound,
		},
	}
	cs := &cliSession{keyring: mk}
	got, err := cs.GetRawToken()
	assert.Nil(err)
	assert.Equal(token.AccessToken, got.AccessToken)
}

func TestCliSession_GetRawToken_ChunkedToken(t *testing.T) {
	assert := assert.New(t)
	token := &oauth2.Token{AccessToken: "chunked", TokenType: "Bearer"}
	data, _ := json.Marshal(token)
	// Split into 2 chunks
	chunk1 := data[:len(data)/2]
	chunk2 := data[len(data)/2:]
	mk := &mockKeyring{
		items: map[string]keyring.Item{
			"kinde_token_chunk_count": {Key: "kinde_token_chunk_count", Data: []byte("2")},
			"kinde_token_chunk_0":     {Key: "kinde_token_chunk_0", Data: chunk1},
			"kinde_token_chunk_1":     {Key: "kinde_token_chunk_1", Data: chunk2},
		},
		getErrs: map[string]error{},
	}
	cs := &cliSession{keyring: mk}
	got, err := cs.GetRawToken()
	assert.Nil(err)
	assert.Equal(token.AccessToken, got.AccessToken)
}

func TestCliSession_GetRawToken_TokenNotFound(t *testing.T) {
	assert := assert.New(t)
	mk := &mockKeyring{
		items:   map[string]keyring.Item{},
		getErrs: map[string]error{"kinde_chunk_count": keyring.ErrKeyNotFound, "kinde_token": keyring.ErrKeyNotFound},
	}
	cs := &cliSession{keyring: mk}
	got, err := cs.GetRawToken()
	assert.NotNil(err)
	assert.Nil(got)
	assert.Contains(err.Error(), "failed to get token")
}

func TestCliSession_GetRawToken_ChunkCountParseError(t *testing.T) {
	assert := assert.New(t)
	mk := &mockKeyring{
		items: map[string]keyring.Item{
			"kinde_token_chunk_count": {Key: "kinde_token_chunk_count", Data: []byte("notanint")},
		},
		getErrs: map[string]error{},
	}
	cs := &cliSession{keyring: mk}
	got, err := cs.GetRawToken()
	assert.NotNil(err)
	assert.Nil(got)
	assert.Contains(err.Error(), "failed to parse chunk count")
}

func TestCliSession_GetRawToken_ChunkMissing(t *testing.T) {
	assert := assert.New(t)
	mk := &mockKeyring{
		items: map[string]keyring.Item{
			"kinde_token_chunk_count": {Key: "kinde_token_chunk_count", Data: []byte("1")},
		},
		getErrs: map[string]error{
			"kinde_token_chunk_0": errors.New("not found"),
		},
	}
	cs := &cliSession{keyring: mk}
	got, err := cs.GetRawToken()
	assert.NotNil(err)
	assert.Nil(got)
	assert.Contains(err.Error(), "failed to get token chunk 0")
}

func TestCliSession_GetRawToken_UnmarshalError(t *testing.T) {
	assert := assert.New(t)
	mk := &mockKeyring{
		items: map[string]keyring.Item{
			"kinde_token": {Key: "kinde_token", Data: []byte("notjson")},
		},
		getErrs: map[string]error{
			"kinde_chunk_count": keyring.ErrKeyNotFound,
		},
	}
	cs := &cliSession{keyring: mk}
	got, err := cs.GetRawToken()
	assert.NotNil(err)
	assert.Nil(got)
	assert.Contains(err.Error(), "failed to unmarshal token")
}
