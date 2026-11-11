package agents

import (
	"fmt"
	"sync"
)

// Storage persists an agent's tokens and dynamic client registration. Its method set matches
// frameworks/cli.ICliSession, so the CLI keyring session can be used directly. GetKey returns
// an error when the key doesn't exist.
type Storage interface {
	GetKey(key string) ([]byte, error)
	SetKey(key string, value []byte) error
	DeleteKey(key string) error
}

type memoryStorage struct {
	mu    sync.Mutex
	items map[string][]byte
}

// NewMemoryStorage returns an in-memory Storage. Tokens are lost when the process exits.
func NewMemoryStorage() Storage {
	return &memoryStorage{items: map[string][]byte{}}
}

func (m *memoryStorage) GetKey(key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.items[key]
	if !ok {
		return nil, fmt.Errorf("key %q not found", key)
	}
	return append([]byte(nil), v...), nil
}

func (m *memoryStorage) SetKey(key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[key] = append([]byte(nil), value...)
	return nil
}

func (m *memoryStorage) DeleteKey(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.items, key)
	return nil
}
