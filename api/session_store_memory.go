package api

import (
	"sync"
	"time"
)

// MemorySessionStore is a thread-safe in-memory SessionStore.
// Sessions are lost on server restart.
type MemorySessionStore struct {
	mu          sync.RWMutex
	data        map[string]authSession
	idleTimeout time.Duration
}

var _ SessionStore = (*MemorySessionStore)(nil)

// NewMemorySessionStore creates an in-memory session store.
// idleTimeout of 0 disables idle timeout checking.
func NewMemorySessionStore(idleTimeout time.Duration) *MemorySessionStore {
	return &MemorySessionStore{
		data:        make(map[string]authSession),
		idleTimeout: idleTimeout,
	}
}

func (s *MemorySessionStore) Get(token string) (authSession, bool) {
	s.mu.RLock()
	session, ok := s.data[token]
	s.mu.RUnlock()
	if !ok {
		return authSession{}, false
	}
	if time.Now().After(session.ExpiresAt) {
		s.Delete(token)
		return authSession{}, false
	}
	if s.idleTimeout > 0 && time.Since(session.LastAccessedAt) > s.idleTimeout {
		s.Delete(token)
		return authSession{}, false
	}
	return session, true
}

func (s *MemorySessionStore) Put(token string, session authSession) {
	s.mu.Lock()
	s.data[token] = session
	s.mu.Unlock()
}

func (s *MemorySessionStore) Delete(token string) {
	s.mu.Lock()
	delete(s.data, token)
	s.mu.Unlock()
}
