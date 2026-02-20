package api

import (
	"sync"
	"time"
)

// MemorySessionStore is a thread-safe in-memory SessionStore.
// Sessions are lost on server restart.
type MemorySessionStore struct {
	mu          sync.RWMutex
	data        map[string]AuthSession
	idleTimeout time.Duration
}

var _ SessionStore = (*MemorySessionStore)(nil)

// NewMemorySessionStore creates an in-memory session store.
// idleTimeout of 0 disables idle timeout checking.
func NewMemorySessionStore(idleTimeout time.Duration) *MemorySessionStore {
	return &MemorySessionStore{
		data:        make(map[string]AuthSession),
		idleTimeout: idleTimeout,
	}
}

func (s *MemorySessionStore) Get(token string) (AuthSession, bool) {
	s.mu.RLock()
	session, ok := s.data[token]
	s.mu.RUnlock()
	if !ok {
		return AuthSession{}, false
	}
	if time.Now().After(session.ExpiresAt) {
		s.Delete(token)
		return AuthSession{}, false
	}
	if s.idleTimeout > 0 && time.Since(session.LastAccessedAt) > s.idleTimeout {
		s.Delete(token)
		return AuthSession{}, false
	}
	return session, true
}

func (s *MemorySessionStore) Put(token string, session AuthSession) {
	s.mu.Lock()
	s.data[token] = session
	s.mu.Unlock()
}

func (s *MemorySessionStore) Delete(token string) {
	s.mu.Lock()
	if session, ok := s.data[token]; ok {
		// Best-effort: remove references to sensitive string fields.
		// This does not zero the backing arrays (Go strings are immutable),
		// but it shortens the window in which references are reachable.
		session.CredentialsBlob = ""
		session.PendingTOTPSecret = ""
		session.WebAuthnSessionData = ""
		s.data[token] = session
	}
	delete(s.data, token)
	s.mu.Unlock()
}
