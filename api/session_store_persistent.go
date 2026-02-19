package api

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/jmcleod/ironhand/internal/util"
	"github.com/jmcleod/ironhand/storage"
)

const (
	sessionVaultID    = "__sessions"
	sessionRecordType = "SESSION"
	sessionKeyType    = "SESSION_KEY"
	sessionKeyID      = "current"
	sessionAADPrefix  = "session:"
	cleanupInterval   = 5 * time.Minute
)

// PersistentSessionStore stores sessions in a storage.Repository, encrypted
// at rest using AES-256-GCM. Sessions survive server restarts.
type PersistentSessionStore struct {
	repo        storage.Repository
	key         []byte // 32-byte AES-256 encryption key
	idleTimeout time.Duration
	stopOnce    sync.Once
	stopCh      chan struct{}
}

var _ SessionStore = (*PersistentSessionStore)(nil)

// NewPersistentSessionStore creates a session store backed by the given
// repository. It generates or loads a session encryption key from storage.
// idleTimeout of 0 disables idle timeout checking.
func NewPersistentSessionStore(repo storage.Repository, idleTimeout time.Duration) (*PersistentSessionStore, error) {
	key, err := loadOrCreateSessionKey(repo)
	if err != nil {
		return nil, err
	}
	s := &PersistentSessionStore{
		repo:        repo,
		key:         key,
		idleTimeout: idleTimeout,
		stopCh:      make(chan struct{}),
	}
	go s.cleanupLoop()
	return s, nil
}

// Close stops the background cleanup goroutine and wipes the encryption key.
func (s *PersistentSessionStore) Close() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
		util.WipeBytes(s.key)
	})
}

func (s *PersistentSessionStore) Get(token string) (AuthSession, bool) {
	env, err := s.repo.Get(sessionVaultID, sessionRecordType, token)
	if err != nil {
		return AuthSession{}, false
	}
	aad := []byte(sessionAADPrefix + token)
	data, err := storage.OpenRecord(s.key, env, aad)
	if err != nil {
		return AuthSession{}, false
	}
	var session AuthSession
	if err := json.Unmarshal(data, &session); err != nil {
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

func (s *PersistentSessionStore) Put(token string, session AuthSession) {
	data, err := json.Marshal(session)
	if err != nil {
		return
	}
	aad := []byte(sessionAADPrefix + token)
	env, err := storage.SealRecord(s.key, data, aad)
	if err != nil {
		return
	}
	_ = s.repo.Put(sessionVaultID, sessionRecordType, token, env)
}

func (s *PersistentSessionStore) Delete(token string) {
	_ = s.repo.Delete(sessionVaultID, sessionRecordType, token)
}

// cleanupLoop periodically removes expired sessions from storage.
func (s *PersistentSessionStore) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.sweepExpired()
		}
	}
}

func (s *PersistentSessionStore) sweepExpired() {
	tokens, err := s.repo.List(sessionVaultID, sessionRecordType)
	if err != nil {
		return
	}
	now := time.Now()
	for _, token := range tokens {
		env, err := s.repo.Get(sessionVaultID, sessionRecordType, token)
		if err != nil {
			continue
		}
		aad := []byte(sessionAADPrefix + token)
		data, err := storage.OpenRecord(s.key, env, aad)
		if err != nil {
			// Corrupt entry — remove it.
			_ = s.repo.Delete(sessionVaultID, sessionRecordType, token)
			continue
		}
		var session AuthSession
		if err := json.Unmarshal(data, &session); err != nil {
			_ = s.repo.Delete(sessionVaultID, sessionRecordType, token)
			continue
		}
		expired := now.After(session.ExpiresAt)
		idle := s.idleTimeout > 0 && now.Sub(session.LastAccessedAt) > s.idleTimeout
		if expired || idle {
			_ = s.repo.Delete(sessionVaultID, sessionRecordType, token)
		}
	}
}

// loadOrCreateSessionKey loads the session encryption key from storage,
// or generates a new 32-byte random key and persists it.
func loadOrCreateSessionKey(repo storage.Repository) ([]byte, error) {
	env, err := repo.Get(sessionVaultID, sessionKeyType, sessionKeyID)
	if err == nil && env != nil {
		// Key is stored as plaintext in the envelope's ciphertext field
		// (no additional encryption layer — the storage itself may be encrypted).
		if len(env.Ciphertext) == 32 {
			key := make([]byte, 32)
			copy(key, env.Ciphertext)
			return key, nil
		}
	}
	if err != nil && !errors.Is(err, storage.ErrNotFound) && !errors.Is(err, storage.ErrVaultNotFound) {
		return nil, err
	}

	// Generate a new key.
	key, err := util.RandomBytes(32)
	if err != nil {
		return nil, err
	}
	env = &storage.Envelope{
		Ver:        1,
		Scheme:     "raw",
		Nonce:      nil,
		Ciphertext: make([]byte, 32),
	}
	copy(env.Ciphertext, key)
	if err := repo.Put(sessionVaultID, sessionKeyType, sessionKeyID, env); err != nil {
		util.WipeBytes(key)
		return nil, err
	}
	return key, nil
}
