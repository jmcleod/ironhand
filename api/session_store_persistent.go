package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jmcleod/ironhand/internal/util"
	"github.com/jmcleod/ironhand/storage"
)

const (
	sessionVaultID        = "__sessions"
	sessionRecordType     = "SESSION"
	sessionKeyType        = "SESSION_KEY"
	sessionKeyID          = "current"
	sessionAADPrefix      = "session:"
	sessionKeyWrappingAAD = "ironhand:session_master_key:v1"
	cleanupInterval       = 5 * time.Minute
)

// PersistentSessionStore stores sessions in a storage.Repository, encrypted
// at rest using AES-256-GCM. Sessions survive server restarts.
//
// The session encryption key is itself sealed with an externally-provided
// wrapping key before being stored, so a repository compromise alone cannot
// recover session data.
type PersistentSessionStore struct {
	repo        storage.Repository
	key         []byte // 32-byte AES-256 session encryption key
	wrappingKey []byte // 32-byte external wrapping key for sealing the session key
	idleTimeout time.Duration
	stopOnce    sync.Once
	stopCh      chan struct{}
}

var _ SessionStore = (*PersistentSessionStore)(nil)

// NewPersistentSessionStore creates a session store backed by the given
// repository. The wrappingKey (32 bytes) is used to seal the session
// encryption key at rest — it must be provided externally (CLI flag,
// environment variable, or file) and is never stored in the repository.
// idleTimeout of 0 disables idle timeout checking.
func NewPersistentSessionStore(repo storage.Repository, idleTimeout time.Duration, wrappingKey []byte) (*PersistentSessionStore, error) {
	if len(wrappingKey) != 32 {
		return nil, fmt.Errorf("wrapping key must be exactly 32 bytes, got %d", len(wrappingKey))
	}
	wk := make([]byte, 32)
	copy(wk, wrappingKey)

	key, err := loadOrCreateSessionKey(repo, wk)
	if err != nil {
		util.WipeBytes(wk)
		return nil, err
	}
	s := &PersistentSessionStore{
		repo:        repo,
		key:         key,
		wrappingKey: wk,
		idleTimeout: idleTimeout,
		stopCh:      make(chan struct{}),
	}
	go s.cleanupLoop()
	return s, nil
}

// Close stops the background cleanup goroutine and wipes key material.
func (s *PersistentSessionStore) Close() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
		util.WipeBytes(s.key)
		util.WipeBytes(s.wrappingKey)
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
	defer util.WipeBytes(data)
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
			util.WipeBytes(data) // wipe immediately; defer would accumulate in loop
			_ = s.repo.Delete(sessionVaultID, sessionRecordType, token)
			continue
		}
		util.WipeBytes(data) // wipe immediately after unmarshal; defer would accumulate in loop
		expired := now.After(session.ExpiresAt)
		idle := s.idleTimeout > 0 && now.Sub(session.LastAccessedAt) > s.idleTimeout
		if expired || idle {
			_ = s.repo.Delete(sessionVaultID, sessionRecordType, token)
		}
	}
}

// loadOrCreateSessionKey loads the session encryption key from storage,
// unsealing it with the wrapping key. If no key exists, a new 32-byte
// random key is generated, sealed with the wrapping key, and persisted.
//
// Migration: if a legacy "raw" scheme envelope is found (pre-wrapping-key
// deployments), the existing key is preserved and re-sealed with the
// wrapping key.
//
// If the wrapping key has changed (decryption fails on an "aes256gcm"
// envelope), a new session key is generated. All existing sessions become
// unreadable — this is the correct security behavior.
func loadOrCreateSessionKey(repo storage.Repository, wrappingKey []byte) ([]byte, error) {
	aad := []byte(sessionKeyWrappingAAD)

	env, err := repo.Get(sessionVaultID, sessionKeyType, sessionKeyID)
	if err == nil && env != nil {
		// Try to unseal a wrapped key.
		if env.Scheme == "aes256gcm" {
			key, err := storage.OpenRecord(wrappingKey, env, aad)
			if err == nil && len(key) == 32 {
				result := make([]byte, 32)
				copy(result, key)
				util.WipeBytes(key)
				return result, nil
			}
			// Wrong wrapping key or corrupt — fall through to regenerate.
			// Old sessions will be unreadable, which is acceptable:
			// the operator changed the wrapping key.
		}

		// Legacy "raw" scheme: migrate to wrapped storage.
		if env.Scheme == "raw" && len(env.Ciphertext) == 32 {
			key := make([]byte, 32)
			copy(key, env.Ciphertext)
			// Re-seal with the wrapping key.
			sealed, sealErr := storage.SealRecord(wrappingKey, key, aad)
			if sealErr != nil {
				util.WipeBytes(key)
				return nil, fmt.Errorf("migrating session key to wrapped storage: %w", sealErr)
			}
			if putErr := repo.Put(sessionVaultID, sessionKeyType, sessionKeyID, sealed); putErr != nil {
				util.WipeBytes(key)
				return nil, fmt.Errorf("persisting migrated session key: %w", putErr)
			}
			return key, nil
		}
	}
	if err != nil && !errors.Is(err, storage.ErrNotFound) && !errors.Is(err, storage.ErrVaultNotFound) {
		return nil, err
	}

	// Generate a new session encryption key.
	key, err := util.RandomBytes(32)
	if err != nil {
		return nil, err
	}
	sealed, err := storage.SealRecord(wrappingKey, key, aad)
	if err != nil {
		util.WipeBytes(key)
		return nil, fmt.Errorf("sealing new session key: %w", err)
	}
	if err := repo.Put(sessionVaultID, sessionKeyType, sessionKeyID, sealed); err != nil {
		util.WipeBytes(key)
		return nil, err
	}
	return key, nil
}
