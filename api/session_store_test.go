package api

import (
	"testing"
	"time"

	"github.com/jmcleod/ironhand/storage/memory"
)

// sessionStoreTests runs the common suite against any SessionStore implementation.
func sessionStoreTests(t *testing.T, store SessionStore) {
	t.Helper()

	t.Run("PutAndGet", func(t *testing.T) {
		s := AuthSession{
			SecretKeyID:       "sk-1",
			SessionPassphrase: "pass",
			CredentialsBlob:   "blob",
			ExpiresAt:         time.Now().Add(time.Hour),
			LastAccessedAt:    time.Now(),
		}
		store.Put("tok-1", s)
		got, ok := store.Get("tok-1")
		if !ok {
			t.Fatal("expected to find session")
		}
		if got.SecretKeyID != "sk-1" {
			t.Fatalf("got SecretKeyID %q, want %q", got.SecretKeyID, "sk-1")
		}
		if got.SessionPassphrase != "pass" {
			t.Fatalf("got SessionPassphrase %q, want %q", got.SessionPassphrase, "pass")
		}
	})

	t.Run("GetMissing", func(t *testing.T) {
		_, ok := store.Get("no-such-token")
		if ok {
			t.Fatal("expected not found for missing token")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		s := AuthSession{
			SecretKeyID:    "sk-del",
			ExpiresAt:      time.Now().Add(time.Hour),
			LastAccessedAt: time.Now(),
		}
		store.Put("tok-del", s)
		store.Delete("tok-del")
		_, ok := store.Get("tok-del")
		if ok {
			t.Fatal("expected session to be deleted")
		}
	})

	t.Run("DeleteMissing", func(t *testing.T) {
		// Should not panic.
		store.Delete("never-existed")
	})

	t.Run("Overwrite", func(t *testing.T) {
		s1 := AuthSession{
			SecretKeyID:    "sk-v1",
			ExpiresAt:      time.Now().Add(time.Hour),
			LastAccessedAt: time.Now(),
		}
		store.Put("tok-ow", s1)

		s2 := AuthSession{
			SecretKeyID:    "sk-v2",
			ExpiresAt:      time.Now().Add(time.Hour),
			LastAccessedAt: time.Now(),
		}
		store.Put("tok-ow", s2)

		got, ok := store.Get("tok-ow")
		if !ok {
			t.Fatal("expected session after overwrite")
		}
		if got.SecretKeyID != "sk-v2" {
			t.Fatalf("got SecretKeyID %q, want %q", got.SecretKeyID, "sk-v2")
		}
	})

	t.Run("ExpiredSession", func(t *testing.T) {
		s := AuthSession{
			SecretKeyID:    "sk-exp",
			ExpiresAt:      time.Now().Add(-time.Second),
			LastAccessedAt: time.Now(),
		}
		store.Put("tok-exp", s)
		_, ok := store.Get("tok-exp")
		if ok {
			t.Fatal("expected expired session to be rejected")
		}
	})

	t.Run("PendingTOTPFields", func(t *testing.T) {
		s := AuthSession{
			SecretKeyID:       "sk-totp",
			ExpiresAt:         time.Now().Add(time.Hour),
			LastAccessedAt:    time.Now(),
			PendingTOTPSecret: "JBSWY3DPEHPK3PXP",
			PendingTOTPExpiry: time.Now().Add(5 * time.Minute),
		}
		store.Put("tok-totp", s)
		got, ok := store.Get("tok-totp")
		if !ok {
			t.Fatal("expected to find session")
		}
		if got.PendingTOTPSecret != "JBSWY3DPEHPK3PXP" {
			t.Fatalf("got PendingTOTPSecret %q, want %q", got.PendingTOTPSecret, "JBSWY3DPEHPK3PXP")
		}
	})

	t.Run("WebAuthnFields", func(t *testing.T) {
		s := AuthSession{
			SecretKeyID:           "sk-wa",
			ExpiresAt:             time.Now().Add(time.Hour),
			LastAccessedAt:        time.Now(),
			WebAuthnSessionData:   `{"challenge":"abc"}`,
			WebAuthnSessionExpiry: time.Now().Add(5 * time.Minute),
		}
		store.Put("tok-wa", s)
		got, ok := store.Get("tok-wa")
		if !ok {
			t.Fatal("expected to find session")
		}
		if got.WebAuthnSessionData != `{"challenge":"abc"}` {
			t.Fatalf("got WebAuthnSessionData %q", got.WebAuthnSessionData)
		}
	})
}

func TestMemorySessionStore(t *testing.T) {
	store := NewMemorySessionStore(30 * time.Minute)
	sessionStoreTests(t, store)

	t.Run("IdleTimeout", func(t *testing.T) {
		s := NewMemorySessionStore(100 * time.Millisecond)
		s.Put("tok-idle", AuthSession{
			SecretKeyID:    "sk-idle",
			ExpiresAt:      time.Now().Add(time.Hour),
			LastAccessedAt: time.Now().Add(-200 * time.Millisecond),
		})
		_, ok := s.Get("tok-idle")
		if ok {
			t.Fatal("expected idle session to be rejected")
		}
	})

	t.Run("IdleTimeoutDisabled", func(t *testing.T) {
		s := NewMemorySessionStore(0)
		s.Put("tok-no-idle", AuthSession{
			SecretKeyID:    "sk-no-idle",
			ExpiresAt:      time.Now().Add(time.Hour),
			LastAccessedAt: time.Now().Add(-24 * time.Hour),
		})
		_, ok := s.Get("tok-no-idle")
		if !ok {
			t.Fatal("expected session to be valid when idle timeout is disabled")
		}
	})
}

func TestPersistentSessionStore(t *testing.T) {
	repo := memory.NewRepository()
	store, err := NewPersistentSessionStore(repo, 30*time.Minute)
	if err != nil {
		t.Fatalf("NewPersistentSessionStore: %v", err)
	}
	defer store.Close()

	sessionStoreTests(t, store)

	t.Run("IdleTimeout", func(t *testing.T) {
		repo2 := memory.NewRepository()
		s, err := NewPersistentSessionStore(repo2, 100*time.Millisecond)
		if err != nil {
			t.Fatalf("NewPersistentSessionStore: %v", err)
		}
		defer s.Close()

		s.Put("tok-idle", AuthSession{
			SecretKeyID:    "sk-idle",
			ExpiresAt:      time.Now().Add(time.Hour),
			LastAccessedAt: time.Now().Add(-200 * time.Millisecond),
		})
		_, ok := s.Get("tok-idle")
		if ok {
			t.Fatal("expected idle session to be rejected")
		}
	})

	t.Run("SurvivesReopen", func(t *testing.T) {
		// Verify that sessions persist when a new store is created
		// against the same underlying repository.
		repo3 := memory.NewRepository()
		s1, err := NewPersistentSessionStore(repo3, 30*time.Minute)
		if err != nil {
			t.Fatalf("NewPersistentSessionStore: %v", err)
		}
		s1.Put("tok-persist", AuthSession{
			SecretKeyID:       "sk-persist",
			SessionPassphrase: "p",
			CredentialsBlob:   "b",
			ExpiresAt:         time.Now().Add(time.Hour),
			LastAccessedAt:    time.Now(),
		})
		s1.Close()

		s2, err := NewPersistentSessionStore(repo3, 30*time.Minute)
		if err != nil {
			t.Fatalf("NewPersistentSessionStore (reopen): %v", err)
		}
		defer s2.Close()

		got, ok := s2.Get("tok-persist")
		if !ok {
			t.Fatal("expected session to survive store reopen")
		}
		if got.SecretKeyID != "sk-persist" {
			t.Fatalf("got SecretKeyID %q, want %q", got.SecretKeyID, "sk-persist")
		}
	})

	t.Run("KeyReused", func(t *testing.T) {
		// The encryption key should be loaded (not regenerated) on reopen.
		repo4 := memory.NewRepository()
		s1, err := NewPersistentSessionStore(repo4, 30*time.Minute)
		if err != nil {
			t.Fatalf("NewPersistentSessionStore: %v", err)
		}
		key1 := make([]byte, len(s1.key))
		copy(key1, s1.key)
		s1.Close()

		s2, err := NewPersistentSessionStore(repo4, 30*time.Minute)
		if err != nil {
			t.Fatalf("NewPersistentSessionStore (reopen): %v", err)
		}
		defer s2.Close()

		// After s1.Close() the key is wiped, but s2 should have loaded
		// the same key from storage (compare with copy we made).
		if len(s2.key) != 32 {
			t.Fatalf("expected 32-byte key, got %d bytes", len(s2.key))
		}
		for i := range key1 {
			if key1[i] != s2.key[i] {
				t.Fatal("expected same encryption key on reopen")
			}
		}
	})

	t.Run("SweepExpired", func(t *testing.T) {
		repo5 := memory.NewRepository()
		s, err := NewPersistentSessionStore(repo5, 30*time.Minute)
		if err != nil {
			t.Fatalf("NewPersistentSessionStore: %v", err)
		}
		defer s.Close()

		// Add an expired session.
		s.Put("tok-sweep", AuthSession{
			SecretKeyID:    "sk-sweep",
			ExpiresAt:      time.Now().Add(-time.Hour),
			LastAccessedAt: time.Now(),
		})

		// Trigger a sweep.
		s.sweepExpired()

		// The session should be gone from storage.
		_, err = repo5.Get(sessionVaultID, sessionRecordType, "tok-sweep")
		if err == nil {
			t.Fatal("expected expired session to be removed by sweep")
		}
	})
}
