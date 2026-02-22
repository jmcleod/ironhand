package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"sync"
	"time"
)

const (
	inviteTokenBytes      = 32
	invitePassphraseBytes = 32
	defaultInviteTTL      = 1 * time.Hour
)

// inviteState holds the server-side state for a pending vault invite.
// Invite tokens are stored in-memory only (like webauthn ceremonies) and
// do not survive server restarts.
type inviteState struct {
	Token          string
	VaultID        string
	VaultName      string
	Role           string
	CreatorID      string // SecretKey ID of the invite creator
	CredentialBlob []byte // ExportCredentialsBytes output (Argon2id-encrypted)
	ExpiresAt      time.Time
	Accepted       bool
}

// inviteStore is a thread-safe in-memory store for pending vault invites.
type inviteStore struct {
	mu      sync.Mutex
	invites map[string]*inviteState // token → state
}

func newInviteStore() *inviteStore {
	return &inviteStore{
		invites: make(map[string]*inviteState),
	}
}

// generateInvitePassphrase returns a random hex-encoded passphrase.
// The passphrase is used as the encryption key for the credential blob
// and is NOT stored server-side — it must be shared with the invitee
// who will present it when accepting. Wrong passphrase = decryption
// failure = invite rejected.
func generateInvitePassphrase() (string, error) {
	passphraseBytes := make([]byte, invitePassphraseBytes)
	if _, err := rand.Read(passphraseBytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(passphraseBytes), nil
}

// create stores a new invite and returns the token.
// The credBlob must already be encrypted with the invite passphrase
// via vault.ExportCredentials — the passphrase is not stored.
func (s *inviteStore) create(vaultID, vaultName, role, creatorID string, credBlob []byte, ttl time.Duration) (token string, err error) {
	tokenBytes := make([]byte, inviteTokenBytes)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token = base64.RawURLEncoding.EncodeToString(tokenBytes)

	invite := &inviteState{
		Token:          token,
		VaultID:        vaultID,
		VaultName:      vaultName,
		Role:           role,
		CreatorID:      creatorID,
		CredentialBlob: credBlob,
		ExpiresAt:      time.Now().Add(ttl),
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Opportunistic cleanup of expired invites.
	s.cleanupLocked()

	s.invites[token] = invite
	return token, nil
}

// get returns a pending invite if it exists and is still valid.
func (s *inviteStore) get(token string) (*inviteState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	inv, ok := s.invites[token]
	if !ok || inv.Accepted || time.Now().After(inv.ExpiresAt) {
		return nil, false
	}
	return inv, true
}

// accept marks an invite as accepted and returns it. Returns false if the
// invite doesn't exist, is expired, or was already accepted.
func (s *inviteStore) accept(token string) (*inviteState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	inv, ok := s.invites[token]
	if !ok || inv.Accepted || time.Now().After(inv.ExpiresAt) {
		return nil, false
	}
	inv.Accepted = true
	return inv, true
}

// unaccept reverts the accepted flag so the invite can be retried
// (e.g. after a wrong passphrase attempt).
func (s *inviteStore) unaccept(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if inv, ok := s.invites[token]; ok {
		inv.Accepted = false
	}
}

// list returns all active (non-expired, non-accepted) invites for a vault.
func (s *inviteStore) list(vaultID string) []*inviteState {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	var result []*inviteState
	for _, inv := range s.invites {
		if inv.VaultID == vaultID && !inv.Accepted && now.Before(inv.ExpiresAt) {
			result = append(result, inv)
		}
	}
	return result
}

// cancel removes an invite if the caller is the creator.
func (s *inviteStore) cancel(token, creatorID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	inv, ok := s.invites[token]
	if !ok || inv.CreatorID != creatorID {
		return false
	}
	delete(s.invites, token)
	return true
}

// cleanupLocked removes expired or accepted invites. Must be called with mu held.
func (s *inviteStore) cleanupLocked() {
	now := time.Now()
	for token, inv := range s.invites {
		if inv.Accepted || now.After(inv.ExpiresAt) {
			delete(s.invites, token)
		}
	}
}
