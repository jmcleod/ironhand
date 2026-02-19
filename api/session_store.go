package api

import "time"

// SessionStore abstracts session CRUD so that sessions can be stored
// in-memory (default) or in persistent backing storage.
type SessionStore interface {
	// Get retrieves a session by token. Returns false if the session
	// does not exist, has expired, or has exceeded the idle timeout.
	Get(token string) (authSession, bool)
	// Put creates or updates a session for the given token.
	Put(token string, session authSession)
	// Delete removes a session by token.
	Delete(token string)
}

// authSession holds the server-side state for an authenticated session.
type authSession struct {
	SecretKeyID           string    `json:"secret_key_id"`
	SessionPassphrase     string    `json:"session_passphrase"`
	CredentialsBlob       string    `json:"credentials_blob"`
	ExpiresAt             time.Time `json:"expires_at"`
	LastAccessedAt        time.Time `json:"last_accessed_at"`
	PendingTOTPSecret     string    `json:"pending_totp_secret,omitempty"`
	PendingTOTPExpiry     time.Time `json:"pending_totp_expiry,omitempty"`
	WebAuthnSessionData   string    `json:"webauthn_session_data,omitempty"`
	WebAuthnSessionExpiry time.Time `json:"webauthn_session_expiry,omitempty"`
}
