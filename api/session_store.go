package api

import "time"

// SessionStore abstracts session CRUD so that sessions can be stored
// in-memory (default) or in persistent backing storage.
type SessionStore interface {
	// Get retrieves a session by token. Returns false if the session
	// does not exist, has expired, or has exceeded the idle timeout.
	Get(token string) (AuthSession, bool)
	// Put creates or updates a session for the given token.
	Put(token string, session AuthSession)
	// Delete removes a session by token.
	Delete(token string)
}

// AuthSession holds the server-side state for an authenticated session.
//
// The session passphrase is intentionally NOT stored here. It is derived
// at request time from the session token and a client-held secret cookie
// using HMAC-SHA256 (see deriveSessionPassphrase in middleware.go). This
// ensures that a session store compromise alone cannot reconstruct
// credentials — the attacker also needs the per-session client cookie.
type AuthSession struct {
	SecretKeyID           string    `json:"secret_key_id"`
	CredentialsBlob       string    `json:"credentials_blob"`
	ExpiresAt             time.Time `json:"expires_at"`
	LastAccessedAt        time.Time `json:"last_accessed_at"`
	PendingTOTPSecret     string    `json:"pending_totp_secret,omitempty"`
	PendingTOTPExpiry     time.Time `json:"pending_totp_expiry,omitempty"`
	WebAuthnSessionData   string    `json:"webauthn_session_data,omitempty"`
	WebAuthnSessionExpiry time.Time `json:"webauthn_session_expiry,omitempty"`
	StepUpVerifiedAt      time.Time `json:"step_up_verified_at,omitempty"`
	StepUpMethod          string    `json:"step_up_method,omitempty"` // "totp" or "passkey"
}
