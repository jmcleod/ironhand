package vault

import "errors"

var (
	// ErrUnauthorized indicates the caller is not permitted for the attempted operation.
	ErrUnauthorized = errors.New("unauthorized")
	// ErrStaleSession indicates the session epoch is behind the vault's current epoch.
	ErrStaleSession = errors.New("stale session")
	// ErrSessionClosed indicates the session has already been closed and its key material destroyed.
	ErrSessionClosed = errors.New("session closed")
)
