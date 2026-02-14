package vault

import "fmt"

// UnauthorizedError indicates the caller is not permitted for the attempted operation.
type UnauthorizedError struct {
	Message string
}

func (e UnauthorizedError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return "unauthorized"
}

// StaleSessionError indicates the session epoch is behind the vault's current epoch.
type StaleSessionError struct{}

func (e StaleSessionError) Error() string {
	return "stale session"
}

// SessionClosedError indicates the session has already been closed and its key material destroyed.
type SessionClosedError struct{}

func (e SessionClosedError) Error() string {
	return "session closed"
}

// RollbackError indicates a rollback attempt was detected.
type RollbackError struct{}

func (e RollbackError) Error() string {
	return "rollback detected"
}

// ValidationError indicates a caller-provided parameter is invalid.
type ValidationError struct {
	Message string
}

func (e ValidationError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return "validation failed"
}

// VaultExistsError indicates a vault with the same ID already exists.
type VaultExistsError struct{}

func (e VaultExistsError) Error() string {
	return "vault already exists"
}

func validationErrorf(format string, args ...any) error {
	return ValidationError{Message: fmt.Sprintf(format, args...)}
}

var (
	// ErrUnauthorized is a sentinel for generic unauthorized errors.
	ErrUnauthorized = UnauthorizedError{}
	// ErrStaleSession is a sentinel for stale session errors.
	ErrStaleSession = StaleSessionError{}
	// ErrSessionClosed is a sentinel for closed session errors.
	ErrSessionClosed = SessionClosedError{}
	// ErrRollbackDetected is a sentinel for rollback detected errors.
	ErrRollbackDetected = RollbackError{}
	// ErrValidationFailed is a sentinel for input validation errors.
	ErrValidationFailed = ValidationError{}
	// ErrVaultAlreadyExists is a sentinel for duplicate vault creation.
	ErrVaultAlreadyExists = VaultExistsError{}
)
