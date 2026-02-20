package api

import (
	"log/slog"
	"net/http"
	"time"
)

// AuditEvent identifies the type of security-relevant action being logged.
type AuditEvent string

const (
	AuditLoginSuccess         AuditEvent = "login_success"
	AuditLoginFailure         AuditEvent = "login_failure"
	AuditLoginRateLimited     AuditEvent = "login_rate_limited"
	AuditRegister             AuditEvent = "register"
	AuditLogout               AuditEvent = "logout"
	AuditTwoFactorEnabled     AuditEvent = "2fa_enabled"
	AuditTwoFactorSetup       AuditEvent = "2fa_setup"
	AuditVaultCreated         AuditEvent = "vault_created"
	AuditVaultDeleted         AuditEvent = "vault_deleted"
	AuditMemberAdded          AuditEvent = "member_added"
	AuditMemberRevoked        AuditEvent = "member_revoked"
	AuditItemCreated          AuditEvent = "item_created"
	AuditItemUpdated          AuditEvent = "item_updated"
	AuditItemDeleted          AuditEvent = "item_deleted"
	AuditVaultExported        AuditEvent = "vault_exported"
	AuditVaultImported        AuditEvent = "vault_imported"
	AuditCAInitialized        AuditEvent = "ca_initialized"
	AuditCertIssued           AuditEvent = "cert_issued"
	AuditCertRevoked          AuditEvent = "cert_revoked"
	AuditCertRenewed          AuditEvent = "cert_renewed"
	AuditCRLGenerated         AuditEvent = "crl_generated"
	AuditCSRSigned            AuditEvent = "csr_signed"
	AuditPrivateKeyAccessed   AuditEvent = "private_key_accessed"
	AuditWebAuthnRegistered   AuditEvent = "webauthn_registered"
	AuditWebAuthnLoginSuccess AuditEvent = "webauthn_login_success"
	AuditRegisterRateLimited  AuditEvent = "register_rate_limited"
	AuditCeremonyCapExceeded  AuditEvent = "ceremony_cap_exceeded"
)

// auditLogger wraps slog.Logger for structured security audit logging.
type auditLogger struct {
	logger  *slog.Logger
	metrics *metricsCollector
}

func newAuditLogger(logger *slog.Logger) *auditLogger {
	return &auditLogger{
		logger: logger.With("component", "audit"),
	}
}

// log writes a structured audit log entry. The accountID is the secret key ID
// (not the raw secret key) — a short, stable identifier safe for logs.
func (al *auditLogger) log(event AuditEvent, r *http.Request, attrs ...slog.Attr) {
	baseAttrs := []slog.Attr{
		slog.String("event", string(event)),
		slog.String("remote_addr", r.RemoteAddr),
		slog.String("timestamp", time.Now().UTC().Format(time.RFC3339)),
	}
	baseAttrs = append(baseAttrs, attrs...)

	args := make([]any, len(baseAttrs))
	for i, a := range baseAttrs {
		args[i] = a
	}
	al.logger.LogAttrs(r.Context(), slog.LevelInfo, "audit", baseAttrs...)
	if al.metrics != nil {
		al.metrics.recordEvent(event)
	}
}

// logEvent is a convenience for events with an account ID.
func (al *auditLogger) logEvent(event AuditEvent, r *http.Request, accountID string, extra ...slog.Attr) {
	attrs := []slog.Attr{
		slog.String("account_id", accountID),
	}
	attrs = append(attrs, extra...)
	al.log(event, r, attrs...)
}

// logFailure logs a failed authentication attempt.
func (al *auditLogger) logFailure(event AuditEvent, r *http.Request, reason string, extra ...slog.Attr) {
	attrs := []slog.Attr{
		slog.String("reason", reason),
	}
	attrs = append(attrs, extra...)
	al.log(event, r, attrs...)
}
