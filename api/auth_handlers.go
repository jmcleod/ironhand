package api

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jmcleod/ironhand/internal/uuid"
	"github.com/jmcleod/ironhand/vault"
)

const (
	sessionDuration = 24 * time.Hour
	// minPassphraseLen is the minimum passphrase length required for
	// registration. The passphrase is one of two secrets in the MUK
	// derivation scheme; enforcing a minimum length ensures a baseline
	// of entropy from the human-chosen input.
	minPassphraseLen = 10
)

// Register handles POST /auth/register.
func (a *API) Register(w http.ResponseWriter, r *http.Request) {
	// Rate-limit registration before any expensive work.
	clientIP := a.extractClientIP(r)
	if blocked, retryAfter := a.regGlobalLimiter.check(); blocked {
		a.audit.logFailure(AuditRegisterRateLimited, r, "global rate limited")
		writeRegistrationRateLimited(w, retryAfter)
		return
	}
	if blocked, retryAfter := a.regIPLimiter.check(clientIP); blocked {
		a.audit.logFailure(AuditRegisterRateLimited, r, "ip rate limited",
			slog.String("client_ip", clientIP))
		writeRegistrationRateLimited(w, retryAfter)
		return
	}

	req, ok := decodeJSON[RegisterRequest](w, r, maxAuthBodySize)
	if !ok {
		return
	}
	if req.Passphrase == "" {
		writeError(w, http.StatusBadRequest, "passphrase is required")
		return
	}
	if len(req.Passphrase) < minPassphraseLen {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("passphrase must be at least %d characters", minPassphraseLen))
		return
	}

	// Record the request against both limiters before the expensive KDF.
	a.regIPLimiter.record(clientIP)
	a.regGlobalLimiter.record()

	creds, err := vault.NewCredentials(req.Passphrase)
	if err != nil {
		writeInternalError(w, "failed to create account credentials", err)
		return
	}
	defer creds.Destroy()

	secretKey := creds.SecretKey().String()
	loginPassphrase := combineLoginPassphrase(req.Passphrase, secretKey)
	exported, err := vault.ExportCredentials(creds, loginPassphrase)
	if err != nil {
		writeInternalError(w, "failed to export account credentials", err)
		return
	}
	record := accountRecord{
		SecretKeyID:     creds.SecretKey().ID(),
		CredentialsBlob: base64.StdEncoding.EncodeToString(exported),
		CreatedAt:       time.Now().UTC(),
	}
	if err := a.saveAccountRecord(secretKey, record); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to persist account")
		return
	}

	token := uuid.New()
	sessionSecret := uuid.New()
	sessionPassphrase := deriveSessionPassphrase(token, sessionSecret)
	sessionBlob, err := vault.ExportCredentials(creds, sessionPassphrase)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to initialize session")
		return
	}

	expiresAt := time.Now().Add(sessionDuration)
	a.sessions.Put(token, AuthSession{
		SecretKeyID:     record.SecretKeyID,
		CredentialsBlob: base64.StdEncoding.EncodeToString(sessionBlob),
		ExpiresAt:       expiresAt,
		LastAccessedAt:  time.Now(),
	})
	writeSessionCookie(w, r, token, expiresAt)
	writeSessionSecretCookie(w, r, sessionSecret, expiresAt)
	writeCSRFCookie(w, r)

	a.audit.logEvent(AuditRegister, r, record.SecretKeyID)
	writeJSON(w, http.StatusCreated, RegisterResponse{SecretKey: secretKey})
}

// Login handles POST /auth/login.
func (a *API) Login(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeJSON[LoginRequest](w, r, maxAuthBodySize)
	if !ok {
		return
	}
	if req.Passphrase == "" {
		writeError(w, http.StatusBadRequest, "passphrase is required")
		return
	}
	if req.SecretKey == "" {
		writeError(w, http.StatusBadRequest, "secret_key is required")
		return
	}

	// Derive the account lookup ID for rate-limit tracking.
	// This is a SHA-256 hash — safe for logs and maps.
	accountID, _ := accountLookupID(req.SecretKey)
	clientIP := a.extractClientIP(r)

	// Check rate limits before any expensive work: global → IP → per-account.
	if blocked, retryAfter := a.globalLimiter.check(); blocked {
		a.audit.logFailure(AuditLoginRateLimited, r, "global rate limited")
		writeRateLimited(w, retryAfter)
		return
	}
	if blocked, retryAfter := a.ipLimiter.check(clientIP); blocked {
		a.audit.logFailure(AuditLoginRateLimited, r, "ip rate limited",
			slog.String("client_ip", clientIP))
		writeRateLimited(w, retryAfter)
		return
	}
	if accountID != "" {
		if blocked, retryAfter := a.rateLimiter.check(accountID); blocked {
			a.audit.logFailure(AuditLoginRateLimited, r, "rate limited",
				slog.String("account_id", accountID))
			writeRateLimited(w, retryAfter)
			return
		}
	}

	// recordLoginFailure records a failure across all three rate limiters.
	recordLoginFailure := func() {
		a.globalLimiter.recordFailure()
		a.ipLimiter.recordFailure(clientIP)
		if accountID != "" {
			a.rateLimiter.recordFailure(accountID)
		}
	}

	record, err := a.loadAccountRecord(req.SecretKey)
	if err != nil {
		recordLoginFailure()
		a.audit.logFailure(AuditLoginFailure, r, "account not found")
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if record.TOTPEnabled && !verifyTOTPCode(record.TOTPSecret, req.TOTPCode, time.Now()) {
		recordLoginFailure()
		a.audit.logFailure(AuditLoginFailure, r, "invalid totp code",
			slog.String("account_id", record.SecretKeyID))
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	blob, err := base64.StdEncoding.DecodeString(record.CredentialsBlob)
	if err != nil {
		recordLoginFailure()
		a.audit.logFailure(AuditLoginFailure, r, "corrupt credentials blob",
			slog.String("account_id", record.SecretKeyID))
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	loginPassphrase := combineLoginPassphrase(req.Passphrase, req.SecretKey)
	creds, err := vault.ImportCredentials(blob, loginPassphrase)
	if err != nil {
		recordLoginFailure()
		a.audit.logFailure(AuditLoginFailure, r, "invalid passphrase",
			slog.String("account_id", record.SecretKeyID))
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	defer creds.Destroy()

	token := uuid.New()
	sessionSecret := uuid.New()
	sessionPassphrase := deriveSessionPassphrase(token, sessionSecret)
	sessionBlob, err := vault.ExportCredentials(creds, sessionPassphrase)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to initialize session")
		return
	}

	// Login succeeded — clear rate-limit state.
	a.rateLimiter.recordSuccess(accountID)
	a.ipLimiter.recordSuccess(clientIP)

	expiresAt := time.Now().Add(sessionDuration)
	a.sessions.Put(token, AuthSession{
		SecretKeyID:     record.SecretKeyID,
		CredentialsBlob: base64.StdEncoding.EncodeToString(sessionBlob),
		ExpiresAt:       expiresAt,
		LastAccessedAt:  time.Now(),
	})
	writeSessionCookie(w, r, token, expiresAt)
	writeSessionSecretCookie(w, r, sessionSecret, expiresAt)
	writeCSRFCookie(w, r)

	a.audit.logEvent(AuditLoginSuccess, r, record.SecretKeyID)
	writeJSON(w, http.StatusOK, struct{}{})
}

// TwoFactorStatus handles GET /auth/2fa.
func (a *API) TwoFactorStatus(w http.ResponseWriter, r *http.Request) {
	creds := credentialsFromContext(r.Context())
	if creds == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	record, err := a.loadAccountRecord(creds.SecretKey().String())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load account")
		return
	}
	writeJSON(w, http.StatusOK, TwoFactorStatusResponse{
		Enabled: record.TOTPEnabled,
	})
}

// SetupTwoFactor handles POST /auth/2fa/setup.
func (a *API) SetupTwoFactor(w http.ResponseWriter, r *http.Request) {
	// Rate-limit MFA setup to prevent TOTP secret generation spam.
	clientIP := a.extractClientIP(r)
	if blocked, retryAfter := a.regIPLimiter.check(clientIP); blocked {
		a.audit.logFailure(AuditRegisterRateLimited, r, "mfa setup ip rate limited",
			slog.String("client_ip", clientIP))
		writeRegistrationRateLimited(w, retryAfter)
		return
	}
	a.regIPLimiter.record(clientIP)

	creds := credentialsFromContext(r.Context())
	if creds == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	token, session, ok := a.sessionFromRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	secret, err := generateTOTPSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate 2fa secret")
		return
	}

	session.PendingTOTPSecret = secret
	session.PendingTOTPExpiry = time.Now().Add(totpSetupTTL)
	a.sessions.Put(token, session)

	a.audit.logEvent(AuditTwoFactorSetup, r, session.SecretKeyID)
	writeJSON(w, http.StatusOK, SetupTwoFactorResponse{
		Secret:     secret,
		OtpauthURL: otpAuthURL(secret, session.SecretKeyID),
		ExpiresAt:  session.PendingTOTPExpiry.UTC().Format(time.RFC3339),
	})
}

// EnableTwoFactor handles POST /auth/2fa/enable.
func (a *API) EnableTwoFactor(w http.ResponseWriter, r *http.Request) {
	creds := credentialsFromContext(r.Context())
	if creds == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	req, ok := decodeJSON[EnableTwoFactorRequest](w, r, maxAuthBodySize)
	if !ok {
		return
	}

	token, session, ok := a.sessionFromRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	if session.PendingTOTPSecret == "" || time.Now().After(session.PendingTOTPExpiry) {
		writeError(w, http.StatusBadRequest, "2fa setup expired; start setup again")
		return
	}
	if !verifyTOTPCode(session.PendingTOTPSecret, req.Code, time.Now()) {
		writeError(w, http.StatusUnauthorized, "invalid one-time code")
		return
	}

	secretKey := creds.SecretKey().String()
	record, err := a.loadAccountRecord(secretKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load account")
		return
	}
	record.TOTPEnabled = true
	record.TOTPSecret = session.PendingTOTPSecret
	if err := a.updateAccountRecord(secretKey, *record); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to enable 2fa")
		return
	}

	session.PendingTOTPSecret = ""
	session.PendingTOTPExpiry = time.Time{}
	a.sessions.Put(token, session)

	a.audit.logEvent(AuditTwoFactorEnabled, r, session.SecretKeyID)
	writeJSON(w, http.StatusOK, TwoFactorStatusResponse{Enabled: true})
}

func (a *API) sessionFromRequest(r *http.Request) (string, AuthSession, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return "", AuthSession{}, false
	}
	token := cookie.Value
	session, ok := a.sessions.Get(token)
	if !ok {
		return "", AuthSession{}, false
	}
	return token, session, true
}

// Logout handles POST /auth/logout.
func (a *API) Logout(w http.ResponseWriter, r *http.Request) {
	var secretKeyID string
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil && cookie.Value != "" {
		if session, ok := a.sessions.Get(cookie.Value); ok {
			secretKeyID = session.SecretKeyID
		}
		a.sessions.Delete(cookie.Value)
	}
	clearSessionCookie(w, r)
	clearCSRFCookie(w, r)
	a.audit.logEvent(AuditLogout, r, secretKeyID)
	writeJSON(w, http.StatusOK, struct{}{})
}
