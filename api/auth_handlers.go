package api

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jmcleod/ironhand/internal/util"
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
	defer func() { req.Passphrase = "" }() // best-effort: remove string reference
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

	kdfParams := a.kdfParamsForNewVault()
	creds, err := vault.NewCredentials(req.Passphrase,
		vault.WithCredentialKDFParams(kdfParams),
	)
	if err != nil {
		writeInternalError(w, "failed to create account credentials", err)
		return
	}
	defer creds.Destroy()

	secretKey := creds.SecretKey().String()
	defer func() { secretKey = "" }() // best-effort: remove string reference

	loginBuf := combineLoginPassphrase(req.Passphrase, secretKey)
	defer loginBuf.Destroy()
	exported, err := vault.ExportCredentialsBytes(creds, loginBuf.Bytes())
	if err != nil {
		writeInternalError(w, "failed to export account credentials", err)
		return
	}
	defer util.WipeBytes(exported)
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
	defer func() { sessionSecret = "" }() // best-effort: remove string reference

	sessBuf := deriveSessionPassphrase(token, sessionSecret)
	defer sessBuf.Destroy()
	sessionBlob, err := vault.ExportCredentialsBytes(creds, sessBuf.Bytes())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to initialize session")
		return
	}
	defer util.WipeBytes(sessionBlob)

	expiresAt := time.Now().Add(sessionDuration)
	a.sessions.Put(token, AuthSession{
		SecretKeyID:     record.SecretKeyID,
		CredentialsBlob: base64.StdEncoding.EncodeToString(sessionBlob),
		ExpiresAt:       expiresAt,
		LastAccessedAt:  time.Now(),
	})
	writeSessionCookie(w, r, token, expiresAt, a.trustedProxies)
	writeSessionSecretCookie(w, r, sessionSecret, expiresAt, a.trustedProxies)
	writeCSRFCookie(w, r, a.trustedProxies)

	a.audit.logEvent(AuditRegister, r, record.SecretKeyID)
	writeJSON(w, http.StatusCreated, RegisterResponse{SecretKey: secretKey})
}

// Login handles POST /auth/login.
func (a *API) Login(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeJSON[LoginRequest](w, r, maxAuthBodySize)
	if !ok {
		return
	}
	defer func() { req.Passphrase = ""; req.SecretKey = ""; req.RecoveryCode = "" }() // best-effort: remove string references
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

	// Enforce passkey login based on the account's passkey policy.
	// When policy is "required" (or unset, the default), password-based
	// login is only permitted with a valid recovery code.
	// When policy is "optional", password+TOTP login is allowed even
	// with passkeys registered.
	var recoveryCodeUsedIdx = -1
	if len(record.WebAuthnCredentials) > 0 {
		policy := record.PasskeyPolicy
		if policy == "" {
			policy = "required"
		}
		if policy == "required" {
			if req.RecoveryCode == "" {
				// No recovery code provided — passkey is required.
				a.audit.logFailure(AuditLoginFailure, r, "passkey required, password login rejected",
					slog.String("account_id", record.SecretKeyID))
				writeError(w, http.StatusForbidden, "passkey_required")
				return
			}
			idx, valid := validateRecoveryCode(record.RecoveryCodes, req.RecoveryCode)
			if !valid {
				recordLoginFailure()
				a.audit.logFailure(AuditLoginFailure, r, "invalid recovery code",
					slog.String("account_id", record.SecretKeyID))
				writeError(w, http.StatusUnauthorized, "invalid credentials")
				return
			}
			// Mark the code as used BEFORE passphrase validation to prevent
			// brute-force reuse if the passphrase check fails.
			record.RecoveryCodes[idx].Used = true
			recoveryCodeUsedIdx = idx
		}
		// "optional": skip enforcement, fall through to TOTP/passphrase checks
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
	loginBuf := combineLoginPassphrase(req.Passphrase, req.SecretKey)
	defer loginBuf.Destroy()
	creds, err := vault.ImportCredentialsBytes(blob, loginBuf.Bytes())
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
	defer func() { sessionSecret = "" }() // best-effort: remove string reference

	sessBuf := deriveSessionPassphrase(token, sessionSecret)
	defer sessBuf.Destroy()
	sessionBlob, err := vault.ExportCredentialsBytes(creds, sessBuf.Bytes())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to initialize session")
		return
	}
	defer util.WipeBytes(sessionBlob)

	// Login succeeded — clear rate-limit state.
	a.rateLimiter.recordSuccess(accountID)
	a.ipLimiter.recordSuccess(clientIP)

	// Persist consumed recovery code (if one was used).
	if recoveryCodeUsedIdx >= 0 {
		if err := a.updateAccountRecord(req.SecretKey, *record); err != nil {
			// Non-fatal: the login session will proceed but the code
			// won't be marked used on disk. Log and continue.
			slog.Warn("failed to persist consumed recovery code",
				slog.String("account_id", record.SecretKeyID),
				slog.String("error", err.Error()))
		}
		a.audit.logEvent(AuditRecoveryCodeUsed, r, record.SecretKeyID,
			slog.Int("codes_remaining", countUnusedRecoveryCodes(record.RecoveryCodes)))
	}

	expiresAt := time.Now().Add(sessionDuration)
	a.sessions.Put(token, AuthSession{
		SecretKeyID:     record.SecretKeyID,
		CredentialsBlob: base64.StdEncoding.EncodeToString(sessionBlob),
		ExpiresAt:       expiresAt,
		LastAccessedAt:  time.Now(),
	})
	writeSessionCookie(w, r, token, expiresAt, a.trustedProxies)
	writeSessionSecretCookie(w, r, sessionSecret, expiresAt, a.trustedProxies)
	writeCSRFCookie(w, r, a.trustedProxies)

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
	sk := creds.SecretKey().String()
	defer func() { sk = "" }()
	record, err := a.loadAccountRecord(sk)
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
	defer func() { secret = "" }() // best-effort: remove string reference

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
	defer func() { secretKey = "" }() // best-effort: remove string reference
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

// DisableTwoFactor handles POST /auth/2fa/disable.
func (a *API) DisableTwoFactor(w http.ResponseWriter, r *http.Request) {
	creds := credentialsFromContext(r.Context())
	if creds == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	req, ok := decodeJSON[DisableTwoFactorRequest](w, r, maxAuthBodySize)
	if !ok {
		return
	}

	secretKey := creds.SecretKey().String()
	defer func() { secretKey = "" }()
	record, err := a.loadAccountRecord(secretKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load account")
		return
	}
	if !record.TOTPEnabled {
		writeError(w, http.StatusBadRequest, "2fa is not enabled")
		return
	}
	if !verifyTOTPCode(record.TOTPSecret, req.Code, time.Now()) {
		writeError(w, http.StatusUnauthorized, "invalid one-time code")
		return
	}

	record.TOTPEnabled = false
	record.TOTPSecret = ""
	if err := a.updateAccountRecord(secretKey, *record); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to disable 2fa")
		return
	}

	a.audit.logEvent(AuditTwoFactorDisabled, r, record.SecretKeyID)
	writeJSON(w, http.StatusOK, TwoFactorStatusResponse{Enabled: false})
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

// GetAuthSettings handles GET /auth/settings.
func (a *API) GetAuthSettings(w http.ResponseWriter, r *http.Request) {
	creds := credentialsFromContext(r.Context())
	if creds == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	sk := creds.SecretKey().String()
	defer func() { sk = "" }()
	record, err := a.loadAccountRecord(sk)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load account")
		return
	}
	policy := record.PasskeyPolicy
	if policy == "" {
		policy = "required"
	}
	writeJSON(w, http.StatusOK, AuthSettingsResponse{
		PasskeyPolicy: policy,
		TOTPEnabled:   record.TOTPEnabled,
	})
}

// UpdateAuthSettings handles PUT /auth/settings.
func (a *API) UpdateAuthSettings(w http.ResponseWriter, r *http.Request) {
	creds := credentialsFromContext(r.Context())
	if creds == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	req, ok := decodeJSON[UpdateAuthSettingsRequest](w, r, maxAuthBodySize)
	if !ok {
		return
	}
	if req.PasskeyPolicy != "optional" && req.PasskeyPolicy != "required" {
		writeError(w, http.StatusBadRequest, "passkey_policy must be \"optional\" or \"required\"")
		return
	}

	sk := creds.SecretKey().String()
	defer func() { sk = "" }()
	record, err := a.loadAccountRecord(sk)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load account")
		return
	}
	record.PasskeyPolicy = req.PasskeyPolicy
	if err := a.updateAccountRecord(sk, *record); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save settings")
		return
	}

	a.audit.logEvent(AuditAuthSettingsChanged, r, record.SecretKeyID,
		slog.String("passkey_policy", req.PasskeyPolicy))
	writeJSON(w, http.StatusOK, AuthSettingsResponse{
		PasskeyPolicy: req.PasskeyPolicy,
		TOTPEnabled:   record.TOTPEnabled,
	})
}

// RecoveryCodesStatus handles GET /auth/recovery-codes.
// Returns whether recovery codes exist and how many are unused.
func (a *API) RecoveryCodesStatus(w http.ResponseWriter, r *http.Request) {
	creds := credentialsFromContext(r.Context())
	if creds == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	sk := creds.SecretKey().String()
	defer func() { sk = "" }()
	record, err := a.loadAccountRecord(sk)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load account")
		return
	}
	unused := countUnusedRecoveryCodes(record.RecoveryCodes)
	writeJSON(w, http.StatusOK, RecoveryCodesStatusResponse{
		HasCodes:    len(record.RecoveryCodes) > 0,
		CodesTotal:  len(record.RecoveryCodes),
		CodesUnused: unused,
	})
}

// GenerateRecoveryCodes handles POST /auth/recovery-codes.
// Generates a new batch of recovery codes, replacing any existing ones.
// Returns the plaintext codes once — they are never stored.
func (a *API) GenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	creds := credentialsFromContext(r.Context())
	if creds == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	sk := creds.SecretKey().String()
	defer func() { sk = "" }()
	record, err := a.loadAccountRecord(sk)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load account")
		return
	}

	plaintext, hashed, err := generateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate recovery codes")
		return
	}

	record.RecoveryCodes = hashed
	if err := a.updateAccountRecord(sk, *record); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save recovery codes")
		return
	}

	a.audit.logEvent(AuditRecoveryCodesGenerated, r, record.SecretKeyID)
	writeJSON(w, http.StatusOK, GenerateRecoveryCodesResponse{Codes: plaintext})
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
	clearSessionCookie(w, r, a.trustedProxies)
	clearCSRFCookie(w, r, a.trustedProxies)
	a.audit.logEvent(AuditLogout, r, secretKeyID)
	writeJSON(w, http.StatusOK, struct{}{})
}
