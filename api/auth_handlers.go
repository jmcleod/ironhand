package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jmcleod/ironhand/internal/uuid"
	"github.com/jmcleod/ironhand/vault"
)

const sessionDuration = 24 * time.Hour

// Register handles POST /auth/register.
func (a *API) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.Passphrase == "" {
		writeError(w, http.StatusBadRequest, "passphrase is required")
		return
	}

	creds, err := vault.NewCredentials(req.Passphrase)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create account credentials: "+err.Error())
		return
	}
	defer creds.Destroy()

	secretKey := creds.SecretKey().String()
	loginPassphrase := combineLoginPassphrase(req.Passphrase, secretKey)
	exported, err := vault.ExportCredentials(creds, loginPassphrase)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to export account credentials: "+err.Error())
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

	sessionPassphrase := uuid.New()
	sessionBlob, err := vault.ExportCredentials(creds, sessionPassphrase)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to initialize session")
		return
	}

	token := uuid.New()
	expiresAt := time.Now().Add(sessionDuration)
	a.sessions.mu.Lock()
	a.sessions.data[token] = authSession{
		SecretKeyID:       record.SecretKeyID,
		SessionPassphrase: sessionPassphrase,
		CredentialsBlob:   base64.StdEncoding.EncodeToString(sessionBlob),
		ExpiresAt:         expiresAt,
	}
	a.sessions.mu.Unlock()
	writeSessionCookie(w, r, token, expiresAt)

	writeJSON(w, http.StatusCreated, RegisterResponse{SecretKey: secretKey})
}

// Login handles POST /auth/login.
func (a *API) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
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

	record, err := a.loadAccountRecord(req.SecretKey)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if record.TOTPEnabled && !verifyTOTPCode(record.TOTPSecret, req.TOTPCode, time.Now()) {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	blob, err := base64.StdEncoding.DecodeString(record.CredentialsBlob)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	loginPassphrase := combineLoginPassphrase(req.Passphrase, req.SecretKey)
	creds, err := vault.ImportCredentials(blob, loginPassphrase)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	defer creds.Destroy()

	sessionPassphrase := uuid.New()
	sessionBlob, err := vault.ExportCredentials(creds, sessionPassphrase)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to initialize session")
		return
	}

	token := uuid.New()
	expiresAt := time.Now().Add(sessionDuration)
	a.sessions.mu.Lock()
	a.sessions.data[token] = authSession{
		SecretKeyID:       record.SecretKeyID,
		SessionPassphrase: sessionPassphrase,
		CredentialsBlob:   base64.StdEncoding.EncodeToString(sessionBlob),
		ExpiresAt:         expiresAt,
	}
	a.sessions.mu.Unlock()
	writeSessionCookie(w, r, token, expiresAt)
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
	a.sessions.mu.Lock()
	a.sessions.data[token] = session
	a.sessions.mu.Unlock()

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

	var req EnableTwoFactorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
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
	a.sessions.mu.Lock()
	a.sessions.data[token] = session
	a.sessions.mu.Unlock()

	writeJSON(w, http.StatusOK, TwoFactorStatusResponse{Enabled: true})
}

func (a *API) sessionFromRequest(r *http.Request) (string, authSession, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return "", authSession{}, false
	}
	token := cookie.Value
	a.sessions.mu.RLock()
	session, ok := a.sessions.data[token]
	a.sessions.mu.RUnlock()
	if !ok || time.Now().After(session.ExpiresAt) {
		return "", authSession{}, false
	}
	return token, session, true
}

// Logout handles POST /auth/logout.
func (a *API) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil && cookie.Value != "" {
		a.sessions.mu.Lock()
		delete(a.sessions.data, cookie.Value)
		a.sessions.mu.Unlock()
	}
	clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, struct{}{})
}
