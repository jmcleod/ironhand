package api

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/jmcleod/ironhand/internal/uuid"
	"github.com/jmcleod/ironhand/vault"
)

const (
	webauthnCeremonyTTL = 5 * time.Minute
)

// webauthnUser adapts an accountRecord to the webauthn.User interface.
type webauthnUser struct {
	id          []byte
	name        string
	credentials []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte                         { return u.id }
func (u *webauthnUser) WebAuthnName() string                       { return u.name }
func (u *webauthnUser) WebAuthnDisplayName() string                { return u.name }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func newWebAuthnUser(record *accountRecord) *webauthnUser {
	return &webauthnUser{
		id:          []byte(record.SecretKeyID),
		name:        record.SecretKeyID,
		credentials: record.WebAuthnCredentials,
	}
}

// WebAuthnStatus handles GET /auth/webauthn/status.
// Returns whether WebAuthn is configured and how many credentials are registered.
func (a *API) WebAuthnStatus(w http.ResponseWriter, r *http.Request) {
	enabled := a.webauthn != nil
	credCount := 0

	creds := credentialsFromContext(r.Context())
	if creds != nil && enabled {
		record, err := a.loadAccountRecord(creds.SecretKey().String())
		if err == nil {
			credCount = len(record.WebAuthnCredentials)
		}
	}

	writeJSON(w, http.StatusOK, struct {
		Enabled         bool `json:"enabled"`
		CredentialCount int  `json:"credential_count"`
	}{
		Enabled:         enabled,
		CredentialCount: credCount,
	})
}

// BeginWebAuthnRegistration handles POST /auth/webauthn/register/begin.
// Starts the WebAuthn registration ceremony and returns the credential
// creation options.
func (a *API) BeginWebAuthnRegistration(w http.ResponseWriter, r *http.Request) {
	if a.webauthn == nil {
		writeError(w, http.StatusNotFound, "webauthn not configured")
		return
	}
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

	user := newWebAuthnUser(record)
	options, sessionData, err := a.webauthn.BeginRegistration(user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to begin webauthn registration: "+err.Error())
		return
	}

	// Store ceremony state in the session.
	token, session, ok := a.sessionFromRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to serialize ceremony state")
		return
	}
	session.WebAuthnSessionData = string(sessionJSON)
	session.WebAuthnSessionExpiry = time.Now().Add(webauthnCeremonyTTL)
	a.sessions.Put(token, session)

	writeJSON(w, http.StatusOK, options)
}

// FinishWebAuthnRegistration handles POST /auth/webauthn/register/finish.
// Completes the registration ceremony and stores the credential.
func (a *API) FinishWebAuthnRegistration(w http.ResponseWriter, r *http.Request) {
	if a.webauthn == nil {
		writeError(w, http.StatusNotFound, "webauthn not configured")
		return
	}
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
	if session.WebAuthnSessionData == "" || time.Now().After(session.WebAuthnSessionExpiry) {
		writeError(w, http.StatusBadRequest, "webauthn registration expired; start again")
		return
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(session.WebAuthnSessionData), &sessionData); err != nil {
		writeError(w, http.StatusInternalServerError, "corrupt ceremony state")
		return
	}

	record, err := a.loadAccountRecord(creds.SecretKey().String())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load account")
		return
	}
	user := newWebAuthnUser(record)

	credential, err := a.webauthn.FinishRegistration(user, sessionData, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "webauthn registration failed: "+err.Error())
		return
	}

	// Store the new credential on the account.
	record.WebAuthnCredentials = append(record.WebAuthnCredentials, *credential)
	secretKey := creds.SecretKey().String()
	if err := a.updateAccountRecord(secretKey, *record); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save webauthn credential")
		return
	}

	// Clear ceremony state.
	session.WebAuthnSessionData = ""
	session.WebAuthnSessionExpiry = time.Time{}
	a.sessions.Put(token, session)

	a.audit.logEvent(AuditWebAuthnRegistered, r, record.SecretKeyID)
	writeJSON(w, http.StatusOK, struct {
		CredentialID string `json:"credential_id"`
	}{
		CredentialID: protocol.URLEncodedBase64(credential.ID).String(),
	})
}

// BeginWebAuthnLogin handles POST /auth/webauthn/login/begin.
// Starts the WebAuthn login ceremony. Requires secret_key and passphrase in
// the body — the passphrase is needed for vault decryption after successful
// WebAuthn verification.
func (a *API) BeginWebAuthnLogin(w http.ResponseWriter, r *http.Request) {
	if a.webauthn == nil {
		writeError(w, http.StatusNotFound, "webauthn not configured")
		return
	}

	var req struct {
		SecretKey  string `json:"secret_key"`
		Passphrase string `json:"passphrase"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.SecretKey == "" {
		writeError(w, http.StatusBadRequest, "secret_key is required")
		return
	}
	if req.Passphrase == "" {
		writeError(w, http.StatusBadRequest, "passphrase is required")
		return
	}

	// Rate-limit checks — same pattern as Login handler.
	accountID, _ := accountLookupID(req.SecretKey)
	clientIP := extractClientIP(r)
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

	record, err := a.loadAccountRecord(req.SecretKey)
	if err != nil || len(record.WebAuthnCredentials) == 0 {
		writeError(w, http.StatusBadRequest, "no webauthn credentials registered")
		return
	}

	user := newWebAuthnUser(record)
	options, sessionData, err := a.webauthn.BeginLogin(user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to begin webauthn login: "+err.Error())
		return
	}

	// Store ceremony state keyed by the challenge to retrieve later.
	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to serialize ceremony state")
		return
	}

	a.webauthnCeremonyMu.Lock()
	a.webauthnCeremonies[sessionData.Challenge] = webauthnCeremonyState{
		SecretKey:   req.SecretKey,
		Passphrase:  req.Passphrase,
		SessionData: string(sessionJSON),
		ExpiresAt:   time.Now().Add(webauthnCeremonyTTL),
	}
	a.webauthnCeremonyMu.Unlock()

	writeJSON(w, http.StatusOK, options)
}

// FinishWebAuthnLogin handles POST /auth/webauthn/login/finish.
// Completes the WebAuthn login ceremony and creates a full session.
func (a *API) FinishWebAuthnLogin(w http.ResponseWriter, r *http.Request) {
	if a.webauthn == nil {
		writeError(w, http.StatusNotFound, "webauthn not configured")
		return
	}

	// Parse the credential assertion to extract the challenge.
	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid webauthn response: "+err.Error())
		return
	}

	challenge := parsedResponse.Response.CollectedClientData.Challenge

	a.webauthnCeremonyMu.Lock()
	state, ok := a.webauthnCeremonies[challenge]
	if ok {
		delete(a.webauthnCeremonies, challenge)
	}
	a.webauthnCeremonyMu.Unlock()

	if !ok || time.Now().After(state.ExpiresAt) {
		writeError(w, http.StatusBadRequest, "webauthn login expired; start again")
		return
	}

	// Rate-limit recording helpers.
	accountID, _ := accountLookupID(state.SecretKey)
	clientIP := extractClientIP(r)
	recordLoginFailure := func() {
		a.globalLimiter.recordFailure()
		a.ipLimiter.recordFailure(clientIP)
		if accountID != "" {
			a.rateLimiter.recordFailure(accountID)
		}
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(state.SessionData), &sessionData); err != nil {
		writeError(w, http.StatusInternalServerError, "corrupt ceremony state")
		return
	}

	record, err := a.loadAccountRecord(state.SecretKey)
	if err != nil {
		recordLoginFailure()
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	user := newWebAuthnUser(record)

	_, err = a.webauthn.ValidateLogin(user, sessionData, parsedResponse)
	if err != nil {
		recordLoginFailure()
		a.audit.logFailure(AuditLoginFailure, r, "webauthn validation failed",
			slog.String("account_id", record.SecretKeyID))
		writeError(w, http.StatusUnauthorized, "webauthn login failed: "+err.Error())
		return
	}

	// WebAuthn verified — now decrypt the credentials blob to create a
	// session, exactly like the password-based Login handler.
	blob, err := base64.StdEncoding.DecodeString(record.CredentialsBlob)
	if err != nil {
		recordLoginFailure()
		a.audit.logFailure(AuditLoginFailure, r, "corrupt credentials blob",
			slog.String("account_id", record.SecretKeyID))
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	loginPassphrase := combineLoginPassphrase(state.Passphrase, state.SecretKey)
	creds, err := vault.ImportCredentials(blob, loginPassphrase)
	if err != nil {
		recordLoginFailure()
		a.audit.logFailure(AuditLoginFailure, r, "invalid passphrase (webauthn)",
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

	a.audit.logEvent(AuditWebAuthnLoginSuccess, r, record.SecretKeyID)
	writeJSON(w, http.StatusOK, struct{}{})
}

// webauthnCeremonyState holds state for an in-progress WebAuthn login ceremony.
type webauthnCeremonyState struct {
	SecretKey   string
	Passphrase  string
	SessionData string
	ExpiresAt   time.Time
}
