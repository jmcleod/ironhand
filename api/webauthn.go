package api

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/awnumar/memguard"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/jmcleod/ironhand/internal/util"
	"github.com/jmcleod/ironhand/internal/uuid"
	"github.com/jmcleod/ironhand/vault"
)

const (
	webauthnCeremonyTTL = 5 * time.Minute
	// maxCeremonyEntries is the hard cap on concurrent WebAuthn login
	// ceremonies. When inserting a new ceremony would exceed this limit,
	// expired entries are evicted first. If active ceremonies still exceed
	// the cap after eviction, the new ceremony is rejected with 503.
	maxCeremonyEntries = 1000
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
		writeInternalError(w, "failed to begin webauthn registration", err)
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
	// Cap body size before the WebAuthn library reads from r.
	r.Body = http.MaxBytesReader(w, r.Body, maxWebAuthnBodySize)

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
		slog.Warn("webauthn registration failed",
			slog.String("error", err.Error()))
		writeError(w, http.StatusBadRequest, "webauthn registration failed")
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
	r.Body = http.MaxBytesReader(w, r.Body, maxAuthBodySize)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	defer func() { req.Passphrase = ""; req.SecretKey = "" }() // best-effort: remove string references
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
	clientIP := a.extractClientIP(r)
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
		writeInternalError(w, "failed to begin webauthn login", err)
		return
	}

	// Derive the login passphrase immediately and seal it into a memguard
	// Enclave (encrypted at rest in memory). The raw passphrase and secret
	// key are combined into the login passphrase that ImportCredentials
	// needs later. By computing and sealing it now we avoid retaining
	// plaintext secrets in ceremony state.
	loginBuf := combineLoginPassphrase(req.Passphrase, req.SecretKey)
	loginEnclave := loginBuf.Seal() // melts, encrypts, and destroys loginBuf

	// Seal the secret key into an Enclave for at-rest protection.
	skBytes := []byte(req.SecretKey)
	skEnclave := memguard.NewEnclave(skBytes) // encrypts + wipes skBytes

	// Evict expired ceremonies before inserting to bound memory usage.
	a.webauthnCeremonyMu.Lock()
	a.evictExpiredCeremoniesLocked()

	// Hard-cap: reject if active ceremonies still exceed the limit after
	// eviction. This prevents an attacker from flooding the map faster
	// than entries expire.
	if len(a.webauthnCeremonies) >= maxCeremonyEntries {
		a.webauthnCeremonyMu.Unlock()
		a.audit.logFailure(AuditCeremonyCapExceeded, r, "webauthn ceremony cap exceeded",
			slog.Int("active_ceremonies", len(a.webauthnCeremonies)))
		if a.metrics != nil {
			a.metrics.recordCeremonyPressure(len(a.webauthnCeremonies))
		}
		writeError(w, http.StatusServiceUnavailable, "too many active login ceremonies; try again later")
		return
	}

	a.webauthnCeremonies[sessionData.Challenge] = webauthnCeremonyState{
		SecretKey:       skEnclave,
		LoginPassphrase: loginEnclave,
		SessionData:     *sessionData,
		ExpiresAt:       time.Now().Add(webauthnCeremonyTTL),
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

	// Cap body size before handing off to the WebAuthn library.
	r.Body = http.MaxBytesReader(w, r.Body, maxWebAuthnBodySize)

	// Parse the credential assertion to extract the challenge.
	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid webauthn response")
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

	// Open the secret key Enclave for account lookup and rate limiting.
	skBuf, err := state.SecretKey.Open()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer skBuf.Destroy()
	secretKey := string(skBuf.Bytes()) // short-lived string for accountLookupID/loadAccountRecord
	defer func() { secretKey = "" }()  // best-effort: remove string reference

	// Rate-limit recording helpers.
	accountID, _ := accountLookupID(secretKey)
	clientIP := a.extractClientIP(r)
	recordLoginFailure := func() {
		a.globalLimiter.recordFailure()
		a.ipLimiter.recordFailure(clientIP)
		if accountID != "" {
			a.rateLimiter.recordFailure(accountID)
		}
	}

	record, err := a.loadAccountRecord(secretKey)
	if err != nil {
		recordLoginFailure()
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	user := newWebAuthnUser(record)

	_, err = a.webauthn.ValidateLogin(user, state.SessionData, parsedResponse)
	if err != nil {
		recordLoginFailure()
		a.audit.logFailure(AuditLoginFailure, r, "webauthn validation failed",
			slog.String("account_id", record.SecretKeyID),
			slog.String("error", err.Error()))
		writeError(w, http.StatusUnauthorized, "invalid credentials")
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
	defer util.WipeBytes(blob)

	// Open the login passphrase Enclave for credential import.
	lpBuf, err := state.LoginPassphrase.Open()
	if err != nil {
		recordLoginFailure()
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer lpBuf.Destroy()
	creds, err := vault.ImportCredentialsBytes(blob, lpBuf.Bytes())
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

	a.audit.logEvent(AuditWebAuthnLoginSuccess, r, record.SecretKeyID)
	writeJSON(w, http.StatusOK, struct{}{})
}

// webauthnCeremonyState holds state for an in-progress WebAuthn login ceremony.
//
// The raw passphrase is NOT stored. Instead, LoginPassphrase holds the
// pre-derived login passphrase (passphrase + ":" + secretKey) sealed inside
// a memguard Enclave (encrypted at rest in memory). The SecretKey is also
// stored as an Enclave. Both are only opened briefly when the ceremony
// completes. This minimises the lifetime and exposure of secret material
// while ceremonies sit in the map for up to 5 minutes.
//
// SessionData is stored as the typed webauthn.SessionData directly,
// avoiding unnecessary marshal/unmarshal churn.
type webauthnCeremonyState struct {
	SecretKey       *memguard.Enclave
	LoginPassphrase *memguard.Enclave
	SessionData     webauthn.SessionData
	ExpiresAt       time.Time
}

// evictExpiredCeremoniesLocked removes all expired ceremonies from the map.
// The caller must hold a.webauthnCeremonyMu.
//
// Enclaves store data encrypted at rest; the GC reclaims them safely — no
// explicit Destroy is needed for *memguard.Enclave.
func (a *API) evictExpiredCeremoniesLocked() {
	now := time.Now()
	for k, v := range a.webauthnCeremonies {
		if now.After(v.ExpiresAt) {
			delete(a.webauthnCeremonies, k)
			_ = v // Enclaves hold only ciphertext; GC-safe.
		}
	}
}
