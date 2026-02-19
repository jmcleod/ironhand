package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
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
	a.sessions.mu.Lock()
	a.sessions.data[token] = session
	a.sessions.mu.Unlock()

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
	a.sessions.mu.Lock()
	a.sessions.data[token] = session
	a.sessions.mu.Unlock()

	writeJSON(w, http.StatusOK, struct {
		CredentialID string `json:"credential_id"`
	}{
		CredentialID: protocol.URLEncodedBase64(credential.ID).String(),
	})
}

// BeginWebAuthnLogin handles POST /auth/webauthn/login/begin.
// Starts the WebAuthn login ceremony. Requires secret_key in the body to
// identify the account, but does NOT require an active session.
func (a *API) BeginWebAuthnLogin(w http.ResponseWriter, r *http.Request) {
	if a.webauthn == nil {
		writeError(w, http.StatusNotFound, "webauthn not configured")
		return
	}

	var req struct {
		SecretKey string `json:"secret_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.SecretKey == "" {
		writeError(w, http.StatusBadRequest, "secret_key is required")
		return
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
		SessionData: string(sessionJSON),
		ExpiresAt:   time.Now().Add(webauthnCeremonyTTL),
	}
	a.webauthnCeremonyMu.Unlock()

	writeJSON(w, http.StatusOK, options)
}

// FinishWebAuthnLogin handles POST /auth/webauthn/login/finish.
// Completes the WebAuthn login ceremony.
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

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(state.SessionData), &sessionData); err != nil {
		writeError(w, http.StatusInternalServerError, "corrupt ceremony state")
		return
	}

	record, err := a.loadAccountRecord(state.SecretKey)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	user := newWebAuthnUser(record)

	_, err = a.webauthn.ValidateLogin(user, sessionData, parsedResponse)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "webauthn login failed: "+err.Error())
		return
	}

	a.audit.logEvent(AuditLoginSuccess, r, record.SecretKeyID)
	writeJSON(w, http.StatusOK, struct {
		Status string `json:"status"`
	}{Status: "webauthn_verified"})
}

// webauthnCeremonyState holds state for an in-progress WebAuthn login ceremony.
type webauthnCeremonyState struct {
	SecretKey   string
	SessionData string
	ExpiresAt   time.Time
}
