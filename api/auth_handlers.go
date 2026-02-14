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
	if err := a.saveAccountRecord(record); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to persist account: "+err.Error())
		return
	}

	token := uuid.New()
	expiresAt := time.Now().Add(sessionDuration)
	a.sessions.mu.Lock()
	a.sessions.data[token] = authSession{
		SecretKeyID:     record.SecretKeyID,
		LoginPassphrase: loginPassphrase,
		ExpiresAt:       expiresAt,
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

	secretKeyID, err := parseSecretKeyID(req.SecretKey)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	record, err := a.loadAccountRecord(secretKeyID)
	if err != nil {
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
	creds.Destroy()

	token := uuid.New()
	expiresAt := time.Now().Add(sessionDuration)
	a.sessions.mu.Lock()
	a.sessions.data[token] = authSession{
		SecretKeyID:     secretKeyID,
		LoginPassphrase: loginPassphrase,
		ExpiresAt:       expiresAt,
	}
	a.sessions.mu.Unlock()
	writeSessionCookie(w, r, token, expiresAt)
	writeJSON(w, http.StatusOK, struct{}{})
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
