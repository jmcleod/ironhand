package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

const stepUpTTL = 5 * time.Minute

// StepUpTOTP handles POST /auth/step-up.
// Verifies a TOTP code to grant a time-limited step-up session.
func (a *API) StepUpTOTP(w http.ResponseWriter, r *http.Request) {
	creds := credentialsFromContext(r.Context())
	if creds == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	req, ok := decodeJSON[StepUpTOTPRequest](w, r, maxAuthBodySize)
	if !ok {
		return
	}

	sk := creds.SecretKey().String()
	defer func() { sk = "" }()
	record, err := a.loadAccountRecord(sk)
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

	token, session, ok := a.sessionFromRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	now := time.Now()
	session.StepUpVerifiedAt = now
	session.StepUpMethod = "totp"
	a.sessions.Put(token, session)

	a.audit.logEvent(AuditStepUpTOTP, r, session.SecretKeyID)
	writeJSON(w, http.StatusOK, StepUpResponse{
		Verified:  true,
		Method:    "totp",
		ExpiresAt: now.Add(stepUpTTL).UTC().Format(time.RFC3339),
	})
}

// BeginStepUpPasskey handles POST /auth/step-up/passkey/begin.
// Starts a WebAuthn assertion ceremony for step-up authentication.
func (a *API) BeginStepUpPasskey(w http.ResponseWriter, r *http.Request) {
	if a.webauthn == nil {
		writeError(w, http.StatusNotFound, "webauthn not configured")
		return
	}

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
	if len(record.WebAuthnCredentials) == 0 {
		writeError(w, http.StatusBadRequest, "no passkeys registered")
		return
	}

	user := newWebAuthnUser(record)
	options, sessionData, err := a.webauthn.BeginLogin(user)
	if err != nil {
		writeInternalError(w, "failed to begin step-up passkey", err)
		return
	}

	token, session, ok := a.sessionFromRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	// Store ceremony state in the existing session fields.
	sdBytes, err := json.Marshal(sessionData)
	if err != nil {
		writeInternalError(w, "failed to serialize session data", err)
		return
	}
	session.WebAuthnSessionData = string(sdBytes)
	session.WebAuthnSessionExpiry = time.Now().Add(webauthnCeremonyTTL)
	a.sessions.Put(token, session)

	writeJSON(w, http.StatusOK, options)
}

// FinishStepUpPasskey handles POST /auth/step-up/passkey/finish.
// Completes the WebAuthn assertion and grants step-up authentication.
func (a *API) FinishStepUpPasskey(w http.ResponseWriter, r *http.Request) {
	if a.webauthn == nil {
		writeError(w, http.StatusNotFound, "webauthn not configured")
		return
	}

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

	token, session, ok := a.sessionFromRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	if session.WebAuthnSessionData == "" || time.Now().After(session.WebAuthnSessionExpiry) {
		writeError(w, http.StatusBadRequest, "step-up passkey ceremony expired; start again")
		return
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(session.WebAuthnSessionData), &sessionData); err != nil {
		writeError(w, http.StatusInternalServerError, "corrupt ceremony state")
		return
	}

	user := newWebAuthnUser(record)
	_, err = a.webauthn.FinishLogin(user, sessionData, r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "passkey verification failed")
		return
	}

	now := time.Now()
	session.StepUpVerifiedAt = now
	session.StepUpMethod = "passkey"
	session.WebAuthnSessionData = ""
	session.WebAuthnSessionExpiry = time.Time{}
	a.sessions.Put(token, session)

	a.audit.logEvent(AuditStepUpPasskey, r, session.SecretKeyID)
	writeJSON(w, http.StatusOK, StepUpResponse{
		Verified:  true,
		Method:    "passkey",
		ExpiresAt: now.Add(stepUpTTL).UTC().Format(time.RFC3339),
	})
}

// requireStepUp checks whether the current session has a valid step-up
// verification. If no MFA methods are configured, step-up is skipped.
// Returns true if the request may proceed, false if a 403 was written.
func (a *API) requireStepUp(w http.ResponseWriter, r *http.Request) bool {
	creds := credentialsFromContext(r.Context())
	if creds == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return false
	}

	sk := creds.SecretKey().String()
	defer func() { sk = "" }()
	record, err := a.loadAccountRecord(sk)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load account")
		return false
	}

	// Build the list of available step-up methods.
	var methods []string
	if record.TOTPEnabled {
		methods = append(methods, "totp")
	}
	if len(record.WebAuthnCredentials) > 0 {
		methods = append(methods, "passkey")
	}

	// If no MFA is configured, skip step-up (nothing to verify against).
	if len(methods) == 0 {
		return true
	}

	_, session, ok := a.sessionFromRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return false
	}

	// Check if step-up is still valid.
	if !session.StepUpVerifiedAt.IsZero() && time.Since(session.StepUpVerifiedAt) < stepUpTTL {
		return true
	}

	// Step-up required.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(StepUpRequiredResponse{
		Error:   "step_up_required",
		Methods: methods,
	})
	return false
}
