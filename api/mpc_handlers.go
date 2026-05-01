package api

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/jmcleod/ironhand/internal/mpc"
	"github.com/jmcleod/ironhand/internal/mpcsigner"
	"github.com/jmcleod/ironhand/internal/uuid"
	"github.com/jmcleod/ironhand/vault"
)

func (a *API) requireExperimentalMPC(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.experimentalMPCEnabled {
			writeError(w, http.StatusForbidden, "experimental MPC is disabled; start the server with --enable-experimental-mpc to use experimental-p256-schnorr-v1")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) ListMPCProviders(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, struct {
		Providers []mpc.ProviderInfo `json:"providers"`
	}{Providers: mpc.SupportedProviders()})
}

func (a *API) GetMPCMetrics(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	creds := credentialsFromContext(r.Context())

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()
	metrics, err := session.MPCMetrics(r.Context())
	if err != nil {
		mapError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, MPCMetricsResponse(*metrics))
}

func (a *API) validateMPCProviderForUse(algorithm string) error {
	provider, err := mpc.GetProvider(algorithm)
	if err != nil {
		return vault.ValidationError{Message: err.Error()}
	}
	info := provider.Info()
	if a.mpcProductionMode && !info.ProductionReady {
		message := fmt.Sprintf("MPC provider %q is not production ready", info.Algorithm)
		if len(info.ProductionBlockers) > 0 {
			message = fmt.Sprintf("%s: %v", message, info.ProductionBlockers)
		}
		return vault.ValidationError{Message: message}
	}
	return nil
}

func (a *API) RegisterMPCSigner(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	memberID := chi.URLParam(r, "memberID")
	creds := credentialsFromContext(r.Context())

	if !a.requireStepUp(w, r) {
		return
	}
	req, ok := decodeJSON[RegisterMPCSignerRequest](w, r, maxSmallBodySize)
	if !ok {
		return
	}
	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	if err := session.RegisterMPCSigner(r.Context(), memberID, vault.MPCSignerRegistration{
		URL:                 req.URL,
		EncryptionPublicKey: req.EncryptionPublicKey,
		ApprovalPublicKey:   req.ApprovalPublicKey,
		Status:              vault.MPCSignerStatus(req.Status),
	}); err != nil {
		mapError(w, err)
		return
	}
	a.audit.logEvent(AuditMPCSignerRegistered, r, creds.SecretKey().ID(),
		slog.String("vault_id", vaultID),
		slog.String("member_id", memberID))
	writeJSON(w, http.StatusOK, struct{}{})
}

func (a *API) CreateMPCKey(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	creds := credentialsFromContext(r.Context())

	if !a.requireStepUp(w, r) {
		return
	}
	req, ok := decodeJSON[CreateMPCKeyRequest](w, r, maxSmallBodySize)
	if !ok {
		return
	}
	if err := a.validateMPCProviderForUse(req.Algorithm); err != nil {
		mapError(w, err)
		return
	}
	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	var dkg *mpcDKGOrchestration
	hasManualArtifacts := len(req.Commitments) > 0 || len(req.Fragments) > 0
	if !hasManualArtifacts {
		prepared, orchestration, err := a.orchestrateMPCDKG(r.Context(), session, vaultID, req)
		if err != nil {
			mapError(w, err)
			return
		}
		req = prepared
		dkg = orchestration
		req.DKGSessionID = orchestration.SessionID
	} else {
		if req.ImportMode != string(vault.MPCKeyImportModeRecovery) {
			writeError(w, http.StatusBadRequest, "manual MPC key artifacts require import_mode \"recovery\"")
			return
		}
		if !a.mpcRecoveryImportEnabled {
			writeError(w, http.StatusForbidden, "MPC recovery import is disabled; start the server with --enable-mpc-recovery-import to accept manual recovery artifacts")
			return
		}
		if len(req.Commitments) == 0 || len(req.Fragments) == 0 {
			writeError(w, http.StatusBadRequest, "recovery MPC key import requires commitments and fragments")
			return
		}
		if req.DKGSessionID == "" {
			writeError(w, http.StatusBadRequest, "recovery MPC key import requires dkg_session_id")
			return
		}
	}
	key, err := session.CreateMPCKey(r.Context(), vault.MPCKeyCreate{
		KeyID:        req.KeyID,
		Algorithm:    req.Algorithm,
		ImportMode:   vault.MPCKeyImportMode(req.ImportMode),
		DKGSessionID: req.DKGSessionID,
		Threshold:    req.Threshold,
		MemberIDs:    req.MemberIDs,
		Commitments:  req.Commitments,
		Fragments:    req.Fragments,
		Policy:       req.Policy,
	})
	if err != nil {
		if dkg != nil {
			a.abortMPCDKG(r.Context(), dkg)
			if attempt, getErr := session.GetMPCDKGAttempt(r.Context(), dkg.SessionID); getErr == nil {
				attempt.Status = vault.MPCDKGStatusAborted
				attempt.LastError = err.Error()
				_, _ = session.SaveMPCDKGAttempt(r.Context(), *attempt)
			}
		}
		mapError(w, err)
		return
	}
	if dkg != nil {
		if err := a.commitMPCDKG(r.Context(), dkg); err != nil {
			_, _ = session.SetMPCKeyStatus(r.Context(), key.KeyID, vault.MPCKeyStatusDisabled)
			if attempt, getErr := session.GetMPCDKGAttempt(r.Context(), dkg.SessionID); getErr == nil {
				attempt.Status = vault.MPCDKGStatusFailed
				attempt.LastError = err.Error()
				_, _ = session.SaveMPCDKGAttempt(r.Context(), *attempt)
			}
			mapError(w, err)
			return
		}
		if attempt, err := session.GetMPCDKGAttempt(r.Context(), dkg.SessionID); err == nil {
			attempt.Status = vault.MPCDKGStatusCommitted
			attempt.LastError = ""
			_, _ = session.SaveMPCDKGAttempt(r.Context(), *attempt)
		}
		a.audit.logEvent(AuditMPCDKGCommitted, r, creds.SecretKey().ID(),
			slog.String("vault_id", vaultID),
			slog.String("mpc_key_id", key.KeyID),
			slog.String("dkg_session_id", dkg.SessionID))
	}
	a.audit.logEvent(AuditMPCKeyCreated, r, creds.SecretKey().ID(),
		slog.String("vault_id", vaultID),
		slog.String("mpc_key_id", key.KeyID),
		slog.Int("threshold", key.Threshold))
	writeJSON(w, http.StatusCreated, MPCKeyResponse(*key))
}

func (a *API) ListMPCKeys(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	creds := credentialsFromContext(r.Context())

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	keys, err := session.ListMPCKeys(r.Context())
	if err != nil {
		mapError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Keys []vault.MPCKey `json:"keys"`
	}{Keys: keys})
}

func (a *API) GetMPCKey(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	keyID := chi.URLParam(r, "keyID")
	creds := credentialsFromContext(r.Context())

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	key, err := session.GetMPCKey(r.Context(), keyID)
	if err != nil {
		mapError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, MPCKeyResponse(*key))
}

func (a *API) UpdateMPCKeyStatus(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	keyID := chi.URLParam(r, "keyID")
	creds := credentialsFromContext(r.Context())

	if !a.requireStepUp(w, r) {
		return
	}
	req, ok := decodeJSON[UpdateMPCKeyStatusRequest](w, r, maxSmallBodySize)
	if !ok {
		return
	}
	if req.Status == "" {
		writeError(w, http.StatusBadRequest, "status is required")
		return
	}
	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	key, err := session.SetMPCKeyStatus(r.Context(), keyID, req.Status)
	if err != nil {
		mapError(w, err)
		return
	}
	a.audit.logEvent(AuditMPCKeyStatusChanged, r, creds.SecretKey().ID(),
		slog.String("vault_id", vaultID),
		slog.String("mpc_key_id", key.KeyID),
		slog.String("status", string(key.Status)))
	writeJSON(w, http.StatusOK, MPCKeyResponse(*key))
}

func (a *API) RotateMPCKey(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	keyID := chi.URLParam(r, "keyID")
	creds := credentialsFromContext(r.Context())

	if !a.requireStepUp(w, r) {
		return
	}
	req, ok := decodeJSON[RotateMPCKeyRequest](w, r, maxSmallBodySize)
	if !ok {
		return
	}
	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	oldKey, err := session.GetMPCKey(r.Context(), keyID)
	if err != nil {
		mapError(w, err)
		return
	}
	if err := a.validateMPCProviderForUse(oldKey.Algorithm); err != nil {
		mapError(w, err)
		return
	}
	if oldKey.Status == vault.MPCKeyStatusDestroyed {
		writeError(w, http.StatusConflict, "destroyed MPC keys cannot be rotated")
		return
	}
	memberIDs := req.MemberIDs
	if len(memberIDs) == 0 {
		memberIDs, err = activeReplacementMembers(r.Context(), session, oldKey)
		if err != nil {
			mapError(w, err)
			return
		}
	}
	threshold := req.Threshold
	if threshold == 0 {
		threshold = oldKey.Threshold
	}
	policy := req.Policy
	if policy.ApprovalMode == "" && len(policy.AllowedRoles) == 0 && len(policy.AllowedDestinations) == 0 && len(policy.DeniedDestinations) == 0 && policy.MaxValue == "" {
		policy = oldKey.Policy
	}
	newKeyID := req.KeyID
	if newKeyID == "" {
		newKeyID = uuid.New()
	}
	createReq := CreateMPCKeyRequest{KeyID: newKeyID, Algorithm: oldKey.Algorithm, Threshold: threshold, MemberIDs: memberIDs, Policy: policy}
	prepared, dkg, err := a.orchestrateMPCDKG(r.Context(), session, vaultID, createReq)
	if err != nil {
		mapError(w, err)
		return
	}
	key, err := session.CreateMPCKey(r.Context(), vault.MPCKeyCreate{
		KeyID:         prepared.KeyID,
		Algorithm:     prepared.Algorithm,
		ImportMode:    vault.MPCKeyImportModeOrchestrated,
		DKGSessionID:  dkg.SessionID,
		Threshold:     prepared.Threshold,
		MemberIDs:     prepared.MemberIDs,
		Commitments:   prepared.Commitments,
		Fragments:     prepared.Fragments,
		Policy:        prepared.Policy,
		ReplacesKeyID: oldKey.KeyID,
	})
	if err != nil {
		a.abortMPCDKG(r.Context(), dkg)
		mapError(w, err)
		return
	}
	if err := a.commitMPCDKG(r.Context(), dkg); err != nil {
		_, _ = session.SetMPCKeyStatus(r.Context(), key.KeyID, vault.MPCKeyStatusDisabled)
		if attempt, getErr := session.GetMPCDKGAttempt(r.Context(), dkg.SessionID); getErr == nil {
			attempt.Status = vault.MPCDKGStatusFailed
			attempt.LastError = err.Error()
			_, _ = session.SaveMPCDKGAttempt(r.Context(), *attempt)
		}
		mapError(w, err)
		return
	}
	a.audit.logEvent(AuditMPCDKGCommitted, r, creds.SecretKey().ID(),
		slog.String("vault_id", vaultID),
		slog.String("mpc_key_id", key.KeyID),
		slog.String("dkg_session_id", dkg.SessionID))
	if req.ArchiveOld == nil || *req.ArchiveOld {
		if _, err := session.MarkMPCKeyReplaced(r.Context(), oldKey.KeyID, key.KeyID); err != nil {
			mapError(w, err)
			return
		}
	}
	a.audit.logEvent(AuditMPCKeyRotated, r, creds.SecretKey().ID(),
		slog.String("vault_id", vaultID),
		slog.String("old_mpc_key_id", oldKey.KeyID),
		slog.String("new_mpc_key_id", key.KeyID),
		slog.Int("threshold", key.Threshold))
	writeJSON(w, http.StatusCreated, MPCKeyResponse(*key))
}

func (a *API) ListMPCDKGAttempts(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	creds := credentialsFromContext(r.Context())

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	attempts, err := session.ListMPCDKGAttempts(r.Context())
	if err != nil {
		mapError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Attempts []vault.MPCDKGAttempt `json:"attempts"`
	}{Attempts: attempts})
}

func (a *API) ListMPCSigningSessions(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	creds := credentialsFromContext(r.Context())

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	sessions, err := session.ListMPCSigningSessions(r.Context())
	if err != nil {
		mapError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Sessions []vault.MPCSigningSession `json:"sessions"`
	}{Sessions: sessions})
}

func (a *API) GetMPCDKGAttempt(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	dkgSessionID := chi.URLParam(r, "dkgSessionID")
	creds := credentialsFromContext(r.Context())

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	attempt, err := session.GetMPCDKGAttempt(r.Context(), dkgSessionID)
	if err != nil {
		mapError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, MPCDKGAttemptResponse(*attempt))
}

func (a *API) AbortMPCDKGAttempt(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	dkgSessionID := chi.URLParam(r, "dkgSessionID")
	creds := credentialsFromContext(r.Context())

	if !a.requireStepUp(w, r) {
		return
	}
	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	attempt, err := session.GetMPCDKGAttempt(r.Context(), dkgSessionID)
	if err != nil {
		mapError(w, err)
		return
	}
	if attempt.Status == vault.MPCDKGStatusCommitted {
		writeError(w, http.StatusConflict, "committed MPC DKG attempts cannot be aborted")
		return
	}
	dkg := &mpcDKGOrchestration{SessionID: attempt.DKGSessionID, KeyID: attempt.KeyID, Members: signerMembersFromDKGAttempt(attempt)}
	a.abortMPCDKG(r.Context(), dkg)
	attempt.Status = vault.MPCDKGStatusAborted
	attempt.LastError = "aborted by operator"
	attempt, err = session.SaveMPCDKGAttempt(r.Context(), *attempt)
	if err != nil {
		mapError(w, err)
		return
	}
	a.audit.logEvent(AuditMPCDKGAborted, r, creds.SecretKey().ID(),
		slog.String("vault_id", vaultID),
		slog.String("mpc_key_id", attempt.KeyID),
		slog.String("dkg_session_id", attempt.DKGSessionID))
	writeJSON(w, http.StatusOK, MPCDKGAttemptResponse(*attempt))
}

func (a *API) CreateMPCSigningSession(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	keyID := chi.URLParam(r, "keyID")
	creds := credentialsFromContext(r.Context())

	if !a.requireStepUp(w, r) {
		return
	}
	req, ok := decodeJSON[CreateMPCSigningSessionRequest](w, r, maxSmallBodySize)
	if !ok {
		return
	}
	message, err := base64.StdEncoding.DecodeString(req.MessageBase64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "message_base64 must be valid base64")
		return
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()
	key, err := session.GetMPCKey(r.Context(), keyID)
	if err != nil {
		mapError(w, err)
		return
	}
	if err := a.validateMPCProviderForUse(key.Algorithm); err != nil {
		mapError(w, err)
		return
	}

	signingSession, err := session.CreateMPCSigningSessionWithOptions(r.Context(), keyID, vault.MPCSigningSessionCreate{
		Message:      message,
		Participants: req.Participants,
		TTL:          ttl,
		MessageType:  req.MessageType,
		Chain:        req.Chain,
		Network:      req.Network,
		Transaction:  req.TransactionMetadata,
	})
	if err != nil {
		mapError(w, err)
		return
	}
	a.audit.logEvent(AuditMPCSigningRequested, r, creds.SecretKey().ID(),
		slog.String("vault_id", vaultID),
		slog.String("mpc_key_id", keyID),
		slog.String("mpc_session_id", signingSession.SessionID))
	writeJSON(w, http.StatusCreated, MPCSigningSessionResponse(*signingSession))
}

func (a *API) AddMPCApproval(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	sessionID := chi.URLParam(r, "sessionID")
	creds := credentialsFromContext(r.Context())

	if !a.requireStepUp(w, r) {
		return
	}
	req, ok := decodeJSON[AddMPCApprovalRequest](w, r, maxSmallBodySize)
	if !ok {
		return
	}
	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	if req.Approval.Signature == "" {
		partyID := req.PartyID
		if partyID == 0 {
			writeError(w, http.StatusBadRequest, "party_id is required when approval is omitted")
			return
		}
		signingSession, err := a.requestMPCSessionApprovalWithSigner(r.Context(), session, sessionID, partyID)
		if err != nil {
			mapError(w, err)
			return
		}
		a.audit.logEvent(AuditMPCSigningApprovalRequested, r, creds.SecretKey().ID(),
			slog.String("vault_id", vaultID),
			slog.String("mpc_key_id", signingSession.KeyID),
			slog.String("mpc_session_id", signingSession.SessionID),
			slog.Int("party_id", int(partyID)))
		writeJSON(w, http.StatusAccepted, MPCSigningSessionResponse(*signingSession))
		return
	}
	signingSession, err := session.AddMPCApproval(r.Context(), sessionID, req.Approval)
	if err != nil {
		mapError(w, err)
		return
	}
	a.audit.logEvent(AuditMPCSigningApproved, r, creds.SecretKey().ID(),
		slog.String("vault_id", vaultID),
		slog.String("mpc_key_id", signingSession.KeyID),
		slog.String("mpc_session_id", signingSession.SessionID),
		slog.Int("party_id", req.Approval.PartyID))
	writeJSON(w, http.StatusOK, MPCSigningSessionResponse(*signingSession))
}

func (a *API) CompleteMPCSigningSession(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	sessionID := chi.URLParam(r, "sessionID")
	creds := credentialsFromContext(r.Context())

	if !a.requireStepUp(w, r) {
		return
	}
	req, ok := decodeJSON[CompleteMPCSigningSessionRequest](w, r, maxSmallBodySize)
	if !ok {
		return
	}
	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	if req.Signature == nil {
		completed, err := a.completeMPCSessionWithSigners(r.Context(), session, sessionID)
		if err != nil {
			mapError(w, err)
			return
		}
		a.audit.logEvent(AuditMPCSigningCompleted, r, creds.SecretKey().ID(),
			slog.String("vault_id", vaultID),
			slog.String("mpc_key_id", completed.KeyID),
			slog.String("mpc_session_id", completed.SessionID))
		writeJSON(w, http.StatusOK, MPCSigningSessionResponse(*completed))
		return
	}
	existingSession, err := session.GetMPCSigningSession(r.Context(), sessionID)
	if err != nil {
		mapError(w, err)
		return
	}
	key, err := session.GetMPCKey(r.Context(), existingSession.KeyID)
	if err != nil {
		mapError(w, err)
		return
	}
	if err := a.validateMPCProviderForUse(key.Algorithm); err != nil {
		mapError(w, err)
		return
	}
	signingSession, err := session.CompleteMPCSigningSession(r.Context(), sessionID, req.Commitments, req.Signature)
	if err != nil {
		mapError(w, err)
		return
	}
	a.audit.logEvent(AuditMPCSigningCompleted, r, creds.SecretKey().ID(),
		slog.String("vault_id", vaultID),
		slog.String("mpc_key_id", signingSession.KeyID),
		slog.String("mpc_session_id", signingSession.SessionID))
	writeJSON(w, http.StatusOK, MPCSigningSessionResponse(*signingSession))
}

type mpcDKGOrchestration struct {
	SessionID string
	KeyID     string
	Members   []mpcsigner.Member
}

func (a *API) orchestrateMPCDKG(ctx context.Context, session *vault.Session, vaultID string, req CreateMPCKeyRequest) (CreateMPCKeyRequest, *mpcDKGOrchestration, error) {
	if req.KeyID == "" {
		req.KeyID = uuid.New()
	}
	if req.Threshold == 0 {
		req.Threshold = 2
	}
	if req.Threshold < 2 {
		return req, nil, vault.ValidationError{Message: "MPC threshold must be at least 2"}
	}
	members, err := session.ListMembers(ctx)
	if err != nil {
		return req, nil, err
	}
	selected := make([]mpcsigner.Member, 0, len(members))
	allowed := make(map[string]bool, len(req.MemberIDs))
	for _, id := range req.MemberIDs {
		allowed[id] = true
	}
	for _, member := range members {
		if len(allowed) > 0 && !allowed[member.MemberID] {
			continue
		}
		if member.Status != vault.StatusActive || member.MPCSignerStatus != vault.MPCSignerStatusActive {
			continue
		}
		if member.MPCSignerURL == "" || member.MPCEncryptionPublicKey == "" || member.MPCApprovalPublicKey == "" {
			continue
		}
		selected = append(selected, mpcsigner.Member{
			MemberID:            member.MemberID,
			PartyID:             member.MPCPartyID,
			URL:                 member.MPCSignerURL,
			EncryptionPublicKey: member.MPCEncryptionPublicKey,
			ApprovalPublicKey:   member.MPCApprovalPublicKey,
		})
	}
	if len(selected) < req.Threshold {
		return req, nil, vault.ValidationError{Message: fmt.Sprintf("need at least %d active MPC signers, found %d", req.Threshold, len(selected))}
	}
	provider, err := mpc.GetProvider(req.Algorithm)
	if err != nil {
		return req, nil, vault.ValidationError{Message: err.Error()}
	}
	req.Algorithm = provider.Info().Algorithm
	dkg := &mpcDKGOrchestration{SessionID: uuid.New(), KeyID: req.KeyID, Members: selected}
	attempt := vault.MPCDKGAttempt{
		DKGSessionID: dkg.SessionID,
		VaultID:      vaultID,
		KeyID:        req.KeyID,
		Algorithm:    provider.Info().Algorithm,
		Threshold:    req.Threshold,
		Status:       vault.MPCDKGStatusStarted,
		Members:      dkgAttemptMembers(selected),
	}
	savedAttempt, err := session.SaveMPCDKGAttempt(ctx, attempt)
	if err != nil {
		return req, nil, err
	}
	attempt = *savedAttempt
	start := mpcsigner.StartDKGRequest{DKGSessionID: dkg.SessionID, VaultID: vaultID, KeyID: req.KeyID, Threshold: req.Threshold, Members: selected}
	req.Commitments = make([]mpc.PublicCommitment, 0, len(selected))
	for _, member := range selected {
		var resp mpcsigner.StartDKGResponse
		if err := a.mpcClient.PostJSON(member.URL+"/signer/dkg/start", start, &resp); err != nil {
			a.abortMPCDKG(ctx, dkg)
			attempt.Status = vault.MPCDKGStatusFailed
			attempt.LastError = err.Error()
			_, _ = session.SaveMPCDKGAttempt(ctx, attempt)
			return req, nil, err
		}
		req.Commitments = append(req.Commitments, resp.Commitment)
		attempt.Commitments = append([]mpc.PublicCommitment(nil), req.Commitments...)
		_, _ = session.SaveMPCDKGAttempt(ctx, attempt)
	}
	finalize := mpcsigner.FinalizeDKGRequest{DKGSessionID: dkg.SessionID, VaultID: vaultID, KeyID: req.KeyID, Threshold: req.Threshold, Members: selected, Commitments: req.Commitments}
	req.Fragments = make(map[string]mpc.EncryptedFragment, len(selected))
	finalized := make([]mpcsigner.Member, 0, len(selected))
	attempt.Status = vault.MPCDKGStatusFinalizing
	attempt.Commitments = append([]mpc.PublicCommitment(nil), req.Commitments...)
	_, _ = session.SaveMPCDKGAttempt(ctx, attempt)
	for _, member := range selected {
		var resp mpcsigner.FinalizeDKGResponse
		if err := a.mpcClient.PostJSON(member.URL+"/signer/dkg/finalize", finalize, &resp); err != nil {
			a.abortMPCDKG(ctx, &mpcDKGOrchestration{SessionID: dkg.SessionID, KeyID: req.KeyID, Members: selected})
			attempt.Status = vault.MPCDKGStatusFailed
			attempt.LastError = err.Error()
			_, _ = session.SaveMPCDKGAttempt(ctx, attempt)
			return req, nil, err
		}
		finalized = append(finalized, member)
		req.Fragments[member.MemberID] = resp.EncryptedFragment
		attempt.Fragments = copyMPCFragments(req.Fragments)
		_, _ = session.SaveMPCDKGAttempt(ctx, attempt)
	}
	dkg.Members = append([]mpcsigner.Member(nil), finalized...)
	return req, dkg, nil
}

func (a *API) abortMPCDKG(ctx context.Context, dkg *mpcDKGOrchestration) {
	if dkg == nil {
		return
	}
	payload := mpcsigner.AbortDKGRequest{DKGSessionID: dkg.SessionID, KeyID: dkg.KeyID}
	for _, member := range dkg.Members {
		if err := a.mpcClient.PostJSON(member.URL+"/signer/dkg/abort", payload, nil); err != nil {
			a.audit.logger.WarnContext(ctx, "failed to abort MPC DKG signer state",
				slog.String("mpc_key_id", dkg.KeyID),
				slog.String("dkg_session_id", dkg.SessionID),
				slog.Uint64("party_id", uint64(member.PartyID)),
				slog.String("error", err.Error()))
		}
	}
}

func (a *API) commitMPCDKG(ctx context.Context, dkg *mpcDKGOrchestration) error {
	if dkg == nil {
		return nil
	}
	payload := mpcsigner.CommitDKGRequest{DKGSessionID: dkg.SessionID, KeyID: dkg.KeyID}
	errs := make([]error, 0)
	for _, member := range dkg.Members {
		if err := a.mpcClient.PostJSON(member.URL+"/signer/dkg/commit", payload, nil); err != nil {
			a.audit.logger.WarnContext(ctx, "failed to commit MPC DKG signer state",
				slog.String("mpc_key_id", dkg.KeyID),
				slog.String("dkg_session_id", dkg.SessionID),
				slog.Uint64("party_id", uint64(member.PartyID)),
				slog.String("error", err.Error()))
			errs = append(errs, fmt.Errorf("party %d commit failed: %w", member.PartyID, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("MPC DKG commit failed for key %q: %w", dkg.KeyID, errors.Join(errs...))
	}
	return nil
}

func (a *API) requestMPCSessionApprovalWithSigner(ctx context.Context, session *vault.Session, sessionID string, partyID uint32) (*vault.MPCSigningSession, error) {
	signingSession, err := session.GetMPCSigningSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	key, err := session.GetMPCKey(ctx, signingSession.KeyID)
	if err != nil {
		return nil, err
	}
	var participant vault.MPCParticipant
	found := false
	for _, candidate := range key.Participants {
		if candidate.PartyID == partyID {
			participant = candidate
			found = true
			break
		}
	}
	if !found {
		return nil, vault.ValidationError{Message: fmt.Sprintf("party %d is not part of this MPC key", partyID)}
	}
	participants := make([]int, 0, len(signingSession.Participants))
	for _, participantID := range signingSession.Participants {
		participants = append(participants, int(participantID))
	}
	payload := mpcsigner.ApprovalRequest{
		VaultID:           signingSession.VaultID,
		SessionID:         signingSession.SessionID,
		KeyID:             signingSession.KeyID,
		Threshold:         key.Threshold,
		Participants:      participants,
		MessageHash:       signingSession.MessageHash,
		MessageType:       signingSession.MessageType,
		Chain:             signingSession.Chain,
		Network:           signingSession.Network,
		TransactionDigest: signingSession.Transaction.Digest,
		ExpiresAt:         signingSession.ExpiresAt,
	}
	var resp mpcsigner.CreateApprovalRequestResponse
	if err := a.mpcClient.PostJSON(participant.SignerURL+"/signer/approval-requests", payload, &resp); err != nil {
		return nil, err
	}
	if resp.Request.Approval != nil && resp.Request.Approval.Signature != "" {
		return session.AddMPCApproval(ctx, sessionID, *resp.Request.Approval)
	}
	return signingSession, nil
}

func (a *API) completeMPCSessionWithSigners(ctx context.Context, session *vault.Session, sessionID string) (*vault.MPCSigningSession, error) {
	signingSession, err := session.GetMPCSigningSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	key, err := session.GetMPCKey(ctx, signingSession.KeyID)
	if err != nil {
		return nil, err
	}
	if err := a.validateMPCProviderForUse(key.Algorithm); err != nil {
		return nil, err
	}
	signingSession, err = a.collectMPCApprovalsFromSigners(ctx, session, signingSession, key)
	if err != nil {
		return nil, err
	}
	approved := make([]uint32, 0, key.Threshold)
	for _, participantID := range signingSession.Participants {
		for _, approval := range signingSession.Approvals {
			if approval.PartyID == int(participantID) {
				approved = append(approved, participantID)
				break
			}
		}
		if len(approved) == key.Threshold {
			break
		}
	}
	if len(approved) < key.Threshold {
		return nil, vault.ValidationError{Message: fmt.Sprintf("need %d approvals, have %d", key.Threshold, len(approved))}
	}
	commitments := make([]mpc.Commitment, 0, len(approved))
	for _, partyID := range approved {
		participant, _ := findMPCParticipant(key.Participants, partyID)
		var commitment mpc.Commitment
		if err := a.mpcClient.PostJSON(participant.SignerURL+"/signer/sign/commit", mpcsigner.NonceCommitRequest{KeyID: key.KeyID, SessionID: signingSession.SessionID, MessageHash: signingSession.MessageHash}, &commitment); err != nil {
			return nil, err
		}
		commitments = append(commitments, commitment)
	}
	provider, err := mpc.GetProvider(key.Algorithm)
	if err != nil {
		return nil, err
	}
	aggregateR, err := provider.AggregateCommitments(commitments)
	if err != nil {
		return nil, err
	}
	challenge, err := provider.ChallengeHex(key.PublicKeyPoint(), aggregateR, signingSession.Message)
	if err != nil {
		return nil, err
	}
	participants := make([]int, 0, len(approved))
	for _, partyID := range approved {
		participants = append(participants, int(partyID))
	}
	shares := make([]mpc.ShareProof, 0, len(approved))
	for _, partyID := range approved {
		participant, _ := findMPCParticipant(key.Participants, partyID)
		fragment, err := session.GetMPCKeyFragment(ctx, key.KeyID, participant.MemberID)
		if err != nil {
			return nil, err
		}
		approval, _ := findMPCApproval(signingSession.Approvals, partyID)
		var share mpc.ShareProof
		payload := mpcsigner.SignShareRequest{KeyID: key.KeyID, SessionID: signingSession.SessionID, MessageB64: base64.StdEncoding.EncodeToString(signingSession.Message), Participants: participants, AggregateR: aggregateR, Fragment: fragment.Fragment, Approval: approval}
		if err := a.mpcClient.PostJSON(participant.SignerURL+"/signer/sign/share", payload, &share); err != nil {
			return nil, err
		}
		shares = append(shares, share)
	}
	z, err := provider.CombineSignatureShares(shares)
	if err != nil {
		return nil, err
	}
	signature := &mpc.Signature{Curve: provider.Info().Curve, R: aggregateR, Z: z, Challenge: challenge, Commitments: commitments, Shares: shares}
	return session.CompleteMPCSigningSession(ctx, sessionID, commitments, signature)
}

func (a *API) collectMPCApprovalsFromSigners(ctx context.Context, session *vault.Session, signingSession *vault.MPCSigningSession, key *vault.MPCKey) (*vault.MPCSigningSession, error) {
	current := signingSession
	for _, partyID := range current.Participants {
		if _, ok := findMPCApproval(current.Approvals, partyID); ok {
			continue
		}
		participant, ok := findMPCParticipant(key.Participants, partyID)
		if !ok {
			continue
		}
		requestID := fmt.Sprintf("%s-%d", current.SessionID, partyID)
		var resp mpcsigner.CreateApprovalRequestResponse
		if err := a.mpcClient.GetJSON(participant.SignerURL+"/signer/approval-requests/"+requestID, &resp); err != nil {
			continue
		}
		if resp.Request.Status != mpcsigner.ApprovalRequestApproved || resp.Request.Approval == nil || resp.Request.Approval.Signature == "" {
			continue
		}
		updated, err := session.AddMPCApproval(ctx, current.SessionID, *resp.Request.Approval)
		if err != nil {
			return nil, err
		}
		current = updated
	}
	return current, nil
}

func findMPCParticipant(participants []vault.MPCParticipant, partyID uint32) (vault.MPCParticipant, bool) {
	for _, participant := range participants {
		if participant.PartyID == partyID {
			return participant, true
		}
	}
	return vault.MPCParticipant{}, false
}

func findMPCApproval(approvals []mpc.Approval, partyID uint32) (mpc.Approval, bool) {
	for _, approval := range approvals {
		if approval.PartyID == int(partyID) {
			return approval, true
		}
	}
	return mpc.Approval{}, false
}

func dkgAttemptMembers(members []mpcsigner.Member) []vault.MPCDKGMember {
	out := make([]vault.MPCDKGMember, 0, len(members))
	for _, member := range members {
		out = append(out, vault.MPCDKGMember{
			MemberID:            member.MemberID,
			PartyID:             member.PartyID,
			URL:                 member.URL,
			EncryptionPublicKey: member.EncryptionPublicKey,
			ApprovalPublicKey:   member.ApprovalPublicKey,
		})
	}
	return out
}

func signerMembersFromDKGAttempt(attempt *vault.MPCDKGAttempt) []mpcsigner.Member {
	out := make([]mpcsigner.Member, 0, len(attempt.Members))
	for _, member := range attempt.Members {
		out = append(out, mpcsigner.Member{
			MemberID:            member.MemberID,
			PartyID:             member.PartyID,
			URL:                 member.URL,
			EncryptionPublicKey: member.EncryptionPublicKey,
			ApprovalPublicKey:   member.ApprovalPublicKey,
		})
	}
	return out
}

func activeReplacementMembers(ctx context.Context, session *vault.Session, key *vault.MPCKey) ([]string, error) {
	members, err := session.ListMembers(ctx)
	if err != nil {
		return nil, err
	}
	active := make(map[string]struct{}, len(members))
	for _, member := range members {
		if member.Status == vault.StatusActive && member.MPCSignerStatus == vault.MPCSignerStatusActive {
			active[member.MemberID] = struct{}{}
		}
	}
	memberIDs := make([]string, 0, len(key.Participants))
	for _, participant := range key.Participants {
		if _, ok := active[participant.MemberID]; ok {
			memberIDs = append(memberIDs, participant.MemberID)
		}
	}
	if len(memberIDs) < key.Threshold {
		return nil, vault.ValidationError{Message: fmt.Sprintf("replacement key needs at least %d active original participants, found %d", key.Threshold, len(memberIDs))}
	}
	return memberIDs, nil
}

func copyMPCFragments(in map[string]mpc.EncryptedFragment) map[string]mpc.EncryptedFragment {
	out := make(map[string]mpc.EncryptedFragment, len(in))
	for memberID, fragment := range in {
		out[memberID] = fragment
	}
	return out
}
