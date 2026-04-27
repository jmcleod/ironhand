package api

import (
	"context"
	"encoding/base64"
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
	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	var dkg *mpcDKGOrchestration
	if len(req.Commitments) == 0 && len(req.Fragments) == 0 {
		prepared, orchestration, err := a.orchestrateMPCDKG(r.Context(), session, vaultID, req)
		if err != nil {
			mapError(w, err)
			return
		}
		req = prepared
		dkg = orchestration
	}
	key, err := session.CreateMPCKey(r.Context(), vault.MPCKeyCreate{
		KeyID:       req.KeyID,
		Algorithm:   req.Algorithm,
		Threshold:   req.Threshold,
		MemberIDs:   req.MemberIDs,
		Commitments: req.Commitments,
		Fragments:   req.Fragments,
	})
	if err != nil {
		if dkg != nil {
			a.abortMPCDKG(r.Context(), dkg)
		}
		mapError(w, err)
		return
	}
	if dkg != nil {
		a.commitMPCDKG(r.Context(), dkg)
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

	signingSession, err := session.CreateMPCSigningSession(r.Context(), keyID, message, req.Participants, ttl)
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
		approval, err := a.approveMPCSessionWithSigner(r.Context(), session, sessionID, partyID)
		if err != nil {
			mapError(w, err)
			return
		}
		req.Approval = *approval
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
	dkg := &mpcDKGOrchestration{SessionID: uuid.New(), KeyID: req.KeyID, Members: selected}
	start := mpcsigner.StartDKGRequest{DKGSessionID: dkg.SessionID, VaultID: vaultID, KeyID: req.KeyID, Threshold: req.Threshold, Members: selected}
	req.Commitments = make([]mpc.PublicCommitment, 0, len(selected))
	for _, member := range selected {
		var resp mpcsigner.StartDKGResponse
		if err := a.mpcClient.PostJSON(member.URL+"/signer/dkg/start", start, &resp); err != nil {
			a.abortMPCDKG(ctx, dkg)
			return req, nil, err
		}
		req.Commitments = append(req.Commitments, resp.Commitment)
	}
	finalize := mpcsigner.FinalizeDKGRequest{DKGSessionID: dkg.SessionID, VaultID: vaultID, KeyID: req.KeyID, Threshold: req.Threshold, Members: selected, Commitments: req.Commitments}
	req.Fragments = make(map[string]mpc.EncryptedFragment, len(selected))
	finalized := make([]mpcsigner.Member, 0, len(selected))
	for _, member := range selected {
		var resp mpcsigner.FinalizeDKGResponse
		if err := a.mpcClient.PostJSON(member.URL+"/signer/dkg/finalize", finalize, &resp); err != nil {
			a.abortMPCDKG(ctx, &mpcDKGOrchestration{SessionID: dkg.SessionID, KeyID: req.KeyID, Members: selected})
			return req, nil, err
		}
		finalized = append(finalized, member)
		req.Fragments[member.MemberID] = resp.EncryptedFragment
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

func (a *API) commitMPCDKG(ctx context.Context, dkg *mpcDKGOrchestration) {
	if dkg == nil {
		return
	}
	payload := mpcsigner.CommitDKGRequest{DKGSessionID: dkg.SessionID, KeyID: dkg.KeyID}
	for _, member := range dkg.Members {
		if err := a.mpcClient.PostJSON(member.URL+"/signer/dkg/commit", payload, nil); err != nil {
			a.audit.logger.WarnContext(ctx, "failed to commit MPC DKG signer state",
				slog.String("mpc_key_id", dkg.KeyID),
				slog.String("dkg_session_id", dkg.SessionID),
				slog.Uint64("party_id", uint64(member.PartyID)),
				slog.String("error", err.Error()))
		}
	}
}

func (a *API) approveMPCSessionWithSigner(ctx context.Context, session *vault.Session, sessionID string, partyID uint32) (*mpc.Approval, error) {
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
		VaultID:      signingSession.VaultID,
		SessionID:    signingSession.SessionID,
		KeyID:        signingSession.KeyID,
		Threshold:    key.Threshold,
		Participants: participants,
		MessageHash:  signingSession.MessageHash,
		ExpiresAt:    signingSession.ExpiresAt,
	}
	var approval mpc.Approval
	if err := a.mpcClient.PostJSON(participant.SignerURL+"/signer/approve", payload, &approval); err != nil {
		return nil, err
	}
	return &approval, nil
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
	aggregateR, err := mpc.AggregateCommitments(commitments)
	if err != nil {
		return nil, err
	}
	challenge, err := mpc.ChallengeHex(key.PublicKeyPoint(), aggregateR, signingSession.Message)
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
	z, err := mpc.CombineSignatureShares(shares)
	if err != nil {
		return nil, err
	}
	signature := &mpc.Signature{Curve: mpc.CurveName, R: aggregateR, Z: z, Challenge: challenge, Commitments: commitments, Shares: shares}
	return session.CompleteMPCSigningSession(ctx, sessionID, commitments, signature)
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
