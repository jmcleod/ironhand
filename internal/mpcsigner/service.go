package mpcsigner

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jmcleod/ironhand/internal/mpc"
	"github.com/jmcleod/ironhand/internal/mpcclient"
)

type Service struct {
	memberID string
	partyID  uint32
	logger   *slog.Logger
	client   *mpcclient.Client
	shared   []byte
	replay   *mpcclient.ReplayCache
	store    *FileStore
	ecdhPriv *ecdh.PrivateKey
	edPriv   ed25519.PrivateKey
	identity mpc.SignerIdentity
	operator []byte

	mu        sync.Mutex
	keys      map[string]*keyState
	approvals map[string]*ApprovalRequestRecord
}

type keyState struct {
	vaultID        string
	dkgSessionID   string
	dkgStatus      string
	threshold      int
	members        []Member
	commitments    map[int]mpc.PublicCommitment
	inbox          map[int]string
	outgoingShares map[int]string
	fragment       mpc.EncryptedFragment
	publicKey      mpc.Point
	nonces         map[string]*nonceState
}

type nonceState struct {
	KeyID       string
	SessionID   string
	MessageHash string
	Nonce       *big.Int
}

func New(memberID string, partyID uint32, name, url string, sharedKey []byte, logger *slog.Logger) (*Service, error) {
	return NewWithStore(memberID, partyID, name, url, sharedKey, nil, logger)
}

func NewWithStore(memberID string, partyID uint32, name, url string, sharedKey []byte, store *FileStore, logger *slog.Logger) (*Service, error) {
	if logger == nil {
		logger = slog.Default()
	}
	var (
		ecdhPriv  *ecdh.PrivateKey
		edPriv    ed25519.PrivateKey
		identity  mpc.SignerIdentity
		keys      = make(map[string]*keyState)
		approvals = make(map[string]*ApprovalRequestRecord)
	)
	if store != nil {
		snapshot, ok, err := store.Load()
		if err != nil {
			return nil, fmt.Errorf("load signer state: %w", err)
		}
		if ok {
			if snapshot.MemberID != memberID || snapshot.PartyID != partyID {
				return nil, fmt.Errorf("signer state belongs to member %s party %d", snapshot.MemberID, snapshot.PartyID)
			}
			ecdhPriv, edPriv, identity, keys, approvals, err = serviceStateFromSnapshot(snapshot)
			if err != nil {
				return nil, err
			}
			if name != "" {
				identity.Name = name
			}
			if url != "" {
				identity.URL = NormalizeURL(url)
			}
		}
	}
	if ecdhPriv == nil {
		var err error
		ecdhPriv, edPriv, identity, err = mpc.GenerateSignerIdentity(int(partyID), name, url)
		if err != nil {
			return nil, err
		}
	}
	service := &Service{
		memberID:  memberID,
		partyID:   partyID,
		logger:    logger,
		client:    mpcclient.New(sharedKey, nil),
		shared:    append([]byte(nil), sharedKey...),
		replay:    mpcclient.NewReplayCache(2 * time.Minute),
		store:     store,
		ecdhPriv:  ecdhPriv,
		edPriv:    edPriv,
		identity:  identity,
		keys:      keys,
		approvals: approvals,
	}
	if store != nil {
		service.mu.Lock()
		err := service.saveLocked()
		service.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	return service, nil
}

func (s *Service) SetOperatorToken(token []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.operator = append([]byte(nil), token...)
}

func (s *Service) Identity() mpc.SignerIdentity {
	return s.identity
}

func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /signer/identity", s.handleIdentity)
	mux.HandleFunc("GET /signer/health", s.handleHealth)
	mux.HandleFunc("GET /signer/ready", s.handleReady)
	mux.HandleFunc("POST /signer/dkg/start", s.handleStartDKG)
	mux.HandleFunc("POST /signer/dkg/share", s.handleReceiveShare)
	mux.HandleFunc("POST /signer/dkg/finalize", s.handleFinalizeDKG)
	mux.HandleFunc("POST /signer/dkg/abort", s.handleAbortDKG)
	mux.HandleFunc("POST /signer/dkg/commit", s.handleCommitDKG)
	mux.HandleFunc("POST /signer/approve", s.handleApprove)
	mux.HandleFunc("POST /signer/approval-requests", s.handleCreateApprovalRequest)
	mux.HandleFunc("GET /signer/approval-requests", s.handleListApprovalRequests)
	mux.HandleFunc("GET /signer/approval-requests/{requestID}", s.handleGetApprovalRequest)
	mux.HandleFunc("POST /signer/approval-requests/{requestID}/approve", s.handleApproveApprovalRequest)
	mux.HandleFunc("POST /signer/approval-requests/{requestID}/reject", s.handleRejectApprovalRequest)
	mux.HandleFunc("POST /signer/sign/commit", s.handleNonceCommit)
	mux.HandleFunc("POST /signer/sign/share", s.handleSignShare)
	return s.withAuth(s.withLogging(mux))
}

func (s *Service) handleIdentity(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, IdentityResponse{Member: s.identity})
}

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.healthSnapshot("ok"))
}

func (s *Service) handleReady(w http.ResponseWriter, r *http.Request) {
	status := "ready"
	s.mu.Lock()
	hasIdentity := s.identity.EncryptionPublicKey != "" && s.identity.ApprovalPublicKey != ""
	s.mu.Unlock()
	if !hasIdentity {
		status = "not_ready"
	}
	if status != "ready" {
		writeJSON(w, http.StatusServiceUnavailable, s.healthSnapshot(status))
		return
	}
	writeJSON(w, http.StatusOK, s.healthSnapshot(status))
}

func (s *Service) handleStartDKG(w http.ResponseWriter, r *http.Request) {
	var req StartDKGRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateRequest(req.KeyID, req.Threshold, req.Members, s.partyID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.DKGSessionID == "" || req.VaultID == "" {
		writeError(w, http.StatusBadRequest, "dkg_session_id and vault_id are required")
		return
	}
	s.mu.Lock()
	if state, ok := s.keys[req.KeyID]; ok {
		if state.dkgSessionID != req.DKGSessionID {
			s.mu.Unlock()
			writeError(w, http.StatusConflict, "MPC key is already bound to a different DKG session")
			return
		}
		if state.dkgStatus == "aborted" {
			s.mu.Unlock()
			writeError(w, http.StatusConflict, "DKG session was aborted")
			return
		}
		if commitment, ok := state.commitments[int(s.partyID)]; ok {
			if state.dkgStatus == "finalized" || state.dkgStatus == "committed" || len(state.outgoingShares) == 0 {
				s.mu.Unlock()
				writeJSON(w, http.StatusOK, StartDKGResponse{PartyID: s.partyID, Commitment: commitment})
				return
			}
			outgoing := make(map[int]string, len(state.outgoingShares))
			for partyID, share := range state.outgoingShares {
				outgoing[partyID] = share
			}
			members := append([]Member(nil), state.members...)
			s.mu.Unlock()
			if err := s.sendDKGShares(req, members, commitment, outgoing); err != nil {
				writeError(w, http.StatusBadGateway, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, StartDKGResponse{PartyID: s.partyID, Commitment: commitment})
			return
		}
	}
	s.mu.Unlock()

	poly, err := mpc.GeneratePolynomial(req.Threshold)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer mpc.ZeroScalars(poly)
	commitment := mpc.CommitmentsForPolynomial(int(s.partyID), poly)
	selfShare := mpc.EvalPolynomial(poly, big.NewInt(int64(s.partyID)))
	outgoing := make(map[int]string, len(req.Members)-1)
	for _, recipient := range req.Members {
		if recipient.PartyID == s.partyID {
			continue
		}
		share := mpc.EvalPolynomial(poly, big.NewInt(int64(recipient.PartyID)))
		outgoing[int(recipient.PartyID)] = mpc.EncodeScalar(share)
		share.SetInt64(0)
	}

	s.mu.Lock()
	state := s.ensureStateLocked(req.KeyID, req.Threshold, req.Members)
	state.vaultID = req.VaultID
	state.dkgSessionID = req.DKGSessionID
	state.dkgStatus = "pending"
	state.commitments[int(s.partyID)] = commitment
	state.inbox[int(s.partyID)] = mpc.EncodeScalar(selfShare)
	state.outgoingShares = outgoing
	if err := s.saveLocked(); err != nil {
		s.mu.Unlock()
		selfShare.SetInt64(0)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("persist signer state: %v", err))
		return
	}
	s.mu.Unlock()
	selfShare.SetInt64(0)

	if err := s.sendDKGShares(req, req.Members, commitment, outgoing); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, StartDKGResponse{PartyID: s.partyID, Commitment: commitment})
}

func (s *Service) handleReceiveShare(w http.ResponseWriter, r *http.Request) {
	var req DKGShareRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.ToPartyID != s.partyID {
		writeError(w, http.StatusBadRequest, "share was not addressed to this party")
		return
	}
	if err := validateRequest(req.KeyID, req.Threshold, req.Members, s.partyID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.DKGSessionID == "" || req.VaultID == "" {
		writeError(w, http.StatusBadRequest, "dkg_session_id and vault_id are required")
		return
	}
	if _, ok := memberByPartyID(req.Members, req.FromPartyID); !ok {
		writeError(w, http.StatusBadRequest, "share sender is not a DKG member")
		return
	}
	if !mpc.VerifyPolynomialShare(req.Share, int(s.partyID), req.Commitment) {
		writeError(w, http.StatusBadRequest, "share does not match public commitment")
		return
	}
	s.mu.Lock()
	state := s.ensureStateLocked(req.KeyID, req.Threshold, req.Members)
	if state.dkgSessionID != "" && state.dkgSessionID != req.DKGSessionID {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "MPC key is already bound to a different DKG session")
		return
	}
	if state.dkgStatus == "aborted" {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "DKG session was aborted")
		return
	}
	if state.dkgStatus == "finalized" || state.dkgStatus == "committed" {
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{"status": "stored"})
		return
	}
	state.vaultID = req.VaultID
	state.dkgSessionID = req.DKGSessionID
	if state.dkgStatus == "" {
		state.dkgStatus = "pending"
	}
	state.commitments[int(req.FromPartyID)] = req.Commitment
	state.inbox[int(req.FromPartyID)] = req.Share
	if err := s.saveLocked(); err != nil {
		s.mu.Unlock()
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("persist signer state: %v", err))
		return
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "stored"})
}

func (s *Service) handleFinalizeDKG(w http.ResponseWriter, r *http.Request) {
	var req FinalizeDKGRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateRequest(req.KeyID, req.Threshold, req.Members, s.partyID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.DKGSessionID == "" || req.VaultID == "" {
		writeError(w, http.StatusBadRequest, "dkg_session_id and vault_id are required")
		return
	}
	publicKey, err := mpc.CombinePublicKey(req.Commitments)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	state := s.ensureStateLocked(req.KeyID, req.Threshold, req.Members)
	if state.dkgSessionID != "" && state.dkgSessionID != req.DKGSessionID {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "MPC key is already bound to a different DKG session")
		return
	}
	if state.dkgStatus == "aborted" {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "DKG session was aborted")
		return
	}
	if (state.dkgStatus == "finalized" || state.dkgStatus == "committed") && state.fragment.KeyID != "" {
		fragment := state.fragment
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, FinalizeDKGResponse{PartyID: s.partyID, PublicKey: publicKey, EncryptedFragment: fragment})
		return
	}
	state.vaultID = req.VaultID
	state.dkgSessionID = req.DKGSessionID
	for _, commitment := range req.Commitments {
		state.commitments[commitment.PartyID] = commitment
	}
	if len(state.inbox) < len(req.Members) {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "not all DKG shares have arrived")
		return
	}
	share := big.NewInt(0)
	for _, member := range req.Members {
		encodedShare, ok := state.inbox[int(member.PartyID)]
		if !ok {
			s.mu.Unlock()
			writeError(w, http.StatusConflict, fmt.Sprintf("missing share from party %d", member.PartyID))
			return
		}
		if !mpc.VerifyPolynomialShare(encodedShare, int(s.partyID), state.commitments[int(member.PartyID)]) {
			s.mu.Unlock()
			writeError(w, http.StatusBadRequest, fmt.Sprintf("share from party %d no longer matches commitment", member.PartyID))
			return
		}
		value, ok := mpc.DecodeScalar(encodedShare)
		if !ok {
			s.mu.Unlock()
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid share from party %d", member.PartyID))
			return
		}
		share.Add(share, value)
		share.Mod(share, mpc.CurveOrder())
		value.SetInt64(0)
	}
	s.mu.Unlock()

	publicShare, err := mpc.PublicShareCommitment(req.Commitments, int(s.partyID))
	if err != nil {
		share.SetInt64(0)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	fragment, err := mpc.EncryptFragment(req.KeyID, int(s.partyID), s.identity.EncryptionPublicKey, []byte(mpc.EncodeScalar(share)), publicShare)
	share.SetInt64(0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	commitmentsHash, err := mpc.CommitmentsHash(req.Commitments)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	attestation, err := mpc.SignFragmentAttestation(s.edPriv, mpc.FragmentAttestation{
		VaultID:               req.VaultID,
		DKGSessionID:          req.DKGSessionID,
		KeyID:                 req.KeyID,
		PartyID:               int(s.partyID),
		PublicShareCommitment: publicShare,
		CommitmentsHash:       commitmentsHash,
		ApprovalPublicKey:     s.identity.ApprovalPublicKey,
		CreatedAt:             time.Now().UTC(),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	fragment.Attestation = &attestation
	s.mu.Lock()
	state, ok := s.keys[req.KeyID]
	if !ok || state.dkgSessionID != req.DKGSessionID {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "DKG session is no longer active")
		return
	}
	if state.dkgStatus == "aborted" {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "DKG session was aborted")
		return
	}
	state.vaultID = req.VaultID
	state.dkgSessionID = req.DKGSessionID
	state.dkgStatus = "finalized"
	state.publicKey = publicKey
	state.fragment = fragment
	state.nonces = make(map[string]*nonceState)
	state.inbox = make(map[int]string)
	state.outgoingShares = nil
	if err := s.saveLocked(); err != nil {
		s.mu.Unlock()
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("persist signer state: %v", err))
		return
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, FinalizeDKGResponse{PartyID: s.partyID, PublicKey: publicKey, EncryptedFragment: fragment})
}

func (s *Service) handleAbortDKG(w http.ResponseWriter, r *http.Request) {
	var req AbortDKGRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.KeyID == "" || req.DKGSessionID == "" {
		writeError(w, http.StatusBadRequest, "key_id and dkg_session_id are required")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.keys[req.KeyID]
	if !ok {
		writeJSON(w, http.StatusOK, map[string]string{"status": "absent"})
		return
	}
	if state.dkgSessionID != req.DKGSessionID {
		writeError(w, http.StatusConflict, "MPC key is bound to a different DKG session")
		return
	}
	if state.dkgStatus == "committed" {
		writeError(w, http.StatusConflict, "DKG session is already committed")
		return
	}
	delete(s.keys, req.KeyID)
	if err := s.saveLocked(); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("persist signer state: %v", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "aborted"})
}

func (s *Service) handleCommitDKG(w http.ResponseWriter, r *http.Request) {
	var req CommitDKGRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.KeyID == "" || req.DKGSessionID == "" {
		writeError(w, http.StatusBadRequest, "key_id and dkg_session_id are required")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.keys[req.KeyID]
	if !ok || state.publicKey.X == "" {
		writeError(w, http.StatusNotFound, "key metadata not found")
		return
	}
	if state.dkgSessionID != req.DKGSessionID {
		writeError(w, http.StatusConflict, "MPC key is bound to a different DKG session")
		return
	}
	state.dkgStatus = "committed"
	if err := s.saveLocked(); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("persist signer state: %v", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "committed"})
}

func (s *Service) handleApprove(w http.ResponseWriter, r *http.Request) {
	var req ApprovalRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeError(w, http.StatusGone, "direct signer approval is disabled; create an approval request and approve it locally")
}

func (s *Service) handleCreateApprovalRequest(w http.ResponseWriter, r *http.Request) {
	var req ApprovalRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.VaultID == "" || req.KeyID == "" || req.SessionID == "" || req.MessageHash == "" {
		writeError(w, http.StatusBadRequest, "vault_id, key_id, session_id, and message_hash are required")
		return
	}
	if req.Threshold < 2 || len(req.Participants) < req.Threshold {
		writeError(w, http.StatusBadRequest, "threshold and threshold-sized participants are required")
		return
	}
	if req.ExpiresAt.IsZero() {
		req.ExpiresAt = time.Now().UTC().Add(5 * time.Minute)
	}
	if time.Now().UTC().After(req.ExpiresAt) {
		writeError(w, http.StatusBadRequest, "approval request is expired")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.keys[req.KeyID]
	if !ok || state.publicKey.X == "" || state.dkgStatus == "aborted" {
		writeError(w, http.StatusNotFound, "key metadata not found")
		return
	}
	if state.vaultID != "" && state.vaultID != req.VaultID {
		writeError(w, http.StatusUnauthorized, "approval vault does not match signer key state")
		return
	}
	if state.threshold != req.Threshold {
		writeError(w, http.StatusBadRequest, "approval threshold does not match signer key state")
		return
	}
	if err := validateApprovalParticipants(req.Participants, state.members, s.partyID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	requestID := approvalRequestID(req.SessionID, s.partyID)
	if existing, ok := s.approvals[requestID]; ok {
		if !sameApprovalRequest(existing.Request, req) {
			writeError(w, http.StatusConflict, "approval request ID is already bound to a different session context")
			return
		}
		refreshApprovalRequestStatus(existing, time.Now().UTC())
		writeJSON(w, http.StatusAccepted, CreateApprovalRequestResponse{Request: *existing})
		return
	}
	now := time.Now().UTC()
	record := &ApprovalRequestRecord{
		RequestID: requestID,
		PartyID:   s.partyID,
		Status:    ApprovalRequestPending,
		Request:   req,
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.approvals[requestID] = record
	if err := s.saveLocked(); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("persist signer state: %v", err))
		return
	}
	writeJSON(w, http.StatusAccepted, CreateApprovalRequestResponse{Request: *record})
}

func (s *Service) handleListApprovalRequests(w http.ResponseWriter, r *http.Request) {
	if !s.verifyOperator(w, r) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	requests := make([]ApprovalRequestRecord, 0, len(s.approvals))
	for _, request := range s.approvals {
		refreshApprovalRequestStatus(request, now)
		requests = append(requests, *request)
	}
	writeJSON(w, http.StatusOK, ListApprovalRequestsResponse{Requests: requests})
}

func (s *Service) handleGetApprovalRequest(w http.ResponseWriter, r *http.Request) {
	requestID := r.PathValue("requestID")
	s.mu.Lock()
	defer s.mu.Unlock()
	request, ok := s.approvals[requestID]
	if !ok {
		writeError(w, http.StatusNotFound, "approval request not found")
		return
	}
	refreshApprovalRequestStatus(request, time.Now().UTC())
	writeJSON(w, http.StatusOK, CreateApprovalRequestResponse{Request: *request})
}

func (s *Service) handleApproveApprovalRequest(w http.ResponseWriter, r *http.Request) {
	if !s.verifyOperator(w, r) {
		return
	}
	requestID := r.PathValue("requestID")
	s.mu.Lock()
	request, ok := s.approvals[requestID]
	if !ok {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "approval request not found")
		return
	}
	refreshApprovalRequestStatus(request, time.Now().UTC())
	if request.Status == ApprovalRequestExpired {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "approval request is expired")
		return
	}
	if request.Status == ApprovalRequestRejected {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "approval request was rejected")
		return
	}
	if request.Status == ApprovalRequestApproved {
		response := *request
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, CreateApprovalRequestResponse{Request: response})
		return
	}
	req := request.Request
	s.mu.Unlock()

	approval, err := mpc.SignApproval(s.edPriv, mpc.Approval{
		VaultID:           req.VaultID,
		SessionID:         req.SessionID,
		KeyID:             req.KeyID,
		PartyID:           int(s.partyID),
		Threshold:         req.Threshold,
		Participants:      append([]int(nil), req.Participants...),
		MessageHash:       req.MessageHash,
		MessageType:       req.MessageType,
		Chain:             req.Chain,
		Network:           req.Network,
		TransactionDigest: req.TransactionDigest,
		ExpiresAt:         req.ExpiresAt.UTC(),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.mu.Lock()
	request, ok = s.approvals[requestID]
	if !ok {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "approval request not found")
		return
	}
	now := time.Now().UTC()
	request.Status = ApprovalRequestApproved
	request.Approval = &approval
	request.UpdatedAt = now
	request.ApprovedAt = now
	if err := s.saveLocked(); err != nil {
		s.mu.Unlock()
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("persist signer state: %v", err))
		return
	}
	response := *request
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, CreateApprovalRequestResponse{Request: response})
}

func (s *Service) handleRejectApprovalRequest(w http.ResponseWriter, r *http.Request) {
	if !s.verifyOperator(w, r) {
		return
	}
	var req RejectApprovalRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	requestID := r.PathValue("requestID")
	s.mu.Lock()
	defer s.mu.Unlock()
	request, ok := s.approvals[requestID]
	if !ok {
		writeError(w, http.StatusNotFound, "approval request not found")
		return
	}
	now := time.Now().UTC()
	request.Status = ApprovalRequestRejected
	request.Reason = req.Reason
	request.UpdatedAt = now
	request.RejectedAt = now
	if err := s.saveLocked(); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("persist signer state: %v", err))
		return
	}
	writeJSON(w, http.StatusOK, CreateApprovalRequestResponse{Request: *request})
}

func (s *Service) handleNonceCommit(w http.ResponseWriter, r *http.Request) {
	var req NonceCommitRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.KeyID == "" || req.SessionID == "" || req.MessageHash == "" {
		writeError(w, http.StatusBadRequest, "key_id, session_id, and message_hash are required")
		return
	}
	s.mu.Lock()
	state, ok := s.keys[req.KeyID]
	if !ok || state.publicKey.X == "" || state.dkgStatus == "aborted" {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "key metadata not found")
		return
	}
	if existing, ok := state.nonces[req.SessionID]; ok {
		if existing.KeyID != req.KeyID || existing.MessageHash != req.MessageHash {
			s.mu.Unlock()
			writeError(w, http.StatusConflict, "nonce session is already bound to a different transcript")
			return
		}
		commitment := mpc.Commitment{PartyID: int(s.partyID), R: mpc.ScalarBasePoint(existing.Nonce)}
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, commitment)
		return
	}
	nonce, err := mpc.RandomScalar()
	if err != nil {
		s.mu.Unlock()
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	state.nonces[req.SessionID] = &nonceState{KeyID: req.KeyID, SessionID: req.SessionID, MessageHash: req.MessageHash, Nonce: nonce}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, mpc.Commitment{PartyID: int(s.partyID), R: mpc.ScalarBasePoint(nonce)})
}

func (s *Service) handleSignShare(w http.ResponseWriter, r *http.Request) {
	var req SignShareRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Fragment.PartyID != int(s.partyID) || req.Approval.PartyID != int(s.partyID) {
		writeError(w, http.StatusBadRequest, "fragment and approval must belong to this party")
		return
	}
	if req.Fragment.KeyID != req.KeyID || req.Approval.KeyID != req.KeyID || req.Approval.SessionID != req.SessionID {
		writeError(w, http.StatusBadRequest, "fragment or approval does not match signing request")
		return
	}
	if !mpc.VerifyApproval(s.identity.ApprovalPublicKey, req.Approval, time.Now().UTC()) {
		writeError(w, http.StatusUnauthorized, "approval signature is invalid or expired")
		return
	}
	message, err := base64.StdEncoding.DecodeString(req.MessageB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid message_base64: %v", err))
		return
	}
	if req.Approval.MessageHash != mpc.MessageHash(message) {
		writeError(w, http.StatusUnauthorized, "approval does not match message")
		return
	}
	s.mu.Lock()
	state, ok := s.keys[req.KeyID]
	if !ok || state.publicKey.X == "" || state.dkgStatus == "aborted" {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "key metadata not found")
		return
	}
	if state.vaultID != "" && req.Approval.VaultID != state.vaultID {
		s.mu.Unlock()
		writeError(w, http.StatusUnauthorized, "approval vault does not match signer key state")
		return
	}
	if req.Approval.Threshold != state.threshold {
		s.mu.Unlock()
		writeError(w, http.StatusBadRequest, "approval threshold does not match signer key state")
		return
	}
	if err := validateApprovalParticipants(req.Approval.Participants, state.members, s.partyID); err != nil {
		s.mu.Unlock()
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateSigningParticipants(req.Participants, req.Approval.Participants, req.Approval.Threshold, s.partyID); err != nil {
		s.mu.Unlock()
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	nonceRecord, ok := state.nonces[req.SessionID]
	if !ok {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "nonce commitment not found for session")
		return
	}
	if nonceRecord.KeyID != req.KeyID || nonceRecord.MessageHash != req.Approval.MessageHash {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "nonce commitment is bound to a different transcript")
		return
	}
	nonce := nonceRecord.Nonce
	delete(state.nonces, req.SessionID)
	publicKey := state.publicKey
	s.mu.Unlock()

	plaintext, err := mpc.DecryptFragment(s.ecdhPriv, req.Fragment)
	if err != nil {
		nonce.SetInt64(0)
		writeError(w, http.StatusUnauthorized, fmt.Sprintf("decrypt fragment: %v", err))
		return
	}
	defer zeroBytes(plaintext)
	localShare, ok := mpc.DecodeScalar(string(plaintext))
	if !ok {
		nonce.SetInt64(0)
		writeError(w, http.StatusBadRequest, "decrypted fragment is not a valid scalar")
		return
	}
	defer localShare.SetInt64(0)
	challenge, err := mpc.Challenge(publicKey, req.AggregateR, message)
	if err != nil {
		nonce.SetInt64(0)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	z, err := mpc.SignShare(localShare, nonce, challenge, int(s.partyID), req.Participants)
	nonce.SetInt64(0)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, mpc.ShareProof{PartyID: int(s.partyID), Z: mpc.EncodeScalar(z)})
}

func (s *Service) ensureStateLocked(keyID string, threshold int, members []Member) *keyState {
	state, ok := s.keys[keyID]
	if !ok {
		state = &keyState{threshold: threshold, members: append([]Member(nil), members...), commitments: make(map[int]mpc.PublicCommitment), inbox: make(map[int]string), outgoingShares: make(map[int]string), nonces: make(map[string]*nonceState)}
		s.keys[keyID] = state
		return state
	}
	state.threshold = threshold
	state.members = append([]Member(nil), members...)
	if state.commitments == nil {
		state.commitments = make(map[int]mpc.PublicCommitment)
	}
	if state.inbox == nil {
		state.inbox = make(map[int]string)
	}
	if state.outgoingShares == nil {
		state.outgoingShares = make(map[int]string)
	}
	if state.nonces == nil {
		state.nonces = make(map[string]*nonceState)
	}
	return state
}

func (s *Service) healthSnapshot(status string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	dkg := make(map[string]int)
	for _, state := range s.keys {
		keyStatus := state.dkgStatus
		if keyStatus == "" {
			keyStatus = "unknown"
		}
		dkg[keyStatus]++
	}
	approvals := make(map[ApprovalRequestStatus]int)
	now := time.Now().UTC()
	for _, request := range s.approvals {
		refreshApprovalRequestStatus(request, now)
		approvals[request.Status]++
	}
	return map[string]any{
		"status":                  status,
		"member_id":               s.memberID,
		"party_id":                s.partyID,
		"url":                     s.identity.URL,
		"durable_state":           s.store != nil,
		"keys":                    len(s.keys),
		"dkg_statuses":            dkg,
		"approval_request_counts": approvals,
	}
}

func (s *Service) sendDKGShares(req StartDKGRequest, members []Member, commitment mpc.PublicCommitment, outgoing map[int]string) error {
	for _, recipient := range members {
		if recipient.PartyID == s.partyID {
			continue
		}
		share, ok := outgoing[int(recipient.PartyID)]
		if !ok {
			return fmt.Errorf("missing outgoing share for party %d", recipient.PartyID)
		}
		payload := DKGShareRequest{
			DKGSessionID: req.DKGSessionID,
			VaultID:      req.VaultID,
			KeyID:        req.KeyID,
			Threshold:    req.Threshold,
			Members:      req.Members,
			FromPartyID:  s.partyID,
			ToPartyID:    recipient.PartyID,
			Share:        share,
			Commitment:   commitment,
		}
		if err := s.client.PostJSON(recipient.URL+"/signer/dkg/share", payload, nil); err != nil {
			return fmt.Errorf("send share to party %d: %w", recipient.PartyID, err)
		}
	}
	return nil
}

func (s *Service) saveLocked() error {
	if s.store == nil {
		return nil
	}
	return s.store.Save(snapshotFromService(s))
}

func (s *Service) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.isOperatorRoute(r) && s.checkOperatorRequest(r) {
			next.ServeHTTP(w, r)
			return
		}
		_, ok, err := mpcclient.VerifyRequestWithReplay(r, s.shared, 2*time.Minute, s.replay)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !ok {
			writeError(w, http.StatusUnauthorized, "invalid MPC request signature")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Service) isOperatorRoute(r *http.Request) bool {
	if r.Method == http.MethodGet && r.URL.Path == "/signer/approval-requests" {
		return true
	}
	if r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, "/signer/approval-requests/") {
		return false
	}
	return strings.HasSuffix(r.URL.Path, "/approve") || strings.HasSuffix(r.URL.Path, "/reject")
}

func (s *Service) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.logger.Info("mpc signer request", "party_id", s.partyID, "method", r.Method, "path", r.URL.Path, "duration", time.Since(start))
	})
}

func validateRequest(keyID string, threshold int, members []Member, selfID uint32) error {
	if keyID == "" {
		return errors.New("key_id is required")
	}
	if threshold < 2 {
		return errors.New("threshold must be at least 2")
	}
	if len(members) < threshold {
		return errors.New("members must be greater than or equal to threshold")
	}
	for _, member := range members {
		if member.PartyID == selfID {
			return nil
		}
	}
	return fmt.Errorf("party %d is not in the requested vault MPC group", selfID)
}

func memberByPartyID(members []Member, partyID uint32) (Member, bool) {
	for _, member := range members {
		if member.PartyID == partyID {
			return member, true
		}
	}
	return Member{}, false
}

func validateApprovalParticipants(participants []int, members []Member, selfID uint32) error {
	allowed := make(map[int]struct{}, len(members))
	for _, member := range members {
		allowed[int(member.PartyID)] = struct{}{}
	}
	seen := make(map[int]struct{}, len(participants))
	hasSelf := false
	for _, partyID := range participants {
		if _, ok := allowed[partyID]; !ok {
			return fmt.Errorf("approval participant %d is not part of this key", partyID)
		}
		if _, ok := seen[partyID]; ok {
			return fmt.Errorf("approval participant %d was provided more than once", partyID)
		}
		seen[partyID] = struct{}{}
		if uint32(partyID) == selfID {
			hasSelf = true
		}
	}
	if !hasSelf {
		return fmt.Errorf("approval participants do not include this signer party %d", selfID)
	}
	return nil
}

func validateSigningParticipants(signing, approved []int, threshold int, selfID uint32) error {
	if len(signing) < threshold {
		return fmt.Errorf("signing request needs at least %d participants", threshold)
	}
	approvedSet := make(map[int]struct{}, len(approved))
	for _, partyID := range approved {
		approvedSet[partyID] = struct{}{}
	}
	seen := make(map[int]struct{}, len(signing))
	hasSelf := false
	for _, partyID := range signing {
		if _, ok := approvedSet[partyID]; !ok {
			return fmt.Errorf("signing participant %d is not approved for this session", partyID)
		}
		if _, ok := seen[partyID]; ok {
			return fmt.Errorf("signing participant %d was provided more than once", partyID)
		}
		seen[partyID] = struct{}{}
		if uint32(partyID) == selfID {
			hasSelf = true
		}
	}
	if !hasSelf {
		return fmt.Errorf("signing participants do not include this signer party %d", selfID)
	}
	return nil
}

func approvalRequestID(sessionID string, partyID uint32) string {
	return fmt.Sprintf("%s-%d", sessionID, partyID)
}

func refreshApprovalRequestStatus(request *ApprovalRequestRecord, now time.Time) {
	if request.Status == ApprovalRequestPending && now.After(request.Request.ExpiresAt) {
		request.Status = ApprovalRequestExpired
		request.UpdatedAt = now
	}
}

func sameApprovalRequest(left, right ApprovalRequest) bool {
	if left.VaultID != right.VaultID || left.SessionID != right.SessionID || left.KeyID != right.KeyID {
		return false
	}
	if left.Threshold != right.Threshold || left.MessageHash != right.MessageHash || !left.ExpiresAt.Equal(right.ExpiresAt) {
		return false
	}
	if left.MessageType != right.MessageType || left.Chain != right.Chain || left.Network != right.Network || left.TransactionDigest != right.TransactionDigest {
		return false
	}
	if len(left.Participants) != len(right.Participants) {
		return false
	}
	for i := range left.Participants {
		if left.Participants[i] != right.Participants[i] {
			return false
		}
	}
	return true
}

func (s *Service) verifyOperator(w http.ResponseWriter, r *http.Request) bool {
	if s.checkOperatorRequest(r) {
		return true
	}
	writeError(w, http.StatusUnauthorized, "invalid operator token")
	return false
}

func (s *Service) checkOperatorRequest(r *http.Request) bool {
	s.mu.Lock()
	token := append([]byte(nil), s.operator...)
	s.mu.Unlock()
	if len(token) == 0 {
		return isLoopbackRemote(r.RemoteAddr)
	}
	got := []byte(r.Header.Get("X-Ironhand-Signer-Operator-Token"))
	return subtle.ConstantTimeCompare(got, token) == 1
}

func isLoopbackRemote(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func zeroBytes(bytes []byte) {
	for i := range bytes {
		bytes[i] = 0
	}
}

func readJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": http.StatusText(status), "detail": message})
}

func NormalizeURL(url string) string { return strings.TrimRight(url, "/") }
