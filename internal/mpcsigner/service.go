package mpcsigner

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
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
	store    *FileStore
	ecdhPriv *ecdh.PrivateKey
	edPriv   ed25519.PrivateKey
	identity mpc.SignerIdentity

	mu   sync.Mutex
	keys map[string]*keyState
}

type keyState struct {
	threshold   int
	members     []Member
	commitments map[int]mpc.PublicCommitment
	inbox       map[int]string
	publicKey   mpc.Point
	nonces      map[string]*big.Int
}

func New(memberID string, partyID uint32, name, url string, sharedKey []byte, logger *slog.Logger) (*Service, error) {
	return NewWithStore(memberID, partyID, name, url, sharedKey, nil, logger)
}

func NewWithStore(memberID string, partyID uint32, name, url string, sharedKey []byte, store *FileStore, logger *slog.Logger) (*Service, error) {
	if logger == nil {
		logger = slog.Default()
	}
	var (
		ecdhPriv *ecdh.PrivateKey
		edPriv   ed25519.PrivateKey
		identity mpc.SignerIdentity
		keys     = make(map[string]*keyState)
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
			ecdhPriv, edPriv, identity, keys, err = serviceStateFromSnapshot(snapshot)
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
		memberID: memberID,
		partyID:  partyID,
		logger:   logger,
		client:   mpcclient.New(sharedKey, nil),
		shared:   append([]byte(nil), sharedKey...),
		store:    store,
		ecdhPriv: ecdhPriv,
		edPriv:   edPriv,
		identity: identity,
		keys:     keys,
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

func (s *Service) Identity() mpc.SignerIdentity {
	return s.identity
}

func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /signer/identity", s.handleIdentity)
	mux.HandleFunc("GET /signer/health", s.handleHealth)
	mux.HandleFunc("POST /signer/dkg/start", s.handleStartDKG)
	mux.HandleFunc("POST /signer/dkg/share", s.handleReceiveShare)
	mux.HandleFunc("POST /signer/dkg/finalize", s.handleFinalizeDKG)
	mux.HandleFunc("POST /signer/approve", s.handleApprove)
	mux.HandleFunc("POST /signer/sign/commit", s.handleNonceCommit)
	mux.HandleFunc("POST /signer/sign/share", s.handleSignShare)
	return s.withAuth(s.withLogging(mux))
}

func (s *Service) handleIdentity(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, IdentityResponse{Member: s.identity})
}

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "member_id": s.memberID, "party_id": s.partyID})
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
	poly, err := mpc.GeneratePolynomial(req.Threshold)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer mpc.ZeroScalars(poly)
	commitment := mpc.CommitmentsForPolynomial(int(s.partyID), poly)
	selfShare := mpc.EvalPolynomial(poly, big.NewInt(int64(s.partyID)))

	s.mu.Lock()
	state := s.ensureStateLocked(req.KeyID, req.Threshold, req.Members)
	state.commitments[int(s.partyID)] = commitment
	state.inbox[int(s.partyID)] = mpc.EncodeScalar(selfShare)
	if err := s.saveLocked(); err != nil {
		s.mu.Unlock()
		selfShare.SetInt64(0)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("persist signer state: %v", err))
		return
	}
	s.mu.Unlock()
	selfShare.SetInt64(0)

	for _, recipient := range req.Members {
		if recipient.PartyID == s.partyID {
			continue
		}
		share := mpc.EvalPolynomial(poly, big.NewInt(int64(recipient.PartyID)))
		payload := DKGShareRequest{KeyID: req.KeyID, Threshold: req.Threshold, Members: req.Members, FromPartyID: s.partyID, ToPartyID: recipient.PartyID, Share: mpc.EncodeScalar(share), Commitment: commitment}
		share.SetInt64(0)
		if err := s.client.PostJSON(recipient.URL+"/signer/dkg/share", payload, nil); err != nil {
			writeError(w, http.StatusBadGateway, fmt.Sprintf("send share to party %d: %v", recipient.PartyID, err))
			return
		}
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
	if !mpc.VerifyPolynomialShare(req.Share, int(s.partyID), req.Commitment) {
		writeError(w, http.StatusBadRequest, "share does not match public commitment")
		return
	}
	s.mu.Lock()
	state := s.ensureStateLocked(req.KeyID, req.Threshold, req.Members)
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
	publicKey, err := mpc.CombinePublicKey(req.Commitments)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	state := s.ensureStateLocked(req.KeyID, req.Threshold, req.Members)
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
	state.publicKey = publicKey
	state.nonces = make(map[string]*big.Int)
	state.inbox = make(map[int]string)
	if err := s.saveLocked(); err != nil {
		s.mu.Unlock()
		share.SetInt64(0)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("persist signer state: %v", err))
		return
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
	writeJSON(w, http.StatusOK, FinalizeDKGResponse{PartyID: s.partyID, PublicKey: publicKey, EncryptedFragment: fragment})
}

func (s *Service) handleApprove(w http.ResponseWriter, r *http.Request) {
	var req ApprovalRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.KeyID == "" || req.SessionID == "" || req.MessageHash == "" {
		writeError(w, http.StatusBadRequest, "key_id, session_id, and message_hash are required")
		return
	}
	if req.ExpiresAt.IsZero() {
		req.ExpiresAt = time.Now().UTC().Add(5 * time.Minute)
	}
	approval, err := mpc.SignApproval(s.edPriv, mpc.Approval{SessionID: req.SessionID, KeyID: req.KeyID, PartyID: int(s.partyID), MessageHash: req.MessageHash, ExpiresAt: req.ExpiresAt.UTC()})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, approval)
}

func (s *Service) handleNonceCommit(w http.ResponseWriter, r *http.Request) {
	var req NonceCommitRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	nonce, err := mpc.RandomScalar()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.mu.Lock()
	state, ok := s.keys[req.KeyID]
	if !ok || state.publicKey.X == "" {
		s.mu.Unlock()
		nonce.SetInt64(0)
		writeError(w, http.StatusNotFound, "key metadata not found")
		return
	}
	state.nonces[req.SessionID] = nonce
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
	if !ok || state.publicKey.X == "" {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "key metadata not found")
		return
	}
	nonce, ok := state.nonces[req.SessionID]
	if !ok {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "nonce commitment not found for session")
		return
	}
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
		state = &keyState{threshold: threshold, members: append([]Member(nil), members...), commitments: make(map[int]mpc.PublicCommitment), inbox: make(map[int]string), nonces: make(map[string]*big.Int)}
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
	if state.nonces == nil {
		state.nonces = make(map[string]*big.Int)
	}
	return state
}

func (s *Service) saveLocked() error {
	if s.store == nil {
		return nil
	}
	return s.store.Save(snapshotFromService(s))
}

func (s *Service) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok, err := mpcclient.VerifyRequest(r, s.shared, 2*time.Minute)
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
