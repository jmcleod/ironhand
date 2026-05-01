package frostsecp256k1

import (
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/bytemare/frost"
	"github.com/bytemare/frost/debug"
	"github.com/bytemare/secret-sharing/keys"
)

type spikeOperations struct {
	gate          OperationGate
	state         DurableState
	configuration *frost.Configuration
	keyShares     map[uint16]*keys.KeyShare
	signers       map[uint16]*frost.Signer
	commitments   map[uint16]*frost.Commitment
	shares        map[uint16]*frost.SignatureShare
	publicKey     string
	signingDigest string
	message       []byte
	participants  []Participant
}

func newSpikeOperations(t *testing.T, gate OperationGate, threshold, maxSigners uint16) *spikeOperations {
	t.Helper()
	keyShares, verificationKey, _ := debug.TrustedDealerKeygen(frost.Secp256k1, nil, threshold, maxSigners)
	publicKeyShares := make([]*keys.PublicKeyShare, len(keyShares))
	participants := make([]Participant, len(keyShares))
	keyShareByID := make(map[uint16]*keys.KeyShare, len(keyShares))
	for i, keyShare := range keyShares {
		public := keyShare.Public()
		publicKeyShares[i] = public
		keyShareByID[keyShare.Identifier()] = keyShare
		participants[i] = Participant{ID: keyShare.Identifier(), PublicKey: public.PublicKey.Hex()}
	}
	configuration := &frost.Configuration{
		Ciphersuite:           frost.Secp256k1,
		Threshold:             threshold,
		MaxSigners:            maxSigners,
		VerificationKey:       verificationKey,
		SignerPublicKeyShares: publicKeyShares,
	}
	if err := configuration.Init(); err != nil {
		t.Fatalf("configuration.Init() error = %v", err)
	}
	return &spikeOperations{
		gate:          gate,
		state:         NewDurableState(),
		configuration: configuration,
		keyShares:     keyShareByID,
		signers:       make(map[uint16]*frost.Signer),
		commitments:   make(map[uint16]*frost.Commitment),
		shares:        make(map[uint16]*frost.SignatureShare),
		publicKey:     verificationKey.Hex(),
		participants:  participants,
	}
}

func (s *spikeOperations) StartDKG(req StartDKGRequest) (StartDKGResponse, error) {
	if err := s.gate.Check(); err != nil {
		return StartDKGResponse{}, err
	}
	if err := ValidateStartDKGRequest(req); err != nil {
		return StartDKGResponse{}, err
	}
	if err := s.state.StartDKG(DKGStateRecord{KeyID: req.KeyID, DKGID: req.DKGID, State: DKGStateStarted, TranscriptDigest: req.TranscriptDigest}); err != nil {
		return StartDKGResponse{}, err
	}
	return StartDKGResponse{TranscriptDigest: req.TranscriptDigest, State: DKGStateStarted}, nil
}

func (s *spikeOperations) AcceptDKGShare(req AcceptDKGShareRequest) error {
	if err := s.gate.Check(); err != nil {
		return err
	}
	return ValidateAcceptDKGShareRequest(req)
}

func (s *spikeOperations) FinalizeDKG(req FinalizeDKGRequest) (FinalizeDKGResponse, error) {
	if err := s.gate.Check(); err != nil {
		return FinalizeDKGResponse{}, err
	}
	if err := ValidateFinalizeDKGRequest(req); err != nil {
		return FinalizeDKGResponse{}, err
	}
	if err := s.state.TransitionDKG(DKGStateRecord{KeyID: req.KeyID, DKGID: req.DKGID, State: DKGStateFinalized, TranscriptDigest: req.TranscriptDigest}); err != nil {
		return FinalizeDKGResponse{}, err
	}
	if err := s.state.TransitionDKG(DKGStateRecord{KeyID: req.KeyID, DKGID: req.DKGID, State: DKGStateCommitted, TranscriptDigest: req.TranscriptDigest}); err != nil {
		return FinalizeDKGResponse{}, err
	}
	return FinalizeDKGResponse{TranscriptDigest: req.TranscriptDigest, State: DKGStateCommitted, PublicKey: req.PublicKey}, nil
}

func (s *spikeOperations) AbortDKG(req AbortDKGRequest) error {
	if err := s.gate.Check(); err != nil {
		return err
	}
	if err := ValidateAbortDKGRequest(req); err != nil {
		return err
	}
	return s.state.TransitionDKG(DKGStateRecord{KeyID: req.KeyID, DKGID: req.DKGID, State: DKGStateAborted, TranscriptDigest: req.TranscriptDigest})
}

func (s *spikeOperations) StartSigning(req StartSigningRequest) (StartSigningResponse, error) {
	if err := s.gate.Check(); err != nil {
		return StartSigningResponse{}, err
	}
	if err := ValidateStartSigningRequest(req); err != nil {
		return StartSigningResponse{}, err
	}
	message, err := hex.DecodeString(req.MessageDigest)
	if err != nil {
		return StartSigningResponse{}, err
	}
	s.message = message
	s.signingDigest = req.TranscriptDigest
	if err := s.state.StartSigning(SigningStateRecord{KeyID: req.KeyID, SessionID: req.SessionID, State: SigningStateStarted, TranscriptDigest: req.TranscriptDigest}); err != nil {
		return StartSigningResponse{}, err
	}
	return StartSigningResponse{TranscriptDigest: req.TranscriptDigest, State: SigningStateStarted}, nil
}

func (s *spikeOperations) ReserveNonceCommitments(req ReserveNonceCommitmentsRequest) (ReserveNonceCommitmentsResponse, error) {
	if err := s.gate.Check(); err != nil {
		return ReserveNonceCommitmentsResponse{}, err
	}
	if err := ValidateReserveNonceCommitmentsRequest(req); err != nil {
		return ReserveNonceCommitmentsResponse{}, err
	}
	if req.TranscriptDigest != s.signingDigest {
		return ReserveNonceCommitmentsResponse{}, fmt.Errorf("reserve nonce commitments transcript digest mismatch")
	}
	keyShare, ok := s.keyShares[req.ParticipantID]
	if !ok {
		return ReserveNonceCommitmentsResponse{}, fmt.Errorf("participant %d is not part of spike key", req.ParticipantID)
	}
	signer, err := s.configuration.Signer(keyShare)
	if err != nil {
		return ReserveNonceCommitmentsResponse{}, err
	}
	commitment := signer.Commit()
	s.signers[req.ParticipantID] = signer
	s.commitments[req.ParticipantID] = commitment
	commitmentIDs := s.commitmentIDs()
	if err := s.state.TransitionSigning(SigningStateRecord{KeyID: req.KeyID, SessionID: req.SessionID, State: SigningStateCommitmentsReserved, TranscriptDigest: req.TranscriptDigest, CommitmentIDs: commitmentIDs}); err != nil {
		return ReserveNonceCommitmentsResponse{}, err
	}
	return ReserveNonceCommitmentsResponse{
		ParticipantID:          req.ParticipantID,
		CommitmentID:           commitment.CommitmentID,
		HidingNonceCommitment:  commitment.HidingNonceCommitment.Hex(),
		BindingNonceCommitment: commitment.BindingNonceCommitment.Hex(),
		TranscriptDigest:       req.TranscriptDigest,
	}, nil
}

func (s *spikeOperations) ProduceSignatureShare(req ProduceSignatureShareRequest) (ProduceSignatureShareResponse, error) {
	if err := s.gate.Check(); err != nil {
		return ProduceSignatureShareResponse{}, err
	}
	if err := ValidateProduceSignatureShareRequest(req); err != nil {
		return ProduceSignatureShareResponse{}, err
	}
	if req.TranscriptDigest != s.signingDigest {
		return ProduceSignatureShareResponse{}, fmt.Errorf("produce signature share transcript digest mismatch")
	}
	if req.MessageDigest != s.messageDigest() {
		return ProduceSignatureShareResponse{}, fmt.Errorf("produce signature share message digest mismatch")
	}
	signer, ok := s.signers[req.ParticipantID]
	if !ok {
		return ProduceSignatureShareResponse{}, fmt.Errorf("participant %d has no reserved commitment", req.ParticipantID)
	}
	commitments := s.commitmentList()
	if len(commitments) < int(s.configuration.Threshold) {
		return ProduceSignatureShareResponse{}, fmt.Errorf("insufficient commitments")
	}
	share, err := signer.Sign(s.message, commitments)
	if err != nil {
		return ProduceSignatureShareResponse{}, err
	}
	if err := s.configuration.VerifySignatureShare(share, s.message, commitments); err != nil {
		return ProduceSignatureShareResponse{}, err
	}
	s.shares[req.ParticipantID] = share
	if err := s.state.TransitionSigning(SigningStateRecord{KeyID: req.KeyID, SessionID: req.SessionID, State: SigningStateSharesProduced, TranscriptDigest: req.TranscriptDigest, CommitmentIDs: s.commitmentIDs(), ConsumedCommitmentIDs: s.commitmentIDs(), ShareParticipantIDs: s.shareParticipantIDs()}); err != nil {
		return ProduceSignatureShareResponse{}, err
	}
	return ProduceSignatureShareResponse{ParticipantID: req.ParticipantID, SignatureShare: share.SignatureShare.Hex(), TranscriptDigest: req.TranscriptDigest}, nil
}

func (s *spikeOperations) AcceptSignatureShare(req AcceptSignatureShareRequest) error {
	if err := s.gate.Check(); err != nil {
		return err
	}
	if err := ValidateAcceptSignatureShareRequest(req); err != nil {
		return err
	}
	if req.TranscriptDigest != s.signingDigest {
		return fmt.Errorf("accept signature share transcript digest mismatch")
	}
	return nil
}

func (s *spikeOperations) AggregateSignature(req AggregateSignatureRequest) (AggregateSignatureResponse, error) {
	if err := s.gate.Check(); err != nil {
		return AggregateSignatureResponse{}, err
	}
	if err := ValidateAggregateSignatureRequest(req); err != nil {
		return AggregateSignatureResponse{}, err
	}
	if req.TranscriptDigest != s.signingDigest {
		return AggregateSignatureResponse{}, fmt.Errorf("aggregate signature transcript digest mismatch")
	}
	if req.MessageDigest != s.messageDigest() {
		return AggregateSignatureResponse{}, fmt.Errorf("aggregate signature message digest mismatch")
	}
	if len(s.shares) < int(s.configuration.Threshold) {
		return AggregateSignatureResponse{}, fmt.Errorf("insufficient signature shares")
	}
	signature, err := s.configuration.AggregateSignatures(s.message, s.signatureShares(), s.commitmentList(), true)
	if err != nil {
		return AggregateSignatureResponse{}, err
	}
	if err := frost.VerifySignature(frost.Secp256k1, s.message, signature, s.configuration.VerificationKey); err != nil {
		return AggregateSignatureResponse{}, err
	}
	if err := s.state.TransitionSigning(SigningStateRecord{KeyID: req.KeyID, SessionID: req.SessionID, State: SigningStateFinalized, TranscriptDigest: req.TranscriptDigest, CommitmentIDs: s.commitmentIDs(), ConsumedCommitmentIDs: s.commitmentIDs(), ShareParticipantIDs: s.shareParticipantIDs()}); err != nil {
		return AggregateSignatureResponse{}, err
	}
	return AggregateSignatureResponse{Signature: hex.EncodeToString(signature.Encode()[1:]), TranscriptDigest: req.TranscriptDigest, State: SigningStateFinalized}, nil
}

func (s *spikeOperations) AbortSigning(req AbortSigningRequest) error {
	if err := s.gate.Check(); err != nil {
		return err
	}
	if err := ValidateAbortSigningRequest(req); err != nil {
		return err
	}
	return s.state.TransitionSigning(SigningStateRecord{KeyID: req.KeyID, SessionID: req.SessionID, State: SigningStateAborted, TranscriptDigest: req.TranscriptDigest, CommitmentIDs: s.commitmentIDs()})
}

func (s *spikeOperations) commitmentList() frost.CommitmentList {
	out := make(frost.CommitmentList, 0, len(s.commitments))
	for _, commitment := range s.commitments {
		out = append(out, commitment)
	}
	out.Sort()
	return out
}

func (s *spikeOperations) signatureShares() []*frost.SignatureShare {
	out := make([]*frost.SignatureShare, 0, len(s.shares))
	for _, share := range s.shares {
		out = append(out, share)
	}
	slices.SortFunc(out, func(a, b *frost.SignatureShare) int {
		return int(a.SignerIdentifier) - int(b.SignerIdentifier)
	})
	return out
}

func (s *spikeOperations) commitmentIDs() []uint64 {
	out := make([]uint64, 0, len(s.commitments))
	for _, commitment := range s.commitments {
		out = append(out, commitment.CommitmentID)
	}
	slices.Sort(out)
	return out
}

func (s *spikeOperations) shareParticipantIDs() []uint16 {
	out := make([]uint16, 0, len(s.shares))
	for participantID := range s.shares {
		out = append(out, participantID)
	}
	slices.Sort(out)
	return out
}

func (s *spikeOperations) messageDigest() string {
	return hex.EncodeToString(s.message)
}

func TestSpikeOperationsFailClosedByDefault(t *testing.T) {
	ops := newSpikeOperations(t, DisabledOperationGate(), 2, 3)
	req, err := spikeStartDKGRequest(ops.participants)
	if err != nil {
		t.Fatalf("spikeStartDKGRequest() error = %v", err)
	}
	if _, err := ops.StartDKG(req); !errors.Is(err, ErrOperationsDisabled) {
		t.Fatalf("StartDKG() error = %v, want ErrOperationsDisabled", err)
	}
}

func TestSpikeOperationsCompleteTrustedDealerFlow(t *testing.T) {
	ops := newSpikeOperations(t, InternalSpikeOperationGate(), 2, 3)
	dkgReq, err := spikeStartDKGRequest(ops.participants)
	if err != nil {
		t.Fatalf("spikeStartDKGRequest() error = %v", err)
	}
	dkgStarted, err := ops.StartDKG(dkgReq)
	if err != nil {
		t.Fatalf("StartDKG() error = %v", err)
	}
	if dkgStarted.State != DKGStateStarted {
		t.Fatalf("StartDKG() state = %s, want %s", dkgStarted.State, DKGStateStarted)
	}
	finalized, err := ops.FinalizeDKG(FinalizeDKGRequest{KeyID: dkgReq.KeyID, DKGID: dkgReq.DKGID, TranscriptDigest: dkgReq.TranscriptDigest, PublicKey: ops.publicKey})
	if err != nil {
		t.Fatalf("FinalizeDKG() error = %v", err)
	}
	if finalized.State != DKGStateCommitted {
		t.Fatalf("FinalizeDKG() state = %s, want %s", finalized.State, DKGStateCommitted)
	}

	signReq, err := spikeStartSigningRequest(ops.participants, []byte("ironhand spike operations"))
	if err != nil {
		t.Fatalf("spikeStartSigningRequest() error = %v", err)
	}
	if _, err := ops.StartSigning(signReq); err != nil {
		t.Fatalf("StartSigning() error = %v", err)
	}
	commitmentOne, err := ops.ReserveNonceCommitments(ReserveNonceCommitmentsRequest{KeyID: signReq.KeyID, SessionID: signReq.SessionID, ParticipantID: 1, TranscriptDigest: signReq.TranscriptDigest})
	if err != nil {
		t.Fatalf("ReserveNonceCommitments(1) error = %v", err)
	}
	commitmentThree, err := ops.ReserveNonceCommitments(ReserveNonceCommitmentsRequest{KeyID: signReq.KeyID, SessionID: signReq.SessionID, ParticipantID: 3, TranscriptDigest: signReq.TranscriptDigest})
	if err != nil {
		t.Fatalf("ReserveNonceCommitments(3) error = %v", err)
	}
	commitments := []CommitmentTranscript{
		{ParticipantID: 1, HidingNonceCommitment: commitmentOne.HidingNonceCommitment, BindingNonceCommitment: commitmentOne.BindingNonceCommitment, CommitmentID: commitmentOne.CommitmentID},
		{ParticipantID: 3, HidingNonceCommitment: commitmentThree.HidingNonceCommitment, BindingNonceCommitment: commitmentThree.BindingNonceCommitment, CommitmentID: commitmentThree.CommitmentID},
	}
	shareOne, err := ops.ProduceSignatureShare(ProduceSignatureShareRequest{KeyID: signReq.KeyID, SessionID: signReq.SessionID, ParticipantID: 1, MessageDigest: signReq.MessageDigest, Commitments: commitments, TranscriptDigest: signReq.TranscriptDigest})
	if err != nil {
		t.Fatalf("ProduceSignatureShare(1) error = %v", err)
	}
	shareThree, err := ops.ProduceSignatureShare(ProduceSignatureShareRequest{KeyID: signReq.KeyID, SessionID: signReq.SessionID, ParticipantID: 3, MessageDigest: signReq.MessageDigest, Commitments: commitments, TranscriptDigest: signReq.TranscriptDigest})
	if err != nil {
		t.Fatalf("ProduceSignatureShare(3) error = %v", err)
	}
	shares := []SignatureShareTranscript{
		{ParticipantID: 1, SignatureShare: shareOne.SignatureShare},
		{ParticipantID: 3, SignatureShare: shareThree.SignatureShare},
	}
	aggregate, err := ops.AggregateSignature(AggregateSignatureRequest{KeyID: signReq.KeyID, SessionID: signReq.SessionID, MessageDigest: signReq.MessageDigest, Commitments: commitments, Shares: shares, TranscriptDigest: signReq.TranscriptDigest})
	if err != nil {
		t.Fatalf("AggregateSignature() error = %v", err)
	}
	if aggregate.State != SigningStateFinalized {
		t.Fatalf("AggregateSignature() state = %s, want %s", aggregate.State, SigningStateFinalized)
	}
	if aggregate.Signature == "" {
		t.Fatal("AggregateSignature() signature is empty")
	}
}

func TestSpikeOperationsRejectBadInputs(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, *spikeOperations)
		want string
	}{
		{
			name: "wrong DKG digest",
			run: func(t *testing.T, ops *spikeOperations) {
				req, err := spikeStartDKGRequest(ops.participants)
				if err != nil {
					t.Fatal(err)
				}
				req.TranscriptDigest = "wrong"
				_, err = ops.StartDKG(req)
				assertErrorContains(t, err, "digest mismatch")
			},
		},
		{
			name: "unsupported chain",
			run: func(t *testing.T, ops *spikeOperations) {
				req, err := spikeStartSigningRequest(ops.participants, []byte("message"))
				if err != nil {
					t.Fatal(err)
				}
				req.Chain = "development"
				_, err = ops.StartSigning(req)
				assertErrorContains(t, err, "chain")
			},
		},
		{
			name: "wrong signing digest",
			run: func(t *testing.T, ops *spikeOperations) {
				req, err := spikeStartSigningRequest(ops.participants, []byte("message"))
				if err != nil {
					t.Fatal(err)
				}
				req.TranscriptDigest = "wrong"
				_, err = ops.StartSigning(req)
				assertErrorContains(t, err, "digest mismatch")
			},
		},
		{
			name: "wrong message digest",
			run: func(t *testing.T, ops *spikeOperations) {
				req, err := spikeStartSigningRequest(ops.participants, []byte("message"))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := ops.StartSigning(req); err != nil {
					t.Fatal(err)
				}
				wrongDigest := frostMessageDigest([]byte("different message"))
				_, err = ops.ProduceSignatureShare(ProduceSignatureShareRequest{KeyID: req.KeyID, SessionID: req.SessionID, ParticipantID: 1, MessageDigest: hex.EncodeToString(wrongDigest), Commitments: []CommitmentTranscript{{ParticipantID: 1, HidingNonceCommitment: "h", BindingNonceCommitment: "b"}}, TranscriptDigest: req.TranscriptDigest})
				assertErrorContains(t, err, "message digest mismatch")
			},
		},
		{
			name: "insufficient shares",
			run: func(t *testing.T, ops *spikeOperations) {
				req, err := spikeStartSigningRequest(ops.participants, []byte("message"))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := ops.StartSigning(req); err != nil {
					t.Fatal(err)
				}
				_, err = ops.AggregateSignature(AggregateSignatureRequest{KeyID: req.KeyID, SessionID: req.SessionID, MessageDigest: req.MessageDigest, Commitments: []CommitmentTranscript{{ParticipantID: 1, HidingNonceCommitment: "h", BindingNonceCommitment: "b"}}, Shares: []SignatureShareTranscript{{ParticipantID: 1, SignatureShare: "share"}}, TranscriptDigest: req.TranscriptDigest})
				assertErrorContains(t, err, "insufficient")
			},
		},
		{
			name: "replayed commitment",
			run: func(t *testing.T, ops *spikeOperations) {
				req, err := spikeStartSigningRequest(ops.participants, []byte("message"))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := ops.StartSigning(req); err != nil {
					t.Fatal(err)
				}
				first, err := ops.ReserveNonceCommitments(ReserveNonceCommitmentsRequest{KeyID: req.KeyID, SessionID: req.SessionID, ParticipantID: 1, TranscriptDigest: req.TranscriptDigest})
				if err != nil {
					t.Fatal(err)
				}
				second, err := ops.ReserveNonceCommitments(ReserveNonceCommitmentsRequest{KeyID: req.KeyID, SessionID: req.SessionID, ParticipantID: 3, TranscriptDigest: req.TranscriptDigest})
				if err != nil {
					t.Fatal(err)
				}
				commitments := []CommitmentTranscript{
					{ParticipantID: 1, HidingNonceCommitment: first.HidingNonceCommitment, BindingNonceCommitment: first.BindingNonceCommitment, CommitmentID: first.CommitmentID},
					{ParticipantID: 3, HidingNonceCommitment: second.HidingNonceCommitment, BindingNonceCommitment: second.BindingNonceCommitment, CommitmentID: second.CommitmentID},
				}
				if _, err := ops.ProduceSignatureShare(ProduceSignatureShareRequest{KeyID: req.KeyID, SessionID: req.SessionID, ParticipantID: 1, MessageDigest: req.MessageDigest, Commitments: commitments, TranscriptDigest: req.TranscriptDigest}); err != nil {
					t.Fatal(err)
				}
				replayReq, err := spikeStartSigningRequest(ops.participants, []byte("other message"))
				if err != nil {
					t.Fatal(err)
				}
				replayReq.SessionID = "session-2"
				_, replayDigest, err := BuildSigningTranscript(replayReq)
				if err != nil {
					t.Fatal(err)
				}
				replayReq.TranscriptDigest = replayDigest
				if _, err := ops.StartSigning(replayReq); err != nil {
					t.Fatal(err)
				}
				err = ops.state.TransitionSigning(SigningStateRecord{KeyID: replayReq.KeyID, SessionID: replayReq.SessionID, State: SigningStateCommitmentsReserved, TranscriptDigest: replayReq.TranscriptDigest, CommitmentIDs: []uint64{first.CommitmentID, 999}})
				if err != nil {
					t.Fatal(err)
				}
				err = ops.state.TransitionSigning(SigningStateRecord{KeyID: replayReq.KeyID, SessionID: replayReq.SessionID, State: SigningStateSharesProduced, TranscriptDigest: replayReq.TranscriptDigest, CommitmentIDs: []uint64{first.CommitmentID, 999}, ConsumedCommitmentIDs: []uint64{first.CommitmentID, 999}, ShareParticipantIDs: []uint16{1, 2}})
				assertErrorContains(t, err, "already consumed")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ops := newSpikeOperations(t, InternalSpikeOperationGate(), 2, 3)
			tt.run(t, ops)
		})
	}
}

func spikeStartDKGRequest(participants []Participant) (StartDKGRequest, error) {
	req := StartDKGRequest{
		VaultID:      "vault-1",
		KeyID:        "key-1",
		DKGID:        "dkg-1",
		Threshold:    2,
		Participants: participants,
	}
	_, digest, err := BuildDKGTranscript(req)
	req.TranscriptDigest = digest
	return req, err
}

func spikeStartSigningRequest(participants []Participant, message []byte) (StartSigningRequest, error) {
	digest := frostMessageDigest(message)
	req := StartSigningRequest{
		VaultID:       "vault-1",
		KeyID:         "key-1",
		DKGID:         "dkg-1",
		SessionID:     "session-1",
		Threshold:     2,
		Participants:  participants,
		Chain:         "evm-secp256k1",
		MessageDigest: hex.EncodeToString(digest),
	}
	_, transcriptDigest, err := BuildSigningTranscript(req)
	req.TranscriptDigest = transcriptDigest
	return req, err
}

func frostMessageDigest(message []byte) []byte {
	// The operation contract signs a 32-byte chain digest.
	out := make([]byte, 32)
	copy(out, message)
	return out
}

func assertErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want substring %q", err, want)
	}
}
