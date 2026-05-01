package frostsecp256k1

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"testing"

	"github.com/bytemare/frost"
	"github.com/bytemare/frost/debug"
	"github.com/bytemare/secret-sharing/keys"
)

type trustedDealerHarness struct {
	configuration *frost.Configuration
	keyShares     []*keys.KeyShare
	publicKey     []byte
	participants  []Participant
}

type harnessSigningResult struct {
	transcript       SigningTranscript
	transcriptDigest string
	message          []byte
	publicKey        []byte
	signature        []byte
}

func newTrustedDealerHarness(t *testing.T, threshold, maxSigners uint16) trustedDealerHarness {
	t.Helper()
	keyShares, verificationKey, _ := debug.TrustedDealerKeygen(frost.Secp256k1, nil, threshold, maxSigners)
	publicKeyShares := make([]*keys.PublicKeyShare, len(keyShares))
	participants := make([]Participant, len(keyShares))
	for i, keyShare := range keyShares {
		public := keyShare.Public()
		publicKeyShares[i] = public
		participants[i] = Participant{
			ID:        keyShare.Identifier(),
			PublicKey: public.PublicKey.Hex(),
		}
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
	return trustedDealerHarness{
		configuration: configuration,
		keyShares:     keyShares,
		publicKey:     verificationKey.Encode(),
		participants:  participants,
	}
}

func (h trustedDealerHarness) sign(t *testing.T, selected []uint16, message []byte) harnessSigningResult {
	t.Helper()
	if len(selected) < int(h.configuration.Threshold) {
		t.Fatalf("selected participants = %d, need at least threshold %d", len(selected), h.configuration.Threshold)
	}
	selectedParticipants := make([]Participant, 0, len(selected))
	signers := make([]*frost.Signer, 0, len(selected))
	for _, participantID := range selected {
		keyShare := h.keyShare(participantID)
		if keyShare == nil {
			t.Fatalf("participant %d is not part of harness key", participantID)
		}
		signer, err := h.configuration.Signer(keyShare)
		if err != nil {
			t.Fatalf("configuration.Signer(%d) error = %v", participantID, err)
		}
		signers = append(signers, signer)
		selectedParticipants = append(selectedParticipants, h.participant(participantID))
	}

	commitments := make(frost.CommitmentList, len(signers))
	transcriptCommitments := make([]CommitmentTranscript, len(signers))
	for i, signer := range signers {
		commitment := signer.Commit()
		commitments[i] = commitment
		transcriptCommitments[i] = CommitmentTranscript{
			ParticipantID:          commitment.SignerID,
			HidingNonceCommitment:  commitment.HidingNonceCommitment.Hex(),
			BindingNonceCommitment: commitment.BindingNonceCommitment.Hex(),
			CommitmentID:           commitment.CommitmentID,
		}
	}
	commitments.Sort()

	shares := make([]*frost.SignatureShare, len(signers))
	transcriptShares := make([]SignatureShareTranscript, len(signers))
	for i, signer := range signers {
		share, err := signer.Sign(message, commitments)
		if err != nil {
			t.Fatalf("signer.Sign(%d) error = %v", signer.KeyShare.Identifier(), err)
		}
		if err := h.configuration.VerifySignatureShare(share, message, commitments); err != nil {
			t.Fatalf("VerifySignatureShare(%d) error = %v", share.SignerIdentifier, err)
		}
		shares[i] = share
		transcriptShares[i] = SignatureShareTranscript{
			ParticipantID:  share.SignerIdentifier,
			SignatureShare: share.SignatureShare.Hex(),
		}
	}

	signature, err := h.configuration.AggregateSignatures(message, shares, commitments, true)
	if err != nil {
		t.Fatalf("AggregateSignatures() error = %v", err)
	}
	if err := frost.VerifySignature(frost.Secp256k1, message, signature, h.configuration.VerificationKey); err != nil {
		t.Fatalf("frost.VerifySignature() error = %v", err)
	}

	messageDigest := sha256.Sum256(message)
	transcript := NewSigningTranscript("vault-1", "key-1", "dkg-1", "session-1", h.configuration.Threshold, selectedParticipants, "evm-secp256k1", hex.EncodeToString(messageDigest[:]))
	transcript.Commitments = transcriptCommitments
	transcript.Shares = transcriptShares
	transcriptDigest, err := SigningTranscriptDigest(transcript)
	if err != nil {
		t.Fatalf("SigningTranscriptDigest() error = %v", err)
	}

	return harnessSigningResult{
		transcript:       transcript,
		transcriptDigest: transcriptDigest,
		message:          slices.Clone(message),
		publicKey:        slices.Clone(h.publicKey),
		signature:        signature.Encode()[1:],
	}
}

func (h trustedDealerHarness) keyShare(participantID uint16) *keys.KeyShare {
	for _, keyShare := range h.keyShares {
		if keyShare.Identifier() == participantID {
			return keyShare
		}
	}
	return nil
}

func (h trustedDealerHarness) participant(participantID uint16) Participant {
	for _, participant := range h.participants {
		if participant.ID == participantID {
			return participant
		}
	}
	panic(fmt.Sprintf("participant %d is not part of harness key", participantID))
}

func TestTrustedDealerHarnessSignsAndBindsTranscript(t *testing.T) {
	harness := newTrustedDealerHarness(t, 2, 3)
	result := harness.sign(t, []uint16{1, 3}, []byte("ironhand frost secp256k1 harness"))

	if err := VerifySignature(result.message, result.publicKey, result.signature); err != nil {
		t.Fatalf("VerifySignature() error = %v", err)
	}
	recomputedDigest, err := SigningTranscriptDigest(result.transcript)
	if err != nil {
		t.Fatalf("SigningTranscriptDigest() error = %v", err)
	}
	if result.transcriptDigest != recomputedDigest {
		t.Fatalf("transcript digest = %s, recomputed %s", result.transcriptDigest, recomputedDigest)
	}
}

func TestTrustedDealerHarnessTranscriptDigestChangesOnSessionMessageAndParticipants(t *testing.T) {
	harness := newTrustedDealerHarness(t, 2, 3)
	result := harness.sign(t, []uint16{1, 3}, []byte("ironhand frost secp256k1 harness"))

	sessionChanged := result.transcript
	sessionChanged.SessionID = "session-2"
	sessionDigest, err := SigningTranscriptDigest(sessionChanged)
	if err != nil {
		t.Fatalf("SigningTranscriptDigest(sessionChanged) error = %v", err)
	}
	if sessionDigest == result.transcriptDigest {
		t.Fatal("transcript digest did not change after session ID changed")
	}

	messageChanged := result.transcript
	changedMessageDigest := sha256.Sum256([]byte("different message"))
	messageChanged.MessageDigest = hex.EncodeToString(changedMessageDigest[:])
	messageDigest, err := SigningTranscriptDigest(messageChanged)
	if err != nil {
		t.Fatalf("SigningTranscriptDigest(messageChanged) error = %v", err)
	}
	if messageDigest == result.transcriptDigest {
		t.Fatal("transcript digest did not change after message digest changed")
	}

	participantsChanged := result.transcript
	participantsChanged.Participants = []Participant{harness.participant(1), harness.participant(2)}
	participantsChanged.Commitments[1].ParticipantID = 2
	participantsChanged.Shares[1].ParticipantID = 2
	participantDigest, err := SigningTranscriptDigest(participantsChanged)
	if err != nil {
		t.Fatalf("SigningTranscriptDigest(participantsChanged) error = %v", err)
	}
	if participantDigest == result.transcriptDigest {
		t.Fatal("transcript digest did not change after participant set changed")
	}
}

func TestTrustedDealerHarnessRejectsBadTranscriptInputs(t *testing.T) {
	harness := newTrustedDealerHarness(t, 2, 3)
	result := harness.sign(t, []uint16{1, 3}, []byte("ironhand frost secp256k1 harness"))

	tests := []struct {
		name   string
		mutate func(*SigningTranscript)
	}{
		{
			name: "wrong chain",
			mutate: func(transcript *SigningTranscript) {
				transcript.Chain = "development"
			},
		},
		{
			name: "tampered message digest",
			mutate: func(transcript *SigningTranscript) {
				transcript.MessageDigest = "not-hex"
			},
		},
		{
			name: "duplicate nonce commitment",
			mutate: func(transcript *SigningTranscript) {
				transcript.Commitments = append(transcript.Commitments, transcript.Commitments[0])
			},
		},
		{
			name: "duplicate signature share",
			mutate: func(transcript *SigningTranscript) {
				transcript.Shares = append(transcript.Shares, transcript.Shares[0])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transcript := result.transcript
			tt.mutate(&transcript)
			if _, err := SigningTranscriptDigest(transcript); err == nil {
				t.Fatal("SigningTranscriptDigest() error = nil, want transcript rejection")
			}
		})
	}
}

func TestTrustedDealerHarnessRejectsInsufficientShares(t *testing.T) {
	harness := newTrustedDealerHarness(t, 2, 3)
	signer, err := harness.configuration.Signer(harness.keyShare(1))
	if err != nil {
		t.Fatalf("configuration.Signer() error = %v", err)
	}
	commitments := frost.CommitmentList{signer.Commit()}
	if _, err := signer.Sign([]byte("insufficient shares"), commitments); err == nil {
		t.Fatal("signer.Sign() error = nil, want insufficient-commitment rejection")
	}
}
