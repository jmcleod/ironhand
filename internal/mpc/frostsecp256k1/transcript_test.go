package frostsecp256k1

import (
	"bytes"
	"strings"
	"testing"
)

const testMessageDigest = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func testParticipants() []Participant {
	return []Participant{
		{ID: 3, PublicKey: "pk-3"},
		{ID: 1, PublicKey: "pk-1"},
		{ID: 2, PublicKey: "pk-2"},
	}
}

func testSigningTranscript() SigningTranscript {
	transcript := NewSigningTranscript("vault-1", "key-1", "dkg-1", "session-1", 2, testParticipants(), "evm-secp256k1", testMessageDigest)
	transcript.Commitments = []CommitmentTranscript{
		{ParticipantID: 3, HidingNonceCommitment: "h3", BindingNonceCommitment: "b3", BindingFactorInput: "input-3", BindingFactor: "factor-3"},
		{ParticipantID: 1, HidingNonceCommitment: "h1", BindingNonceCommitment: "b1", BindingFactorInput: "input-1", BindingFactor: "factor-1"},
	}
	transcript.Shares = []SignatureShareTranscript{
		{ParticipantID: 3, SignatureShare: "share-3"},
		{ParticipantID: 1, SignatureShare: "share-1"},
	}
	return transcript
}

func TestCanonicalSigningTranscriptStableAcrossInputOrder(t *testing.T) {
	first := testSigningTranscript()
	second := testSigningTranscript()
	second.Participants = []Participant{
		{ID: 1, PublicKey: "pk-1"},
		{ID: 2, PublicKey: "pk-2"},
		{ID: 3, PublicKey: "pk-3"},
	}
	second.Commitments = []CommitmentTranscript{
		{ParticipantID: 1, HidingNonceCommitment: "h1", BindingNonceCommitment: "b1", BindingFactorInput: "input-1", BindingFactor: "factor-1"},
		{ParticipantID: 3, HidingNonceCommitment: "h3", BindingNonceCommitment: "b3", BindingFactorInput: "input-3", BindingFactor: "factor-3"},
	}
	second.Shares = []SignatureShareTranscript{
		{ParticipantID: 1, SignatureShare: "share-1"},
		{ParticipantID: 3, SignatureShare: "share-3"},
	}

	firstBytes, err := CanonicalSigningTranscript(first)
	if err != nil {
		t.Fatalf("CanonicalSigningTranscript(first) error = %v", err)
	}
	secondBytes, err := CanonicalSigningTranscript(second)
	if err != nil {
		t.Fatalf("CanonicalSigningTranscript(second) error = %v", err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatalf("canonical transcripts differ:\n%s\n%s", firstBytes, secondBytes)
	}
}

func TestSigningTranscriptDigestChangesOnMeaningfulFieldChange(t *testing.T) {
	first := testSigningTranscript()
	firstDigest, err := SigningTranscriptDigest(first)
	if err != nil {
		t.Fatalf("SigningTranscriptDigest(first) error = %v", err)
	}
	second := testSigningTranscript()
	second.SessionID = "session-2"
	secondDigest, err := SigningTranscriptDigest(second)
	if err != nil {
		t.Fatalf("SigningTranscriptDigest(second) error = %v", err)
	}
	if firstDigest == secondDigest {
		t.Fatal("SigningTranscriptDigest() did not change after session ID changed")
	}
}

func TestCanonicalDKGTranscriptStableAcrossParticipantOrder(t *testing.T) {
	first := NewDKGTranscript("vault-1", "key-1", "dkg-1", 2, testParticipants())
	second := NewDKGTranscript("vault-1", "key-1", "dkg-1", 2, []Participant{
		{ID: 1, PublicKey: "pk-1"},
		{ID: 2, PublicKey: "pk-2"},
		{ID: 3, PublicKey: "pk-3"},
	})

	firstBytes, err := CanonicalDKGTranscript(first)
	if err != nil {
		t.Fatalf("CanonicalDKGTranscript(first) error = %v", err)
	}
	secondBytes, err := CanonicalDKGTranscript(second)
	if err != nil {
		t.Fatalf("CanonicalDKGTranscript(second) error = %v", err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatalf("canonical DKG transcripts differ:\n%s\n%s", firstBytes, secondBytes)
	}
}

func TestDKGTranscriptDigestRejectsWrongProviderMetadata(t *testing.T) {
	transcript := NewDKGTranscript("vault-1", "key-1", "dkg-1", 2, testParticipants())
	transcript.ContextString = "wrong-context"
	if _, err := DKGTranscriptDigest(transcript); err == nil || !strings.Contains(err.Error(), "context") {
		t.Fatalf("DKGTranscriptDigest() error = %v, want context rejection", err)
	}
}

func TestSigningTranscriptValidationRejectsBadInputs(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*SigningTranscript)
		wantErr string
	}{
		{
			name: "duplicate participants",
			mutate: func(transcript *SigningTranscript) {
				transcript.Participants = append(transcript.Participants, Participant{ID: 1})
			},
			wantErr: "participant 1",
		},
		{
			name: "threshold exceeds participants",
			mutate: func(transcript *SigningTranscript) {
				transcript.Threshold = 4
			},
			wantErr: "threshold",
		},
		{
			name: "unsupported chain",
			mutate: func(transcript *SigningTranscript) {
				transcript.Chain = "solana-ed25519"
			},
			wantErr: "chain",
		},
		{
			name: "missing message digest",
			mutate: func(transcript *SigningTranscript) {
				transcript.MessageDigest = ""
			},
			wantErr: "message digest",
		},
		{
			name: "short message digest",
			mutate: func(transcript *SigningTranscript) {
				transcript.MessageDigest = "abcd"
			},
			wantErr: "message digest",
		},
		{
			name: "duplicate commitments",
			mutate: func(transcript *SigningTranscript) {
				transcript.Commitments = append(transcript.Commitments, CommitmentTranscript{ParticipantID: 1, HidingNonceCommitment: "h1b", BindingNonceCommitment: "b1b"})
			},
			wantErr: "commitment for participant 1",
		},
		{
			name: "commitment participant mismatch",
			mutate: func(transcript *SigningTranscript) {
				transcript.Commitments = append(transcript.Commitments, CommitmentTranscript{ParticipantID: 9, HidingNonceCommitment: "h9", BindingNonceCommitment: "b9"})
			},
			wantErr: "commitment participant 9",
		},
		{
			name: "duplicate shares",
			mutate: func(transcript *SigningTranscript) {
				transcript.Shares = append(transcript.Shares, SignatureShareTranscript{ParticipantID: 1, SignatureShare: "share-1b"})
			},
			wantErr: "signature share for participant 1",
		},
		{
			name: "share participant mismatch",
			mutate: func(transcript *SigningTranscript) {
				transcript.Shares = append(transcript.Shares, SignatureShareTranscript{ParticipantID: 9, SignatureShare: "share-9"})
			},
			wantErr: "signature share participant 9",
		},
		{
			name: "wrong provider",
			mutate: func(transcript *SigningTranscript) {
				transcript.Provider = "experimental-p256-schnorr-v1"
			},
			wantErr: "provider",
		},
		{
			name: "missing session ID",
			mutate: func(transcript *SigningTranscript) {
				transcript.SessionID = ""
			},
			wantErr: "session ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transcript := testSigningTranscript()
			tt.mutate(&transcript)
			_, err := CanonicalSigningTranscript(transcript)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("CanonicalSigningTranscript() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
