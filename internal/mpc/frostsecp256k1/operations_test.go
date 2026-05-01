package frostsecp256k1

import (
	"errors"
	"strings"
	"testing"
)

func TestOperationGateFailsClosedByDefault(t *testing.T) {
	if err := DisabledOperationGate().Check(); !errors.Is(err, ErrOperationsDisabled) {
		t.Fatalf("DisabledOperationGate().Check() error = %v, want ErrOperationsDisabled", err)
	}
	if err := (OperationGate{}).Check(); !errors.Is(err, ErrOperationsDisabled) {
		t.Fatalf("zero OperationGate.Check() error = %v, want ErrOperationsDisabled", err)
	}
	if err := InternalSpikeOperationGate().Check(); err != nil {
		t.Fatalf("InternalSpikeOperationGate().Check() error = %v", err)
	}
}

func TestValidateStartDKGRequestRequiresCanonicalDigest(t *testing.T) {
	req := StartDKGRequest{
		VaultID:      "vault-1",
		KeyID:        "key-1",
		DKGID:        "dkg-1",
		Threshold:    2,
		Participants: testParticipants(),
	}
	_, digest, err := BuildDKGTranscript(req)
	if err != nil {
		t.Fatalf("BuildDKGTranscript() error = %v", err)
	}
	req.TranscriptDigest = digest
	if err := ValidateStartDKGRequest(req); err != nil {
		t.Fatalf("ValidateStartDKGRequest() error = %v", err)
	}
	req.TranscriptDigest = "wrong"
	if err := ValidateStartDKGRequest(req); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("ValidateStartDKGRequest() error = %v, want digest mismatch", err)
	}
}

func TestValidateStartSigningRequestRequiresCanonicalDigest(t *testing.T) {
	req := StartSigningRequest{
		VaultID:       "vault-1",
		KeyID:         "key-1",
		DKGID:         "dkg-1",
		SessionID:     "session-1",
		Threshold:     2,
		Participants:  testParticipants(),
		Chain:         "evm-secp256k1",
		MessageDigest: testMessageDigest,
	}
	_, digest, err := BuildSigningTranscript(req)
	if err != nil {
		t.Fatalf("BuildSigningTranscript() error = %v", err)
	}
	req.TranscriptDigest = digest
	if err := ValidateStartSigningRequest(req); err != nil {
		t.Fatalf("ValidateStartSigningRequest() error = %v", err)
	}
	req.Chain = "development"
	if err := ValidateStartSigningRequest(req); err == nil || !strings.Contains(err.Error(), "chain") {
		t.Fatalf("ValidateStartSigningRequest() error = %v, want chain rejection", err)
	}
}

func TestValidateOperationRequestsRejectMissingFields(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "accept DKG share missing participant",
			err: ValidateAcceptDKGShareRequest(AcceptDKGShareRequest{
				KeyID:            "key-1",
				DKGID:            "dkg-1",
				ToParticipant:    2,
				SharePackage:     "share",
				TranscriptDigest: "digest",
			}),
			want: "participant",
		},
		{
			name: "finalize DKG missing public key",
			err:  ValidateFinalizeDKGRequest(FinalizeDKGRequest{KeyID: "key-1", DKGID: "dkg-1", TranscriptDigest: "digest"}),
			want: "public key",
		},
		{
			name: "abort DKG missing digest",
			err:  ValidateAbortDKGRequest(AbortDKGRequest{KeyID: "key-1", DKGID: "dkg-1"}),
			want: "transcript digest",
		},
		{
			name: "reserve nonce missing participant",
			err:  ValidateReserveNonceCommitmentsRequest(ReserveNonceCommitmentsRequest{KeyID: "key-1", SessionID: "session-1", TranscriptDigest: "digest"}),
			want: "participant",
		},
		{
			name: "produce share bad digest",
			err: ValidateProduceSignatureShareRequest(ProduceSignatureShareRequest{
				KeyID:            "key-1",
				SessionID:        "session-1",
				ParticipantID:    1,
				MessageDigest:    "not-hex",
				Commitments:      []CommitmentTranscript{{ParticipantID: 1, HidingNonceCommitment: "h", BindingNonceCommitment: "b"}},
				TranscriptDigest: "digest",
			}),
			want: "message digest",
		},
		{
			name: "accept share missing share",
			err:  ValidateAcceptSignatureShareRequest(AcceptSignatureShareRequest{KeyID: "key-1", SessionID: "session-1", ParticipantID: 1, TranscriptDigest: "digest"}),
			want: "signature share",
		},
		{
			name: "aggregate missing shares",
			err: ValidateAggregateSignatureRequest(AggregateSignatureRequest{
				KeyID:            "key-1",
				SessionID:        "session-1",
				MessageDigest:    testMessageDigest,
				Commitments:      []CommitmentTranscript{{ParticipantID: 1, HidingNonceCommitment: "h", BindingNonceCommitment: "b"}},
				TranscriptDigest: "digest",
			}),
			want: "signature shares",
		},
		{
			name: "abort signing missing session",
			err:  ValidateAbortSigningRequest(AbortSigningRequest{KeyID: "key-1", TranscriptDigest: "digest"}),
			want: "session ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil || !strings.Contains(tt.err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", tt.err, tt.want)
			}
		})
	}
}

func TestValidateOperationRequestsAcceptWellFormedRequests(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "accept DKG share",
			err: ValidateAcceptDKGShareRequest(AcceptDKGShareRequest{
				KeyID:            "key-1",
				DKGID:            "dkg-1",
				FromParticipant:  1,
				ToParticipant:    2,
				SharePackage:     "share",
				TranscriptDigest: "digest",
			}),
		},
		{
			name: "finalize DKG",
			err:  ValidateFinalizeDKGRequest(FinalizeDKGRequest{KeyID: "key-1", DKGID: "dkg-1", PublicKey: "public", TranscriptDigest: "digest"}),
		},
		{
			name: "abort DKG",
			err:  ValidateAbortDKGRequest(AbortDKGRequest{KeyID: "key-1", DKGID: "dkg-1", TranscriptDigest: "digest"}),
		},
		{
			name: "reserve nonce",
			err:  ValidateReserveNonceCommitmentsRequest(ReserveNonceCommitmentsRequest{KeyID: "key-1", SessionID: "session-1", ParticipantID: 1, TranscriptDigest: "digest"}),
		},
		{
			name: "produce share",
			err: ValidateProduceSignatureShareRequest(ProduceSignatureShareRequest{
				KeyID:            "key-1",
				SessionID:        "session-1",
				ParticipantID:    1,
				MessageDigest:    testMessageDigest,
				Commitments:      []CommitmentTranscript{{ParticipantID: 1, HidingNonceCommitment: "h", BindingNonceCommitment: "b"}},
				TranscriptDigest: "digest",
			}),
		},
		{
			name: "accept share",
			err:  ValidateAcceptSignatureShareRequest(AcceptSignatureShareRequest{KeyID: "key-1", SessionID: "session-1", ParticipantID: 1, SignatureShare: "share", TranscriptDigest: "digest"}),
		},
		{
			name: "aggregate",
			err: ValidateAggregateSignatureRequest(AggregateSignatureRequest{
				KeyID:            "key-1",
				SessionID:        "session-1",
				MessageDigest:    testMessageDigest,
				Commitments:      []CommitmentTranscript{{ParticipantID: 1, HidingNonceCommitment: "h", BindingNonceCommitment: "b"}},
				Shares:           []SignatureShareTranscript{{ParticipantID: 1, SignatureShare: "share"}},
				TranscriptDigest: "digest",
			}),
		},
		{
			name: "abort signing",
			err:  ValidateAbortSigningRequest(AbortSigningRequest{KeyID: "key-1", SessionID: "session-1", TranscriptDigest: "digest"}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err != nil {
				t.Fatalf("validation error = %v", tt.err)
			}
		})
	}
}
