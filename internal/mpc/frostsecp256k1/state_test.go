package frostsecp256k1

import (
	"strings"
	"testing"
)

const (
	testDKGDigest     = "dkg-digest"
	testSigningDigest = "signing-digest"
)

func TestDurableStateAllowsValidDKGFlow(t *testing.T) {
	state := NewDurableState()
	if err := state.StartDKG(DKGStateRecord{KeyID: "key-1", DKGID: "dkg-1", State: DKGStateStarted, TranscriptDigest: testDKGDigest}); err != nil {
		t.Fatalf("StartDKG() error = %v", err)
	}
	if err := state.TransitionDKG(DKGStateRecord{KeyID: "key-1", DKGID: "dkg-1", State: DKGStateFinalized, TranscriptDigest: testDKGDigest}); err != nil {
		t.Fatalf("TransitionDKG(finalized) error = %v", err)
	}
	if err := state.TransitionDKG(DKGStateRecord{KeyID: "key-1", DKGID: "dkg-1", State: DKGStateCommitted, TranscriptDigest: testDKGDigest}); err != nil {
		t.Fatalf("TransitionDKG(committed) error = %v", err)
	}
	if got := state.DKG[recordKey("key-1", "dkg-1")].State; got != DKGStateCommitted {
		t.Fatalf("DKG state = %s, want %s", got, DKGStateCommitted)
	}
}

func TestDurableStateRejectsInvalidDKGTransitions(t *testing.T) {
	tests := []struct {
		name    string
		records []DKGStateRecord
		wantErr string
	}{
		{
			name: "commit before finalize",
			records: []DKGStateRecord{
				{KeyID: "key-1", DKGID: "dkg-1", State: DKGStateStarted, TranscriptDigest: testDKGDigest},
				{KeyID: "key-1", DKGID: "dkg-1", State: DKGStateCommitted, TranscriptDigest: testDKGDigest},
			},
			wantErr: "invalid DKG transition",
		},
		{
			name: "abort after commit",
			records: []DKGStateRecord{
				{KeyID: "key-1", DKGID: "dkg-1", State: DKGStateStarted, TranscriptDigest: testDKGDigest},
				{KeyID: "key-1", DKGID: "dkg-1", State: DKGStateFinalized, TranscriptDigest: testDKGDigest},
				{KeyID: "key-1", DKGID: "dkg-1", State: DKGStateCommitted, TranscriptDigest: testDKGDigest},
				{KeyID: "key-1", DKGID: "dkg-1", State: DKGStateAborted, TranscriptDigest: testDKGDigest},
			},
			wantErr: "invalid DKG transition",
		},
		{
			name: "duplicate committed state",
			records: []DKGStateRecord{
				{KeyID: "key-1", DKGID: "dkg-1", State: DKGStateStarted, TranscriptDigest: testDKGDigest},
				{KeyID: "key-1", DKGID: "dkg-1", State: DKGStateFinalized, TranscriptDigest: testDKGDigest},
				{KeyID: "key-1", DKGID: "dkg-1", State: DKGStateCommitted, TranscriptDigest: testDKGDigest},
				{KeyID: "key-1", DKGID: "dkg-1", State: DKGStateCommitted, TranscriptDigest: testDKGDigest},
			},
			wantErr: "invalid DKG transition",
		},
		{
			name: "digest mismatch",
			records: []DKGStateRecord{
				{KeyID: "key-1", DKGID: "dkg-1", State: DKGStateStarted, TranscriptDigest: testDKGDigest},
				{KeyID: "key-1", DKGID: "dkg-1", State: DKGStateFinalized, TranscriptDigest: "other"},
			},
			wantErr: "digest mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := NewDurableState()
			var err error
			for i, record := range tt.records {
				if i == 0 {
					err = state.StartDKG(record)
				} else {
					err = state.TransitionDKG(record)
				}
				if err != nil {
					break
				}
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("DKG flow error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestDurableStateAllowsValidSigningFlowAndConsumesCommitments(t *testing.T) {
	state := NewDurableState()
	if err := state.StartSigning(SigningStateRecord{KeyID: "key-1", SessionID: "session-1", State: SigningStateStarted, TranscriptDigest: testSigningDigest}); err != nil {
		t.Fatalf("StartSigning() error = %v", err)
	}
	if err := state.TransitionSigning(SigningStateRecord{KeyID: "key-1", SessionID: "session-1", State: SigningStateCommitmentsReserved, TranscriptDigest: testSigningDigest, CommitmentIDs: []uint64{2, 1}}); err != nil {
		t.Fatalf("TransitionSigning(commitments) error = %v", err)
	}
	if err := state.TransitionSigning(SigningStateRecord{KeyID: "key-1", SessionID: "session-1", State: SigningStateSharesProduced, TranscriptDigest: testSigningDigest, CommitmentIDs: []uint64{2, 1}, ConsumedCommitmentIDs: []uint64{1, 2}, ShareParticipantIDs: []uint16{3, 1}}); err != nil {
		t.Fatalf("TransitionSigning(shares) error = %v", err)
	}
	if err := state.TransitionSigning(SigningStateRecord{KeyID: "key-1", SessionID: "session-1", State: SigningStateFinalized, TranscriptDigest: testSigningDigest, CommitmentIDs: []uint64{1, 2}, ConsumedCommitmentIDs: []uint64{1, 2}, ShareParticipantIDs: []uint16{1, 3}}); err != nil {
		t.Fatalf("TransitionSigning(finalized) error = %v", err)
	}
	record := state.Signing[recordKey("key-1", "session-1")]
	if got := record.State; got != SigningStateFinalized {
		t.Fatalf("signing state = %s, want %s", got, SigningStateFinalized)
	}
	if record.CommitmentIDs[0] != 1 || record.ShareParticipantIDs[0] != 1 {
		t.Fatalf("record was not normalized: %+v", record)
	}
	if owner := state.Consumed[commitmentUseKey("key-1", 1)]; owner != "session-1" {
		t.Fatalf("commitment owner = %q, want session-1", owner)
	}
}

func TestDurableStateRejectsInvalidSigningTransitions(t *testing.T) {
	tests := []struct {
		name    string
		records []SigningStateRecord
		wantErr string
	}{
		{
			name: "shares without commitments",
			records: []SigningStateRecord{
				{KeyID: "key-1", SessionID: "session-1", State: SigningStateStarted, TranscriptDigest: testSigningDigest},
				{KeyID: "key-1", SessionID: "session-1", State: SigningStateSharesProduced, TranscriptDigest: testSigningDigest, ConsumedCommitmentIDs: []uint64{1}, ShareParticipantIDs: []uint16{1}},
			},
			wantErr: "invalid signing transition",
		},
		{
			name: "finalize without shares",
			records: []SigningStateRecord{
				{KeyID: "key-1", SessionID: "session-1", State: SigningStateStarted, TranscriptDigest: testSigningDigest},
				{KeyID: "key-1", SessionID: "session-1", State: SigningStateCommitmentsReserved, TranscriptDigest: testSigningDigest, CommitmentIDs: []uint64{1, 2}},
				{KeyID: "key-1", SessionID: "session-1", State: SigningStateFinalized, TranscriptDigest: testSigningDigest, CommitmentIDs: []uint64{1, 2}, ConsumedCommitmentIDs: []uint64{1, 2}},
			},
			wantErr: "invalid signing transition",
		},
		{
			name: "abort after finalize",
			records: []SigningStateRecord{
				{KeyID: "key-1", SessionID: "session-1", State: SigningStateStarted, TranscriptDigest: testSigningDigest},
				{KeyID: "key-1", SessionID: "session-1", State: SigningStateCommitmentsReserved, TranscriptDigest: testSigningDigest, CommitmentIDs: []uint64{1, 2}},
				{KeyID: "key-1", SessionID: "session-1", State: SigningStateSharesProduced, TranscriptDigest: testSigningDigest, CommitmentIDs: []uint64{1, 2}, ConsumedCommitmentIDs: []uint64{1, 2}, ShareParticipantIDs: []uint16{1, 2}},
				{KeyID: "key-1", SessionID: "session-1", State: SigningStateFinalized, TranscriptDigest: testSigningDigest, CommitmentIDs: []uint64{1, 2}, ConsumedCommitmentIDs: []uint64{1, 2}, ShareParticipantIDs: []uint16{1, 2}},
				{KeyID: "key-1", SessionID: "session-1", State: SigningStateAborted, TranscriptDigest: testSigningDigest},
			},
			wantErr: "invalid signing transition",
		},
		{
			name: "duplicate finalized state",
			records: []SigningStateRecord{
				{KeyID: "key-1", SessionID: "session-1", State: SigningStateStarted, TranscriptDigest: testSigningDigest},
				{KeyID: "key-1", SessionID: "session-1", State: SigningStateCommitmentsReserved, TranscriptDigest: testSigningDigest, CommitmentIDs: []uint64{1, 2}},
				{KeyID: "key-1", SessionID: "session-1", State: SigningStateSharesProduced, TranscriptDigest: testSigningDigest, CommitmentIDs: []uint64{1, 2}, ConsumedCommitmentIDs: []uint64{1, 2}, ShareParticipantIDs: []uint16{1, 2}},
				{KeyID: "key-1", SessionID: "session-1", State: SigningStateFinalized, TranscriptDigest: testSigningDigest, CommitmentIDs: []uint64{1, 2}, ConsumedCommitmentIDs: []uint64{1, 2}, ShareParticipantIDs: []uint16{1, 2}},
				{KeyID: "key-1", SessionID: "session-1", State: SigningStateFinalized, TranscriptDigest: testSigningDigest, CommitmentIDs: []uint64{1, 2}, ConsumedCommitmentIDs: []uint64{1, 2}, ShareParticipantIDs: []uint16{1, 2}},
			},
			wantErr: "invalid signing transition",
		},
		{
			name: "digest mismatch",
			records: []SigningStateRecord{
				{KeyID: "key-1", SessionID: "session-1", State: SigningStateStarted, TranscriptDigest: testSigningDigest},
				{KeyID: "key-1", SessionID: "session-1", State: SigningStateCommitmentsReserved, TranscriptDigest: "other", CommitmentIDs: []uint64{1}},
			},
			wantErr: "digest mismatch",
		},
		{
			name: "duplicate commitments",
			records: []SigningStateRecord{
				{KeyID: "key-1", SessionID: "session-1", State: SigningStateStarted, TranscriptDigest: testSigningDigest},
				{KeyID: "key-1", SessionID: "session-1", State: SigningStateCommitmentsReserved, TranscriptDigest: testSigningDigest, CommitmentIDs: []uint64{1, 1}},
			},
			wantErr: "duplicate commitment IDs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := NewDurableState()
			var err error
			for i, record := range tt.records {
				if i == 0 {
					err = state.StartSigning(record)
				} else {
					err = state.TransitionSigning(record)
				}
				if err != nil {
					break
				}
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("signing flow error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestDurableStateRejectsReplayedCommitmentAcrossSessions(t *testing.T) {
	state := NewDurableState()
	runSigningToShares(t, &state, "session-1", testSigningDigest, []uint64{1, 2})

	if err := state.StartSigning(SigningStateRecord{KeyID: "key-1", SessionID: "session-2", State: SigningStateStarted, TranscriptDigest: "digest-2"}); err != nil {
		t.Fatalf("StartSigning(session-2) error = %v", err)
	}
	if err := state.TransitionSigning(SigningStateRecord{KeyID: "key-1", SessionID: "session-2", State: SigningStateCommitmentsReserved, TranscriptDigest: "digest-2", CommitmentIDs: []uint64{1, 3}}); err != nil {
		t.Fatalf("TransitionSigning(session-2 commitments) error = %v", err)
	}
	err := state.TransitionSigning(SigningStateRecord{KeyID: "key-1", SessionID: "session-2", State: SigningStateSharesProduced, TranscriptDigest: "digest-2", CommitmentIDs: []uint64{1, 3}, ConsumedCommitmentIDs: []uint64{1, 3}, ShareParticipantIDs: []uint16{1, 2}})
	if err == nil || !strings.Contains(err.Error(), "already consumed") {
		t.Fatalf("TransitionSigning(session-2 shares) error = %v, want replay rejection", err)
	}
}

func TestDurableStateAllowsAbortBeforeFinalization(t *testing.T) {
	state := NewDurableState()
	if err := state.StartSigning(SigningStateRecord{KeyID: "key-1", SessionID: "session-1", State: SigningStateStarted, TranscriptDigest: testSigningDigest}); err != nil {
		t.Fatalf("StartSigning() error = %v", err)
	}
	if err := state.TransitionSigning(SigningStateRecord{KeyID: "key-1", SessionID: "session-1", State: SigningStateCommitmentsReserved, TranscriptDigest: testSigningDigest, CommitmentIDs: []uint64{1, 2}}); err != nil {
		t.Fatalf("TransitionSigning(commitments) error = %v", err)
	}
	if err := state.TransitionSigning(SigningStateRecord{KeyID: "key-1", SessionID: "session-1", State: SigningStateAborted, TranscriptDigest: testSigningDigest, CommitmentIDs: []uint64{1, 2}}); err != nil {
		t.Fatalf("TransitionSigning(aborted) error = %v", err)
	}
	if got := state.Signing[recordKey("key-1", "session-1")].State; got != SigningStateAborted {
		t.Fatalf("signing state = %s, want %s", got, SigningStateAborted)
	}
}

func TestReconstructDurableStateRestoresConsumedCommitments(t *testing.T) {
	reconstructed, err := ReconstructDurableState(
		[]DKGStateRecord{{KeyID: "key-1", DKGID: "dkg-1", State: DKGStateCommitted, TranscriptDigest: testDKGDigest}},
		[]SigningStateRecord{{
			KeyID:                 "key-1",
			SessionID:             "session-1",
			State:                 SigningStateSharesProduced,
			TranscriptDigest:      testSigningDigest,
			CommitmentIDs:         []uint64{2, 1},
			ConsumedCommitmentIDs: []uint64{2, 1},
			ShareParticipantIDs:   []uint16{2, 1},
		}},
	)
	if err != nil {
		t.Fatalf("ReconstructDurableState() error = %v", err)
	}
	if owner := reconstructed.Consumed[commitmentUseKey("key-1", 1)]; owner != "session-1" {
		t.Fatalf("restored consumed commitment owner = %q, want session-1", owner)
	}
	record := reconstructed.Signing[recordKey("key-1", "session-1")]
	if record.ConsumedCommitmentIDs[0] != 1 || record.ShareParticipantIDs[0] != 1 {
		t.Fatalf("reconstructed record was not normalized: %+v", record)
	}
}

func TestReconstructDurableStateRejectsDuplicateRecords(t *testing.T) {
	_, err := ReconstructDurableState(
		[]DKGStateRecord{
			{KeyID: "key-1", DKGID: "dkg-1", State: DKGStateStarted, TranscriptDigest: testDKGDigest},
			{KeyID: "key-1", DKGID: "dkg-1", State: DKGStateFinalized, TranscriptDigest: testDKGDigest},
		},
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), "duplicate DKG record") {
		t.Fatalf("ReconstructDurableState() DKG error = %v, want duplicate rejection", err)
	}

	_, err = ReconstructDurableState(nil, []SigningStateRecord{
		{KeyID: "key-1", SessionID: "session-1", State: SigningStateStarted, TranscriptDigest: testSigningDigest},
		{KeyID: "key-1", SessionID: "session-1", State: SigningStateStarted, TranscriptDigest: testSigningDigest},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate signing record") {
		t.Fatalf("ReconstructDurableState() signing error = %v, want duplicate rejection", err)
	}
}

func runSigningToShares(t *testing.T, state *DurableState, sessionID, digest string, commitments []uint64) {
	t.Helper()
	if err := state.StartSigning(SigningStateRecord{KeyID: "key-1", SessionID: sessionID, State: SigningStateStarted, TranscriptDigest: digest}); err != nil {
		t.Fatalf("StartSigning(%s) error = %v", sessionID, err)
	}
	if err := state.TransitionSigning(SigningStateRecord{KeyID: "key-1", SessionID: sessionID, State: SigningStateCommitmentsReserved, TranscriptDigest: digest, CommitmentIDs: commitments}); err != nil {
		t.Fatalf("TransitionSigning(%s commitments) error = %v", sessionID, err)
	}
	if err := state.TransitionSigning(SigningStateRecord{KeyID: "key-1", SessionID: sessionID, State: SigningStateSharesProduced, TranscriptDigest: digest, CommitmentIDs: commitments, ConsumedCommitmentIDs: commitments, ShareParticipantIDs: []uint16{1, 2}}); err != nil {
		t.Fatalf("TransitionSigning(%s shares) error = %v", sessionID, err)
	}
}
