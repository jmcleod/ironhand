package mpcsigner

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/jmcleod/ironhand/internal/mpc/frostsecp256k1"
	"github.com/stretchr/testify/require"
)

func TestSignerFROSTHarnessPersistsTranscriptBoundStateAcrossRestart(t *testing.T) {
	path := t.TempDir() + "/signer.sealed"
	store, err := NewFileStore(path, "test-state-passphrase")
	require.NoError(t, err)
	service, err := NewWithStore("member-1", 1, "Signer One", "https://signer-one.test", nil, store, nil)
	require.NoError(t, err)

	dkgTranscript := frostsecp256k1.NewDKGTranscript("vault-1", "key-1", "dkg-1", 2, frostHarnessParticipants())
	dkgDigest, err := frostsecp256k1.DKGTranscriptDigest(dkgTranscript)
	require.NoError(t, err)
	signingTranscript := frostHarnessSigningTranscript("session-1", []uint64{101, 102})
	signingDigest, err := frostsecp256k1.SigningTranscriptDigest(signingTranscript)
	require.NoError(t, err)

	require.NoError(t, recordFROSTHarnessDKGState(service, "key-1", "dkg-1", dkgDigest))
	require.NoError(t, recordFROSTHarnessSigningState(service, "key-1", "session-1", signingDigest, []uint64{101, 102}, []uint16{1, 2}))

	reopenedStore, err := NewFileStore(path, "test-state-passphrase")
	require.NoError(t, err)
	reopened, err := NewWithStore("member-1", 1, "Signer One", "https://signer-one.test", nil, reopenedStore, nil)
	require.NoError(t, err)

	require.Equal(t, frostsecp256k1.DKGStateCommitted, reopened.frost.DKG["key-1:dkg-1"].State)
	require.Equal(t, dkgDigest, reopened.frost.DKG["key-1:dkg-1"].TranscriptDigest)
	reloadedSigning := reopened.frost.Signing["key-1:session-1"]
	require.Equal(t, frostsecp256k1.SigningStateSharesProduced, reloadedSigning.State)
	require.Equal(t, signingDigest, reloadedSigning.TranscriptDigest)
	require.Equal(t, []uint64{101, 102}, reloadedSigning.ConsumedCommitmentIDs)
	require.Equal(t, "session-1", reopened.frost.Consumed["key-1:101"])
}

func TestSignerFROSTHarnessRejectsReplayAfterRestart(t *testing.T) {
	path := t.TempDir() + "/signer.sealed"
	store, err := NewFileStore(path, "test-state-passphrase")
	require.NoError(t, err)
	service, err := NewWithStore("member-1", 1, "Signer One", "https://signer-one.test", nil, store, nil)
	require.NoError(t, err)

	signingTranscript := frostHarnessSigningTranscript("session-1", []uint64{201, 202})
	signingDigest, err := frostsecp256k1.SigningTranscriptDigest(signingTranscript)
	require.NoError(t, err)
	require.NoError(t, recordFROSTHarnessSigningState(service, "key-1", "session-1", signingDigest, []uint64{201, 202}, []uint16{1, 2}))

	reopenedStore, err := NewFileStore(path, "test-state-passphrase")
	require.NoError(t, err)
	reopened, err := NewWithStore("member-1", 1, "Signer One", "https://signer-one.test", nil, reopenedStore, nil)
	require.NoError(t, err)

	replayTranscript := frostHarnessSigningTranscript("session-2", []uint64{201, 203})
	replayDigest, err := frostsecp256k1.SigningTranscriptDigest(replayTranscript)
	require.NoError(t, err)
	err = recordFROSTHarnessSigningState(reopened, "key-1", "session-2", replayDigest, []uint64{201, 203}, []uint16{1, 2})
	require.Error(t, err)
	require.Contains(t, err.Error(), "already consumed")
}

func recordFROSTHarnessDKGState(service *Service, keyID, dkgID, transcriptDigest string) error {
	service.mu.Lock()
	defer service.mu.Unlock()
	if err := service.frost.StartDKG(frostsecp256k1.DKGStateRecord{KeyID: keyID, DKGID: dkgID, State: frostsecp256k1.DKGStateStarted, TranscriptDigest: transcriptDigest}); err != nil {
		return err
	}
	if err := service.frost.TransitionDKG(frostsecp256k1.DKGStateRecord{KeyID: keyID, DKGID: dkgID, State: frostsecp256k1.DKGStateFinalized, TranscriptDigest: transcriptDigest}); err != nil {
		return err
	}
	if err := service.frost.TransitionDKG(frostsecp256k1.DKGStateRecord{KeyID: keyID, DKGID: dkgID, State: frostsecp256k1.DKGStateCommitted, TranscriptDigest: transcriptDigest}); err != nil {
		return err
	}
	return service.saveLocked()
}

func recordFROSTHarnessSigningState(service *Service, keyID, sessionID, transcriptDigest string, commitmentIDs []uint64, shareParticipantIDs []uint16) error {
	service.mu.Lock()
	defer service.mu.Unlock()
	if err := service.frost.StartSigning(frostsecp256k1.SigningStateRecord{KeyID: keyID, SessionID: sessionID, State: frostsecp256k1.SigningStateStarted, TranscriptDigest: transcriptDigest}); err != nil {
		return err
	}
	if err := service.frost.TransitionSigning(frostsecp256k1.SigningStateRecord{KeyID: keyID, SessionID: sessionID, State: frostsecp256k1.SigningStateCommitmentsReserved, TranscriptDigest: transcriptDigest, CommitmentIDs: commitmentIDs}); err != nil {
		return err
	}
	if err := service.frost.TransitionSigning(frostsecp256k1.SigningStateRecord{KeyID: keyID, SessionID: sessionID, State: frostsecp256k1.SigningStateSharesProduced, TranscriptDigest: transcriptDigest, CommitmentIDs: commitmentIDs, ConsumedCommitmentIDs: commitmentIDs, ShareParticipantIDs: shareParticipantIDs}); err != nil {
		return err
	}
	return service.saveLocked()
}

func frostHarnessSigningTranscript(sessionID string, commitmentIDs []uint64) frostsecp256k1.SigningTranscript {
	messageDigest := sha256.Sum256([]byte(sessionID + ":ironhand-frost-signer-harness"))
	transcript := frostsecp256k1.NewSigningTranscript("vault-1", "key-1", "dkg-1", sessionID, 2, frostHarnessParticipants(), "evm-secp256k1", hex.EncodeToString(messageDigest[:]))
	transcript.Commitments = []frostsecp256k1.CommitmentTranscript{
		{ParticipantID: 1, HidingNonceCommitment: "hiding-1", BindingNonceCommitment: "binding-1", CommitmentID: commitmentIDs[0]},
		{ParticipantID: 2, HidingNonceCommitment: "hiding-2", BindingNonceCommitment: "binding-2", CommitmentID: commitmentIDs[1]},
	}
	transcript.Shares = []frostsecp256k1.SignatureShareTranscript{
		{ParticipantID: 1, SignatureShare: "share-1"},
		{ParticipantID: 2, SignatureShare: "share-2"},
	}
	return transcript
}

func frostHarnessParticipants() []frostsecp256k1.Participant {
	return []frostsecp256k1.Participant{
		{ID: 1, PublicKey: "public-1"},
		{ID: 2, PublicKey: "public-2"},
		{ID: 3, PublicKey: "public-3"},
	}
}
