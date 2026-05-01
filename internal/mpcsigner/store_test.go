package mpcsigner

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jmcleod/ironhand/internal/mpc/frostsecp256k1"
	"github.com/stretchr/testify/require"
)

func TestFileStorePersistsSignerIdentity(t *testing.T) {
	path := t.TempDir() + "/signer.sealed"
	store, err := NewFileStore(path, "test-state-passphrase")
	require.NoError(t, err)

	service, err := NewWithStore("member-1", 7, "Signer One", "https://signer-one.test", []byte("shared"), store, nil)
	require.NoError(t, err)
	first := service.Identity()

	reopenedStore, err := NewFileStore(path, "test-state-passphrase")
	require.NoError(t, err)
	reopened, err := NewWithStore("member-1", 7, "Signer One", "https://signer-one.test", []byte("shared"), reopenedStore, nil)
	require.NoError(t, err)

	require.Equal(t, first.EncryptionPublicKey, reopened.Identity().EncryptionPublicKey)
	require.Equal(t, first.ApprovalPublicKey, reopened.Identity().ApprovalPublicKey)
	require.Equal(t, first.PartyID, reopened.Identity().PartyID)
}

func TestFileStoreRejectsWrongMember(t *testing.T) {
	path := t.TempDir() + "/signer.sealed"
	store, err := NewFileStore(path, "test-state-passphrase")
	require.NoError(t, err)
	_, err = NewWithStore("member-1", 7, "Signer One", "https://signer-one.test", []byte("shared"), store, nil)
	require.NoError(t, err)

	reopenedStore, err := NewFileStore(path, "test-state-passphrase")
	require.NoError(t, err)
	_, err = NewWithStore("member-2", 7, "Signer Two", "https://signer-two.test", []byte("shared"), reopenedStore, nil)
	require.Error(t, err)
}

func TestFileStorePersistsNonceCommitments(t *testing.T) {
	path := t.TempDir() + "/signer.sealed"
	store, err := NewFileStore(path, "test-state-passphrase")
	require.NoError(t, err)
	service, err := NewWithStore("member-1", 1, "Signer One", "https://signer-one.test", nil, store, nil)
	require.NoError(t, err)
	installTestSignerKey(service, "vault-1", "key-1")
	service.mu.Lock()
	require.NoError(t, service.saveLocked())
	service.mu.Unlock()

	first := postSignerJSON(t, service, "/signer/sign/commit", NonceCommitRequest{
		KeyID:       "key-1",
		SessionID:   "session-1",
		MessageHash: "hash-1",
	})
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())

	reopenedStore, err := NewFileStore(path, "test-state-passphrase")
	require.NoError(t, err)
	reopened, err := NewWithStore("member-1", 1, "Signer One", "https://signer-one.test", nil, reopenedStore, nil)
	require.NoError(t, err)
	second := postSignerJSON(t, reopened, "/signer/sign/commit", NonceCommitRequest{
		KeyID:       "key-1",
		SessionID:   "session-1",
		MessageHash: "hash-1",
	})
	require.Equal(t, http.StatusOK, second.Code, second.Body.String())
	require.JSONEq(t, first.Body.String(), second.Body.String())

	conflict := postSignerJSON(t, reopened, "/signer/sign/commit", NonceCommitRequest{
		KeyID:       "key-1",
		SessionID:   "session-1",
		MessageHash: "hash-2",
	})
	require.Equal(t, http.StatusConflict, conflict.Code, conflict.Body.String())

	var commitment map[string]any
	require.NoError(t, json.Unmarshal(first.Body.Bytes(), &commitment))
	require.Equal(t, float64(1), commitment["partyId"])
	require.NotEmpty(t, commitment["r"])
}

func TestFileStorePersistsFROSTDurableState(t *testing.T) {
	path := t.TempDir() + "/signer.sealed"
	store, err := NewFileStore(path, "test-state-passphrase")
	require.NoError(t, err)
	service, err := NewWithStore("member-1", 1, "Signer One", "https://signer-one.test", nil, store, nil)
	require.NoError(t, err)

	service.mu.Lock()
	require.NoError(t, seedFROSTState(&service.frost))
	require.NoError(t, service.saveLocked())
	service.mu.Unlock()

	reopenedStore, err := NewFileStore(path, "test-state-passphrase")
	require.NoError(t, err)
	reopened, err := NewWithStore("member-1", 1, "Signer One", "https://signer-one.test", nil, reopenedStore, nil)
	require.NoError(t, err)

	require.Equal(t, frostsecp256k1.DKGStateCommitted, reopened.frost.DKG["key-1:dkg-1"].State)
	signing := reopened.frost.Signing["key-1:session-1"]
	require.Equal(t, frostsecp256k1.SigningStateSharesProduced, signing.State)
	require.Equal(t, []uint64{1, 2}, signing.ConsumedCommitmentIDs)
	require.Equal(t, "session-1", reopened.frost.Consumed["key-1:1"])

	err = reopened.frost.StartSigning(frostsecp256k1.SigningStateRecord{KeyID: "key-1", SessionID: "session-2", State: frostsecp256k1.SigningStateStarted, TranscriptDigest: "digest-2"})
	require.NoError(t, err)
	err = reopened.frost.TransitionSigning(frostsecp256k1.SigningStateRecord{KeyID: "key-1", SessionID: "session-2", State: frostsecp256k1.SigningStateCommitmentsReserved, TranscriptDigest: "digest-2", CommitmentIDs: []uint64{1, 3}})
	require.NoError(t, err)
	err = reopened.frost.TransitionSigning(frostsecp256k1.SigningStateRecord{KeyID: "key-1", SessionID: "session-2", State: frostsecp256k1.SigningStateSharesProduced, TranscriptDigest: "digest-2", CommitmentIDs: []uint64{1, 3}, ConsumedCommitmentIDs: []uint64{1, 3}, ShareParticipantIDs: []uint16{1, 2}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "already consumed")
}

func TestFileStoreRejectsInvalidFROSTDurableState(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*frostStateSnapshot)
		wantErr string
	}{
		{
			name: "invalid DKG state",
			mutate: func(snapshot *frostStateSnapshot) {
				snapshot.DKG[0].State = frostsecp256k1.DKGState("not-a-state")
			},
			wantErr: "invalid DKG state",
		},
		{
			name: "duplicate records",
			mutate: func(snapshot *frostStateSnapshot) {
				snapshot.Signing = append(snapshot.Signing, snapshot.Signing[0])
			},
			wantErr: "duplicate signing record",
		},
		{
			name: "mismatched consumed ownership",
			mutate: func(snapshot *frostStateSnapshot) {
				snapshot.Consumed["key-1:1"] = "session-2"
			},
			wantErr: "consumed commitment ownership",
		},
		{
			name: "missing transcript digest",
			mutate: func(snapshot *frostStateSnapshot) {
				snapshot.Signing[0].TranscriptDigest = ""
			},
			wantErr: "transcript digest",
		},
		{
			name: "bad FROST state version",
			mutate: func(snapshot *frostStateSnapshot) {
				snapshot.Version = 99
			},
			wantErr: "unsupported FROST signer state version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := t.TempDir() + "/signer.sealed"
			store, err := NewFileStore(path, "test-state-passphrase")
			require.NoError(t, err)
			service, err := NewWithStore("member-1", 1, "Signer One", "https://signer-one.test", nil, store, nil)
			require.NoError(t, err)
			service.mu.Lock()
			require.NoError(t, seedFROSTState(&service.frost))
			snapshot := snapshotFromService(service)
			service.mu.Unlock()
			require.NotNil(t, snapshot.FROSTState)
			tt.mutate(snapshot.FROSTState)
			require.NoError(t, store.Save(snapshot))

			reopenedStore, err := NewFileStore(path, "test-state-passphrase")
			require.NoError(t, err)
			_, err = NewWithStore("member-1", 1, "Signer One", "https://signer-one.test", nil, reopenedStore, nil)
			require.Error(t, err)
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("NewWithStore() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func seedFROSTState(state *frostsecp256k1.DurableState) error {
	if state.DKG == nil && state.Signing == nil && state.Consumed == nil {
		*state = frostsecp256k1.NewDurableState()
	}
	if err := state.StartDKG(frostsecp256k1.DKGStateRecord{KeyID: "key-1", DKGID: "dkg-1", State: frostsecp256k1.DKGStateStarted, TranscriptDigest: "dkg-digest"}); err != nil {
		return err
	}
	if err := state.TransitionDKG(frostsecp256k1.DKGStateRecord{KeyID: "key-1", DKGID: "dkg-1", State: frostsecp256k1.DKGStateFinalized, TranscriptDigest: "dkg-digest"}); err != nil {
		return err
	}
	if err := state.TransitionDKG(frostsecp256k1.DKGStateRecord{KeyID: "key-1", DKGID: "dkg-1", State: frostsecp256k1.DKGStateCommitted, TranscriptDigest: "dkg-digest"}); err != nil {
		return err
	}
	if err := state.StartSigning(frostsecp256k1.SigningStateRecord{KeyID: "key-1", SessionID: "session-1", State: frostsecp256k1.SigningStateStarted, TranscriptDigest: "signing-digest"}); err != nil {
		return err
	}
	if err := state.TransitionSigning(frostsecp256k1.SigningStateRecord{KeyID: "key-1", SessionID: "session-1", State: frostsecp256k1.SigningStateCommitmentsReserved, TranscriptDigest: "signing-digest", CommitmentIDs: []uint64{2, 1}}); err != nil {
		return err
	}
	return state.TransitionSigning(frostsecp256k1.SigningStateRecord{KeyID: "key-1", SessionID: "session-1", State: frostsecp256k1.SigningStateSharesProduced, TranscriptDigest: "signing-digest", CommitmentIDs: []uint64{2, 1}, ConsumedCommitmentIDs: []uint64{2, 1}, ShareParticipantIDs: []uint16{2, 1}})
}
