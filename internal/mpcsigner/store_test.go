package mpcsigner

import (
	"encoding/json"
	"net/http"
	"testing"

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
