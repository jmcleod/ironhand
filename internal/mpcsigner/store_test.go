package mpcsigner

import (
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
