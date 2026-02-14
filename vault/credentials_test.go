package vault

import (
	"testing"

	"github.com/jmcleod/ironhand/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredentials_Destroy(t *testing.T) {
	creds, err := NewCredentials("test-passphrase")
	require.NoError(t, err)

	creds.Destroy()

	assert.Equal(t, "", creds.MemberID())
	assert.Nil(t, creds.SecretKey())
	assert.Equal(t, [32]byte{}, creds.PrivateKey())
	assert.Equal(t, [32]byte{}, creds.PublicKey())
	assert.Equal(t, CredentialProfile{}, creds.Profile())

	_, err = ExportCredentials(creds, "export-passphrase")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "destroyed")
}

func TestVault_OpenWithDestroyedCredentials(t *testing.T) {
	ctx := t.Context()
	repo := memory.NewRepository()

	ownerCreds, err := NewCredentials("test-passphrase")
	require.NoError(t, err)
	defer ownerCreds.Destroy()

	v := New("default", repo)
	session, err := v.Create(ctx, ownerCreds)
	require.NoError(t, err)
	session.Close()

	openCreds, err := OpenCredentials(
		ownerCreds.SecretKey(),
		"test-passphrase",
		ownerCreds.MemberID(),
		ownerCreds.PrivateKey(),
		WithCredentialProfile(ownerCreds.Profile()),
	)
	require.NoError(t, err)
	openCreds.Destroy()

	_, err = v.Open(ctx, openCreds)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "member ID must not be empty")
}
