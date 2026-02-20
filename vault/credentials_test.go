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

func TestExportImportCredentialsBytes_RoundTrip(t *testing.T) {
	creds, err := NewCredentials("test-passphrase")
	require.NoError(t, err)
	defer creds.Destroy()

	passphrase := []byte("export-passphrase")

	// Export using []byte variant.
	exported, err := ExportCredentialsBytes(creds, passphrase)
	require.NoError(t, err)
	require.NotEmpty(t, exported)

	// Import using []byte variant.
	imported, err := ImportCredentialsBytes(exported, passphrase)
	require.NoError(t, err)
	defer imported.Destroy()

	// Verify round-trip: member ID and secret key ID must match.
	assert.Equal(t, creds.MemberID(), imported.MemberID())
	assert.Equal(t, creds.SecretKey().ID(), imported.SecretKey().ID())
	assert.Equal(t, creds.PublicKey(), imported.PublicKey())
	assert.Equal(t, creds.PrivateKey(), imported.PrivateKey())
}

func TestExportImportCredentialsBytes_InteropWithString(t *testing.T) {
	creds, err := NewCredentials("test-passphrase")
	require.NoError(t, err)
	defer creds.Destroy()

	pass := "interop-passphrase"

	// Export using string variant, import using []byte variant.
	exported, err := ExportCredentials(creds, pass)
	require.NoError(t, err)

	// The string variant normalizes; the byte variant expects pre-normalized.
	// Since "interop-passphrase" is ASCII, NFKD normalization is a no-op.
	imported, err := ImportCredentialsBytes(exported, []byte(pass))
	require.NoError(t, err)
	defer imported.Destroy()
	assert.Equal(t, creds.MemberID(), imported.MemberID())

	// And the reverse: export with []byte, import with string.
	exported2, err := ExportCredentialsBytes(creds, []byte(pass))
	require.NoError(t, err)

	imported2, err := ImportCredentials(exported2, pass)
	require.NoError(t, err)
	defer imported2.Destroy()
	assert.Equal(t, creds.MemberID(), imported2.MemberID())
}

func TestExportCredentialsBytes_EmptyPassphrase(t *testing.T) {
	creds, err := NewCredentials("test-passphrase")
	require.NoError(t, err)
	defer creds.Destroy()

	_, err = ExportCredentialsBytes(creds, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")

	_, err = ExportCredentialsBytes(creds, []byte{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestImportCredentialsBytes_EmptyPassphrase(t *testing.T) {
	_, err := ImportCredentialsBytes([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
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
