package vault

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/awnumar/memguard"
	"github.com/jmcleod/ironhand/crypto"
	icrypto "github.com/jmcleod/ironhand/internal/crypto"
	"github.com/jmcleod/ironhand/storage"
	"github.com/jmcleod/ironhand/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestVault(t *testing.T) (*Vault, *Session, *Credentials) {
	t.Helper()
	ctx := t.Context()
	repo := memory.NewRepository()

	creds, err := NewCredentials("test-passphrase")
	require.NoError(t, err)

	v := New("default", repo)
	session, err := v.Create(ctx, creds)
	require.NoError(t, err)
	t.Cleanup(session.Close)

	return v, session, creds
}

func TestVault_CreateAndOpen(t *testing.T) {
	ctx := t.Context()
	repo := memory.NewRepository()

	creds, err := NewCredentials("test-passphrase")
	require.NoError(t, err)

	v := New("default", repo)
	session, err := v.Create(ctx, creds)
	require.NoError(t, err)
	defer session.Close()

	assert.Equal(t, uint64(1), session.Epoch())
	assert.Equal(t, creds.MemberID(), session.MemberID)

	// Re-open the vault
	openCreds, err := OpenCredentials(
		creds.SecretKey(),
		"test-passphrase",
		creds.MemberID(),
		creds.PrivateKey(),
		WithCredentialProfile(creds.Profile()),
	)
	require.NoError(t, err)

	session2, err := v.Open(ctx, openCreds)
	require.NoError(t, err)
	defer session2.Close()

	assert.Equal(t, uint64(1), session2.Epoch())
}

func TestVault_PutAndGet(t *testing.T) {
	ctx := t.Context()
	_, session, _ := createTestVault(t)

	secretData := []byte("This is a highly confidential message.")
	err := session.Put(ctx, "item-1", secretData, WithContentType("text/plain"))
	require.NoError(t, err)

	decrypted, err := session.Get(ctx, "item-1")
	require.NoError(t, err)
	assert.Equal(t, secretData, decrypted)
}

func TestVault_PutDefaultContentType(t *testing.T) {
	ctx := t.Context()
	_, session, _ := createTestVault(t)

	err := session.Put(ctx, "item-1", []byte("data"))
	require.NoError(t, err)

	decrypted, err := session.Get(ctx, "item-1")
	require.NoError(t, err)
	assert.Equal(t, []byte("data"), decrypted)
}

func TestVault_Update(t *testing.T) {
	ctx := t.Context()
	_, session, _ := createTestVault(t)

	// Put initial value
	err := session.Put(ctx, "item-1", []byte("version-1"), WithContentType("text/plain"))
	require.NoError(t, err)

	// Update
	err = session.Update(ctx, "item-1", []byte("version-2"))
	require.NoError(t, err)

	// Get updated value
	val, err := session.Get(ctx, "item-1")
	require.NoError(t, err)
	assert.Equal(t, []byte("version-2"), val)
}

func TestVault_UpdateWithContentType(t *testing.T) {
	ctx := t.Context()
	_, session, _ := createTestVault(t)

	err := session.Put(ctx, "item-1", []byte("{}"), WithContentType("text/plain"))
	require.NoError(t, err)

	err = session.Update(ctx, "item-1", []byte(`{"key":"val"}`), WithContentType("application/json"))
	require.NoError(t, err)

	val, err := session.Get(ctx, "item-1")
	require.NoError(t, err)
	assert.Equal(t, []byte(`{"key":"val"}`), val)
}

func TestVault_ConcurrentUpdate(t *testing.T) {
	ctx := t.Context()
	_, session, _ := createTestVault(t)

	err := session.Put(ctx, "item-1", []byte("initial"))
	require.NoError(t, err)

	const n = 10
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make(chan error, n)

	for range n {
		go func() {
			defer wg.Done()
			if err := session.Update(ctx, "item-1", []byte("updated")); err != nil {
				errs <- err
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		if !errors.Is(err, storage.ErrCASFailed) {
			require.NoError(t, err)
		}
	}
}

func TestVault_Session_List_Delete(t *testing.T) {
	ctx := t.Context()
	_, session, _ := createTestVault(t)

	err := session.Put(ctx, "item-1", []byte("data1"))
	require.NoError(t, err)
	err = session.Put(ctx, "item-2", []byte("data2"))
	require.NoError(t, err)

	items, err := session.List(ctx)
	require.NoError(t, err)
	assert.Len(t, items, 2)
	assert.Contains(t, items, "item-1")
	assert.Contains(t, items, "item-2")

	err = session.Delete(ctx, "item-1")
	require.NoError(t, err)

	items, err = session.List(ctx)
	require.NoError(t, err)
	assert.Len(t, items, 1)
	assert.NotContains(t, items, "item-1")
}

func TestVault_TamperProtection(t *testing.T) {
	ctx := context.Background()
	v, session, _ := createTestVault(t)

	err := session.Put(ctx, "item1", []byte("secret"), WithContentType("text/plain"))
	require.NoError(t, err)

	t.Run("Flip ciphertext byte", func(t *testing.T) {
		envelope, _ := v.repo.Get(v.id, "ITEM", "item1")
		envelope.Ciphertext[0] ^= 0xFF
		require.NoError(t, v.repo.Put(v.id, "ITEM", "item1", envelope))

		_, err := session.Get(ctx, "item1")
		assert.Error(t, err)
	})

	t.Run("Swap envelopes between items", func(t *testing.T) {
		session.Put(ctx, "item2", []byte("other"), WithContentType("text/plain"))
		env2, _ := v.repo.Get(v.id, "ITEM", "item2")

		v.repo.Put(v.id, "ITEM", "item1", env2)

		_, err := session.Get(ctx, "item1")
		assert.Error(t, err, "Should fail due to AAD mismatch (itemID)")
	})
}

func TestVault_Revocation(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewRepository()

	aliceCreds, err := NewCredentials("test-passphrase")
	require.NoError(t, err)

	bobKP, err := crypto.GenerateX25519Keypair()
	require.NoError(t, err)

	v := New("default", repo)
	aliceSession, err := v.Create(ctx, aliceCreds)
	require.NoError(t, err)
	defer aliceSession.Close()

	// Add Bob
	err = aliceSession.AddMember(ctx, "bob", bobKP.Public, RoleWriter)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), aliceSession.Epoch())

	// Bob opens vault (uses vault's secret key + passphrase, his own identity)
	bobCreds, err := OpenCredentials(
		aliceCreds.SecretKey(),
		"test-passphrase",
		"bob",
		bobKP.Private,
		WithCredentialProfile(aliceCreds.Profile()),
	)
	require.NoError(t, err)
	bobSession, err := v.Open(ctx, bobCreds)
	require.NoError(t, err)
	defer bobSession.Close()

	// Alice adds an item
	err = aliceSession.Put(ctx, "item1", []byte("shared secret"), WithContentType("text/plain"))
	require.NoError(t, err)

	// Bob can decrypt
	val, err := bobSession.Get(ctx, "item1")
	require.NoError(t, err)
	assert.Equal(t, "shared secret", string(val))

	// Revoke Bob
	err = aliceSession.RevokeMember(ctx, "bob")
	require.NoError(t, err)
	assert.Equal(t, uint64(3), aliceSession.Epoch())

	// Bob fails to open vault at current epoch
	_, err = v.Open(ctx, bobCreds)
	assert.Error(t, err)

	// Bob's old session still has old KEK, but the item was rewrapped
	_, err = bobSession.Get(ctx, "item1")
	assert.Error(t, err, "Bob's old session should fail to decrypt rewrapped item")
}

func TestVault_RollbackDetection(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewRepository()

	creds, err := NewCredentials("test-passphrase")
	require.NoError(t, err)

	v := New("default", repo)
	session, err := v.Create(ctx, creds)
	require.NoError(t, err)
	defer session.Close()

	// Add a member to bump epoch to 2
	bobKP, _ := crypto.GenerateX25519Keypair()
	err = session.AddMember(ctx, "bob", bobKP.Public, RoleReader)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), session.Epoch())

	// Verify epoch cache
	cache := v.epochCache.(*MemoryEpochCache)
	assert.Equal(t, uint64(2), cache.GetMaxEpochSeen("default"))

	// Simulate malicious rollback: overwrite state with epoch 1
	mukBuf, err := creds.muk.Open()
	require.NoError(t, err)
	defer mukBuf.Destroy()
	recordKey, _ := icrypto.DeriveRecordKey(mukBuf.Bytes(), "default")
	profile := creds.Profile()
	state1 := &vaultState{
		VaultID:    "default",
		Epoch:      1,
		KDFParams:  profile.KDFParams,
		SaltPass:   profile.SaltPass,
		SaltSecret: profile.SaltSecret,
		Ver:        1,
	}
	env, _ := sealVaultState(recordKey, state1)
	repo.Put("default", "STATE", "current", env)

	openCreds, err := OpenCredentials(
		creds.SecretKey(),
		"test-passphrase",
		creds.MemberID(),
		creds.PrivateKey(),
		WithCredentialProfile(creds.Profile()),
	)
	require.NoError(t, err)
	_, err = v.Open(ctx, openCreds)
	assert.ErrorIs(t, err, ErrRollbackDetected)
}

func TestVault_SessionClose(t *testing.T) {
	session := &Session{
		kek:       memguard.NewEnclave([]byte{1, 2, 3, 4, 5}),
		recordKey: memguard.NewEnclave([]byte{10, 20, 30, 40, 50}),
	}
	session.Close()

	assert.Nil(t, session.kek)
	assert.Nil(t, session.recordKey)
}

func TestVault_InputValidation(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewRepository()

	t.Run("Empty vault ID", func(t *testing.T) {
		v := New("", repo)
		creds := &Credentials{memberID: "alice"}
		_, err := v.Open(ctx, creds)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "vault ID must not be empty")
	})

	t.Run("Vault ID with colon", func(t *testing.T) {
		v := New("vault:1", repo)
		creds := &Credentials{memberID: "alice"}
		_, err := v.Open(ctx, creds)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "forbidden character")
	})

	t.Run("Empty member ID", func(t *testing.T) {
		v := New("vault1", repo)
		creds := &Credentials{memberID: ""}
		_, err := v.Open(ctx, creds)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "member ID must not be empty")
	})
}

func TestVault_AuthorizationEnforced(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewRepository()

	aliceCreds, err := NewCredentials("test-passphrase")
	require.NoError(t, err)
	v := New("default", repo)
	aliceSession, err := v.Create(ctx, aliceCreds)
	require.NoError(t, err)
	defer aliceSession.Close()

	readerKP, err := crypto.GenerateX25519Keypair()
	require.NoError(t, err)
	require.NoError(t, aliceSession.AddMember(ctx, "reader", readerKP.Public, RoleReader))

	readerCreds, err := OpenCredentials(
		aliceCreds.SecretKey(),
		"test-passphrase",
		"reader",
		readerKP.Private,
		WithCredentialProfile(aliceCreds.Profile()),
	)
	require.NoError(t, err)
	readerSession, err := v.Open(ctx, readerCreds)
	require.NoError(t, err)
	defer readerSession.Close()

	require.NoError(t, aliceSession.Put(ctx, "item-1", []byte("hello"), WithContentType("text/plain")))
	_, err = readerSession.Get(ctx, "item-1")
	require.NoError(t, err)

	err = readerSession.Put(ctx, "item-2", []byte("denied"), WithContentType("text/plain"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthorized))

	err = readerSession.AddMember(ctx, "other", readerKP.Public, RoleReader)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthorized))
}

func TestVault_StaleSessionRejected(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewRepository()

	aliceCreds, err := NewCredentials("test-passphrase")
	require.NoError(t, err)
	v := New("default", repo)
	aliceSession, err := v.Create(ctx, aliceCreds)
	require.NoError(t, err)
	defer aliceSession.Close()

	writerKP, err := crypto.GenerateX25519Keypair()
	require.NoError(t, err)
	require.NoError(t, aliceSession.AddMember(ctx, "writer", writerKP.Public, RoleWriter))

	writerCreds, err := OpenCredentials(
		aliceCreds.SecretKey(),
		"test-passphrase",
		"writer",
		writerKP.Private,
		WithCredentialProfile(aliceCreds.Profile()),
	)
	require.NoError(t, err)
	writerSession, err := v.Open(ctx, writerCreds)
	require.NoError(t, err)
	defer writerSession.Close()

	require.NoError(t, aliceSession.AddMember(ctx, "reader2", writerKP.Public, RoleReader))

	err = writerSession.Put(ctx, "item-stale", []byte("stale"), WithContentType("text/plain"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrStaleSession))
}
