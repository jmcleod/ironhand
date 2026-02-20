package vault

import (
	"context"
	"errors"
	"fmt"
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

func TestVault_Create_DuplicateVaultID(t *testing.T) {
	ctx := t.Context()
	repo := memory.NewRepository()

	firstCreds, err := NewCredentials("test-passphrase")
	require.NoError(t, err)
	defer firstCreds.Destroy()

	secondCreds, err := NewCredentials("test-passphrase")
	require.NoError(t, err)
	defer secondCreds.Destroy()

	v := New("default", repo)
	firstSession, err := v.Create(ctx, firstCreds)
	require.NoError(t, err)
	defer firstSession.Close()

	_, err = v.Create(ctx, secondCreds)
	require.ErrorIs(t, err, ErrVaultAlreadyExists)
}

func TestVault_PutAndGet(t *testing.T) {
	ctx := t.Context()
	_, session, _ := createTestVault(t)

	fields := Fields{
		"username": []byte("admin"),
		"password": []byte("s3cret"),
	}
	err := session.Put(ctx, "item-1", fields)
	require.NoError(t, err)

	result, err := session.Get(ctx, "item-1")
	require.NoError(t, err)
	assert.Equal(t, []byte("admin"), result["username"])
	assert.Equal(t, []byte("s3cret"), result["password"])
}

func TestVault_PutSingleField(t *testing.T) {
	ctx := t.Context()
	_, session, _ := createTestVault(t)

	err := session.Put(ctx, "item-1", Fields{"note": []byte("data")})
	require.NoError(t, err)

	result, err := session.Get(ctx, "item-1")
	require.NoError(t, err)
	assert.Equal(t, []byte("data"), result["note"])
	assert.Len(t, result, 1)
}

func TestVault_Update(t *testing.T) {
	ctx := t.Context()
	_, session, _ := createTestVault(t)

	err := session.Put(ctx, "item-1", Fields{"password": []byte("version-1")})
	require.NoError(t, err)

	err = session.Update(ctx, "item-1", Fields{"password": []byte("version-2"), "username": []byte("admin")})
	require.NoError(t, err)

	result, err := session.Get(ctx, "item-1")
	require.NoError(t, err)
	assert.Equal(t, []byte("version-2"), result["password"])
	assert.Equal(t, []byte("admin"), result["username"])
}

func TestVault_UpdateReplacesAllFields(t *testing.T) {
	ctx := t.Context()
	_, session, _ := createTestVault(t)

	err := session.Put(ctx, "item-1", Fields{"a": []byte("1"), "b": []byte("2")})
	require.NoError(t, err)

	// Update with only field "c" — fields "a" and "b" should be gone
	err = session.Update(ctx, "item-1", Fields{"c": []byte("3")})
	require.NoError(t, err)

	result, err := session.Get(ctx, "item-1")
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, []byte("3"), result["c"])
}

func TestVault_ConcurrentUpdate(t *testing.T) {
	ctx := t.Context()
	_, session, _ := createTestVault(t)

	err := session.Put(ctx, "item-1", Fields{"data": []byte("initial")})
	require.NoError(t, err)

	const n = 10
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make(chan error, n)

	for range n {
		go func() {
			defer wg.Done()
			if err := session.Update(ctx, "item-1", Fields{"data": []byte("updated")}); err != nil {
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

	err := session.Put(ctx, "item-1", Fields{"data": []byte("data1")})
	require.NoError(t, err)
	err = session.Put(ctx, "item-2", Fields{"data": []byte("data2")})
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

	err := session.Put(ctx, "item1", Fields{"secret": []byte("value")})
	require.NoError(t, err)

	t.Run("Flip ciphertext byte", func(t *testing.T) {
		envelope, _ := v.repo.Get(v.id, "ITEM", "item1")
		envelope.Ciphertext[0] ^= 0xFF
		require.NoError(t, v.repo.Put(v.id, "ITEM", "item1", envelope))

		_, err := session.Get(ctx, "item1")
		assert.Error(t, err)
	})

	t.Run("Swap envelopes between items", func(t *testing.T) {
		session.Put(ctx, "item2", Fields{"other": []byte("value")})
		env2, _ := v.repo.Get(v.id, "ITEM", "item2")

		v.repo.Put(v.id, "ITEM", "item1", env2)

		_, err := session.Get(ctx, "item1")
		assert.Error(t, err, "Should fail due to AAD mismatch (itemID)")
	})
}

func TestVault_FieldValidation(t *testing.T) {
	ctx := t.Context()
	_, session, _ := createTestVault(t)

	t.Run("Empty fields rejected", func(t *testing.T) {
		err := session.Put(ctx, "item-1", Fields{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least one field")
	})

	t.Run("Empty field name rejected", func(t *testing.T) {
		err := session.Put(ctx, "item-1", Fields{"": []byte("value")})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "field name must not be empty")
	})

	t.Run("Field name with colon rejected", func(t *testing.T) {
		err := session.Put(ctx, "item-1", Fields{"bad:name": []byte("value")})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "forbidden character")
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
	err = aliceSession.Put(ctx, "item1", Fields{"secret": []byte("shared secret")})
	require.NoError(t, err)

	// Bob can decrypt
	val, err := bobSession.Get(ctx, "item1")
	require.NoError(t, err)
	assert.Equal(t, "shared secret", string(val["secret"]))

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

	require.NoError(t, aliceSession.Put(ctx, "item-1", Fields{"greeting": []byte("hello")}))
	_, err = readerSession.Get(ctx, "item-1")
	require.NoError(t, err)

	err = readerSession.Put(ctx, "item-2", Fields{"data": []byte("denied")})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthorized))

	err = readerSession.AddMember(ctx, "other", readerKP.Public, RoleReader)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthorized))
}

func TestVault_UpdateCreatesHistory(t *testing.T) {
	ctx := t.Context()
	_, session, _ := createTestVault(t)

	err := session.Put(ctx, "item-1", Fields{"password": []byte("original")})
	require.NoError(t, err)

	err = session.Update(ctx, "item-1", Fields{"password": []byte("updated")})
	require.NoError(t, err)

	history, err := session.GetHistory(ctx, "item-1")
	require.NoError(t, err)
	require.Len(t, history, 1)
	assert.Equal(t, uint64(1), history[0].Version)
	assert.NotEmpty(t, history[0].UpdatedAt)
	assert.NotEmpty(t, history[0].UpdatedBy)
}

func TestVault_GetHistoryVersion(t *testing.T) {
	ctx := t.Context()
	_, session, _ := createTestVault(t)

	err := session.Put(ctx, "item-1", Fields{"password": []byte("original"), "username": []byte("alice")})
	require.NoError(t, err)

	err = session.Update(ctx, "item-1", Fields{"password": []byte("updated"), "username": []byte("bob")})
	require.NoError(t, err)

	fields, err := session.GetHistoryVersion(ctx, "item-1", 1)
	require.NoError(t, err)
	assert.Equal(t, []byte("original"), fields["password"])
	assert.Equal(t, []byte("alice"), fields["username"])
}

func TestVault_MultipleUpdatesHistory(t *testing.T) {
	ctx := t.Context()
	_, session, _ := createTestVault(t)

	err := session.Put(ctx, "item-1", Fields{"val": []byte("v1")})
	require.NoError(t, err)

	for i := 2; i <= 4; i++ {
		err = session.Update(ctx, "item-1", Fields{"val": []byte(fmt.Sprintf("v%d", i))})
		require.NoError(t, err)
	}

	history, err := session.GetHistory(ctx, "item-1")
	require.NoError(t, err)
	require.Len(t, history, 3)

	// Sorted newest-first
	assert.Equal(t, uint64(3), history[0].Version)
	assert.Equal(t, uint64(2), history[1].Version)
	assert.Equal(t, uint64(1), history[2].Version)
}

func TestVault_HistoryPreservesFields(t *testing.T) {
	ctx := t.Context()
	_, session, _ := createTestVault(t)

	original := Fields{
		"username": []byte("alice"),
		"password": []byte("s3cret123"),
		"url":      []byte("https://example.com"),
	}
	err := session.Put(ctx, "item-1", original)
	require.NoError(t, err)

	err = session.Update(ctx, "item-1", Fields{"username": []byte("bob"), "password": []byte("newpass")})
	require.NoError(t, err)

	// Historical version should have exact original fields
	fields, err := session.GetHistoryVersion(ctx, "item-1", 1)
	require.NoError(t, err)
	assert.Len(t, fields, 3)
	assert.Equal(t, []byte("alice"), fields["username"])
	assert.Equal(t, []byte("s3cret123"), fields["password"])
	assert.Equal(t, []byte("https://example.com"), fields["url"])
}

func TestVault_HistoryAfterEpochRotation(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewRepository()

	aliceCreds, err := NewCredentials("test-passphrase")
	require.NoError(t, err)

	v := New("default", repo)
	session, err := v.Create(ctx, aliceCreds)
	require.NoError(t, err)
	defer session.Close()

	err = session.Put(ctx, "item-1", Fields{"data": []byte("original")})
	require.NoError(t, err)

	err = session.Update(ctx, "item-1", Fields{"data": []byte("updated")})
	require.NoError(t, err)

	// Verify history exists before rotation
	history, err := session.GetHistory(ctx, "item-1")
	require.NoError(t, err)
	require.Len(t, history, 1)

	// Trigger epoch rotation by adding a member
	bobKP, err := crypto.GenerateX25519Keypair()
	require.NoError(t, err)
	err = session.AddMember(ctx, "bob", bobKP.Public, RoleWriter)
	require.NoError(t, err)

	// History should still be accessible after rotation
	history, err = session.GetHistory(ctx, "item-1")
	require.NoError(t, err)
	require.Len(t, history, 1)

	fields, err := session.GetHistoryVersion(ctx, "item-1", 1)
	require.NoError(t, err)
	assert.Equal(t, []byte("original"), fields["data"])
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

	err = writerSession.Put(ctx, "item-stale", Fields{"data": []byte("stale")})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrStaleSession))
}

// TestVault_BackwardCompat_OldKDFParams verifies that vaults created with
// the old default KDF parameters (Time=1, Memory=64MiB) can still be
// opened after the default was raised to Time=3.
func TestVault_BackwardCompat_OldKDFParams(t *testing.T) {
	ctx := t.Context()
	repo := memory.NewRepository()

	oldParams := Argon2idParams{Time: 1, MemoryKiB: 64 * 1024, Parallelism: 4, KeyLen: 32}
	creds, err := NewCredentials("test-passphrase",
		WithCredentialKDFParams(oldParams),
	)
	require.NoError(t, err)
	defer creds.Destroy()

	// Verify the credentials use the old params.
	assert.Equal(t, oldParams, creds.Profile().KDFParams)

	v := New("compat-test", repo, WithEpochCache(NewMemoryEpochCache()))
	session, err := v.Create(ctx, creds, WithKDFParams(oldParams))
	require.NoError(t, err)
	defer session.Close()

	// Store some data.
	require.NoError(t, session.Put(ctx, "item1", Fields{"key": []byte("value")}))
	session.Close()

	// Re-open with the stored profile (which contains old params).
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

	// Verify the stored data is intact.
	fields, err := session2.Get(ctx, "item1")
	require.NoError(t, err)
	assert.Equal(t, []byte("value"), fields["key"])
}

// TestVault_WithCredentialKDFParams_OverridesDefault verifies that
// WithCredentialKDFParams overrides the default KDF parameters while
// still generating fresh salts.
func TestVault_WithCredentialKDFParams_OverridesDefault(t *testing.T) {
	customParams := Argon2idParams{Time: 5, MemoryKiB: 32 * 1024, Parallelism: 2, KeyLen: 32}
	creds, err := NewCredentials("test-passphrase",
		WithCredentialKDFParams(customParams),
	)
	require.NoError(t, err)
	defer creds.Destroy()

	profile := creds.Profile()
	assert.Equal(t, customParams, profile.KDFParams)
	assert.NotEmpty(t, profile.SaltPass, "salts should be generated")
	assert.NotEmpty(t, profile.SaltSecret, "salts should be generated")
}
