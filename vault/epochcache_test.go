package vault

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBoltEpochCache(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ironhand-test-")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.db")

	// 1. Create a new cache from a file
	cache, err := NewBoltEpochCacheFromFile(dbPath, nil)
	require.NoError(t, err)
	require.NotNil(t, cache)

	vaultID1 := "vault1"
	vaultID2 := "vault2"

	// 2. Set and get max epoch seen
	err = cache.SetMaxEpochSeen(vaultID1, 10)
	require.NoError(t, err)
	epoch := cache.GetMaxEpochSeen(vaultID1)
	require.Equal(t, uint64(10), epoch)

	err = cache.SetMaxEpochSeen(vaultID2, 20)
	require.NoError(t, err)
	epoch = cache.GetMaxEpochSeen(vaultID2)
	require.Equal(t, uint64(20), epoch)

	// 3. Check persistence
	// Close and reopen the cache
	err = cache.db.Close()
	require.NoError(t, err)
	cache2, err := NewBoltEpochCacheFromFile(dbPath, nil)
	require.NoError(t, err)

	epoch = cache2.GetMaxEpochSeen(vaultID1)
	require.Equal(t, uint64(10), epoch)
	epoch = cache2.GetMaxEpochSeen(vaultID2)
	require.Equal(t, uint64(20), epoch)

	// 4. Check rollback detection
	err = cache2.SetMaxEpochSeen(vaultID1, 9)
	require.Error(t, err)
	_, ok := errors.AsType[RollbackError](err)
	require.True(t, ok)

	// Set a higher epoch
	err = cache2.SetMaxEpochSeen(vaultID1, 11)
	require.NoError(t, err)
	epoch = cache2.GetMaxEpochSeen(vaultID1)
	require.Equal(t, uint64(11), epoch)

	err = cache2.db.Close()
	require.NoError(t, err)
}

func TestMemoryEpochCache(t *testing.T) {
	cache := NewMemoryEpochCache()
	require.NotNil(t, cache)

	vaultID := "vault1"

	// Set and get max epoch seen
	err := cache.SetMaxEpochSeen(vaultID, 10)
	require.NoError(t, err)
	epoch := cache.GetMaxEpochSeen(vaultID)
	require.Equal(t, uint64(10), epoch)

	// Check rollback detection
	err = cache.SetMaxEpochSeen(vaultID, 9)
	require.Error(t, err)
	_, ok2 := errors.AsType[RollbackError](err)
	require.True(t, ok2)
}
