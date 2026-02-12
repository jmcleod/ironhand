package vault

import (
	"testing"
	"time"

	"github.com/jmcleod/ironhand/internal/util"
	"github.com/stretchr/testify/assert"
)

func TestNewVaultState(t *testing.T) {
	vaultID := "test-vault"

	t.Run("Default values", func(t *testing.T) {
		s := newVaultState(vaultID)
		assert.Equal(t, vaultID, s.VaultID)
		assert.Equal(t, uint64(1), s.Epoch)
		assert.Equal(t, util.DefaultArgon2idParams(), s.KDFParams)
		assert.Equal(t, 1, s.Ver)
		assert.WithinDuration(t, time.Now(), s.CreatedAt, 1*time.Second)
	})

	t.Run("With options", func(t *testing.T) {
		customTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		customParams := util.Argon2idParams{Time: 2, MemoryKiB: 1024, Parallelism: 1, KeyLen: 32}

		s := newVaultState(vaultID,
			WithEpoch(5),
			WithKDFParams(customParams),
			WithCreatedAt(customTime),
			WithVer(2),
		)

		assert.Equal(t, vaultID, s.VaultID)
		assert.Equal(t, uint64(5), s.Epoch)
		assert.Equal(t, customParams, s.KDFParams)
		assert.Equal(t, customTime, s.CreatedAt)
		assert.Equal(t, 2, s.Ver)
	})
}
