package postgres

import (
	"context"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jmcleod/ironhand/vault"
)

// EpochCache implements vault.EpochCache backed by PostgreSQL.
//
// It uses a write-through cache: reads come from an in-memory map,
// writes persist to PostgreSQL and update the in-memory map atomically.
// This mirrors the BoltEpochCache pattern in vault/epochcache.go.
type EpochCache struct {
	pool  *pgxpool.Pool
	mu    sync.RWMutex
	cache map[string]uint64
}

var _ vault.EpochCache = (*EpochCache)(nil)

// NewEpochCache returns a persistent epoch cache backed by PostgreSQL.
// It loads all existing entries into memory on initialisation.
func NewEpochCache(ctx context.Context, pool *pgxpool.Pool) (*EpochCache, error) {
	c := &EpochCache{
		pool:  pool,
		cache: make(map[string]uint64),
	}

	rows, err := pool.Query(ctx, `SELECT vault_id, max_epoch FROM epoch_cache`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var vaultID string
		var epoch uint64
		if err := rows.Scan(&vaultID, &epoch); err != nil {
			return nil, err
		}
		c.cache[vaultID] = epoch
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return c, nil
}

// GetMaxEpochSeen returns the highest epoch seen for a vault.
func (c *EpochCache) GetMaxEpochSeen(vaultID string) uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cache[vaultID]
}

// SetMaxEpochSeen persists the new max epoch for a vault. It returns
// vault.ErrRollbackDetected if the provided epoch is less than the
// currently stored value.
func (c *EpochCache) SetMaxEpochSeen(vaultID string, epoch uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if epoch < c.cache[vaultID] {
		return vault.ErrRollbackDetected
	}

	_, err := c.pool.Exec(context.Background(),
		`INSERT INTO epoch_cache (vault_id, max_epoch) VALUES ($1, $2)
		 ON CONFLICT (vault_id) DO UPDATE SET max_epoch = $2`,
		vaultID, epoch)
	if err != nil {
		return err
	}

	c.cache[vaultID] = epoch
	return nil
}
