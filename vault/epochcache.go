package vault

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"go.etcd.io/bbolt"
)

// ErrRollbackDetected is returned when the storage epoch is older than the cached epoch.
var ErrRollbackDetected = errors.New("rollback detected: storage epoch is older than cached epoch")

// EpochCache tracks the maximum epoch seen per vault to detect rollback attacks.
type EpochCache interface {
	GetMaxEpochSeen(vaultID string) uint64
	SetMaxEpochSeen(vaultID string, epoch uint64) error
}

// MemoryEpochCache is an in-memory implementation suitable for tests.
type MemoryEpochCache struct {
	mu     sync.RWMutex
	epochs map[string]uint64
}

// NewMemoryEpochCache returns an in-memory epoch cache suitable for testing and single-process use.
func NewMemoryEpochCache() *MemoryEpochCache {
	return &MemoryEpochCache{
		epochs: make(map[string]uint64),
	}
}

func (c *MemoryEpochCache) GetMaxEpochSeen(vaultID string) uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.epochs[vaultID]
}

func (c *MemoryEpochCache) SetMaxEpochSeen(vaultID string, epoch uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if epoch < c.epochs[vaultID] {
		return ErrRollbackDetected
	}
	c.epochs[vaultID] = epoch
	return nil
}

var epochCacheBucket = []byte("__epoch_cache")

// BoltEpochCache persists max-epoch-seen in a dedicated BBolt bucket.
// It uses a write-through cache: reads come from an in-memory map,
// writes persist to BBolt and update the in-memory map atomically.
type BoltEpochCache struct {
	db    *bbolt.DB
	mu    sync.RWMutex
	cache map[string]uint64
}

// NewBoltEpochCache returns a persistent epoch cache backed by a BBolt database.
// This is the recommended EpochCache for production use to ensure rollback
// protection is maintained across application restarts.
func NewBoltEpochCache(db *bbolt.DB) (*BoltEpochCache, error) {
	c := &BoltEpochCache{
		db:    db,
		cache: make(map[string]uint64),
	}
	err := db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(epochCacheBucket)
		if err != nil {
			return err
		}
		return b.ForEach(func(k, v []byte) error {
			if len(v) == 8 {
				c.cache[string(k)] = binary.BigEndian.Uint64(v)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return c, nil
}

// NewBoltEpochCacheFromFile opens a BBolt database at the given path and returns a new BoltEpochCache.
func NewBoltEpochCacheFromFile(path string, options *bbolt.Options) (*BoltEpochCache, error) {
	db, err := bbolt.Open(path, 0600, options)
	if err != nil {
		return nil, fmt.Errorf("opening bbolt db: %w", err)
	}
	return NewBoltEpochCache(db)
}

func (c *BoltEpochCache) GetMaxEpochSeen(vaultID string) uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cache[vaultID]
}

func (c *BoltEpochCache) SetMaxEpochSeen(vaultID string, epoch uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if epoch < c.cache[vaultID] {
		return ErrRollbackDetected
	}

	err := c.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(epochCacheBucket)
		if err != nil {
			return err
		}
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], epoch)
		return b.Put([]byte(vaultID), buf[:])
	})
	if err != nil {
		return err
	}

	c.cache[vaultID] = epoch
	return nil
}
