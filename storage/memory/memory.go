// Package memory provides a thread-safe in-memory implementation of storage.Repository.
package memory

import (
	"sync"

	"github.com/jmcleod/ironhand/storage"
)

// Repository is a thread-safe in-memory implementation of storage.Repository.
// Suitable for testing, demos, and single-process use cases.
type Repository struct {
	mu   sync.RWMutex
	data map[string]map[string]*storage.Envelope
}

var _ storage.Repository = (*Repository)(nil)

// NewRepository creates a new empty in-memory Repository.
func NewRepository() *Repository {
	return &Repository{data: make(map[string]map[string]*storage.Envelope)}
}

func makeKey(recordType, recordID string) string {
	return recordType + ":" + recordID
}

func cloneEnvelope(env *storage.Envelope) *storage.Envelope {
	if env == nil {
		return nil
	}
	return &storage.Envelope{
		Ver:        env.Ver,
		Scheme:     env.Scheme,
		Nonce:      append([]byte(nil), env.Nonce...),
		Ciphertext: append([]byte(nil), env.Ciphertext...),
		Version:    env.Version,
	}
}

func (r *Repository) Put(vaultID, recordType, recordID string, envelope *storage.Envelope) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.putLocked(vaultID, recordType, recordID, envelope)
}

func (r *Repository) putLocked(vaultID, recordType, recordID string, envelope *storage.Envelope) error {
	if _, ok := r.data[vaultID]; !ok {
		r.data[vaultID] = make(map[string]*storage.Envelope)
	}
	r.data[vaultID][makeKey(recordType, recordID)] = cloneEnvelope(envelope)
	return nil
}

func (r *Repository) Get(vaultID, recordType, recordID string) (*storage.Envelope, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.getLocked(vaultID, recordType, recordID)
}

func (r *Repository) getLocked(vaultID, recordType, recordID string) (*storage.Envelope, error) {
	k := makeKey(recordType, recordID)
	vaultData, ok := r.data[vaultID]
	if !ok {
		return nil, storage.ErrNotFound
	}
	env, ok := vaultData[k]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return cloneEnvelope(env), nil
}

func (r *Repository) List(vaultID, recordType string) ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var ids []string
	prefix := recordType + ":"
	for k := range r.data[vaultID] {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			ids = append(ids, k[len(prefix):])
		}
	}
	return ids, nil
}

func (r *Repository) Delete(vaultID, recordType, recordID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.deleteLocked(vaultID, recordType, recordID)
}

func (r *Repository) deleteLocked(vaultID, recordType, recordID string) error {
	k := makeKey(recordType, recordID)
	vaultData, ok := r.data[vaultID]
	if !ok {
		return storage.ErrNotFound
	}
	if _, ok := vaultData[k]; !ok {
		return storage.ErrNotFound
	}
	delete(vaultData, k)
	return nil
}

func (r *Repository) PutCAS(vaultID, recordType, recordID string, expectedVersion uint64, envelope *storage.Envelope) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.putCASLocked(vaultID, recordType, recordID, expectedVersion, envelope)
}

func (r *Repository) putCASLocked(vaultID, recordType, recordID string, expectedVersion uint64, envelope *storage.Envelope) error {
	existing, err := r.getLocked(vaultID, recordType, recordID)
	if err != nil {
		if expectedVersion != 0 {
			return storage.ErrCASFailed
		}
		return r.putLocked(vaultID, recordType, recordID, envelope)
	}
	if existing.Version != expectedVersion {
		return storage.ErrCASFailed
	}
	return r.putLocked(vaultID, recordType, recordID, envelope)
}

// Batch executes fn within a batch transaction. On error, all writes are rolled back.
func (r *Repository) Batch(vaultID string, fn func(tx storage.BatchTx) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	snapshot := r.snapshotVault(vaultID)

	tx := &memoryBatchTx{repo: r, vaultID: vaultID}
	if err := fn(tx); err != nil {
		r.restoreVault(vaultID, snapshot)
		return err
	}
	return nil
}

func (r *Repository) snapshotVault(vaultID string) map[string]*storage.Envelope {
	original, ok := r.data[vaultID]
	if !ok {
		return nil
	}
	cp := make(map[string]*storage.Envelope, len(original))
	for k, v := range original {
		cp[k] = cloneEnvelope(v)
	}
	return cp
}

func (r *Repository) restoreVault(vaultID string, snapshot map[string]*storage.Envelope) {
	if snapshot == nil {
		delete(r.data, vaultID)
	} else {
		r.data[vaultID] = snapshot
	}
}

type memoryBatchTx struct {
	repo    *Repository
	vaultID string
}

func (tx *memoryBatchTx) Put(recordType, recordID string, envelope *storage.Envelope) error {
	return tx.repo.putLocked(tx.vaultID, recordType, recordID, envelope)
}

func (tx *memoryBatchTx) PutCAS(recordType, recordID string, expectedVersion uint64, envelope *storage.Envelope) error {
	return tx.repo.putCASLocked(tx.vaultID, recordType, recordID, expectedVersion, envelope)
}

func (tx *memoryBatchTx) Delete(recordType, recordID string) error {
	return tx.repo.deleteLocked(tx.vaultID, recordType, recordID)
}
