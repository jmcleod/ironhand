// Package bbolt provides a BBolt-backed storage repository.
package bbolt

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/jmcleod/ironhand/storage"
	"go.etcd.io/bbolt"
)

// Store implements storage.Repository backed by a BBolt database.
type Store struct {
	db *bbolt.DB
}

var _ storage.Repository = (*Store)(nil)

// NewRepository returns a Repository backed by the given BBolt database.
func NewRepository(db *bbolt.DB) *Store {
	return &Store{db: db}
}

// NewRepositoryFromFile opens a BBolt database at the given path and returns a new Repository.
func NewRepositoryFromFile(path string, options *bbolt.Options) (*Store, error) {
	db, err := bbolt.Open(path, 0600, options)
	if err != nil {
		return nil, fmt.Errorf("opening bbolt db: %w", err)
	}
	return NewRepository(db), nil
}

// Close closes the underlying BBolt database.
func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) getBucket(tx *bbolt.Tx, vaultID string) (*bbolt.Bucket, error) {
	b, err := tx.CreateBucketIfNotExists([]byte(vaultID))
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (s *Store) Put(vaultID, recordType, recordID string, envelope *storage.Envelope) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := s.getBucket(tx, vaultID)
		if err != nil {
			return err
		}
		data, err := json.Marshal(envelope)
		if err != nil {
			return err
		}
		key := fmt.Sprintf("%s:%s", recordType, recordID)
		return b.Put([]byte(key), data)
	})
}

func (s *Store) Get(vaultID, recordType, recordID string) (*storage.Envelope, error) {
	var envelope storage.Envelope
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(vaultID))
		if b == nil {
			return fmt.Errorf("%s: %w", vaultID, storage.ErrVaultNotFound)
		}
		key := fmt.Sprintf("%s:%s", recordType, recordID)
		data := b.Get([]byte(key))
		if data == nil {
			return fmt.Errorf("%s/%s: %w", recordType, recordID, storage.ErrNotFound)
		}
		return json.Unmarshal(data, &envelope)
	})
	if err != nil {
		return nil, err
	}
	return &envelope, nil
}

func (s *Store) Delete(vaultID, recordType, recordID string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(vaultID))
		if b == nil {
			return fmt.Errorf("%s: %w", vaultID, storage.ErrVaultNotFound)
		}
		key := fmt.Sprintf("%s:%s", recordType, recordID)
		if b.Get([]byte(key)) == nil {
			return fmt.Errorf("%s/%s: %w", recordType, recordID, storage.ErrNotFound)
		}
		return b.Delete([]byte(key))
	})
}

func (s *Store) List(vaultID, recordType string) ([]string, error) {
	var ids []string
	prefix := []byte(recordType + ":")
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(vaultID))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			ids = append(ids, string(k[len(prefix):]))
		}
		return nil
	})
	return ids, err
}

func putCASInBucket(b *bbolt.Bucket, recordType, recordID string, expectedVersion uint64, envelope *storage.Envelope) error {
	key := fmt.Sprintf("%s:%s", recordType, recordID)
	existingData := b.Get([]byte(key))

	if expectedVersion == 0 {
		if existingData != nil {
			return storage.ErrCASFailed
		}
	} else {
		if existingData == nil {
			return storage.ErrCASFailed
		}
		var existing storage.Envelope
		if err := json.Unmarshal(existingData, &existing); err != nil {
			return err
		}
		if existing.Version != expectedVersion {
			return storage.ErrCASFailed
		}
	}

	data, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	return b.Put([]byte(key), data)
}

func (s *Store) PutCAS(vaultID, recordType, recordID string, expectedVersion uint64, envelope *storage.Envelope) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := s.getBucket(tx, vaultID)
		if err != nil {
			return err
		}
		return putCASInBucket(b, recordType, recordID, expectedVersion, envelope)
	})
}

type boltBatchTx struct {
	bucket *bbolt.Bucket
}

func (tx *boltBatchTx) Put(recordType, recordID string, envelope *storage.Envelope) error {
	data, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("%s:%s", recordType, recordID)
	return tx.bucket.Put([]byte(key), data)
}

func (tx *boltBatchTx) PutCAS(recordType, recordID string, expectedVersion uint64, envelope *storage.Envelope) error {
	return putCASInBucket(tx.bucket, recordType, recordID, expectedVersion, envelope)
}

func (tx *boltBatchTx) Delete(recordType, recordID string) error {
	key := fmt.Sprintf("%s:%s", recordType, recordID)
	if tx.bucket.Get([]byte(key)) == nil {
		return fmt.Errorf("%s/%s: %w", recordType, recordID, storage.ErrNotFound)
	}
	return tx.bucket.Delete([]byte(key))
}

func (s *Store) Batch(vaultID string, fn func(tx storage.BatchTx) error) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := s.getBucket(tx, vaultID)
		if err != nil {
			return err
		}
		return fn(&boltBatchTx{bucket: b})
	})
}
