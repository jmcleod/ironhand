// Package storage provides the storage abstraction layer for encrypted vault records.
package storage

import "errors"

// ErrCASFailed is returned when a compare-and-swap version check fails.
var ErrCASFailed = errors.New("CAS version mismatch")

// BatchTx provides Put and PutCAS within an atomic transaction.
// The vaultID is scoped to the batch, so methods don't require it.
type BatchTx interface {
	Put(recordType string, recordID string, envelope *Envelope) error
	PutCAS(recordType string, recordID string, expectedVersion uint64, envelope *Envelope) error
}

// Repository defines the interface for encrypted record storage.
type Repository interface {
	Put(vaultID string, recordType string, recordID string, envelope *Envelope) error
	Get(vaultID string, recordType string, recordID string) (*Envelope, error)
	List(vaultID string, recordType string) ([]string, error)
	PutCAS(vaultID string, recordType string, recordID string, expectedVersion uint64, envelope *Envelope) error
	Batch(vaultID string, fn func(tx BatchTx) error) error
}
