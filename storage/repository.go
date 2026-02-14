// Package storage provides the storage abstraction layer for encrypted vault records.
package storage

import "errors"

// ErrCASFailed is returned when a compare-and-swap version check fails.
var ErrCASFailed = errors.New("CAS version mismatch")

// ErrNotFound is returned when a record does not exist.
var ErrNotFound = errors.New("record not found")

// ErrVaultNotFound is returned when a vault does not exist in storage.
var ErrVaultNotFound = errors.New("vault not found")

// BatchTx provides Put, PutCAS, and Delete within an atomic transaction.
// The vaultID is scoped to the batch, so methods don't require it.
type BatchTx interface {
	Put(recordType string, recordID string, envelope *Envelope) error
	PutCAS(recordType string, recordID string, expectedVersion uint64, envelope *Envelope) error
	Delete(recordType string, recordID string) error
}

// Repository defines the interface for encrypted record storage.
type Repository interface {
	Put(vaultID string, recordType string, recordID string, envelope *Envelope) error
	Get(vaultID string, recordType string, recordID string) (*Envelope, error)
	List(vaultID string, recordType string) ([]string, error)
	ListVaults() ([]string, error)
	Delete(vaultID string, recordType string, recordID string) error
	DeleteVault(vaultID string) error
	PutCAS(vaultID string, recordType string, recordID string, expectedVersion uint64, envelope *Envelope) error
	Batch(vaultID string, fn func(tx BatchTx) error) error
}
