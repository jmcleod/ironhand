package memory

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/jmcleod/ironhand/storage"
)

func TestMemoryRepository(t *testing.T) {
	repo := NewRepository()
	vaultID := "vault1"
	recordType := "type1"
	recordID := "id1"
	env := &storage.Envelope{
		Ver:        1,
		Scheme:     "aes256gcm",
		Nonce:      []byte("nonce1234567"),
		Ciphertext: []byte("ciphertext"),
		Version:    1,
	}

	t.Run("PutAndGet", func(t *testing.T) {
		err := repo.Put(vaultID, recordType, recordID, env)
		if err != nil {
			t.Fatalf("Put failed: %v", err)
		}

		got, err := repo.Get(vaultID, recordType, recordID)
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}

		if got.Ver != env.Ver || got.Scheme != env.Scheme || !bytes.Equal(got.Nonce, env.Nonce) || !bytes.Equal(got.Ciphertext, env.Ciphertext) || got.Version != env.Version {
			t.Errorf("Get returned wrong envelope: %+v", got)
		}

		// Test isolation (cloning)
		got.Nonce[0] = 'X'
		got2, _ := repo.Get(vaultID, recordType, recordID)
		if got2.Nonce[0] == 'X' {
			t.Error("Memory repository should return clones of envelopes")
		}
	})

	t.Run("GetNotFound", func(t *testing.T) {
		_, err := repo.Get("nonexistent", recordType, recordID)
		if err == nil {
			t.Error("Get with nonexistent vault should fail")
		}

		_, err = repo.Get(vaultID, recordType, "nonexistent")
		if err == nil {
			t.Error("Get with nonexistent record should fail")
		}
	})

	t.Run("List", func(t *testing.T) {
		repo.Put(vaultID, "type1", "id2", env)
		repo.Put(vaultID, "type2", "id1", env)

		ids, err := repo.List(vaultID, "type1")
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}
		if len(ids) != 2 {
			t.Errorf("Expected 2 IDs, got %d: %v", len(ids), ids)
		}

		ids, _ = repo.List("nonexistent", "type1")
		if len(ids) != 0 {
			t.Errorf("Expected 0 IDs for nonexistent vault, got %d", len(ids))
		}
	})

	t.Run("PutCAS", func(t *testing.T) {
		repo := NewRepository()
		env1 := &storage.Envelope{Version: 1}
		env2 := &storage.Envelope{Version: 2}

		// Create-only (expectedVersion = 0)
		err := repo.PutCAS(vaultID, recordType, recordID, 0, env1)
		if err != nil {
			t.Fatalf("PutCAS create failed: %v", err)
		}

		// Version mismatch on create
		err = repo.PutCAS(vaultID, "other", "id", 1, env1)
		if err != storage.ErrCASFailed {
			t.Errorf("Expected ErrCASFailed, got %v", err)
		}

		// Version match update
		err = repo.PutCAS(vaultID, recordType, recordID, 1, env2)
		if err != nil {
			t.Fatalf("PutCAS update failed: %v", err)
		}

		// Version mismatch update
		err = repo.PutCAS(vaultID, recordType, recordID, 1, env1)
		if err != storage.ErrCASFailed {
			t.Errorf("Expected ErrCASFailed, got %v", err)
		}
	})

	t.Run("Batch", func(t *testing.T) {
		repo := NewRepository()

		// Successful batch
		err := repo.Batch(vaultID, func(tx storage.BatchTx) error {
			if err := tx.Put("type", "id1", env); err != nil {
				return err
			}
			return tx.PutCAS("type", "id2", 0, env)
		})
		if err != nil {
			t.Fatalf("Batch failed: %v", err)
		}

		if _, err := repo.Get(vaultID, "type", "id1"); err != nil {
			t.Error("Record id1 should exist after batch")
		}

		// Failing batch (rollback)
		err = repo.Batch(vaultID, func(tx storage.BatchTx) error {
			tx.Put("type", "id3", env)
			return fmt.Errorf("simulated error")
		})
		if err == nil {
			t.Error("Expected error from Batch, got nil")
		}

		if _, err := repo.Get(vaultID, "type", "id3"); err == nil {
			t.Error("Record id3 should NOT exist after failed batch")
		}

		// Rollback with pre-existing data
		err = repo.Batch(vaultID, func(tx storage.BatchTx) error {
			tx.Put("type", "id1", &storage.Envelope{Ver: 2})
			return fmt.Errorf("simulated error")
		})
		got, _ := repo.Get(vaultID, "type", "id1")
		if got.Ver != 1 {
			t.Errorf("Expected Ver 1 after rollback, got %d", got.Ver)
		}
	})
}
