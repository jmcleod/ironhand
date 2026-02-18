package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jmcleod/ironhand/storage"
)

func newTestStore(t *testing.T) (*Store, func()) {
	t.Helper()
	dsn := os.Getenv("IRONHAND_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("IRONHAND_TEST_POSTGRES_DSN not set; skipping PostgreSQL tests")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("could not connect to postgres: %v", err)
	}
	if err := EnsureSchema(ctx, pool); err != nil {
		pool.Close()
		t.Fatalf("could not ensure schema: %v", err)
	}

	// Clean tables for test isolation.
	pool.Exec(ctx, "DELETE FROM records")     //nolint:errcheck
	pool.Exec(ctx, "DELETE FROM epoch_cache") //nolint:errcheck

	return NewRepository(pool), func() {
		pool.Exec(ctx, "DELETE FROM records")     //nolint:errcheck
		pool.Exec(ctx, "DELETE FROM epoch_cache") //nolint:errcheck
		pool.Close()
	}
}

func TestPostgresStorage(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	vaultID := "v1"
	recordType := "ITEM"
	recordID := "i1"
	env := &storage.Envelope{Ver: 1, Scheme: "aes256gcm", Nonce: make([]byte, 12), Ciphertext: []byte("cipher")}

	t.Run("PutGet", func(t *testing.T) {
		err := s.Put(vaultID, recordType, recordID, env)
		if err != nil {
			t.Fatalf("Put failed: %v", err)
		}

		got, err := s.Get(vaultID, recordType, recordID)
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		if got.Ver != env.Ver {
			t.Errorf("expected version %d, got %d", env.Ver, got.Ver)
		}
		if got.Scheme != env.Scheme {
			t.Errorf("expected scheme %q, got %q", env.Scheme, got.Scheme)
		}
		if string(got.Ciphertext) != string(env.Ciphertext) {
			t.Errorf("expected ciphertext %q, got %q", env.Ciphertext, got.Ciphertext)
		}
	})

	t.Run("List", func(t *testing.T) {
		s.Put(vaultID, recordType, "i2", env) //nolint:errcheck
		ids, err := s.List(vaultID, recordType)
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}
		if len(ids) != 2 {
			t.Errorf("expected 2 IDs, got %d", len(ids))
		}
	})

	t.Run("PutCAS create-only", func(t *testing.T) {
		err := s.PutCAS(vaultID, recordType, "cas1", 0, env)
		if err != nil {
			t.Fatalf("PutCAS (new) failed: %v", err)
		}

		err = s.PutCAS(vaultID, recordType, "cas1", 0, env)
		if err != storage.ErrCASFailed {
			t.Errorf("expected ErrCASFailed, got %v", err)
		}
	})

	t.Run("PutCAS version match", func(t *testing.T) {
		envV1 := &storage.Envelope{Ver: 1, Scheme: "aes256gcm", Nonce: make([]byte, 12), Ciphertext: []byte("v1"), Version: 1}
		err := s.Put(vaultID, recordType, "cas2", envV1)
		if err != nil {
			t.Fatalf("Put failed: %v", err)
		}

		envV2 := &storage.Envelope{Ver: 1, Scheme: "aes256gcm", Nonce: make([]byte, 12), Ciphertext: []byte("v2"), Version: 2}
		err = s.PutCAS(vaultID, recordType, "cas2", 1, envV2)
		if err != nil {
			t.Fatalf("PutCAS (version match) failed: %v", err)
		}

		got, _ := s.Get(vaultID, recordType, "cas2")
		if got.Version != 2 {
			t.Errorf("expected version 2, got %d", got.Version)
		}
	})

	t.Run("PutCAS version mismatch", func(t *testing.T) {
		envV5 := &storage.Envelope{Ver: 1, Scheme: "aes256gcm", Nonce: make([]byte, 12), Ciphertext: []byte("v5"), Version: 5}
		s.Put(vaultID, recordType, "cas3", envV5) //nolint:errcheck

		envV6 := &storage.Envelope{Ver: 1, Scheme: "aes256gcm", Nonce: make([]byte, 12), Ciphertext: []byte("v6"), Version: 6}
		err := s.PutCAS(vaultID, recordType, "cas3", 3, envV6)
		if err != storage.ErrCASFailed {
			t.Errorf("expected ErrCASFailed, got %v", err)
		}
	})

	t.Run("PutCAS non-zero on missing record", func(t *testing.T) {
		envV1 := &storage.Envelope{Ver: 1, Scheme: "aes256gcm", Nonce: make([]byte, 12), Ciphertext: []byte("v1"), Version: 1}
		err := s.PutCAS(vaultID, recordType, "cas-missing", 1, envV1)
		if err != storage.ErrCASFailed {
			t.Errorf("expected ErrCASFailed for non-zero version on missing record, got %v", err)
		}
	})

	t.Run("Get Errors", func(t *testing.T) {
		_, err := s.Get("nonexistent-vault", recordType, recordID)
		if err == nil {
			t.Error("expected error for nonexistent vault")
		}

		_, err = s.Get(vaultID, recordType, "nonexistent-record")
		if err == nil {
			t.Error("expected error for nonexistent record")
		}
	})

	t.Run("List Nonexistent Vault", func(t *testing.T) {
		ids, err := s.List("nonexistent-vault", recordType)
		if err != nil {
			t.Errorf("expected no error for nonexistent vault in List, got %v", err)
		}
		if len(ids) != 0 {
			t.Errorf("expected 0 ids, got %d", len(ids))
		}
	})

	t.Run("ListVaults and DeleteVault", func(t *testing.T) {
		err := s.Put("list-a", "ITEM", "a", env)
		if err != nil {
			t.Fatalf("Put list-a failed: %v", err)
		}
		err = s.Put("list-b", "ITEM", "b", env)
		if err != nil {
			t.Fatalf("Put list-b failed: %v", err)
		}

		vaults, err := s.ListVaults()
		if err != nil {
			t.Fatalf("ListVaults failed: %v", err)
		}
		if len(vaults) < 2 {
			t.Fatalf("expected at least 2 vaults, got %d", len(vaults))
		}

		if err := s.DeleteVault("list-a"); err != nil {
			t.Fatalf("DeleteVault failed: %v", err)
		}
		_, err = s.Get("list-a", "ITEM", "a")
		if err == nil {
			t.Fatal("expected deleted vault data to be inaccessible")
		}

		err = s.DeleteVault("missing-vault")
		if err == nil {
			t.Fatal("expected missing vault delete to fail")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		delEnv := &storage.Envelope{Ver: 1, Scheme: "aes256gcm", Nonce: make([]byte, 12), Ciphertext: []byte("to-delete")}
		s.Put(vaultID, recordType, "del1", delEnv) //nolint:errcheck

		err := s.Delete(vaultID, recordType, "del1")
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		_, err = s.Get(vaultID, recordType, "del1")
		if err == nil {
			t.Error("expected error after delete")
		}

		err = s.Delete(vaultID, recordType, "del1")
		if err == nil {
			t.Error("expected error deleting nonexistent record")
		}
	})
}

func TestPostgresBatch(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	vaultID := "v1"

	t.Run("atomic batch write", func(t *testing.T) {
		env1 := &storage.Envelope{Ver: 1, Scheme: "aes256gcm", Nonce: make([]byte, 12), Ciphertext: []byte("a")}
		env2 := &storage.Envelope{Ver: 1, Scheme: "aes256gcm", Nonce: make([]byte, 12), Ciphertext: []byte("b")}

		err := s.Batch(vaultID, func(tx storage.BatchTx) error {
			if err := tx.Put("ITEM", "b1", env1); err != nil {
				return err
			}
			env2_1 := *env2
			env2_1.Version = 1
			if err := tx.PutCAS("ITEM", "b2", 0, &env2_1); err != nil {
				return err
			}
			env2_2 := *env2
			env2_2.Version = 2
			return tx.PutCAS("ITEM", "b2", 1, &env2_2)
		})
		if err != nil {
			t.Fatalf("Batch failed: %v", err)
		}

		got1, err := s.Get(vaultID, "ITEM", "b1")
		if err != nil {
			t.Fatalf("Get b1 failed: %v", err)
		}
		if string(got1.Ciphertext) != "a" {
			t.Errorf("expected ciphertext 'a', got %q", string(got1.Ciphertext))
		}

		got2, err := s.Get(vaultID, "ITEM", "b2")
		if err != nil {
			t.Fatalf("Get b2 failed: %v", err)
		}
		if string(got2.Ciphertext) != "b" {
			t.Errorf("expected ciphertext 'b', got %q", string(got2.Ciphertext))
		}
	})

	t.Run("batch rollback on error", func(t *testing.T) {
		env := &storage.Envelope{Ver: 1, Scheme: "aes256gcm", Nonce: make([]byte, 12), Ciphertext: []byte("should-not-exist")}

		err := s.Batch(vaultID, func(tx storage.BatchTx) error {
			tx.Put("ITEM", "rollback-test", env) //nolint:errcheck
			return storage.ErrCASFailed
		})
		if err != storage.ErrCASFailed {
			t.Fatalf("expected ErrCASFailed, got %v", err)
		}

		_, err = s.Get(vaultID, "ITEM", "rollback-test")
		if err == nil {
			t.Error("expected record to not exist after rollback")
		}
	})

	t.Run("batch delete", func(t *testing.T) {
		env := &storage.Envelope{Ver: 1, Scheme: "aes256gcm", Nonce: make([]byte, 12), Ciphertext: []byte("del-me")}
		s.Put(vaultID, "ITEM", "batch-del", env) //nolint:errcheck

		err := s.Batch(vaultID, func(tx storage.BatchTx) error {
			return tx.Delete("ITEM", "batch-del")
		})
		if err != nil {
			t.Fatalf("Batch delete failed: %v", err)
		}

		_, err = s.Get(vaultID, "ITEM", "batch-del")
		if err == nil {
			t.Error("expected record to not exist after batch delete")
		}
	})
}
