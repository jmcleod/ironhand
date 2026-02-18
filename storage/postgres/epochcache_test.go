package postgres

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jmcleod/ironhand/vault"
)

func newTestEpochCache(t *testing.T) (*EpochCache, func()) {
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

	pool.Exec(ctx, "DELETE FROM epoch_cache") //nolint:errcheck

	ec, err := NewEpochCache(ctx, pool)
	if err != nil {
		pool.Close()
		t.Fatalf("could not create epoch cache: %v", err)
	}

	return ec, func() {
		pool.Exec(ctx, "DELETE FROM epoch_cache") //nolint:errcheck
		pool.Close()
	}
}

func TestPostgresEpochCache(t *testing.T) {
	ec, cleanup := newTestEpochCache(t)
	defer cleanup()

	t.Run("initial value is zero", func(t *testing.T) {
		got := ec.GetMaxEpochSeen("vault-1")
		if got != 0 {
			t.Errorf("expected 0, got %d", got)
		}
	})

	t.Run("set and get", func(t *testing.T) {
		err := ec.SetMaxEpochSeen("vault-1", 5)
		if err != nil {
			t.Fatalf("SetMaxEpochSeen failed: %v", err)
		}

		got := ec.GetMaxEpochSeen("vault-1")
		if got != 5 {
			t.Errorf("expected 5, got %d", got)
		}
	})

	t.Run("advance epoch", func(t *testing.T) {
		err := ec.SetMaxEpochSeen("vault-1", 10)
		if err != nil {
			t.Fatalf("SetMaxEpochSeen failed: %v", err)
		}

		got := ec.GetMaxEpochSeen("vault-1")
		if got != 10 {
			t.Errorf("expected 10, got %d", got)
		}
	})

	t.Run("rollback detected", func(t *testing.T) {
		err := ec.SetMaxEpochSeen("vault-1", 3)
		if !errors.Is(err, vault.ErrRollbackDetected) {
			t.Errorf("expected ErrRollbackDetected, got %v", err)
		}

		// Value should remain unchanged.
		got := ec.GetMaxEpochSeen("vault-1")
		if got != 10 {
			t.Errorf("expected 10 after rollback attempt, got %d", got)
		}
	})

	t.Run("multiple vaults isolated", func(t *testing.T) {
		ec.SetMaxEpochSeen("vault-a", 42) //nolint:errcheck
		ec.SetMaxEpochSeen("vault-b", 99) //nolint:errcheck

		if got := ec.GetMaxEpochSeen("vault-a"); got != 42 {
			t.Errorf("vault-a: expected 42, got %d", got)
		}
		if got := ec.GetMaxEpochSeen("vault-b"); got != 99 {
			t.Errorf("vault-b: expected 99, got %d", got)
		}
	})

	t.Run("persistence across instances", func(t *testing.T) {
		ec.SetMaxEpochSeen("persist-test", 77) //nolint:errcheck

		// Create a new EpochCache from the same pool to simulate restart.
		ec2, err := NewEpochCache(context.Background(), ec.pool)
		if err != nil {
			t.Fatalf("NewEpochCache failed: %v", err)
		}

		got := ec2.GetMaxEpochSeen("persist-test")
		if got != 77 {
			t.Errorf("expected 77 after re-init, got %d", got)
		}
	})
}
