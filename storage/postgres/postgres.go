// Package postgres implements storage.Repository backed by PostgreSQL.
//
// The records table uses a composite primary key (vault_id, record_type,
// record_id) that mirrors the key space used by the BBolt and in-memory
// backends. Envelope fields are stored as individual columns to avoid
// JSON serialisation overhead and to leverage native BYTEA storage for
// nonce and ciphertext data.
package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jmcleod/ironhand/storage"
)

// Store implements storage.Repository backed by PostgreSQL.
type Store struct {
	pool *pgxpool.Pool
}

var _ storage.Repository = (*Store)(nil)

// NewRepository returns a Repository backed by the given pgx connection pool.
func NewRepository(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// NewRepositoryFromDSN creates a connection pool from a DSN string, ensures
// the schema exists, and returns a new Repository.
func NewRepositoryFromDSN(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connecting to postgres: %w", err)
	}
	if err := EnsureSchema(ctx, pool); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ensuring schema: %w", err)
	}
	return NewRepository(pool), nil
}

// Pool returns the underlying connection pool. This is useful for sharing
// the pool with other components such as the epoch cache.
func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

// Close closes the underlying connection pool.
func (s *Store) Close() {
	s.pool.Close()
}

// ---------------------------------------------------------------------------
// Repository interface implementation
// ---------------------------------------------------------------------------

func (s *Store) Put(vaultID, recordType, recordID string, envelope *storage.Envelope) error {
	_, err := s.pool.Exec(context.Background(),
		`INSERT INTO records (vault_id, record_type, record_id, ver, scheme, nonce, ciphertext, version)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (vault_id, record_type, record_id)
		 DO UPDATE SET ver = $4, scheme = $5, nonce = $6, ciphertext = $7, version = $8`,
		vaultID, recordType, recordID,
		envelope.Ver, envelope.Scheme, envelope.Nonce, envelope.Ciphertext, envelope.Version)
	return err
}

func (s *Store) Get(vaultID, recordType, recordID string) (*storage.Envelope, error) {
	var env storage.Envelope
	err := s.pool.QueryRow(context.Background(),
		`SELECT ver, scheme, nonce, ciphertext, version
		 FROM records WHERE vault_id = $1 AND record_type = $2 AND record_id = $3`,
		vaultID, recordType, recordID).Scan(
		&env.Ver, &env.Scheme, &env.Nonce, &env.Ciphertext, &env.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFoundError(context.Background(), s.pool, vaultID, recordType, recordID)
	}
	if err != nil {
		return nil, err
	}
	return &env, nil
}

func (s *Store) List(vaultID, recordType string) ([]string, error) {
	rows, err := s.pool.Query(context.Background(),
		`SELECT record_id FROM records WHERE vault_id = $1 AND record_type = $2`,
		vaultID, recordType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) ListVaults() ([]string, error) {
	rows, err := s.pool.Query(context.Background(),
		`SELECT DISTINCT vault_id FROM records ORDER BY vault_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) Delete(vaultID, recordType, recordID string) error {
	tag, err := s.pool.Exec(context.Background(),
		`DELETE FROM records WHERE vault_id = $1 AND record_type = $2 AND record_id = $3`,
		vaultID, recordType, recordID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return notFoundError(context.Background(), s.pool, vaultID, recordType, recordID)
	}
	return nil
}

func (s *Store) DeleteVault(vaultID string) error {
	tag, err := s.pool.Exec(context.Background(),
		`DELETE FROM records WHERE vault_id = $1`, vaultID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%s: %w", vaultID, storage.ErrVaultNotFound)
	}
	return nil
}

func (s *Store) PutCAS(vaultID, recordType, recordID string, expectedVersion uint64, envelope *storage.Envelope) error {
	tx, err := s.pool.Begin(context.Background())
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background()) //nolint:errcheck

	if err := putCASInTx(context.Background(), tx, vaultID, recordType, recordID, expectedVersion, envelope); err != nil {
		return err
	}
	return tx.Commit(context.Background())
}

func (s *Store) Batch(vaultID string, fn func(tx storage.BatchTx) error) error {
	pgTx, err := s.pool.Begin(context.Background())
	if err != nil {
		return err
	}
	defer pgTx.Rollback(context.Background()) //nolint:errcheck

	btx := &pgBatchTx{tx: pgTx, vaultID: vaultID}
	if err := fn(btx); err != nil {
		return err
	}
	return pgTx.Commit(context.Background())
}

// ---------------------------------------------------------------------------
// BatchTx implementation
// ---------------------------------------------------------------------------

type pgBatchTx struct {
	tx      pgx.Tx
	vaultID string
}

var _ storage.BatchTx = (*pgBatchTx)(nil)

func (btx *pgBatchTx) Put(recordType, recordID string, envelope *storage.Envelope) error {
	_, err := btx.tx.Exec(context.Background(),
		`INSERT INTO records (vault_id, record_type, record_id, ver, scheme, nonce, ciphertext, version)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (vault_id, record_type, record_id)
		 DO UPDATE SET ver = $4, scheme = $5, nonce = $6, ciphertext = $7, version = $8`,
		btx.vaultID, recordType, recordID,
		envelope.Ver, envelope.Scheme, envelope.Nonce, envelope.Ciphertext, envelope.Version)
	return err
}

func (btx *pgBatchTx) PutCAS(recordType, recordID string, expectedVersion uint64, envelope *storage.Envelope) error {
	return putCASInTx(context.Background(), btx.tx, btx.vaultID, recordType, recordID, expectedVersion, envelope)
}

func (btx *pgBatchTx) Delete(recordType, recordID string) error {
	tag, err := btx.tx.Exec(context.Background(),
		`DELETE FROM records WHERE vault_id = $1 AND record_type = $2 AND record_id = $3`,
		btx.vaultID, recordType, recordID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%s/%s: %w", recordType, recordID, storage.ErrNotFound)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// putCASInTx performs a compare-and-swap put within an existing transaction.
// It is used by both the top-level PutCAS and the batch PutCAS methods.
func putCASInTx(ctx context.Context, tx pgx.Tx, vaultID, recordType, recordID string, expectedVersion uint64, envelope *storage.Envelope) error {
	var currentVersion uint64
	err := tx.QueryRow(ctx,
		`SELECT version FROM records
		 WHERE vault_id = $1 AND record_type = $2 AND record_id = $3
		 FOR UPDATE`,
		vaultID, recordType, recordID).Scan(&currentVersion)

	if errors.Is(err, pgx.ErrNoRows) {
		// Record does not exist.
		if expectedVersion != 0 {
			return storage.ErrCASFailed
		}
		// Create new record.
		_, err = tx.Exec(ctx,
			`INSERT INTO records (vault_id, record_type, record_id, ver, scheme, nonce, ciphertext, version)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			vaultID, recordType, recordID,
			envelope.Ver, envelope.Scheme, envelope.Nonce, envelope.Ciphertext, envelope.Version)
		return err
	}
	if err != nil {
		return err
	}

	// Record exists.
	if expectedVersion == 0 {
		return storage.ErrCASFailed
	}
	if currentVersion != expectedVersion {
		return storage.ErrCASFailed
	}

	_, err = tx.Exec(ctx,
		`UPDATE records SET ver = $4, scheme = $5, nonce = $6, ciphertext = $7, version = $8
		 WHERE vault_id = $1 AND record_type = $2 AND record_id = $3`,
		vaultID, recordType, recordID,
		envelope.Ver, envelope.Scheme, envelope.Nonce, envelope.Ciphertext, envelope.Version)
	return err
}

// querier abstracts both *pgxpool.Pool and pgx.Tx for shared queries.
type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// notFoundError determines whether a missing record is due to a missing vault
// or a missing record within an existing vault. This preserves the BBolt
// semantic of distinguishing ErrVaultNotFound from ErrNotFound.
func notFoundError(ctx context.Context, q querier, vaultID, recordType, recordID string) error {
	var exists bool
	_ = q.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM records WHERE vault_id = $1 LIMIT 1)`,
		vaultID).Scan(&exists)
	if !exists {
		return fmt.Errorf("%s: %w", vaultID, storage.ErrVaultNotFound)
	}
	return fmt.Errorf("%s/%s: %w", recordType, recordID, storage.ErrNotFound)
}
