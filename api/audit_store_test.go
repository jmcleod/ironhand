package api

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jmcleod/ironhand/storage/memory"
	"github.com/jmcleod/ironhand/vault"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// setupAuditTestAPI creates an API backed by an in-memory repo with the given
// audit retention settings and returns it along with a vault session suitable
// for audit operations.
func setupAuditTestAPI(t testing.TB, maxAge time.Duration, maxEntries int) (*API, *vault.Session, string) {
	t.Helper()

	repo := memory.NewRepository()
	epochCache := vault.NewMemoryEpochCache()

	opts := []Option{
		WithAuditRetention(maxAge, maxEntries),
	}
	a := New(repo, epochCache, opts...)

	// Create a vault and use the session returned by Create.
	ctx := context.Background()
	passphrase := "bench-pass"
	creds, err := vault.NewCredentials(passphrase)
	require.NoError(t, err)

	vaultID := "audit-test-vault"
	v := vault.New(vaultID, repo, vault.WithEpochCache(epochCache))
	session, err := v.Create(ctx, creds)
	require.NoError(t, err)

	return a, session, vaultID
}

// ---------------------------------------------------------------------------
// Unit tests: parseCreatedAt
// ---------------------------------------------------------------------------

func TestParseCreatedAt_RFC3339Nano(t *testing.T) {
	e := auditEntry{CreatedAt: "2024-06-15T12:34:56.789012345Z"}
	e.parseCreatedAt()
	assert.False(t, e.createdAtTime.IsZero())
	assert.Equal(t, 2024, e.createdAtTime.Year())
	assert.Equal(t, time.Month(6), e.createdAtTime.Month())
}

func TestParseCreatedAt_RFC3339(t *testing.T) {
	e := auditEntry{CreatedAt: "2024-06-15T12:34:56Z"}
	e.parseCreatedAt()
	assert.False(t, e.createdAtTime.IsZero())
}

func TestParseCreatedAt_Invalid(t *testing.T) {
	e := auditEntry{CreatedAt: "not-a-timestamp"}
	e.parseCreatedAt()
	assert.True(t, e.createdAtTime.IsZero(), "should remain zero for unparseable timestamps")
}

// ---------------------------------------------------------------------------
// Unit tests: auditRetentionCheckThreshold
// ---------------------------------------------------------------------------

func TestAuditRetentionCheckThreshold(t *testing.T) {
	tests := []struct {
		name        string
		maxEntries  int
		wantAtLeast int
		wantAtMost  int
	}{
		{
			name:        "default threshold when maxEntries is large",
			maxEntries:  1000,
			wantAtLeast: auditRetentionThreshold,
			wantAtMost:  auditRetentionThreshold,
		},
		{
			name:        "halved for small maxEntries",
			maxEntries:  10,
			wantAtLeast: 5,
			wantAtMost:  5,
		},
		{
			name:        "minimum of 1 for very small maxEntries",
			maxEntries:  1,
			wantAtLeast: 1,
			wantAtMost:  1,
		},
		{
			name:        "maxEntries 0 uses default",
			maxEntries:  0,
			wantAtLeast: auditRetentionThreshold,
			wantAtMost:  auditRetentionThreshold,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &API{auditMaxEntries: tt.maxEntries}
			got := a.auditRetentionCheckThreshold()
			assert.GreaterOrEqual(t, got, tt.wantAtLeast)
			assert.LessOrEqual(t, got, tt.wantAtMost)
		})
	}
}

// ---------------------------------------------------------------------------
// Integration test: threshold-triggered retention
// ---------------------------------------------------------------------------

func TestAuditRetention_ThresholdTriggered(t *testing.T) {
	// Use maxEntries=5 so threshold = 2 (5/2=2). Retention should fire
	// every ~2 appends, not on every write.
	a, session, vaultID := setupAuditTestAPI(t, 0, 5)
	defer session.Close()

	// Append 10 entries.
	for i := 0; i < 10; i++ {
		err := a.appendAuditEntry(session, vaultID, fmt.Sprintf("item-%d", i), "member-1", auditActionItemCreated)
		require.NoError(t, err)
	}

	// After retention, at most 5 entries should remain.
	entries, err := a.listAuditEntries(session, vaultID, "")
	require.NoError(t, err)
	assert.LessOrEqual(t, len(entries), 5, "retention should cap entries to maxEntries")
}

func TestAuditRetention_ChainReanchoredAfterPruning(t *testing.T) {
	a, session, vaultID := setupAuditTestAPI(t, 0, 3)
	defer session.Close()

	// Append enough entries to trigger multiple retention cycles.
	for i := 0; i < 8; i++ {
		err := a.appendAuditEntry(session, vaultID, fmt.Sprintf("item-%d", i), "member-1", auditActionItemCreated)
		require.NoError(t, err)
	}

	entries, err := a.listAuditEntries(session, vaultID, "")
	require.NoError(t, err)
	require.LessOrEqual(t, len(entries), 3)

	// The chain should be re-anchored: the oldest retained entry should
	// have a genesis prev_hash.
	if len(entries) > 0 {
		// listAuditEntries returns newest-first; the last element is the oldest.
		oldest := entries[len(entries)-1]
		assert.Equal(t, auditGenesisHash, oldest.PrevHash, "oldest retained entry should be anchored to genesis")
	}
}

func TestAuditRetention_NoRetentionDoesNotPrune(t *testing.T) {
	// No retention configured (both 0).
	a, session, vaultID := setupAuditTestAPI(t, 0, 0)
	defer session.Close()

	for i := 0; i < 20; i++ {
		err := a.appendAuditEntry(session, vaultID, fmt.Sprintf("item-%d", i), "member-1", auditActionItemCreated)
		require.NoError(t, err)
	}

	entries, err := a.listAuditEntries(session, vaultID, "")
	require.NoError(t, err)
	assert.Len(t, entries, 20, "without retention, all entries should be kept")
}

// ---------------------------------------------------------------------------
// Benchmarks: audit append latency with and without retention
// ---------------------------------------------------------------------------

func BenchmarkAuditAppend_NoRetention(b *testing.B) {
	a, session, vaultID := setupAuditTestAPI(b, 0, 0)
	defer session.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := a.appendAuditEntry(session, vaultID, "item-bench", "member-1", auditActionItemCreated); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAuditAppend_Retention100(b *testing.B) {
	a, session, vaultID := setupAuditTestAPI(b, 0, 100)
	defer session.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := a.appendAuditEntry(session, vaultID, "item-bench", "member-1", auditActionItemCreated); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAuditAppend_Retention10(b *testing.B) {
	a, session, vaultID := setupAuditTestAPI(b, 0, 10)
	defer session.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := a.appendAuditEntry(session, vaultID, "item-bench", "member-1", auditActionItemCreated); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAuditAppend_LargeHistory appends to a vault that already has a
// significant history, measuring how append latency scales.
func BenchmarkAuditAppend_LargeHistory(b *testing.B) {
	a, session, vaultID := setupAuditTestAPI(b, 0, 500)
	defer session.Close()

	// Pre-populate with 500 entries.
	for i := 0; i < 500; i++ {
		if err := a.appendAuditEntry(session, vaultID, fmt.Sprintf("pre-%d", i), "member-1", auditActionItemCreated); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := a.appendAuditEntry(session, vaultID, "item-bench", "member-1", auditActionItemCreated); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAuditRetention_Compaction measures the cost of the retention
// compaction itself (reading all entries, pruning, rewriting).
func BenchmarkAuditRetention_Compaction(b *testing.B) {
	a, session, vaultID := setupAuditTestAPI(b, 0, 50)
	defer session.Close()

	// Pre-populate with 200 entries (will be pruned down to 50).
	for i := 0; i < 200; i++ {
		if err := a.appendAuditEntry(session, vaultID, fmt.Sprintf("pre-%d", i), "member-1", auditActionItemCreated); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Force retention check on every iteration.
		a.auditAppendsSinceRetention.Store(int64(a.auditRetentionCheckThreshold()))
		if err := a.appendAuditEntry(session, vaultID, fmt.Sprintf("bench-%d", i), "member-1", auditActionItemCreated); err != nil {
			b.Fatal(err)
		}
	}
}
