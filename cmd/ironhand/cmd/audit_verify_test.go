package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const testGenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

func testChainHash(entryID, prevHash, createdAt string) string {
	h := sha256.Sum256([]byte(entryID + prevHash + createdAt))
	return hex.EncodeToString(h[:])
}

// buildValidChain returns an auditExport with n correctly chained entries.
func buildValidChain(vaultID string, n int) auditExport {
	entries := make([]auditExportEntry, n)
	prevHash := testGenesisHash
	for i := 0; i < n; i++ {
		ts := time.Date(2025, 1, 1, 0, 0, i, 0, time.UTC).Format(time.RFC3339Nano)
		id := fmt.Sprintf("entry-%d", i)
		entries[i] = auditExportEntry{
			ID:        id,
			VaultID:   vaultID,
			ItemID:    fmt.Sprintf("item-%d", i),
			Action:    "item_created",
			MemberID:  "member-1",
			CreatedAt: ts,
			PrevHash:  prevHash,
		}
		prevHash = testChainHash(id, prevHash, ts)
	}
	return auditExport{
		VaultID:   vaultID,
		Entries:   entries,
		Signature: "deadbeef",
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestVerify_ValidChain(t *testing.T) {
	export := buildValidChain("vault-1", 5)
	result := verifyAuditChain(export)

	assert.True(t, result.Valid)
	assert.Equal(t, 5, result.EntryCount)
	assert.Equal(t, "vault-1", result.VaultID)

	for _, c := range result.Checks {
		assert.NotEqual(t, "fail", c.Status, "check %s should not fail", c.Name)
	}
	assert.Contains(t, result.SigNote, "cannot be verified offline")
}

func TestVerify_EmptyChain(t *testing.T) {
	export := auditExport{
		VaultID: "vault-empty",
		Entries: nil,
	}
	result := verifyAuditChain(export)

	assert.True(t, result.Valid)
	assert.Equal(t, 0, result.EntryCount)
	require.Len(t, result.Checks, 1)
	assert.Equal(t, "empty_chain", result.Checks[0].Name)
	assert.Equal(t, "pass", result.Checks[0].Status)
}

func TestVerify_SingleEntry(t *testing.T) {
	export := buildValidChain("vault-1", 1)
	result := verifyAuditChain(export)

	assert.True(t, result.Valid)
	assert.Equal(t, 1, result.EntryCount)
}

func TestVerify_BrokenGenesisHash(t *testing.T) {
	export := buildValidChain("vault-1", 3)
	export.Entries[0].PrevHash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	result := verifyAuditChain(export)

	assert.False(t, result.Valid)
	found := false
	for _, c := range result.Checks {
		if c.Name == "genesis_anchor" {
			assert.Equal(t, "fail", c.Status)
			found = true
		}
	}
	assert.True(t, found, "should have a genesis_anchor check")
}

func TestVerify_BrokenChainLink(t *testing.T) {
	export := buildValidChain("vault-1", 5)
	// Corrupt entry 3's PrevHash.
	export.Entries[3].PrevHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	result := verifyAuditChain(export)

	assert.False(t, result.Valid)
	found := false
	for _, c := range result.Checks {
		if c.Name == "chain_continuity" {
			assert.Equal(t, "fail", c.Status)
			assert.Contains(t, c.Detail, "entry 3")
			found = true
		}
	}
	assert.True(t, found, "should have a chain_continuity check")
}

func TestVerify_DuplicateIDs(t *testing.T) {
	export := buildValidChain("vault-1", 3)
	export.Entries[2].ID = export.Entries[0].ID

	result := verifyAuditChain(export)

	assert.False(t, result.Valid)
	found := false
	for _, c := range result.Checks {
		if c.Name == "no_duplicate_ids" {
			assert.Equal(t, "fail", c.Status)
			assert.Contains(t, c.Detail, export.Entries[0].ID)
			found = true
		}
	}
	assert.True(t, found, "should have a no_duplicate_ids check")
}

func TestVerify_NonMonotonicTimestamps(t *testing.T) {
	export := buildValidChain("vault-1", 3)
	// Make entry 2 earlier than entry 1.
	export.Entries[2].CreatedAt = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)

	result := verifyAuditChain(export)

	// Timestamp ordering produces a warning, not a failure.
	found := false
	for _, c := range result.Checks {
		if c.Name == "monotonic_timestamps" {
			assert.Equal(t, "warn", c.Status)
			assert.Contains(t, c.Detail, "entry 2")
			found = true
		}
	}
	assert.True(t, found, "should have a monotonic_timestamps check")
}

func TestVerify_InconsistentVaultID(t *testing.T) {
	export := buildValidChain("vault-1", 3)
	export.Entries[1].VaultID = "vault-other"

	result := verifyAuditChain(export)

	assert.False(t, result.Valid)
	found := false
	for _, c := range result.Checks {
		if c.Name == "consistent_vault_ids" {
			assert.Equal(t, "fail", c.Status)
			assert.Contains(t, c.Detail, "vault-other")
			found = true
		}
	}
	assert.True(t, found, "should have a consistent_vault_ids check")
}

func TestVerify_NoSignatureNote(t *testing.T) {
	export := buildValidChain("vault-1", 2)
	export.Signature = ""

	result := verifyAuditChain(export)

	assert.True(t, result.Valid)
	assert.Empty(t, result.SigNote)
}

func TestVerify_UnparseableTimestamps(t *testing.T) {
	export := buildValidChain("vault-1", 3)
	export.Entries[1].CreatedAt = "not-a-timestamp"

	result := verifyAuditChain(export)

	// Chain continuity will fail because CreatedAt is used in hash computation.
	// But the monotonic_timestamps check should produce a warning about unparsed timestamps.
	found := false
	for _, c := range result.Checks {
		if c.Name == "monotonic_timestamps" {
			// Either warn (unparseable) or pass (skipped unparseable entries).
			assert.NotEqual(t, "fail", c.Status)
			found = true
		}
	}
	assert.True(t, found)
}

func TestVerify_JSONResultStructure(t *testing.T) {
	export := buildValidChain("vault-json", 2)
	result := verifyAuditChain(export)
	result.File = "/tmp/test.json"

	assert.Equal(t, "/tmp/test.json", result.File)
	assert.Equal(t, "vault-json", result.VaultID)
	assert.Equal(t, 2, result.EntryCount)
	assert.True(t, result.Valid)
	assert.GreaterOrEqual(t, len(result.Checks), 4)
}

func TestVerifyChainHash_Consistency(t *testing.T) {
	// Ensure our local hash function matches the expected formula.
	id := "test-id"
	prev := testGenesisHash
	ts := "2025-01-01T00:00:00Z"
	got := verifyChainHash(id, prev, ts)

	// Compute manually.
	h := sha256.Sum256([]byte(id + prev + ts))
	expected := hex.EncodeToString(h[:])

	assert.Equal(t, expected, got)
	assert.Len(t, got, 64) // hex-encoded SHA-256 is 64 chars
}
