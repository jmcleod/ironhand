package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

// ---------------------------------------------------------------------------
// Local types matching the audit export JSON structure (mirrors api.Export*
// types without importing the api package and its heavy dependency chain).
// ---------------------------------------------------------------------------

type auditExport struct {
	VaultID   string             `json:"vault_id"`
	Entries   []auditExportEntry `json:"entries"`
	Signature string             `json:"signature"`
}

type auditExportEntry struct {
	ID        string `json:"id"`
	VaultID   string `json:"vault_id"`
	ItemID    string `json:"item_id"`
	Action    string `json:"action"`
	MemberID  string `json:"member_id"`
	CreatedAt string `json:"created_at"`
	PrevHash  string `json:"prev_hash"`
}

// ---------------------------------------------------------------------------
// Verification result types
// ---------------------------------------------------------------------------

type verifyResult struct {
	File       string        `json:"file"`
	VaultID    string        `json:"vault_id"`
	EntryCount int           `json:"entry_count"`
	Valid      bool          `json:"valid"`
	Checks     []checkResult `json:"checks"`
	SigNote    string        `json:"signature_note,omitempty"`
}

type checkResult struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "pass", "fail", "warn"
	Detail string `json:"detail,omitempty"`
}

// ---------------------------------------------------------------------------
// Constants (duplicated from api/audit_store.go to avoid import)
// ---------------------------------------------------------------------------

const verifyGenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// verifyChainHash computes the SHA-256 chain link.
// hash = SHA-256( entryID || prevHash || createdAt )
func verifyChainHash(entryID, prevHash, createdAt string) string {
	h := sha256.Sum256([]byte(entryID + prevHash + createdAt))
	return hex.EncodeToString(h[:])
}

// ---------------------------------------------------------------------------
// Core verification logic
// ---------------------------------------------------------------------------

func verifyAuditChain(export auditExport) verifyResult {
	result := verifyResult{
		VaultID:    export.VaultID,
		EntryCount: len(export.Entries),
		Valid:      true,
	}

	// Empty chain is valid.
	if len(export.Entries) == 0 {
		result.Checks = append(result.Checks, checkResult{
			Name: "empty_chain", Status: "pass", Detail: "no entries to verify",
		})
		if export.Signature != "" {
			result.SigNote = "HMAC signature present but cannot be verified offline (requires vault record key)"
		}
		return result
	}

	// 1. Genesis anchor.
	if export.Entries[0].PrevHash == verifyGenesisHash {
		result.Checks = append(result.Checks, checkResult{
			Name: "genesis_anchor", Status: "pass",
		})
	} else {
		result.Valid = false
		result.Checks = append(result.Checks, checkResult{
			Name:   "genesis_anchor",
			Status: "fail",
			Detail: fmt.Sprintf("first entry prev_hash=%s, expected genesis hash", export.Entries[0].PrevHash),
		})
	}

	// 2. Chain continuity.
	chainOK := true
	var chainDetail string
	for i := 1; i < len(export.Entries); i++ {
		prev := export.Entries[i-1]
		expected := verifyChainHash(prev.ID, prev.PrevHash, prev.CreatedAt)
		if export.Entries[i].PrevHash != expected {
			chainOK = false
			chainDetail = fmt.Sprintf("entry %d (id=%s) has prev_hash=%s but expected %s (computed from entry %d)",
				i, export.Entries[i].ID, export.Entries[i].PrevHash, expected, i-1)
			break
		}
	}
	if chainOK {
		result.Checks = append(result.Checks, checkResult{
			Name:   "chain_continuity",
			Status: "pass",
			Detail: fmt.Sprintf("all %d entries link correctly", len(export.Entries)),
		})
	} else {
		result.Valid = false
		result.Checks = append(result.Checks, checkResult{
			Name: "chain_continuity", Status: "fail", Detail: chainDetail,
		})
	}

	// 3. No duplicate IDs.
	seen := make(map[string]int, len(export.Entries))
	dupFound := false
	var dupDetail string
	for i, e := range export.Entries {
		if prev, ok := seen[e.ID]; ok {
			dupFound = true
			dupDetail = fmt.Sprintf("entry %d and entry %d share id=%s", prev, i, e.ID)
			break
		}
		seen[e.ID] = i
	}
	if !dupFound {
		result.Checks = append(result.Checks, checkResult{
			Name: "no_duplicate_ids", Status: "pass",
		})
	} else {
		result.Valid = false
		result.Checks = append(result.Checks, checkResult{
			Name: "no_duplicate_ids", Status: "fail", Detail: dupDetail,
		})
	}

	// 4. Monotonic timestamps.
	tsOK := true
	var tsDetail string
	var prevTime time.Time
	allParsed := true
	for i, e := range export.Entries {
		t, err := parseTimestamp(e.CreatedAt)
		if err != nil {
			allParsed = false
			continue
		}
		if !prevTime.IsZero() && t.Before(prevTime) {
			tsOK = false
			tsDetail = fmt.Sprintf("entry %d (created_at=%s) is earlier than entry %d", i, e.CreatedAt, i-1)
			break
		}
		prevTime = t
	}
	if tsOK {
		status := "pass"
		detail := ""
		if !allParsed {
			status = "warn"
			detail = "some timestamps could not be parsed"
		}
		result.Checks = append(result.Checks, checkResult{
			Name: "monotonic_timestamps", Status: status, Detail: detail,
		})
	} else {
		// Timestamp ordering is a warning, not a hard failure — clock skew
		// can happen in legitimate deployments.
		result.Checks = append(result.Checks, checkResult{
			Name: "monotonic_timestamps", Status: "warn", Detail: tsDetail,
		})
	}

	// 5. Consistent vault IDs.
	vaultOK := true
	var vaultDetail string
	for i, e := range export.Entries {
		if e.VaultID != export.VaultID {
			vaultOK = false
			vaultDetail = fmt.Sprintf("entry %d has vault_id=%s, expected %s", i, e.VaultID, export.VaultID)
			break
		}
	}
	if vaultOK {
		result.Checks = append(result.Checks, checkResult{
			Name: "consistent_vault_ids", Status: "pass",
		})
	} else {
		result.Valid = false
		result.Checks = append(result.Checks, checkResult{
			Name: "consistent_vault_ids", Status: "fail", Detail: vaultDetail,
		})
	}

	// HMAC signature note.
	if export.Signature != "" {
		result.SigNote = "HMAC signature present but cannot be verified offline (requires vault record key)"
	}

	return result
}

// parseTimestamp parses RFC3339Nano, falling back to RFC3339.
func parseTimestamp(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t, err = time.Parse(time.RFC3339, s)
	}
	return t, err
}

// ---------------------------------------------------------------------------
// Output formatting
// ---------------------------------------------------------------------------

func printHumanResult(result verifyResult) {
	fmt.Printf("Audit chain verification: %s\n", result.File)
	fmt.Printf("Vault ID: %s\n", result.VaultID)
	fmt.Printf("Entries:  %d\n\n", result.EntryCount)

	for _, c := range result.Checks {
		tag := "[PASS]"
		switch c.Status {
		case "fail":
			tag = "[FAIL]"
		case "warn":
			tag = "[WARN]"
		}
		if c.Detail != "" {
			fmt.Printf("%s %s: %s\n", tag, c.Name, c.Detail)
		} else {
			fmt.Printf("%s %s\n", tag, c.Name)
		}
	}

	if result.SigNote != "" {
		fmt.Printf("[INFO] %s\n", result.SigNote)
	}

	fmt.Println()
	if result.Valid {
		fmt.Println("Result: VALID")
	} else {
		failures := 0
		warnings := 0
		for _, c := range result.Checks {
			if c.Status == "fail" {
				failures++
			} else if c.Status == "warn" {
				warnings++
			}
		}
		fmt.Printf("Result: INVALID (%d error(s), %d warning(s))\n", failures, warnings)
	}
}

func printJSONResult(result verifyResult) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// ---------------------------------------------------------------------------
// Cobra command
// ---------------------------------------------------------------------------

var verifyJSONOutput bool

var verifyCmd = &cobra.Command{
	Use:   "verify [file]",
	Short: "Verify the integrity of an exported audit chain",
	Long: `Reads an exported audit log JSON file (from GET /vaults/{id}/audit/export)
and verifies hash chain integrity, genesis anchor, and timestamp ordering.

The HMAC signature in the export cannot be verified offline because it
requires the vault's record key, which is only available to vault members.`,
	Args: cobra.ExactArgs(1),
	RunE: runVerify,
}

func init() {
	auditCmd.AddCommand(verifyCmd)
	verifyCmd.Flags().BoolVar(&verifyJSONOutput, "json", false, "Output results as JSON")
}

func runVerify(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot read file: %v\n", err)
		os.Exit(2)
	}

	var export auditExport
	if err := json.Unmarshal(data, &export); err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid JSON: %v\n", err)
		os.Exit(2)
	}

	result := verifyAuditChain(export)
	result.File = filePath

	if verifyJSONOutput {
		if err := printJSONResult(result); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
	} else {
		printHumanResult(result)
	}

	if !result.Valid {
		os.Exit(1)
	}
	return nil
}
