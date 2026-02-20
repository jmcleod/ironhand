package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/jmcleod/ironhand/internal/uuid"
	"github.com/jmcleod/ironhand/storage"
	"github.com/jmcleod/ironhand/vault"
)

// vaultMutex provides per-key mutual exclusion. Each vault ID gets its own
// mutex so audit appends to different vaults can proceed concurrently while
// appends to the same vault are serialised (preventing read-modify-write
// races on the chain tip).
type vaultMutex struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func (vm *vaultMutex) Lock(key string) {
	vm.mu.Lock()
	if vm.locks == nil {
		vm.locks = make(map[string]*sync.Mutex)
	}
	m, ok := vm.locks[key]
	if !ok {
		m = &sync.Mutex{}
		vm.locks[key] = m
	}
	vm.mu.Unlock()
	m.Lock()
}

func (vm *vaultMutex) Unlock(key string) {
	vm.mu.Lock()
	m := vm.locks[key]
	vm.mu.Unlock()
	m.Unlock()
}

const (
	auditRecordType  = "AUDIT"
	auditTipType     = "AUDIT_TIP"
	auditTipRecordID = "tip"
	// auditRetentionThreshold is the number of appends per vault before
	// retention is checked. This amortises the cost of reading all entries
	// over multiple writes.
	auditRetentionThreshold = 50
)

type auditAction string

const (
	auditActionItemAccessed       auditAction = "item_accessed"
	auditActionItemCreated        auditAction = "item_created"
	auditActionItemUpdated        auditAction = "item_updated"
	auditActionItemDeleted        auditAction = "item_deleted"
	auditActionVaultExported      auditAction = "vault_exported"
	auditActionVaultImported      auditAction = "vault_imported"
	auditActionCAInitialized      auditAction = "ca_initialized"
	auditActionCertIssued         auditAction = "cert_issued"
	auditActionCertRevoked        auditAction = "cert_revoked"
	auditActionCertRenewed        auditAction = "cert_renewed"
	auditActionCRLGenerated       auditAction = "crl_generated"
	auditActionCSRSigned          auditAction = "csr_signed"
	auditActionPrivateKeyAccessed auditAction = "private_key_accessed"
)

type auditEntry struct {
	ID        string      `json:"id"`
	VaultID   string      `json:"vault_id"`
	ItemID    string      `json:"item_id"`
	Action    auditAction `json:"action"`
	MemberID  string      `json:"member_id"`
	CreatedAt string      `json:"created_at"`
	PrevHash  string      `json:"prev_hash,omitempty"`

	// createdAtTime is the parsed form of CreatedAt, used for comparisons
	// and sorting. It is not serialised to JSON; it is populated when the
	// entry is created or deserialised.
	createdAtTime time.Time
}

// parseCreatedAt populates createdAtTime from the CreatedAt string.
func (e *auditEntry) parseCreatedAt() {
	t, err := time.Parse(time.RFC3339Nano, e.CreatedAt)
	if err != nil {
		t, err = time.Parse(time.RFC3339, e.CreatedAt)
	}
	if err == nil {
		e.createdAtTime = t
	}
}

// auditGenesisHash is the well-known hash used as PrevHash for the first entry.
const auditGenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// auditChainHash computes the hash linking an entry to its predecessor.
// hash = SHA-256( entryID || prevHash || createdAt )
func auditChainHash(entryID, prevHash, createdAt string) string {
	h := sha256.Sum256([]byte(entryID + prevHash + createdAt))
	return hex.EncodeToString(h[:])
}

// auditAAD builds AAD for an audit entry: "audit:<vaultID>:<entryID>".
func auditAAD(vaultID, entryID string) []byte {
	return []byte("audit:" + vaultID + ":" + entryID)
}

func (a *API) appendAuditEntry(session *vault.Session, vaultID, itemID, memberID string, action auditAction) error {
	// Serialise appends per vault so the read-modify-write of the chain
	// tip cannot race with a concurrent append to the same vault.
	a.auditMu.Lock(vaultID)
	defer a.auditMu.Unlock(vaultID)

	// Load the current chain tip hash from the repo.
	prevHash := auditGenesisHash
	if tipEnv, err := a.repo.Get(vaultID, auditTipType, auditTipRecordID); err == nil && tipEnv != nil {
		if tipData, err := session.OpenAuditRecord(tipEnv, auditAAD(vaultID, auditTipRecordID)); err == nil {
			prevHash = string(tipData)
		}
	}

	now := time.Now().UTC()
	entry := auditEntry{
		ID:            uuid.New(),
		VaultID:       vaultID,
		ItemID:        itemID,
		Action:        action,
		MemberID:      memberID,
		CreatedAt:     now.Format(time.RFC3339Nano),
		PrevHash:      prevHash,
		createdAtTime: now,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	entryEnv, err := session.SealAuditRecord(data, auditAAD(vaultID, entry.ID))
	if err != nil {
		return err
	}

	// Compute the new chain tip.
	newTip := auditChainHash(entry.ID, entry.PrevHash, entry.CreatedAt)
	tipEnv, err := session.SealAuditRecord([]byte(newTip), auditAAD(vaultID, auditTipRecordID))
	if err != nil {
		return err
	}

	// Write the audit entry and the chain tip atomically so a crash
	// between the two writes cannot leave the chain in an inconsistent
	// state (orphaned entry without tip update, or updated tip without
	// the entry it references).
	if err := a.repo.Batch(vaultID, func(tx storage.BatchTx) error {
		if err := tx.Put(auditRecordType, entry.ID, entryEnv); err != nil {
			return err
		}
		return tx.Put(auditTipType, auditTipRecordID, tipEnv)
	}); err != nil {
		return err
	}

	// Check whether retention pruning is needed, but do it on a
	// threshold basis rather than every write to keep the append path
	// O(1). The counter is per-API (not per-vault) for simplicity; the
	// worst case is a slight delay in pruning across vaults.
	if a.auditMaxAge > 0 || a.auditMaxEntries > 0 {
		count := a.auditAppendsSinceRetention.Add(1)
		if count >= int64(a.auditRetentionCheckThreshold()) {
			a.auditAppendsSinceRetention.Store(0)
			if err := a.enforceAuditRetentionLocked(session, vaultID); err != nil {
				return err
			}
		}
	}
	return nil
}

// auditRetentionCheckThreshold returns the number of appends between
// retention checks. It uses the configured auditMaxEntries as a hint:
// check at most every max/2 appends, with a floor of auditRetentionThreshold.
func (a *API) auditRetentionCheckThreshold() int {
	if a.auditMaxEntries > 0 && a.auditMaxEntries/2 < auditRetentionThreshold {
		// For very small max-entries settings, check more frequently
		// so we don't overshoot by too much.
		if a.auditMaxEntries/2 > 0 {
			return a.auditMaxEntries / 2
		}
		return 1
	}
	return auditRetentionThreshold
}

func (a *API) listAuditEntries(session *vault.Session, vaultID, itemID string) ([]auditEntry, error) {
	ids, err := a.repo.List(vaultID, auditRecordType)
	if err != nil {
		return nil, err
	}
	entries := make([]auditEntry, 0, len(ids))
	for _, id := range ids {
		env, err := a.repo.Get(vaultID, auditRecordType, id)
		if err != nil || env == nil {
			continue
		}

		var data []byte
		if env.Scheme == "plain-json" {
			// Legacy unencrypted entries — read directly.
			data = env.Ciphertext
		} else {
			// Encrypted entries — decrypt with vault record key.
			data, err = session.OpenAuditRecord(env, auditAAD(vaultID, id))
			if err != nil {
				continue
			}
		}

		var entry auditEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}
		entry.parseCreatedAt()
		if itemID != "" && entry.ItemID != itemID {
			continue
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		if !entries[i].createdAtTime.IsZero() && !entries[j].createdAtTime.IsZero() {
			return entries[i].createdAtTime.After(entries[j].createdAtTime)
		}
		// Fall back to string comparison for legacy entries with unparseable timestamps.
		return entries[i].CreatedAt > entries[j].CreatedAt
	})
	return entries, nil
}

// enforceAuditRetentionLocked applies configured retention policy and rewrites
// the retained audit chain from a fresh genesis anchor.
//
// The caller must hold a.auditMu lock for vaultID.
func (a *API) enforceAuditRetentionLocked(session *vault.Session, vaultID string) error {
	entries, err := a.listAuditEntries(session, vaultID, "")
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}

	// listAuditEntries returns newest-first. Convert to chronological order.
	sort.Slice(entries, func(i, j int) bool {
		if !entries[i].createdAtTime.IsZero() && !entries[j].createdAtTime.IsZero() {
			return entries[i].createdAtTime.Before(entries[j].createdAtTime)
		}
		return entries[i].CreatedAt < entries[j].CreatedAt
	})

	retained := entries

	// Time-based retention.
	if a.auditMaxAge > 0 {
		cutoff := time.Now().Add(-a.auditMaxAge)
		filtered := make([]auditEntry, 0, len(retained))
		for _, e := range retained {
			// Keep unparseable legacy entries rather than risk data loss.
			if e.createdAtTime.IsZero() || !e.createdAtTime.Before(cutoff) {
				filtered = append(filtered, e)
			}
		}
		retained = filtered
	}

	// Count-based retention.
	if a.auditMaxEntries > 0 && len(retained) > a.auditMaxEntries {
		retained = retained[len(retained)-a.auditMaxEntries:]
	}

	// No pruning needed.
	if len(retained) == len(entries) {
		return nil
	}

	// Rewrite audit records and tip atomically to preserve a contiguous chain.
	return a.repo.Batch(vaultID, func(tx storage.BatchTx) error {
		for _, e := range entries {
			if err := tx.Delete(auditRecordType, e.ID); err != nil && !errors.Is(err, storage.ErrNotFound) {
				return err
			}
		}
		if err := tx.Delete(auditTipType, auditTipRecordID); err != nil && !errors.Is(err, storage.ErrNotFound) {
			return err
		}

		prevHash := auditGenesisHash
		for _, e := range retained {
			e.PrevHash = prevHash
			data, err := json.Marshal(e)
			if err != nil {
				return err
			}
			env, err := session.SealAuditRecord(data, auditAAD(vaultID, e.ID))
			if err != nil {
				return err
			}
			if err := tx.Put(auditRecordType, e.ID, env); err != nil {
				return err
			}
			prevHash = auditChainHash(e.ID, e.PrevHash, e.CreatedAt)
		}

		// If no entries remain, leave tip absent.
		if len(retained) == 0 {
			return nil
		}

		tipEnv, err := session.SealAuditRecord([]byte(prevHash), auditAAD(vaultID, auditTipRecordID))
		if err != nil {
			return err
		}
		return tx.Put(auditTipType, auditTipRecordID, tipEnv)
	})
}
