package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

	entry := auditEntry{
		ID:        uuid.New(),
		VaultID:   vaultID,
		ItemID:    itemID,
		Action:    action,
		MemberID:  memberID,
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		PrevHash:  prevHash,
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
	return a.repo.Batch(vaultID, func(tx storage.BatchTx) error {
		if err := tx.Put(auditRecordType, entry.ID, entryEnv); err != nil {
			return err
		}
		return tx.Put(auditTipType, auditTipRecordID, tipEnv)
	})
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
		if itemID != "" && entry.ItemID != itemID {
			continue
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].CreatedAt > entries[j].CreatedAt
	})
	return entries, nil
}
