package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"github.com/jmcleod/ironhand/internal/uuid"
	"github.com/jmcleod/ironhand/vault"
)

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

	env, err := session.SealAuditRecord(data, auditAAD(vaultID, entry.ID))
	if err != nil {
		return err
	}
	if err := a.repo.Put(vaultID, auditRecordType, entry.ID, env); err != nil {
		return err
	}

	// Update the chain tip.
	newTip := auditChainHash(entry.ID, entry.PrevHash, entry.CreatedAt)
	tipEnv, err := session.SealAuditRecord([]byte(newTip), auditAAD(vaultID, auditTipRecordID))
	if err != nil {
		return err
	}
	return a.repo.Put(vaultID, auditTipType, auditTipRecordID, tipEnv)
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
