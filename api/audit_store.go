package api

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/jmcleod/ironhand/internal/uuid"
	"github.com/jmcleod/ironhand/storage"
)

const (
	auditRecordType = "AUDIT"
)

type auditAction string

const (
	auditActionItemAccessed  auditAction = "item_accessed"
	auditActionItemCreated   auditAction = "item_created"
	auditActionItemUpdated   auditAction = "item_updated"
	auditActionItemDeleted   auditAction = "item_deleted"
	auditActionVaultExported auditAction = "vault_exported"
	auditActionVaultImported auditAction = "vault_imported"
	auditActionCAInitialized auditAction = "ca_initialized"
	auditActionCertIssued    auditAction = "cert_issued"
	auditActionCertRevoked   auditAction = "cert_revoked"
	auditActionCertRenewed   auditAction = "cert_renewed"
	auditActionCRLGenerated  auditAction = "crl_generated"
	auditActionCSRSigned     auditAction = "csr_signed"
)

type auditEntry struct {
	ID        string      `json:"id"`
	VaultID   string      `json:"vault_id"`
	ItemID    string      `json:"item_id"`
	Action    auditAction `json:"action"`
	MemberID  string      `json:"member_id"`
	CreatedAt string      `json:"created_at"`
}

func (a *API) appendAuditEntry(vaultID, itemID, memberID string, action auditAction) error {
	entry := auditEntry{
		ID:        uuid.New(),
		VaultID:   vaultID,
		ItemID:    itemID,
		Action:    action,
		MemberID:  memberID,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	env := &storage.Envelope{
		Ver:        1,
		Scheme:     "plain-json",
		Ciphertext: data,
	}
	return a.repo.Put(vaultID, auditRecordType, entry.ID, env)
}

func (a *API) listAuditEntries(vaultID, itemID string) ([]auditEntry, error) {
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
		var entry auditEntry
		if err := json.Unmarshal(env.Ciphertext, &entry); err != nil {
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
