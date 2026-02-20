package api

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/jmcleod/ironhand/internal/util"
	"github.com/jmcleod/ironhand/internal/uuid"
	"github.com/jmcleod/ironhand/pki"
	"github.com/jmcleod/ironhand/storage"
	"github.com/jmcleod/ironhand/vault"
)

// backupKDFParams are the Argon2id parameters used to derive the encryption key
// for vault backup files. These use the "sensitive" profile because backups are
// long-lived offline artifacts that may be stored on external media.
var backupKDFParams = func() util.Argon2idParams {
	p, _ := util.Argon2idProfile(util.KDFProfileSensitive)
	return p
}()

// isReservedItemID reports whether itemID is reserved for internal use
// (vault metadata or PKI CA state) and should be blocked from user CRUD.
func isReservedItemID(itemID string) bool {
	return itemID == vaultMetadataItemID || pki.IsReservedItemID(itemID)
}

func fieldsFromAPI(apiFields map[string]string) (vault.Fields, error) {
	fields := make(vault.Fields, len(apiFields))
	for k, v := range apiFields {
		// Reject any field that carries the redaction sentinel — writing it
		// back would destroy the real value stored in the vault.
		if sensitiveFields[k] && v == redactionSentinel {
			return nil, fmt.Errorf("field %q contains the redaction placeholder and cannot be written", k)
		}
		if vault.IsAttachmentField(k) {
			decoded, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return nil, fmt.Errorf("invalid base64 in attachment field %q: %w", k, err)
			}
			if len(decoded) > vault.MaxAttachmentSize {
				return nil, fmt.Errorf("attachment %q exceeds maximum size of %d bytes",
					vault.AttachmentFilename(k), vault.MaxAttachmentSize)
			}
			fields[k] = decoded
		} else {
			fields[k] = []byte(v)
		}
	}
	return fields, nil
}

func fieldsToAPI(fields vault.Fields) map[string]string {
	apiFields := make(map[string]string, len(fields))
	for k, v := range fields {
		if vault.IsAttachmentField(k) {
			apiFields[k] = base64.StdEncoding.EncodeToString(v)
		} else {
			apiFields[k] = string(v)
		}
	}
	return apiFields
}

// redactionSentinel is the placeholder value returned for sensitive fields.
// It must never be accepted as a write — doing so would destroy key material.
const redactionSentinel = "[REDACTED]"

// sensitiveFields are field names that should be redacted in normal item
// responses. They are only accessible via dedicated endpoints that enforce
// additional access control (e.g. owner-only private key retrieval).
var sensitiveFields = map[string]bool{
	pki.FieldPrivateKey: true,
}

func fieldsToAPIRedacted(fields vault.Fields) map[string]string {
	apiFields := make(map[string]string, len(fields))
	for k, v := range fields {
		if sensitiveFields[k] {
			apiFields[k] = redactionSentinel
		} else if vault.IsAttachmentField(k) {
			apiFields[k] = base64.StdEncoding.EncodeToString(v)
		} else {
			apiFields[k] = string(v)
		}
	}
	return apiFields
}

// CreateVault handles POST /vaults.
// Creates a new vault for the authenticated account and returns the generated vault ID.
func (a *API) CreateVault(w http.ResponseWriter, r *http.Request) {
	creds := credentialsFromContext(r.Context())
	if creds == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	req, ok := decodeJSON[CreateVaultRequest](w, r, maxSmallBodySize)
	if !ok {
		return
	}

	vaultID := uuid.New()
	v := vault.New(vaultID, a.repo, vault.WithEpochCache(a.epochCache))
	session, err := v.Create(r.Context(), creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	if req.Name != "" || req.Description != "" {
		metaFields := encodeVaultMetadata(strings.TrimSpace(req.Name), strings.TrimSpace(req.Description))
		if err := session.Put(r.Context(), vaultMetadataItemID, metaFields); err != nil {
			mapError(w, err)
			return
		}
	}

	// Update the account's vault index.
	if err := a.addVaultToIndex(creds.SecretKey().String(), vaultID); err != nil {
		slog.Warn("failed to update vault index on create", "error", err)
	}

	a.audit.logEvent(AuditVaultCreated, r, creds.SecretKey().ID(),
		slog.String("vault_id", vaultID))
	writeJSON(w, http.StatusCreated, CreateVaultResponse{
		VaultID:  vaultID,
		MemberID: creds.MemberID(),
		Epoch:    session.Epoch(),
	})
}

// OpenVault handles POST /vaults/{vaultID}/open.
// Validates credentials and returns vault info.
func (a *API) OpenVault(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	creds := credentialsFromContext(r.Context())

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	// Lazily ensure this vault is in the account's index (e.g. added as
	// member by someone else).
	if err := a.addVaultToIndex(creds.SecretKey().String(), vaultID); err != nil {
		slog.Warn("failed to update vault index on open", "error", err)
	}

	writeJSON(w, http.StatusOK, OpenVaultResponse{
		VaultID:  vaultID,
		MemberID: session.MemberID,
		Epoch:    session.Epoch(),
	})
}

// ListItems handles GET /vaults/{vaultID}/items.
func (a *API) ListItems(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	creds := credentialsFromContext(r.Context())

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	items, err := session.List(r.Context())
	if err != nil {
		mapError(w, err)
		return
	}

	filtered := items[:0]
	for _, itemID := range items {
		if isReservedItemID(itemID) {
			continue
		}
		filtered = append(filtered, itemID)
	}
	items = filtered

	summaries := make([]ItemSummary, 0, len(items))
	for _, itemID := range items {
		fields, err := session.Get(r.Context(), itemID)
		if err != nil {
			continue
		}
		name := string(fields["_name"])
		if name == "" {
			name = itemID
		}
		itemType := string(fields["_type"])
		if itemType == "" {
			itemType = "custom"
		}
		summaries = append(summaries, ItemSummary{
			ItemID: itemID,
			Name:   name,
			Type:   itemType,
		})
	}

	writeJSON(w, http.StatusOK, ListItemsResponse{Items: summaries})
}

// PutItem handles POST /vaults/{vaultID}/items/{itemID}.
func (a *API) PutItem(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	itemID := chi.URLParam(r, "itemID")
	if isReservedItemID(itemID) {
		writeError(w, http.StatusBadRequest, "item_id is reserved")
		return
	}
	creds := credentialsFromContext(r.Context())

	req, ok := decodeJSON[PutItemRequest](w, r, maxItemBodySize)
	if !ok {
		return
	}

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	fields, err := fieldsFromAPI(req.Fields)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid item fields")
		return
	}
	if err := session.Put(r.Context(), itemID, fields); err != nil {
		mapError(w, err)
		return
	}
	_ = a.appendAuditEntry(session, vaultID, itemID, session.MemberID, auditActionItemCreated)

	a.audit.logEvent(AuditItemCreated, r, creds.SecretKey().ID(),
		slog.String("vault_id", vaultID),
		slog.String("item_id", itemID))
	writeJSON(w, http.StatusCreated, struct{}{})
}

// GetItem handles GET /vaults/{vaultID}/items/{itemID}.
func (a *API) GetItem(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	itemID := chi.URLParam(r, "itemID")
	if isReservedItemID(itemID) {
		writeError(w, http.StatusBadRequest, "item_id is reserved")
		return
	}
	creds := credentialsFromContext(r.Context())

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	fields, err := session.Get(r.Context(), itemID)
	if err != nil {
		mapError(w, err)
		return
	}
	_ = a.appendAuditEntry(session, vaultID, itemID, session.MemberID, auditActionItemAccessed)

	writeJSON(w, http.StatusOK, GetItemResponse{
		ItemID: itemID,
		Fields: fieldsToAPIRedacted(fields),
	})
}

// GetItemPrivateKey handles GET /vaults/{vaultID}/items/{itemID}/private-key.
// Returns the raw PEM-encoded private key for a certificate item. Requires
// owner (admin) access because private keys are redacted from normal GetItem
// responses.
func (a *API) GetItemPrivateKey(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	itemID := chi.URLParam(r, "itemID")
	creds := credentialsFromContext(r.Context())

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	if err := session.RequireAdmin(r.Context()); err != nil {
		mapError(w, err)
		return
	}

	fields, err := session.Get(r.Context(), itemID)
	if err != nil {
		mapError(w, err)
		return
	}

	keyPEM, ok := fields[pki.FieldPrivateKey]
	if !ok || len(keyPEM) == 0 {
		writeError(w, http.StatusNotFound, "item does not contain a private key")
		return
	}

	_ = a.appendAuditEntry(session, vaultID, itemID, session.MemberID, auditActionPrivateKeyAccessed)
	a.audit.logEvent(AuditPrivateKeyAccessed, r, creds.SecretKey().ID(),
		slog.String("vault_id", vaultID),
		slog.String("item_id", itemID))

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	w.Write(keyPEM)
}

// UpdateItem handles PUT /vaults/{vaultID}/items/{itemID}.
func (a *API) UpdateItem(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	itemID := chi.URLParam(r, "itemID")
	if isReservedItemID(itemID) {
		writeError(w, http.StatusBadRequest, "item_id is reserved")
		return
	}
	creds := credentialsFromContext(r.Context())

	req, ok := decodeJSON[UpdateItemRequest](w, r, maxItemBodySize)
	if !ok {
		return
	}

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	fields, err := fieldsFromAPI(req.Fields)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid item fields")
		return
	}
	if err := session.Update(r.Context(), itemID, fields); err != nil {
		mapError(w, err)
		return
	}
	_ = a.appendAuditEntry(session, vaultID, itemID, session.MemberID, auditActionItemUpdated)

	a.audit.logEvent(AuditItemUpdated, r, creds.SecretKey().ID(),
		slog.String("vault_id", vaultID),
		slog.String("item_id", itemID))
	writeJSON(w, http.StatusOK, struct{}{})
}

// DeleteItem handles DELETE /vaults/{vaultID}/items/{itemID}.
func (a *API) DeleteItem(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	itemID := chi.URLParam(r, "itemID")
	if isReservedItemID(itemID) {
		writeError(w, http.StatusBadRequest, "item_id is reserved")
		return
	}
	creds := credentialsFromContext(r.Context())

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	if err := session.Delete(r.Context(), itemID); err != nil {
		mapError(w, err)
		return
	}
	_ = a.appendAuditEntry(session, vaultID, itemID, session.MemberID, auditActionItemDeleted)

	a.audit.logEvent(AuditItemDeleted, r, creds.SecretKey().ID(),
		slog.String("vault_id", vaultID),
		slog.String("item_id", itemID))
	writeJSON(w, http.StatusOK, struct{}{})
}

// ListVaults handles GET /vaults.
// Uses the per-account vault index instead of iterating all vaults in
// the repository, avoiding O(N) probe of every vault and preventing
// vault-existence leakage.
func (a *API) ListVaults(w http.ResponseWriter, r *http.Request) {
	creds := credentialsFromContext(r.Context())
	secretKey := creds.SecretKey().String()

	idx, err := a.loadVaultIndex(secretKey)
	if err != nil {
		slog.Warn("list vaults: failed to load vault index", "error", err)
		// Fall through with empty index — user sees no vaults.
	}
	sort.Strings(idx.VaultIDs)

	result := make([]VaultSummary, 0, len(idx.VaultIDs))
	for _, vaultID := range idx.VaultIDs {
		session, err := a.openSession(r.Context(), vaultID, creds)
		if err != nil {
			// The vault may have been deleted or access revoked — skip it.
			slog.Debug("list vaults: skipping indexed vault", "vault_id", vaultID, "error", err)
			continue
		}

		meta := vaultMetadata{}
		metaFields, err := session.Get(r.Context(), vaultMetadataItemID)
		if err == nil {
			meta = decodeVaultMetadata(metaFields)
		} else if !errors.Is(err, storage.ErrNotFound) {
			slog.Debug("list vaults: metadata read failed", "vault_id", vaultID, "error", err)
		}
		itemIDs, err := session.List(r.Context())
		epoch := session.Epoch()
		if err != nil {
			slog.Debug("list vaults: list failed", "vault_id", vaultID, "error", err)
			session.Close()
			continue
		}
		session.Close()

		count := 0
		for _, itemID := range itemIDs {
			if itemID != vaultMetadataItemID {
				count++
			}
		}
		result = append(result, VaultSummary{
			VaultID:     vaultID,
			Name:        meta.Name,
			Description: meta.Description,
			Epoch:       epoch,
			ItemCount:   count,
		})
	}

	writeJSON(w, http.StatusOK, ListVaultsResponse{Vaults: result})
}

// DeleteVault handles DELETE /vaults/{vaultID}.
func (a *API) DeleteVault(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	creds := credentialsFromContext(r.Context())

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	// Owner-only operation enforced by admin authorization.
	if err := session.RequireAdmin(r.Context()); err != nil {
		session.Close()
		mapError(w, err)
		return
	}
	session.Close()

	if err := a.repo.DeleteVault(vaultID); err != nil {
		mapError(w, err)
		return
	}

	// Remove from account's vault index.
	if err := a.removeVaultFromIndex(creds.SecretKey().String(), vaultID); err != nil {
		slog.Warn("failed to update vault index on delete", "error", err)
	}

	a.audit.logEvent(AuditVaultDeleted, r, creds.SecretKey().ID(),
		slog.String("vault_id", vaultID))
	writeJSON(w, http.StatusOK, struct{}{})
}

// AddMember handles POST /vaults/{vaultID}/members.
func (a *API) AddMember(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	creds := credentialsFromContext(r.Context())

	req, ok := decodeJSON[AddMemberRequest](w, r, maxSmallBodySize)
	if !ok {
		return
	}

	if req.MemberID == "" {
		writeError(w, http.StatusBadRequest, "member_id is required")
		return
	}
	if req.PubKey == "" {
		writeError(w, http.StatusBadRequest, "pub_key is required")
		return
	}
	if req.Role == "" {
		writeError(w, http.StatusBadRequest, "role is required")
		return
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(req.PubKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 pub_key")
		return
	}
	if len(pubKeyBytes) != 32 {
		writeError(w, http.StatusBadRequest, "pub_key must be exactly 32 bytes")
		return
	}

	var pubKey [32]byte
	copy(pubKey[:], pubKeyBytes)

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	if err := session.AddMember(r.Context(), req.MemberID, pubKey, vault.MemberRole(req.Role)); err != nil {
		mapError(w, err)
		return
	}

	a.audit.logEvent(AuditMemberAdded, r, creds.SecretKey().ID(),
		slog.String("vault_id", vaultID),
		slog.String("member_id", req.MemberID),
		slog.String("role", req.Role))
	writeJSON(w, http.StatusCreated, AddMemberResponse{
		Epoch: session.Epoch(),
	})
}

// RevokeMember handles DELETE /vaults/{vaultID}/members/{memberID}.
func (a *API) RevokeMember(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	memberID := chi.URLParam(r, "memberID")
	creds := credentialsFromContext(r.Context())

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	if err := session.RevokeMember(r.Context(), memberID); err != nil {
		mapError(w, err)
		return
	}

	a.audit.logEvent(AuditMemberRevoked, r, creds.SecretKey().ID(),
		slog.String("vault_id", vaultID),
		slog.String("member_id", memberID))
	writeJSON(w, http.StatusOK, AddMemberResponse{
		Epoch: session.Epoch(),
	})
}

// GetItemHistory handles GET /vaults/{vaultID}/items/{itemID}/history.
func (a *API) GetItemHistory(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	itemID := chi.URLParam(r, "itemID")
	if isReservedItemID(itemID) {
		writeError(w, http.StatusBadRequest, "item_id is reserved")
		return
	}
	creds := credentialsFromContext(r.Context())

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	entries, err := session.GetHistory(r.Context(), itemID)
	if err != nil {
		mapError(w, err)
		return
	}
	_ = a.appendAuditEntry(session, vaultID, itemID, session.MemberID, auditActionItemAccessed)

	history := make([]HistoryEntryResponse, len(entries))
	for i, e := range entries {
		history[i] = HistoryEntryResponse{
			Version:   e.Version,
			UpdatedAt: e.UpdatedAt,
			UpdatedBy: e.UpdatedBy,
		}
	}

	writeJSON(w, http.StatusOK, GetItemHistoryResponse{
		ItemID:  itemID,
		History: history,
	})
}

// GetHistoryVersion handles GET /vaults/{vaultID}/items/{itemID}/history/{version}.
func (a *API) GetHistoryVersion(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	itemID := chi.URLParam(r, "itemID")
	versionStr := chi.URLParam(r, "version")
	if isReservedItemID(itemID) {
		writeError(w, http.StatusBadRequest, "item_id is reserved")
		return
	}

	version, err := strconv.ParseUint(versionStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid version number")
		return
	}

	creds := credentialsFromContext(r.Context())

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	fields, err := session.GetHistoryVersion(r.Context(), itemID, version)
	if err != nil {
		mapError(w, err)
		return
	}
	_ = a.appendAuditEntry(session, vaultID, itemID, session.MemberID, auditActionItemAccessed)

	writeJSON(w, http.StatusOK, GetHistoryVersionResponse{
		ItemID:  itemID,
		Version: version,
		Fields:  fieldsToAPI(fields),
	})
}

// ListAuditLogs handles GET /vaults/{vaultID}/audit.
func (a *API) ListAuditLogs(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	itemID := strings.TrimSpace(r.URL.Query().Get("item_id"))
	creds := credentialsFromContext(r.Context())

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	entries, err := a.listAuditEntries(session, vaultID, itemID)
	if err != nil {
		mapError(w, err)
		return
	}
	resp := make([]AuditEntryResponse, 0, len(entries))
	for _, entry := range entries {
		resp = append(resp, AuditEntryResponse{
			ID:        entry.ID,
			ItemID:    entry.ItemID,
			Action:    string(entry.Action),
			MemberID:  entry.MemberID,
			CreatedAt: entry.CreatedAt,
		})
	}

	writeJSON(w, http.StatusOK, ListAuditLogsResponse{Entries: resp})
}

// ExportAuditLog handles GET /vaults/{vaultID}/audit/export.
// Admin-only. Returns the full audit chain with a tamper-evident HMAC-SHA256
// signature over the serialized entries, computed with the vault's record key.
func (a *API) ExportAuditLog(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	creds := credentialsFromContext(r.Context())

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	if err := session.RequireAdmin(r.Context()); err != nil {
		mapError(w, err)
		return
	}

	entries, err := a.listAuditEntries(session, vaultID, "")
	if err != nil {
		mapError(w, err)
		return
	}

	// Build response entries in chronological order (oldest first).
	// listAuditEntries returns newest-first, so reverse.
	exportEntries := make([]ExportAuditEntryResponse, len(entries))
	for i := range entries {
		e := entries[len(entries)-1-i]
		exportEntries[i] = ExportAuditEntryResponse{
			ID:        e.ID,
			VaultID:   e.VaultID,
			ItemID:    e.ItemID,
			Action:    string(e.Action),
			MemberID:  e.MemberID,
			CreatedAt: e.CreatedAt,
			PrevHash:  e.PrevHash,
		}
	}

	// Compute HMAC-SHA256 over the serialized entries.
	entriesJSON, err := json.Marshal(exportEntries)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to serialize audit entries")
		return
	}
	sig, err := session.HMACAudit(entriesJSON)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to sign audit export")
		return
	}

	writeJSON(w, http.StatusOK, ExportAuditLogResponse{
		VaultID:   vaultID,
		Entries:   exportEntries,
		Signature: hex.EncodeToString(sig),
	})
}

// ExportVault handles POST /vaults/{vaultID}/export.
// Requires owner access. Decrypts all current items, serializes them to JSON,
// and encrypts the blob with the caller-supplied passphrase using Argon2id + AES-256-GCM.
// The response is a binary file: version(1B) || salt(16B) || AES-256-GCM ciphertext.
func (a *API) ExportVault(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	creds := credentialsFromContext(r.Context())

	req, ok := decodeJSON[ExportVaultRequest](w, r, maxSmallBodySize)
	if !ok {
		return
	}
	if req.Passphrase == "" {
		writeError(w, http.StatusBadRequest, "passphrase must not be empty")
		return
	}

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	// Require owner role for export (exposes all plaintext).
	if err := session.RequireAdmin(r.Context()); err != nil {
		mapError(w, err)
		return
	}

	// List all items.
	itemIDs, err := session.List(r.Context())
	if err != nil {
		mapError(w, err)
		return
	}

	// Read vault metadata.
	var vaultName, vaultDesc string
	metaFields, err := session.Get(r.Context(), vaultMetadataItemID)
	if err == nil {
		meta := decodeVaultMetadata(metaFields)
		vaultName = meta.Name
		vaultDesc = meta.Description
	}

	// Decrypt each item (skip metadata item).
	exportItems := make([]vaultExportItem, 0, len(itemIDs))
	for _, itemID := range itemIDs {
		if isReservedItemID(itemID) {
			continue
		}
		fields, err := session.Get(r.Context(), itemID)
		if err != nil {
			slog.Warn("export: skipping unreadable item", "item_id", itemID, "error", err)
			continue
		}
		exportItems = append(exportItems, vaultExportItem{
			Fields: fieldsToAPI(fields),
		})
	}

	payload := vaultExportPayload{
		FormatVersion: 1,
		VaultName:     vaultName,
		VaultDesc:     vaultDesc,
		ExportedAt:    time.Now().UTC().Format(time.RFC3339),
		Items:         exportItems,
	}

	plaintext, err := json.Marshal(payload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Encrypt with passphrase.
	salt, err := util.RandomBytes(16)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	key, err := util.DeriveArgon2idKey(util.Normalize(req.Passphrase), salt, backupKDFParams)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	defer util.WipeBytes(key)

	ciphertext, err := util.EncryptAES(plaintext, key)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Build output: version(1) || salt(16) || ciphertext
	out := make([]byte, 0, 1+16+len(ciphertext))
	out = append(out, 1) // format version
	out = append(out, salt...)
	out = append(out, ciphertext...)

	_ = a.appendAuditEntry(session, vaultID, "", session.MemberID, auditActionVaultExported)
	a.audit.logEvent(AuditVaultExported, r, creds.SecretKey().ID(),
		slog.String("vault_id", vaultID),
		slog.Int("item_count", len(exportItems)))

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="vault-backup.ironhand-backup"`)
	w.WriteHeader(http.StatusOK)
	w.Write(out)
}

// ImportVault handles POST /vaults/{vaultID}/import.
// Accepts multipart form with "file" (the encrypted backup blob) and "passphrase".
// Each imported item receives a new UUID; original IDs are not preserved.
func (a *API) ImportVault(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	creds := credentialsFromContext(r.Context())

	// Cap the total request body to 50 MiB, then parse multipart form.
	r.Body = http.MaxBytesReader(w, r.Body, 50<<20)
	if err := r.ParseMultipartForm(50 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid multipart form")
		return
	}

	passphrase := r.FormValue("passphrase")
	if passphrase == "" {
		writeError(w, http.StatusBadRequest, "passphrase is required")
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "file is required")
		return
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, 50<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read file")
		return
	}

	// Decrypt the backup blob.
	if len(data) < 1+16 {
		writeError(w, http.StatusBadRequest, "backup file too short")
		return
	}
	version := data[0]
	if version != 1 {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported backup version: %d", version))
		return
	}
	salt := data[1:17]
	ct := data[17:]

	key, err := util.DeriveArgon2idKey(util.Normalize(passphrase), salt, backupKDFParams)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	defer util.WipeBytes(key)

	plaintext, err := util.DecryptAES(ct, key)
	if err != nil {
		writeError(w, http.StatusBadRequest, "decryption failed: wrong passphrase or corrupt file")
		return
	}

	var payload vaultExportPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid backup format")
		return
	}
	if payload.FormatVersion != 1 {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported format version: %d", payload.FormatVersion))
		return
	}

	// Open session to target vault (write access required).
	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	// Import each item with a new UUID.
	importedCount := 0
	for _, exportItem := range payload.Items {
		fields, err := fieldsFromAPI(exportItem.Fields)
		if err != nil {
			slog.Warn("import: skipping item with invalid fields", "error", err)
			continue
		}
		newItemID := uuid.New()
		if err := session.Put(r.Context(), newItemID, fields); err != nil {
			slog.Warn("import: failed to put item", "error", err)
			continue
		}
		_ = a.appendAuditEntry(session, vaultID, newItemID, session.MemberID, auditActionItemCreated)
		importedCount++
	}

	_ = a.appendAuditEntry(session, vaultID, "", session.MemberID, auditActionVaultImported)
	a.audit.logEvent(AuditVaultImported, r, creds.SecretKey().ID(),
		slog.String("vault_id", vaultID),
		slog.Int("imported_count", importedCount))

	writeJSON(w, http.StatusOK, ImportVaultResponse{ImportedCount: importedCount})
}

// ---------------------------------------------------------------------------
// PKI / Certificate Authority handlers
// ---------------------------------------------------------------------------

// parseExtKeyUsages converts string names to x509.ExtKeyUsage constants.
func parseExtKeyUsages(names []string) []x509.ExtKeyUsage {
	var usages []x509.ExtKeyUsage
	for _, name := range names {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "server_auth", "serverauth":
			usages = append(usages, x509.ExtKeyUsageServerAuth)
		case "client_auth", "clientauth":
			usages = append(usages, x509.ExtKeyUsageClientAuth)
		case "code_signing", "codesigning":
			usages = append(usages, x509.ExtKeyUsageCodeSigning)
		case "email_protection", "emailprotection":
			usages = append(usages, x509.ExtKeyUsageEmailProtection)
		}
	}
	return usages
}

// parseRevocationReason maps a reason string to an x509 CRL reason code.
func parseRevocationReason(reason string) int {
	switch strings.ToLower(strings.TrimSpace(reason)) {
	case "key_compromise":
		return 1
	case "ca_compromise":
		return 2
	case "affiliation_changed":
		return 3
	case "superseded":
		return 4
	case "cessation_of_operation":
		return 5
	default:
		return 0 // Unspecified
	}
}

// InitCA handles POST /vaults/{vaultID}/pki/init.
func (a *API) InitCA(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	creds := credentialsFromContext(r.Context())

	req, ok := decodeJSON[InitCARequest](w, r, maxSmallBodySize)
	if !ok {
		return
	}
	if req.CommonName == "" {
		writeError(w, http.StatusBadRequest, "common_name is required")
		return
	}
	if req.ValidityYears <= 0 {
		req.ValidityYears = 10
	}

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	if err := session.RequireAdmin(r.Context()); err != nil {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}

	subject := pkix.Name{CommonName: req.CommonName}
	if req.Organization != "" {
		subject.Organization = []string{req.Organization}
	}
	if req.OrgUnit != "" {
		subject.OrganizationalUnit = []string{req.OrgUnit}
	}
	if req.Country != "" {
		subject.Country = []string{req.Country}
	}
	if req.Province != "" {
		subject.Province = []string{req.Province}
	}
	if req.Locality != "" {
		subject.Locality = []string{req.Locality}
	}

	if err := pki.InitCA(r.Context(), session, subject, req.ValidityYears, req.IsIntermediate, a.keyStore); err != nil {
		if errors.Is(err, pki.ErrAlreadyCA) {
			writeError(w, http.StatusConflict, "vault is already initialized as a CA")
			return
		}
		writeInternalError(w, "failed to initialize CA", err)
		return
	}

	_ = a.appendAuditEntry(session, vaultID, "", session.MemberID, auditActionCAInitialized)
	a.audit.logEvent(AuditCAInitialized, r, creds.SecretKey().ID(),
		slog.String("vault_id", vaultID))

	info, _ := pki.GetCAInfo(r.Context(), session)
	resp := InitCAResponse{Subject: ""}
	if info != nil {
		resp.Subject = info.Subject
	}
	writeJSON(w, http.StatusCreated, resp)
}

// GetCAInfo handles GET /vaults/{vaultID}/pki/info.
func (a *API) GetCAInfo(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	creds := credentialsFromContext(r.Context())

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	info, err := pki.GetCAInfo(r.Context(), session)
	if err != nil {
		if errors.Is(err, pki.ErrNotCA) {
			writeError(w, http.StatusNotFound, "vault is not initialized as a CA")
			return
		}
		writeInternalError(w, "failed to retrieve CA info", err)
		return
	}

	writeJSON(w, http.StatusOK, CAInfoResponse{
		IsCA:           info.IsCA,
		IsIntermediate: info.IsIntermediate,
		Subject:        info.Subject,
		NotBefore:      info.NotBefore,
		NotAfter:       info.NotAfter,
		NextSerial:     info.NextSerial,
		CRLNumber:      info.CRLNumber,
		CertCount:      info.CertCount,
	})
}

// GetCACert handles GET /vaults/{vaultID}/pki/ca.pem.
func (a *API) GetCACert(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	creds := credentialsFromContext(r.Context())

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	certPEM, err := pki.GetCACertificate(r.Context(), session)
	if err != nil {
		if errors.Is(err, pki.ErrNotCA) {
			writeError(w, http.StatusNotFound, "vault is not initialized as a CA")
			return
		}
		writeInternalError(w, "failed to retrieve CA certificate", err)
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "attachment; filename=\"ca.pem\"")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(certPEM))
}

// IssueCert handles POST /vaults/{vaultID}/pki/issue.
func (a *API) IssueCert(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	creds := credentialsFromContext(r.Context())

	req, ok := decodeJSON[IssueCertAPIRequest](w, r, maxSmallBodySize)
	if !ok {
		return
	}
	if req.CommonName == "" {
		writeError(w, http.StatusBadRequest, "common_name is required")
		return
	}
	if req.ValidityDays <= 0 {
		req.ValidityDays = 365
	}

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	if err := session.RequireAdmin(r.Context()); err != nil {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}

	subject := pkix.Name{CommonName: req.CommonName}
	if req.Organization != "" {
		subject.Organization = []string{req.Organization}
	}
	if req.OrgUnit != "" {
		subject.OrganizationalUnit = []string{req.OrgUnit}
	}
	if req.Country != "" {
		subject.Country = []string{req.Country}
	}

	// Parse IP addresses.
	var ips []net.IP
	for _, s := range req.IPAddresses {
		if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
			ips = append(ips, ip)
		}
	}

	issueReq := pki.IssueCertRequest{
		Subject:        subject,
		ValidityDays:   req.ValidityDays,
		ExtKeyUsages:   parseExtKeyUsages(req.ExtKeyUsages),
		DNSNames:       req.DNSNames,
		IPAddresses:    ips,
		EmailAddresses: req.EmailAddresses,
	}

	itemID, err := pki.IssueCertificate(r.Context(), session, issueReq, a.keyStore)
	if err != nil {
		if errors.Is(err, pki.ErrNotCA) {
			writeError(w, http.StatusBadRequest, "vault is not initialized as a CA")
			return
		}
		writeInternalError(w, "failed to issue certificate", err)
		return
	}

	// Read back the issued cert fields for the response.
	fields, _ := session.Get(r.Context(), itemID)

	_ = a.appendAuditEntry(session, vaultID, itemID, session.MemberID, auditActionCertIssued)
	a.audit.logEvent(AuditCertIssued, r, creds.SecretKey().ID(),
		slog.String("vault_id", vaultID),
		slog.String("item_id", itemID))

	writeJSON(w, http.StatusCreated, IssueCertResponse{
		ItemID:       itemID,
		SerialNumber: string(fields[pki.FieldSerialNumber]),
		Subject:      string(fields[pki.FieldSubject]),
		NotBefore:    string(fields[pki.FieldNotBefore]),
		NotAfter:     string(fields[pki.FieldNotAfter]),
	})
}

// RevokeCert handles POST /vaults/{vaultID}/pki/items/{itemID}/revoke.
func (a *API) RevokeCert(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	itemID := chi.URLParam(r, "itemID")
	creds := credentialsFromContext(r.Context())

	r.Body = http.MaxBytesReader(w, r.Body, maxSmallBodySize)
	var req RevokeCertAPIRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		// An empty body (io.EOF) is intentionally allowed — it defaults
		// the reason to "unspecified". Any other decode error (malformed
		// JSON, unknown fields, oversized body) is rejected.
		if !errors.Is(err, io.EOF) {
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			} else {
				writeError(w, http.StatusBadRequest, "invalid request body")
			}
			return
		}
		req.Reason = "unspecified"
	}

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	if err := session.RequireAdmin(r.Context()); err != nil {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}

	reason := parseRevocationReason(req.Reason)
	if err := pki.RevokeCertificate(r.Context(), session, itemID, reason); err != nil {
		switch {
		case errors.Is(err, pki.ErrNotCA):
			writeError(w, http.StatusBadRequest, "vault is not initialized as a CA")
		case errors.Is(err, pki.ErrCertNotFound):
			writeError(w, http.StatusNotFound, "certificate not found")
		case errors.Is(err, pki.ErrNotCertificateItem):
			writeError(w, http.StatusBadRequest, "item is not a certificate")
		case errors.Is(err, pki.ErrCertAlreadyRevoked):
			writeError(w, http.StatusConflict, "certificate is already revoked")
		default:
			writeInternalError(w, "failed to revoke certificate", err)
		}
		return
	}

	_ = a.appendAuditEntry(session, vaultID, itemID, session.MemberID, auditActionCertRevoked)
	a.audit.logEvent(AuditCertRevoked, r, creds.SecretKey().ID(),
		slog.String("vault_id", vaultID),
		slog.String("item_id", itemID))

	// Automatically regenerate the cached CRL so that the GET endpoint
	// immediately reflects the revocation without a separate POST /crl.
	if _, err := pki.GenerateCRL(r.Context(), session, a.keyStore); err != nil {
		// Log but don't fail the revocation — the cert is already revoked.
		slog.Error("auto-regenerating CRL after revocation", "error", err, "vault_id", vaultID)
	}

	w.WriteHeader(http.StatusNoContent)
}

// RenewCert handles POST /vaults/{vaultID}/pki/items/{itemID}/renew.
func (a *API) RenewCert(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	itemID := chi.URLParam(r, "itemID")
	creds := credentialsFromContext(r.Context())

	req, ok := decodeJSON[RenewCertAPIRequest](w, r, maxSmallBodySize)
	if !ok {
		return
	}
	if req.ValidityDays <= 0 {
		req.ValidityDays = 365
	}

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	if err := session.RequireAdmin(r.Context()); err != nil {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}

	newItemID, err := pki.RenewCertificate(r.Context(), session, itemID, req.ValidityDays, a.keyStore)
	if err != nil {
		switch {
		case errors.Is(err, pki.ErrNotCA):
			writeError(w, http.StatusBadRequest, "vault is not initialized as a CA")
		case errors.Is(err, pki.ErrCertNotFound):
			writeError(w, http.StatusNotFound, "certificate not found")
		case errors.Is(err, pki.ErrNotCertificateItem):
			writeError(w, http.StatusBadRequest, "item is not a certificate")
		default:
			writeInternalError(w, "failed to renew certificate", err)
		}
		return
	}

	// Read serial from new cert.
	newFields, _ := session.Get(r.Context(), newItemID)

	_ = a.appendAuditEntry(session, vaultID, newItemID, session.MemberID, auditActionCertRenewed)
	a.audit.logEvent(AuditCertRenewed, r, creds.SecretKey().ID(),
		slog.String("vault_id", vaultID),
		slog.String("old_item_id", itemID),
		slog.String("new_item_id", newItemID))

	writeJSON(w, http.StatusOK, RenewCertResponse{
		NewItemID:    newItemID,
		OldItemID:    itemID,
		SerialNumber: string(newFields[pki.FieldSerialNumber]),
	})
}

// GetCRL handles GET /vaults/{vaultID}/pki/crl.pem.
// GetCRL handles GET /vaults/{vaultID}/pki/crl.pem.
// It returns the most recently cached CRL without mutating CA state.
// A CRL is automatically generated during InitCA and after each
// GenerateCRL (POST) or RevokeCert, so a cached copy is always
// available for initialised CAs.
func (a *API) GetCRL(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	creds := credentialsFromContext(r.Context())

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	crlPEM, err := pki.LoadCRL(r.Context(), session)
	if err != nil {
		switch {
		case errors.Is(err, pki.ErrNotCA):
			writeError(w, http.StatusNotFound, "vault is not initialized as a CA")
		case errors.Is(err, pki.ErrNoCRL):
			writeError(w, http.StatusNotFound, "no CRL has been generated; POST to generate one first")
		default:
			writeInternalError(w, "failed to load CRL", err)
		}
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "attachment; filename=\"crl.pem\"")
	w.WriteHeader(http.StatusOK)
	w.Write(crlPEM)
}

// GenerateCRL handles POST /vaults/{vaultID}/pki/crl.
// It regenerates the CRL (incrementing CRLNumber), caches it, and returns
// the PEM-encoded result. This is a state-mutating operation protected by
// CSRF middleware.
func (a *API) GenerateCRL(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	creds := credentialsFromContext(r.Context())

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	crlPEM, err := pki.GenerateCRL(r.Context(), session, a.keyStore)
	if err != nil {
		if errors.Is(err, pki.ErrNotCA) {
			writeError(w, http.StatusNotFound, "vault is not initialized as a CA")
			return
		}
		writeInternalError(w, "failed to generate CRL", err)
		return
	}

	_ = a.appendAuditEntry(session, vaultID, "", session.MemberID, auditActionCRLGenerated)
	a.audit.logEvent(AuditCRLGenerated, r, creds.SecretKey().ID(),
		slog.String("vault_id", vaultID))

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "attachment; filename=\"crl.pem\"")
	w.WriteHeader(http.StatusOK)
	w.Write(crlPEM)
}

// SignCSR handles POST /vaults/{vaultID}/pki/sign-csr.
func (a *API) SignCSR(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	creds := credentialsFromContext(r.Context())

	req, ok := decodeJSON[SignCSRAPIRequest](w, r, maxSmallBodySize)
	if !ok {
		return
	}
	if req.CSR == "" {
		writeError(w, http.StatusBadRequest, "csr is required")
		return
	}
	if req.ValidityDays <= 0 {
		req.ValidityDays = 365
	}

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	if err := session.RequireAdmin(r.Context()); err != nil {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}

	extKeyUsages := parseExtKeyUsages(req.ExtKeyUsages)

	itemID, err := pki.SignCSR(r.Context(), session, req.CSR, req.ValidityDays, extKeyUsages, a.keyStore)
	if err != nil {
		if errors.Is(err, pki.ErrNotCA) {
			writeError(w, http.StatusBadRequest, "vault is not initialized as a CA")
			return
		}
		writeInternalError(w, "failed to sign CSR", err)
		return
	}

	// Read the issued cert PEM.
	fields, _ := session.Get(r.Context(), itemID)

	_ = a.appendAuditEntry(session, vaultID, itemID, session.MemberID, auditActionCSRSigned)
	a.audit.logEvent(AuditCSRSigned, r, creds.SecretKey().ID(),
		slog.String("vault_id", vaultID),
		slog.String("item_id", itemID))

	writeJSON(w, http.StatusCreated, SignCSRResponse{
		ItemID:       itemID,
		SerialNumber: string(fields[pki.FieldSerialNumber]),
		Certificate:  string(fields[pki.FieldCertificate]),
	})
}
