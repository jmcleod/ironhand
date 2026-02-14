package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/jmcleod/ironhand/internal/uuid"
	"github.com/jmcleod/ironhand/vault"
)

// CreateVault handles POST /vaults.
// Creates a new vault for the authenticated account and returns the generated vault ID.
func (a *API) CreateVault(w http.ResponseWriter, r *http.Request) {
	creds := credentialsFromContext(r.Context())
	if creds == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req CreateVaultRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
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
		metaPayload, err := encodeVaultMetadata(strings.TrimSpace(req.Name), strings.TrimSpace(req.Description))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to encode vault metadata: "+err.Error())
			return
		}
		if err := session.Put(r.Context(), vaultMetadataItemID, metaPayload, vault.WithContentType(vaultMetadataContentType)); err != nil {
			mapError(w, err)
			return
		}
	}

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
		if itemID == vaultMetadataItemID {
			continue
		}
		filtered = append(filtered, itemID)
	}
	items = filtered

	if items == nil {
		items = []string{}
	}

	writeJSON(w, http.StatusOK, ListItemsResponse{Items: items})
}

// PutItem handles POST /vaults/{vaultID}/items/{itemID}.
func (a *API) PutItem(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	itemID := chi.URLParam(r, "itemID")
	if itemID == vaultMetadataItemID {
		writeError(w, http.StatusBadRequest, "item_id is reserved")
		return
	}
	creds := credentialsFromContext(r.Context())

	var req PutItemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 data: "+err.Error())
		return
	}

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	var opts []vault.PutOption
	if req.ContentType != "" {
		opts = append(opts, vault.WithContentType(req.ContentType))
	}

	if err := session.Put(r.Context(), itemID, data, opts...); err != nil {
		mapError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, struct{}{})
}

// GetItem handles GET /vaults/{vaultID}/items/{itemID}.
func (a *API) GetItem(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	itemID := chi.URLParam(r, "itemID")
	if itemID == vaultMetadataItemID {
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

	plaintext, err := session.Get(r.Context(), itemID)
	if err != nil {
		mapError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, GetItemResponse{
		ItemID: itemID,
		Data:   base64.StdEncoding.EncodeToString(plaintext),
	})
}

// UpdateItem handles PUT /vaults/{vaultID}/items/{itemID}.
func (a *API) UpdateItem(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	itemID := chi.URLParam(r, "itemID")
	if itemID == vaultMetadataItemID {
		writeError(w, http.StatusBadRequest, "item_id is reserved")
		return
	}
	creds := credentialsFromContext(r.Context())

	var req UpdateItemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 data: "+err.Error())
		return
	}

	session, err := a.openSession(r.Context(), vaultID, creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	var opts []vault.PutOption
	if req.ContentType != "" {
		opts = append(opts, vault.WithContentType(req.ContentType))
	}

	if err := session.Update(r.Context(), itemID, data, opts...); err != nil {
		mapError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, struct{}{})
}

// DeleteItem handles DELETE /vaults/{vaultID}/items/{itemID}.
func (a *API) DeleteItem(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	itemID := chi.URLParam(r, "itemID")
	if itemID == vaultMetadataItemID {
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

	writeJSON(w, http.StatusOK, struct{}{})
}

// ListVaults handles GET /vaults.
func (a *API) ListVaults(w http.ResponseWriter, r *http.Request) {
	creds := credentialsFromContext(r.Context())
	vaultIDs, err := a.repo.ListVaults()
	if err != nil {
		mapError(w, err)
		return
	}

	result := make([]VaultSummary, 0, len(vaultIDs))
	for _, vaultID := range vaultIDs {
		if strings.HasPrefix(vaultID, "__") {
			continue
		}
		session, err := a.openSession(r.Context(), vaultID, creds)
		if err != nil {
			// For list operations, skip vaults that cannot be opened with the
			// current credentials/profile and continue with others.
			continue
		}

		meta := vaultMetadata{}
		metaBytes, err := session.Get(r.Context(), vaultMetadataItemID)
		if err == nil {
			if decoded, decodeErr := decodeVaultMetadata(metaBytes); decodeErr == nil {
				meta = decoded
			}
		}
		itemIDs, err := session.List(r.Context())
		if err != nil {
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
			Epoch:       session.Epoch(),
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
	writeJSON(w, http.StatusOK, struct{}{})
}

// AddMember handles POST /vaults/{vaultID}/members.
func (a *API) AddMember(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	creds := credentialsFromContext(r.Context())

	var req AddMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
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
		writeError(w, http.StatusBadRequest, "invalid base64 pub_key: "+err.Error())
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

	writeJSON(w, http.StatusOK, AddMemberResponse{
		Epoch: session.Epoch(),
	})
}
