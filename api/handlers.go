package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/jmcleod/ironhand/vault"
)

// CreateVault handles POST /vaults.
// Generates new credentials, creates the vault, and returns the export blob.
func (a *API) CreateVault(w http.ResponseWriter, r *http.Request) {
	var req CreateVaultRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	if req.VaultID == "" {
		writeError(w, http.StatusBadRequest, "vault_id is required")
		return
	}
	if req.Passphrase == "" {
		writeError(w, http.StatusBadRequest, "passphrase is required")
		return
	}
	if req.ExportPassphrase == "" {
		writeError(w, http.StatusBadRequest, "export_passphrase is required")
		return
	}

	creds, err := vault.NewCredentials(req.Passphrase)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create credentials: "+err.Error())
		return
	}
	defer creds.Destroy()

	v := vault.New(req.VaultID, a.repo, vault.WithEpochCache(a.epochCache))
	session, err := v.Create(r.Context(), creds)
	if err != nil {
		mapError(w, err)
		return
	}
	defer session.Close()

	exported, err := vault.ExportCredentials(creds, req.ExportPassphrase)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to export credentials: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, CreateVaultResponse{
		VaultID:     req.VaultID,
		MemberID:    creds.MemberID(),
		SecretKey:   creds.SecretKey().String(),
		Credentials: base64.StdEncoding.EncodeToString(exported),
		Epoch:       session.Epoch(),
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

	if items == nil {
		items = []string{}
	}

	writeJSON(w, http.StatusOK, ListItemsResponse{Items: items})
}

// PutItem handles POST /vaults/{vaultID}/items/{itemID}.
func (a *API) PutItem(w http.ResponseWriter, r *http.Request) {
	vaultID := chi.URLParam(r, "vaultID")
	itemID := chi.URLParam(r, "itemID")
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
