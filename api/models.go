package api

// CreateVaultRequest is the JSON body for POST /vaults.
type CreateVaultRequest struct {
	VaultID          string `json:"vault_id"`
	Passphrase       string `json:"passphrase"`
	ExportPassphrase string `json:"export_passphrase"`
}

// CreateVaultResponse is returned from POST /vaults.
type CreateVaultResponse struct {
	VaultID     string `json:"vault_id"`
	MemberID    string `json:"member_id"`
	SecretKey   string `json:"secret_key"`
	Credentials string `json:"credentials"`
	Epoch       uint64 `json:"epoch"`
}

// OpenVaultResponse is returned from POST /vaults/{vaultID}/open.
type OpenVaultResponse struct {
	VaultID  string `json:"vault_id"`
	MemberID string `json:"member_id"`
	Epoch    uint64 `json:"epoch"`
}

// ListItemsResponse is returned from GET /vaults/{vaultID}/items.
type ListItemsResponse struct {
	Items []string `json:"items"`
}

// PutItemRequest is the JSON body for POST /vaults/{vaultID}/items/{itemID}.
type PutItemRequest struct {
	Data        string `json:"data"`
	ContentType string `json:"content_type,omitempty"`
}

// GetItemResponse is returned from GET /vaults/{vaultID}/items/{itemID}.
type GetItemResponse struct {
	ItemID string `json:"item_id"`
	Data   string `json:"data"`
}

// UpdateItemRequest is the JSON body for PUT /vaults/{vaultID}/items/{itemID}.
type UpdateItemRequest struct {
	Data        string `json:"data"`
	ContentType string `json:"content_type,omitempty"`
}

// AddMemberRequest is the JSON body for POST /vaults/{vaultID}/members.
type AddMemberRequest struct {
	MemberID string `json:"member_id"`
	PubKey   string `json:"pub_key"`
	Role     string `json:"role"`
}

// AddMemberResponse is returned from POST /vaults/{vaultID}/members.
type AddMemberResponse struct {
	Epoch uint64 `json:"epoch"`
}

// ErrorResponse is returned for all error cases.
type ErrorResponse struct {
	Error string `json:"error"`
}
