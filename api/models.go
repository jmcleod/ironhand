package api

// CreateVaultRequest is the JSON body for POST /vaults.
type CreateVaultRequest struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// CreateVaultResponse is returned from POST /vaults.
type CreateVaultResponse struct {
	VaultID  string `json:"vault_id"`
	MemberID string `json:"member_id"`
	Epoch    uint64 `json:"epoch"`
}

// RegisterRequest is the JSON body for POST /auth/register.
type RegisterRequest struct {
	Passphrase string `json:"passphrase"`
}

// RegisterResponse is returned from POST /auth/register.
type RegisterResponse struct {
	SecretKey string `json:"secret_key"`
}

// LoginRequest is the JSON body for POST /auth/login.
type LoginRequest struct {
	Passphrase string `json:"passphrase"`
	SecretKey  string `json:"secret_key"`
}

// OpenVaultResponse is returned from POST /vaults/{vaultID}/open.
type OpenVaultResponse struct {
	VaultID  string `json:"vault_id"`
	MemberID string `json:"member_id"`
	Epoch    uint64 `json:"epoch"`
}

// VaultSummary describes a vault visible to the current authenticated member.
type VaultSummary struct {
	VaultID     string `json:"vault_id"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Epoch       uint64 `json:"epoch"`
	ItemCount   int    `json:"item_count"`
}

// ListVaultsResponse is returned from GET /vaults.
type ListVaultsResponse struct {
	Vaults []VaultSummary `json:"vaults"`
}

// ListItemsResponse is returned from GET /vaults/{vaultID}/items.
type ListItemsResponse struct {
	Items []string `json:"items"`
}

// PutItemRequest is the JSON body for POST /vaults/{vaultID}/items/{itemID}.
type PutItemRequest struct {
	Fields map[string]string `json:"fields"`
}

// GetItemResponse is returned from GET /vaults/{vaultID}/items/{itemID}.
type GetItemResponse struct {
	ItemID string            `json:"item_id"`
	Fields map[string]string `json:"fields"`
}

// UpdateItemRequest is the JSON body for PUT /vaults/{vaultID}/items/{itemID}.
type UpdateItemRequest struct {
	Fields map[string]string `json:"fields"`
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

// RevealSecretKeyRequest is the JSON body for POST /auth/reveal-secret-key.
type RevealSecretKeyRequest struct {
	Passphrase string `json:"passphrase"`
}

// RevealSecretKeyResponse is returned from POST /auth/reveal-secret-key.
type RevealSecretKeyResponse struct {
	SecretKey string `json:"secret_key"`
}

// ErrorResponse is returned for all error cases.
type ErrorResponse struct {
	Error string `json:"error"`
}
