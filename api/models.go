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
	TOTPCode   string `json:"totp_code,omitempty"`
}

// SetupTwoFactorResponse is returned from POST /auth/2fa/setup.
type SetupTwoFactorResponse struct {
	Secret     string `json:"secret"`
	OtpauthURL string `json:"otpauth_url"`
	ExpiresAt  string `json:"expires_at"`
}

// EnableTwoFactorRequest is the JSON body for POST /auth/2fa/enable.
type EnableTwoFactorRequest struct {
	Code string `json:"code"`
}

// TwoFactorStatusResponse is returned from GET /auth/2fa and POST /auth/2fa/enable.
type TwoFactorStatusResponse struct {
	Enabled bool `json:"enabled"`
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

// HistoryEntryResponse represents a single version in an item's history.
type HistoryEntryResponse struct {
	Version   uint64 `json:"version"`
	UpdatedAt string `json:"updated_at"`
	UpdatedBy string `json:"updated_by"`
}

// GetItemHistoryResponse is returned from GET /vaults/{vaultID}/items/{itemID}/history.
type GetItemHistoryResponse struct {
	ItemID  string                 `json:"item_id"`
	History []HistoryEntryResponse `json:"history"`
}

// GetHistoryVersionResponse is returned from GET /vaults/{vaultID}/items/{itemID}/history/{version}.
type GetHistoryVersionResponse struct {
	ItemID  string            `json:"item_id"`
	Version uint64            `json:"version"`
	Fields  map[string]string `json:"fields"`
}

// AuditEntryResponse is one vault audit log entry.
type AuditEntryResponse struct {
	ID        string `json:"id"`
	ItemID    string `json:"item_id"`
	Action    string `json:"action"`
	MemberID  string `json:"member_id"`
	CreatedAt string `json:"created_at"`
}

// ListAuditLogsResponse is returned from GET /vaults/{vaultID}/audit.
type ListAuditLogsResponse struct {
	Entries []AuditEntryResponse `json:"entries"`
}

// ErrorResponse is returned for all error cases.
type ErrorResponse struct {
	Error string `json:"error"`
}
