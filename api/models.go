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
	Items []ItemSummary `json:"items"`
}

// ItemSummary is returned in vault item listings.
type ItemSummary struct {
	ItemID string `json:"item_id"`
	Name   string `json:"name,omitempty"`
	Type   string `json:"type,omitempty"`
}

// PutItemRequest is the JSON body for POST /vaults/{vaultID}/items/{itemID}.
//
// Attachments are stored as fields with special prefixes:
//   - "_att.<filename>": base64-encoded binary content (max 768 KiB decoded)
//   - "_attmeta.<filename>": JSON metadata string (content_type, size)
//
// Each attachment consumes two fields toward the MaxFieldCount limit.
type PutItemRequest struct {
	Fields map[string]string `json:"fields"`
}

// GetItemResponse is returned from GET /vaults/{vaultID}/items/{itemID}.
// Attachment content fields ("_att.*") are base64-encoded; all other fields are plain strings.
type GetItemResponse struct {
	ItemID string            `json:"item_id"`
	Fields map[string]string `json:"fields"`
}

// UpdateItemRequest is the JSON body for PUT /vaults/{vaultID}/items/{itemID}.
// See [PutItemRequest] for attachment field conventions.
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

// ExportVaultRequest is the JSON body for POST /vaults/{vaultID}/export.
type ExportVaultRequest struct {
	Passphrase string `json:"passphrase"`
}

// ImportVaultResponse is returned from POST /vaults/{vaultID}/import.
type ImportVaultResponse struct {
	ImportedCount int `json:"imported_count"`
}

// vaultExportPayload is the JSON structure inside the encrypted export blob.
type vaultExportPayload struct {
	FormatVersion int               `json:"format_version"`
	VaultName     string            `json:"vault_name"`
	VaultDesc     string            `json:"vault_description"`
	ExportedAt    string            `json:"exported_at"`
	Items         []vaultExportItem `json:"items"`
}

// vaultExportItem is a single item in the export payload.
type vaultExportItem struct {
	Fields map[string]string `json:"fields"`
}

// ---------------------------------------------------------------------------
// PKI / Certificate Authority
// ---------------------------------------------------------------------------

// InitCARequest is the JSON body for POST /vaults/{vaultID}/pki/init.
type InitCARequest struct {
	CommonName     string `json:"common_name"`
	Organization   string `json:"organization,omitempty"`
	OrgUnit        string `json:"org_unit,omitempty"`
	Country        string `json:"country,omitempty"`
	Province       string `json:"province,omitempty"`
	Locality       string `json:"locality,omitempty"`
	ValidityYears  int    `json:"validity_years"`
	IsIntermediate bool   `json:"is_intermediate"`
}

// InitCAResponse is returned from POST /vaults/{vaultID}/pki/init.
type InitCAResponse struct {
	Subject string `json:"subject"`
}

// CAInfoResponse is returned from GET /vaults/{vaultID}/pki/info.
type CAInfoResponse struct {
	IsCA           bool   `json:"is_ca"`
	IsIntermediate bool   `json:"is_intermediate"`
	Subject        string `json:"subject"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	NextSerial     int64  `json:"next_serial"`
	CRLNumber      int64  `json:"crl_number"`
	CertCount      int    `json:"cert_count"`
}

// IssueCertAPIRequest is the JSON body for POST /vaults/{vaultID}/pki/issue.
type IssueCertAPIRequest struct {
	CommonName     string   `json:"common_name"`
	Organization   string   `json:"organization,omitempty"`
	OrgUnit        string   `json:"org_unit,omitempty"`
	Country        string   `json:"country,omitempty"`
	ValidityDays   int      `json:"validity_days"`
	KeyUsages      []string `json:"key_usages,omitempty"`
	ExtKeyUsages   []string `json:"ext_key_usages,omitempty"`
	DNSNames       []string `json:"dns_names,omitempty"`
	IPAddresses    []string `json:"ip_addresses,omitempty"`
	EmailAddresses []string `json:"email_addresses,omitempty"`
}

// IssueCertResponse is returned from POST /vaults/{vaultID}/pki/issue.
type IssueCertResponse struct {
	ItemID       string `json:"item_id"`
	SerialNumber string `json:"serial_number"`
	Subject      string `json:"subject"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
}

// RevokeCertAPIRequest is the JSON body for POST /vaults/{vaultID}/pki/items/{itemID}/revoke.
type RevokeCertAPIRequest struct {
	Reason string `json:"reason,omitempty"`
}

// RenewCertAPIRequest is the JSON body for POST /vaults/{vaultID}/pki/items/{itemID}/renew.
type RenewCertAPIRequest struct {
	ValidityDays int `json:"validity_days"`
}

// RenewCertResponse is returned from POST /vaults/{vaultID}/pki/items/{itemID}/renew.
type RenewCertResponse struct {
	NewItemID    string `json:"new_item_id"`
	OldItemID    string `json:"old_item_id"`
	SerialNumber string `json:"serial_number"`
}

// SignCSRAPIRequest is the JSON body for POST /vaults/{vaultID}/pki/sign-csr.
type SignCSRAPIRequest struct {
	CSR          string   `json:"csr"`
	ValidityDays int      `json:"validity_days"`
	ExtKeyUsages []string `json:"ext_key_usages,omitempty"`
}

// SignCSRResponse is returned from POST /vaults/{vaultID}/pki/sign-csr.
type SignCSRResponse struct {
	ItemID       string `json:"item_id"`
	SerialNumber string `json:"serial_number"`
	Certificate  string `json:"certificate"`
}
