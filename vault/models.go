// Package vault provides a secure encrypted vault with member-based access control,
// epoch-based key rotation, and rollback detection.
package vault

import (
	"time"

	icrypto "github.com/jmcleod/ironhand/internal/crypto"
	"github.com/jmcleod/ironhand/internal/util"
)

// Argon2idParams configures Argon2id key derivation.
type Argon2idParams = util.Argon2idParams

// vaultState holds the persistent metadata for a vault.
type vaultState struct {
	VaultID    string         `json:"vault_id,omitzero"`
	Epoch      uint64         `json:"epoch,omitzero"`
	KDFParams  Argon2idParams `json:"kdf_params,omitzero"`
	SaltPass   []byte         `json:"salt_pass,omitzero"`
	SaltSecret []byte         `json:"salt_secret,omitzero"`
	CreatedAt  time.Time      `json:"created_at,omitzero"`
	Ver        int            `json:"ver,omitzero"`
}

// newVaultState creates a new vaultState with the given vaultID and options.
func newVaultState(vaultID string, opts ...VaultStateOption) *vaultState {
	s := &vaultState{
		VaultID:   vaultID,
		Epoch:     1,
		KDFParams: util.DefaultArgon2idParams(),
		CreatedAt: time.Now(),
		Ver:       1,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// MemberRole defines the access level of a vault member.
type MemberRole string

const (
	RoleOwner  MemberRole = "owner"
	RoleWriter MemberRole = "writer"
	RoleReader MemberRole = "reader"
)

// MemberStatus represents the current status of a vault member.
type MemberStatus string

const (
	StatusActive  MemberStatus = "active"
	StatusRevoked MemberStatus = "revoked"
)

// Member represents a vault member with their public key and access metadata.
type Member struct {
	MemberID     string       `json:"member_id,omitzero"`
	PubKey       [32]byte     `json:"pub_key,omitzero"`
	Role         MemberRole   `json:"role,omitzero"`
	Status       MemberStatus `json:"status,omitzero"`
	AddedEpoch   uint64       `json:"added_epoch,omitzero"`
	RevokedEpoch uint64       `json:"revoked_epoch,omitzero"`
}

// memberKEKWrap holds a KEK wrapped (sealed) to a specific member at a given epoch.
type memberKEKWrap struct {
	Epoch    uint64             `json:"epoch"`
	MemberID string             `json:"member_id"`
	Wrap     icrypto.SealedWrap `json:"wrap"`
}

// Fields is a map of field name to plaintext value.
type Fields map[string][]byte

// field represents a single encrypted field within an item.
type field struct {
	Ciphertext []byte `json:"ciphertext,omitzero"`
}

// item represents an encrypted item stored in the vault.
// An item is a container for named fields, all encrypted with the same DEK.
type item struct {
	ItemID       string           `json:"item_id,omitzero"`
	ItemVersion  uint64           `json:"item_version,omitzero"`
	Fields       map[string]field `json:"fields,omitzero"`
	WrappedDEK   []byte           `json:"wrapped_dek,omitzero"`
	WrappedEpoch uint64           `json:"wrapped_epoch,omitzero"`
	UpdatedBy    string           `json:"updated_by,omitzero"`
}

// itemHistory represents an encrypted snapshot of an item at a previous version.
type itemHistory struct {
	ItemID       string           `json:"item_id,omitzero"`
	Version      uint64           `json:"version,omitzero"`
	Fields       map[string]field `json:"fields,omitzero"`
	WrappedDEK   []byte           `json:"wrapped_dek,omitzero"`
	WrappedEpoch uint64           `json:"wrapped_epoch,omitzero"`
	UpdatedBy    string           `json:"updated_by,omitzero"`
	UpdatedAt    string           `json:"updated_at,omitzero"`
}

// HistoryEntry is a summary of a single history version (returned by GetHistory).
type HistoryEntry struct {
	Version   uint64
	UpdatedAt string
	UpdatedBy string
}

// Validation constants.
const (
	MaxIDLength        = 256
	MaxFieldNameLength = 128
	MaxFieldCount      = 64
	MaxFieldSize       = 1 << 20 // 1MB per field
	MaxHistoryVersions = 100
)

// Record types for storage
const (
	recordTypeState       = "STATE"
	recordTypeMember      = "MEMBER"
	recordTypeKEKWrap     = "KEKWRAP"
	recordTypeItem        = "ITEM"
	recordTypeItemHistory = "ITEM_HISTORY"
)

// Special record IDs
const (
	recordIDCurrent = "current"
)
