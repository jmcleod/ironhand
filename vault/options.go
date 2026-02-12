package vault

import "time"

// VaultOption configures a Vault.
type VaultOption func(*Vault)

// WithEpochCache sets the epoch cache for the vault.
func WithEpochCache(cache EpochCache) VaultOption {
	return func(v *Vault) {
		v.epochCache = cache
	}
}

// VaultStateOption is a functional option for vault state configuration.
type VaultStateOption func(*vaultState)

// CreateOption configures vault creation.
type CreateOption = VaultStateOption

// WithEpoch sets the epoch for the vault state.
func WithEpoch(epoch uint64) VaultStateOption {
	return func(s *vaultState) {
		s.Epoch = epoch
	}
}

// WithKDFParams sets the KDF parameters for the vault state.
func WithKDFParams(params Argon2idParams) VaultStateOption {
	return func(s *vaultState) {
		s.KDFParams = params
	}
}

// WithCreatedAt sets the creation time for the vault state.
func WithCreatedAt(createdAt time.Time) VaultStateOption {
	return func(s *vaultState) {
		s.CreatedAt = createdAt
	}
}

// WithVer sets the version for the vault state.
func WithVer(ver int) VaultStateOption {
	return func(s *vaultState) {
		s.Ver = ver
	}
}

// PutOption configures item storage.
type PutOption func(*putOptions)

type putOptions struct {
	contentType string
}

// WithContentType sets the content type for an item.
// Default: "application/octet-stream".
func WithContentType(ct string) PutOption {
	return func(o *putOptions) {
		o.contentType = ct
	}
}
