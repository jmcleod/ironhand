package util

import (
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Argon2idParams configures the Argon2id key derivation function.
// Parameters are stored alongside vault state so that existing vaults
// keep working when defaults are raised.
type Argon2idParams struct {
	Time        uint32 `json:"time"`
	MemoryKiB   uint32 `json:"memory"`
	Parallelism uint8  `json:"parallelism"`
	KeyLen      uint32 `json:"key_len"`
}

// Minimum acceptable Argon2id parameters. Any profile or custom
// configuration must meet or exceed these to prevent dangerously weak KDF
// settings. Values are based on OWASP Password Storage Cheat Sheet
// recommendations for Argon2id.
const (
	MinArgon2Time      uint32 = 1
	MinArgon2MemoryKiB uint32 = 19 * 1024 // 19 MiB — OWASP minimum recommendation
	MinArgon2Parallel  uint8  = 1
)

// Named KDF profiles for different deployment scenarios.
// Profiles are ordered from lowest to highest cost.
const (
	// KDFProfileInteractive targets sub-second derivation on modest hardware.
	// Suitable for development, testing, and high-throughput API servers.
	// OWASP: meets minimum recommendation (Argon2id t=2, m=19MiB).
	KDFProfileInteractive = "interactive"

	// KDFProfileModerate is the production default. Balances security and
	// latency for typical web-application deployments.
	// OWASP: exceeds minimum recommendation (Argon2id t=3, m=64MiB).
	KDFProfileModerate = "moderate"

	// KDFProfileSensitive targets higher-value secrets where multi-second
	// derivation is acceptable. Suitable for CA root keys, backup encryption,
	// and credential export.
	// OWASP: well above minimum recommendation (Argon2id t=4, m=128MiB).
	KDFProfileSensitive = "sensitive"
)

// Argon2idProfile returns the Argon2idParams for a named profile.
// Returns an error for unknown profile names.
func Argon2idProfile(name string) (Argon2idParams, error) {
	switch name {
	case KDFProfileInteractive:
		return Argon2idParams{
			Time:        2,
			MemoryKiB:   19 * 1024,
			Parallelism: 4,
			KeyLen:      32,
		}, nil
	case KDFProfileModerate:
		return Argon2idParams{
			Time:        3,
			MemoryKiB:   64 * 1024,
			Parallelism: 4,
			KeyLen:      32,
		}, nil
	case KDFProfileSensitive:
		return Argon2idParams{
			Time:        4,
			MemoryKiB:   128 * 1024,
			Parallelism: 4,
			KeyLen:      32,
		}, nil
	default:
		return Argon2idParams{}, fmt.Errorf("unknown KDF profile %q (valid: interactive, moderate, sensitive)", name)
	}
}

// DefaultArgon2idParams returns the default Argon2id parameters for vault
// operations. This uses the "moderate" profile: Time=3, Memory=64 MiB,
// Parallelism=4 — aligned with OWASP Password Storage Cheat Sheet guidance
// for Argon2id.
//
// Existing vaults are NOT affected by changes to this default because KDF
// parameters are persisted in vault state at creation time. Only newly
// created vaults use the current default.
func DefaultArgon2idParams() Argon2idParams {
	p, _ := Argon2idProfile(KDFProfileModerate)
	return p
}

// ValidateArgon2idParams checks that the given parameters meet the minimum
// acceptable thresholds. Returns an error describing which parameter is too
// low. This prevents operators from accidentally configuring dangerously
// weak KDF settings.
func ValidateArgon2idParams(p Argon2idParams) error {
	if p.KeyLen != 32 {
		return fmt.Errorf("argon2id key length must be 32 bytes, got %d", p.KeyLen)
	}
	if p.Time < MinArgon2Time {
		return fmt.Errorf("argon2id time parameter %d is below minimum %d", p.Time, MinArgon2Time)
	}
	if p.MemoryKiB < MinArgon2MemoryKiB {
		return fmt.Errorf("argon2id memory parameter %d KiB is below minimum %d KiB (%d MiB)", p.MemoryKiB, MinArgon2MemoryKiB, MinArgon2MemoryKiB/1024)
	}
	if p.Parallelism < MinArgon2Parallel {
		return fmt.Errorf("argon2id parallelism parameter %d is below minimum %d", p.Parallelism, MinArgon2Parallel)
	}
	return nil
}

// DeriveArgon2idKey derives a 32-byte key from a passphrase using Argon2id.
func DeriveArgon2idKey(passphrase string, salt []byte, params Argon2idParams) ([]byte, error) {
	if params.KeyLen != 32 {
		return nil, fmt.Errorf("argon2id key length must be 32 bytes")
	}
	key := argon2.IDKey([]byte(passphrase), salt, params.Time, params.MemoryKiB, params.Parallelism, params.KeyLen)
	return key, nil
}

// CompareArgon2idKey derives a key and compares it in constant time to the expected key.
func CompareArgon2idKey(passphrase string, salt []byte, params Argon2idParams, expectedKey []byte) (bool, error) {
	key, err := DeriveArgon2idKey(passphrase, salt, params)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(key, expectedKey) == 1, nil
}
