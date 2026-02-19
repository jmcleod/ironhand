//go:build pkcs11

package pki

import (
	"crypto"
	"crypto/elliptic"
	"fmt"
	"strings"
	"sync"

	"github.com/ThalesGroup/crypto11"

	"github.com/jmcleod/ironhand/internal/uuid"
)

// PKCS11Prefix is the string prefix stored in vault fields to identify
// PKCS#11-managed keys. The full reference is "PKCS11:<label>".
const PKCS11Prefix = "PKCS11:"

// PKCS11Config holds the configuration for connecting to a PKCS#11 token.
type PKCS11Config struct {
	// ModulePath is the path to the PKCS#11 shared library
	// (e.g., /usr/lib/softhsm/libsofthsm2.so).
	ModulePath string

	// TokenLabel identifies the HSM token/slot by label.
	TokenLabel string

	// PIN is the user PIN for the token.
	PIN string

	// SlotNumber optionally specifies a slot number. When non-nil,
	// it overrides TokenLabel for slot selection.
	SlotNumber *int
}

// PKCS11KeyStore holds ECDSA P-256 private keys in a PKCS#11 HSM.
// Keys are identified by a label stored in the HSM and referenced
// via a "PKCS11:<label>" string stored in the vault.
type PKCS11KeyStore struct {
	ctx *crypto11.Context
	mu  sync.Mutex
}

// Compile-time interface check.
var _ KeyStore = (*PKCS11KeyStore)(nil)

// NewPKCS11KeyStore creates a new PKCS11KeyStore connected to the
// configured HSM token. The caller must call Close() when finished.
func NewPKCS11KeyStore(cfg PKCS11Config) (*PKCS11KeyStore, error) {
	config := &crypto11.Config{
		Path:       cfg.ModulePath,
		TokenLabel: cfg.TokenLabel,
		Pin:        cfg.PIN,
	}
	if cfg.SlotNumber != nil {
		config.SlotNumber = cfg.SlotNumber
	}

	ctx, err := crypto11.Configure(config)
	if err != nil {
		return nil, fmt.Errorf("configuring PKCS#11: %w", err)
	}

	return &PKCS11KeyStore{ctx: ctx}, nil
}

// Close releases the PKCS#11 context and cleans up resources.
func (p *PKCS11KeyStore) Close() error {
	if p.ctx != nil {
		return p.ctx.Close()
	}
	return nil
}

// GenerateKey creates a new ECDSA P-256 key pair in the HSM with
// a UUID-based label. Returns a key ID of the form "pkcs11-<label>".
func (p *PKCS11KeyStore) GenerateKey() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	label := "ironhand-" + uuid.New()
	labelBytes := []byte(label)

	_, err := p.ctx.GenerateECDSAKeyPairWithLabel(labelBytes, labelBytes, elliptic.P256())
	if err != nil {
		return "", fmt.Errorf("generating ECDSA P-256 key in HSM: %w", err)
	}

	return "pkcs11-" + label, nil
}

// Signer returns a crypto.Signer backed by the HSM for the given key ID.
func (p *PKCS11KeyStore) Signer(keyID string) (crypto.Signer, error) {
	label := labelFromKeyID(keyID)

	signer, err := p.ctx.FindKeyPair(nil, []byte(label))
	if err != nil {
		return nil, fmt.Errorf("%w: %s (HSM: %v)", ErrKeyNotFound, keyID, err)
	}
	if signer == nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
	}
	return signer, nil
}

// ExportPEM returns a PKCS#11 reference string of the form "PKCS11:<label>".
// This is stored in the vault's private_key field so that ImportPEM can
// later recover the HSM key by label. The actual private key material
// never leaves the HSM.
func (p *PKCS11KeyStore) ExportPEM(keyID string) (string, error) {
	label := labelFromKeyID(keyID)

	// Verify the key exists in the HSM.
	signer, err := p.ctx.FindKeyPair(nil, []byte(label))
	if err != nil {
		return "", fmt.Errorf("verifying key in HSM: %w", err)
	}
	if signer == nil {
		return "", fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
	}

	return PKCS11Prefix + label, nil
}

// ImportPEM handles three cases:
//   - A PKCS#11 reference string (starts with "PKCS11:") — looks up
//     the key by label in the HSM and returns a key ID.
//   - "HSM-MANAGED" sentinel — returns an error since we cannot
//     determine which key to use without a label.
//   - Actual PEM data — returns ErrKeyNotExportable since software
//     keys cannot be imported into a PKCS#11 store.
func (p *PKCS11KeyStore) ImportPEM(pemData string) (string, error) {
	if strings.HasPrefix(pemData, PKCS11Prefix) {
		label := strings.TrimPrefix(pemData, PKCS11Prefix)

		// Verify the key exists in the HSM.
		signer, err := p.ctx.FindKeyPair(nil, []byte(label))
		if err != nil {
			return "", fmt.Errorf("finding key in HSM: %w", err)
		}
		if signer == nil {
			return "", fmt.Errorf("%w: PKCS#11 label %q", ErrKeyNotFound, label)
		}

		return "pkcs11-" + label, nil
	}

	if pemData == "HSM-MANAGED" {
		return "", fmt.Errorf("HSM-MANAGED sentinel without PKCS#11 label; CA was initialized with a different keystore")
	}

	return "", fmt.Errorf("%w: cannot import software PEM keys into PKCS#11 store", ErrKeyNotExportable)
}

// Delete removes the key pair from the HSM.
func (p *PKCS11KeyStore) Delete(keyID string) error {
	label := labelFromKeyID(keyID)

	signer, err := p.ctx.FindKeyPair(nil, []byte(label))
	if err != nil {
		return fmt.Errorf("finding key for deletion: %w", err)
	}
	if signer == nil {
		return nil // Already gone.
	}

	// crypto11.Signer exposes Delete() for key destruction.
	if d, ok := signer.(interface{ Delete() error }); ok {
		return d.Delete()
	}
	return nil
}

// labelFromKeyID extracts the HSM label from a key ID.
// Key IDs are "pkcs11-<label>"; the label is "ironhand-<uuid>".
func labelFromKeyID(keyID string) string {
	return strings.TrimPrefix(keyID, "pkcs11-")
}
