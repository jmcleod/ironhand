package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
)

// KeyStore abstracts private-key operations so that the PKI subsystem can
// work with software keys stored in the vault, HSM-backed keys, or
// cloud KMS keys without changing calling code.
//
// Each KeyStore implementation is responsible for generating, storing, and
// signing with private keys. A KeyID uniquely identifies a key managed by
// the store; its format is implementation-defined (e.g. a vault item ID,
// an HSM slot reference, or a KMS key ARN).
type KeyStore interface {
	// GenerateKey creates a new signing key and returns an opaque identifier.
	// The caller must not assume anything about the key material — for HSM/KMS
	// backends the private key never leaves the hardware.
	GenerateKey() (keyID string, err error)

	// Signer returns a [crypto.Signer] for the key identified by keyID.
	// The returned Signer is used by x509.CreateCertificate and
	// x509.CreateRevocationList, which only need the Sign method and
	// Public() for embedding the public key in certificates.
	//
	// For software keys this wraps the *ecdsa.PrivateKey; for HSM/KMS
	// implementations it delegates signing to the external device.
	Signer(keyID string) (crypto.Signer, error)

	// ExportPEM returns the private key in PEM-encoded PKCS8 or SEC1 format.
	// HSM/KMS implementations may return ErrKeyNotExportable.
	ExportPEM(keyID string) (string, error)

	// ImportPEM loads a PEM-encoded private key into the store and returns
	// its key ID. This is used when reading existing keys from vault storage.
	// HSM/KMS implementations may return ErrKeyNotExportable.
	ImportPEM(pemData string) (keyID string, err error)

	// Delete removes the key identified by keyID from the store.
	// For software stores this is a no-op (vault manages lifecycle).
	// For HSM/KMS this might schedule key destruction.
	Delete(keyID string) error
}

// ErrKeyNotExportable is returned by KeyStore.ExportPEM when the backing
// store does not allow private key material to leave the device (e.g. HSM).
var ErrKeyNotExportable = fmt.Errorf("private key is not exportable")

// ErrKeyNotFound is returned when the referenced key ID does not exist.
var ErrKeyNotFound = fmt.Errorf("key not found")

// ---------------------------------------------------------------------------
// SoftwareKeyStore — default implementation backed by in-memory ECDSA keys
// ---------------------------------------------------------------------------

// SoftwareKeyStore holds ECDSA P-256 private keys in memory. Keys are
// identified by an opaque string generated at creation time. This is the
// default KeyStore used when no HSM/KMS is configured.
//
// Keys in this store are ephemeral — the caller (typically the PKI layer)
// is responsible for persisting them in the vault via ExportPEM/ImportPEM.
type SoftwareKeyStore struct {
	keys map[string]*ecdsa.PrivateKey
	rand io.Reader // defaults to crypto/rand.Reader
	seq  int       // monotonic counter for key IDs
}

// Compile-time interface check.
var _ KeyStore = (*SoftwareKeyStore)(nil)

// NewSoftwareKeyStore returns a SoftwareKeyStore ready for use.
func NewSoftwareKeyStore() *SoftwareKeyStore {
	return &SoftwareKeyStore{
		keys: make(map[string]*ecdsa.PrivateKey),
		rand: rand.Reader,
	}
}

func (s *SoftwareKeyStore) nextID() string {
	s.seq++
	return fmt.Sprintf("sw-%d", s.seq)
}

// GenerateKey creates a new ECDSA P-256 key pair.
func (s *SoftwareKeyStore) GenerateKey() (string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), s.rand)
	if err != nil {
		return "", fmt.Errorf("generating ECDSA P-256 key: %w", err)
	}
	id := s.nextID()
	s.keys[id] = priv
	return id, nil
}

// Signer returns the *ecdsa.PrivateKey (which implements crypto.Signer).
func (s *SoftwareKeyStore) Signer(keyID string) (crypto.Signer, error) {
	priv, ok := s.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
	}
	return priv, nil
}

// ExportPEM encodes the private key as SEC1 "EC PRIVATE KEY" PEM.
func (s *SoftwareKeyStore) ExportPEM(keyID string) (string, error) {
	priv, ok := s.keys[keyID]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), nil
}

// ImportPEM parses an EC private key PEM block and stores it.
func (s *SoftwareKeyStore) ImportPEM(pemData string) (string, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return "", fmt.Errorf("%w: no PEM block found", ErrInvalidPEM)
	}

	var priv *ecdsa.PrivateKey
	var err error

	switch block.Type {
	case "EC PRIVATE KEY":
		priv, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		// PKCS8 generic wrapper.
		key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e != nil {
			return "", fmt.Errorf("%w: %v", ErrInvalidPEM, e)
		}
		var ok bool
		priv, ok = key.(*ecdsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("%w: not an ECDSA key", ErrInvalidPEM)
		}
	default:
		return "", fmt.Errorf("%w: unexpected PEM type %q", ErrInvalidPEM, block.Type)
	}
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidPEM, err)
	}

	id := s.nextID()
	s.keys[id] = priv
	return id, nil
}

// Delete removes the key from memory.
func (s *SoftwareKeyStore) Delete(keyID string) error {
	delete(s.keys, keyID)
	return nil
}
