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
