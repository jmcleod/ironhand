//go:build !pkcs11

package pki

import (
	"crypto"
	"fmt"
)

// PKCS11Prefix is the string prefix stored in vault fields to identify
// PKCS#11-managed keys. Available regardless of build tag for reference
// by other packages.
const PKCS11Prefix = "PKCS11:"

// PKCS11Config holds the configuration for connecting to a PKCS#11 token.
// This is a placeholder when the pkcs11 build tag is not set.
type PKCS11Config struct {
	ModulePath string
	TokenLabel string
	PIN        string
	SlotNumber *int
}

// PKCS11KeyStore is a placeholder type when the pkcs11 build tag is not set.
// It implements KeyStore so that the server CLI compiles without CGo, but
// all methods return errors directing the user to rebuild with -tags pkcs11.
type PKCS11KeyStore struct{}

// Compile-time interface check.
var _ KeyStore = (*PKCS11KeyStore)(nil)

// NewPKCS11KeyStore returns an error when compiled without the pkcs11 build tag.
// Rebuild with: go build -tags pkcs11
func NewPKCS11KeyStore(_ PKCS11Config) (*PKCS11KeyStore, error) {
	return nil, fmt.Errorf("PKCS#11 support not compiled; rebuild with: go build -tags pkcs11")
}

// Close is a no-op for the stub.
func (p *PKCS11KeyStore) Close() error { return nil }

func (p *PKCS11KeyStore) GenerateKey() (string, error) {
	return "", fmt.Errorf("PKCS#11 support not compiled; rebuild with: go build -tags pkcs11")
}

func (p *PKCS11KeyStore) Signer(_ string) (crypto.Signer, error) {
	return nil, fmt.Errorf("PKCS#11 support not compiled; rebuild with: go build -tags pkcs11")
}

func (p *PKCS11KeyStore) ExportPEM(_ string) (string, error) {
	return "", fmt.Errorf("PKCS#11 support not compiled; rebuild with: go build -tags pkcs11")
}

func (p *PKCS11KeyStore) ImportPEM(_ string) (string, error) {
	return "", fmt.Errorf("PKCS#11 support not compiled; rebuild with: go build -tags pkcs11")
}

func (p *PKCS11KeyStore) Delete(_ string) error {
	return fmt.Errorf("PKCS#11 support not compiled; rebuild with: go build -tags pkcs11")
}
