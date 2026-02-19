package pki

import (
	"crypto"
	"fmt"
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
	// HSM/KMS implementations may return ErrKeyNotExportable, or a reference
	// string (e.g. "PKCS11:<label>") that ImportPEM can later interpret.
	ExportPEM(keyID string) (string, error)

	// ImportPEM loads a PEM-encoded private key into the store and returns
	// its key ID. This is used when reading existing keys from vault storage.
	// HSM/KMS implementations may return ErrKeyNotExportable for real PEM data,
	// or interpret reference strings produced by their own ExportPEM.
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
