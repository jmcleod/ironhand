//go:build pkcs11

package pki_test

import (
	"crypto/x509/pkix"
	"os"
	"strings"
	"testing"

	"github.com/jmcleod/ironhand/pki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// softhsmAvailable returns true if SoftHSM2 is configured for testing.
func softhsmAvailable() bool {
	return os.Getenv("SOFTHSM2_MODULE") != "" &&
		os.Getenv("SOFTHSM2_TOKEN_LABEL") != "" &&
		os.Getenv("SOFTHSM2_PIN") != ""
}

func newPKCS11KeyStore(t *testing.T) *pki.PKCS11KeyStore {
	t.Helper()
	if !softhsmAvailable() {
		t.Skip("SoftHSM2 not configured (set SOFTHSM2_MODULE, SOFTHSM2_TOKEN_LABEL, SOFTHSM2_PIN)")
	}
	ks, err := pki.NewPKCS11KeyStore(pki.PKCS11Config{
		ModulePath: os.Getenv("SOFTHSM2_MODULE"),
		TokenLabel: os.Getenv("SOFTHSM2_TOKEN_LABEL"),
		PIN:        os.Getenv("SOFTHSM2_PIN"),
	})
	require.NoError(t, err)
	t.Cleanup(func() { ks.Close() })
	return ks
}

func TestPKCS11KeyStore_GenerateAndSign(t *testing.T) {
	ks := newPKCS11KeyStore(t)

	// Generate a key pair in the HSM.
	keyID, err := ks.GenerateKey()
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(keyID, "pkcs11-ironhand-"))

	// Get a signer from the HSM.
	signer, err := ks.Signer(keyID)
	require.NoError(t, err)
	assert.NotNil(t, signer.Public())

	// ExportPEM should return a PKCS#11 reference, not real PEM.
	ref, err := ks.ExportPEM(keyID)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(ref, pki.PKCS11Prefix))
	assert.False(t, strings.Contains(ref, "BEGIN"), "should be a reference, not PEM")

	// ImportPEM round-trips the reference.
	importedID, err := ks.ImportPEM(ref)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(importedID, "pkcs11-"))

	// Imported key produces the same public key.
	importedSigner, err := ks.Signer(importedID)
	require.NoError(t, err)
	assert.Equal(t, signer.Public(), importedSigner.Public())

	// Cleanup — delete the key from the HSM.
	err = ks.Delete(keyID)
	require.NoError(t, err)
}

func TestPKCS11KeyStore_ImportPEM_RejectsRealPEM(t *testing.T) {
	ks := newPKCS11KeyStore(t)
	_, err := ks.ImportPEM("-----BEGIN EC PRIVATE KEY-----\nfake\n-----END EC PRIVATE KEY-----")
	assert.Error(t, err)
	assert.ErrorIs(t, err, pki.ErrKeyNotExportable)
}

func TestPKCS11KeyStore_ImportPEM_RejectsHSMManaged(t *testing.T) {
	ks := newPKCS11KeyStore(t)
	_, err := ks.ImportPEM("HSM-MANAGED")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HSM-MANAGED sentinel")
}

func TestPKCS11KeyStore_SignerNotFound(t *testing.T) {
	ks := newPKCS11KeyStore(t)
	_, err := ks.Signer("pkcs11-nonexistent-key")
	assert.Error(t, err)
	assert.ErrorIs(t, err, pki.ErrKeyNotFound)
}

func TestPKCS11KeyStore_IntegrationWithInitCA(t *testing.T) {
	ks := newPKCS11KeyStore(t)
	ctx := t.Context()
	session := newTestSession(t)

	// Initialize a CA with the PKCS#11 keystore.
	subject := pkix.Name{
		CommonName:   "PKCS#11 Test CA",
		Organization: []string{"TestOrg"},
	}
	err := pki.InitCA(ctx, session, subject, 5, false, ks)
	require.NoError(t, err)

	// Verify CA was created.
	info, err := pki.GetCAInfo(ctx, session)
	require.NoError(t, err)
	assert.True(t, info.IsCA)

	// Issue a certificate using the HSM-backed CA key.
	itemID, err := pki.IssueCertificate(ctx, session, pki.IssueCertRequest{
		Subject:      pkix.Name{CommonName: "hsm-leaf.example.com"},
		ValidityDays: 365,
	}, ks)
	require.NoError(t, err)
	assert.NotEmpty(t, itemID)

	// Generate a CRL using the HSM-backed CA key.
	crlPEM, err := pki.GenerateCRL(ctx, session, ks)
	require.NoError(t, err)
	assert.Contains(t, string(crlPEM), "BEGIN X509 CRL")
}
