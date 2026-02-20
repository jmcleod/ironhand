package pki_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"github.com/jmcleod/ironhand/pki"
	"github.com/jmcleod/ironhand/storage/memory"
	"github.com/jmcleod/ironhand/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestSession creates a vault with an owner session for testing.
func newTestSession(t *testing.T) *vault.Session {
	t.Helper()
	ctx := t.Context()
	repo := memory.NewRepository()
	creds, err := vault.NewCredentials("test-passphrase")
	require.NoError(t, err)
	v := vault.New("test-vault", repo)
	session, err := v.Create(ctx, creds)
	require.NoError(t, err)
	t.Cleanup(session.Close)
	return session
}

func TestInitCA(t *testing.T) {
	ctx := t.Context()
	session := newTestSession(t)

	subject := pkix.Name{
		CommonName:   "Test Root CA",
		Organization: []string{"TestOrg"},
		Country:      []string{"US"},
	}

	err := pki.InitCA(ctx, session, subject, 10, false, nil)
	require.NoError(t, err)

	// Verify CA info is available.
	info, err := pki.GetCAInfo(ctx, session)
	require.NoError(t, err)
	assert.True(t, info.IsCA)
	assert.False(t, info.IsIntermediate)
	assert.Contains(t, info.Subject, "CN=Test Root CA")
	assert.Contains(t, info.Subject, "O=TestOrg")
	assert.Equal(t, int64(2), info.NextSerial)
	assert.Equal(t, int64(1), info.CRLNumber) // InitCA auto-generates CRL #1
	assert.Equal(t, 0, info.CertCount)

	// Verify CA cert is retrievable and valid.
	certPEM, err := pki.GetCACertificate(ctx, session)
	require.NoError(t, err)
	assert.Contains(t, certPEM, "BEGIN CERTIFICATE")

	parsed, err := pki.ParseCertificatePEM(certPEM)
	require.NoError(t, err)
	assert.Contains(t, parsed["subject"], "CN=Test Root CA")
	assert.Equal(t, "active", parsed["status"])
	assert.Contains(t, parsed["key_algorithm"], "P-256")
}

func TestInitCA_AlreadyInitialized(t *testing.T) {
	ctx := t.Context()
	session := newTestSession(t)

	subject := pkix.Name{CommonName: "Test CA"}
	err := pki.InitCA(ctx, session, subject, 10, false, nil)
	require.NoError(t, err)

	err = pki.InitCA(ctx, session, subject, 10, false, nil)
	assert.ErrorIs(t, err, pki.ErrAlreadyCA)
}

func TestIssueCertificate(t *testing.T) {
	ctx := t.Context()
	session := newTestSession(t)

	// Init CA.
	err := pki.InitCA(ctx, session, pkix.Name{
		CommonName:   "Test CA",
		Organization: []string{"TestOrg"},
	}, 10, false, nil)
	require.NoError(t, err)

	// Issue a certificate.
	itemID, err := pki.IssueCertificate(ctx, session, pki.IssueCertRequest{
		Subject: pkix.Name{
			CommonName:   "server.example.com",
			Organization: []string{"TestOrg"},
		},
		ValidityDays: 365,
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"server.example.com", "*.example.com"},
	}, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, itemID)

	// Verify the item fields.
	fields, err := session.Get(ctx, itemID)
	require.NoError(t, err)
	assert.Equal(t, "server.example.com", string(fields["_name"]))
	assert.Equal(t, "certificate", string(fields["_type"]))
	assert.Equal(t, "active", string(fields["status"]))
	assert.Equal(t, "true", string(fields["issued_by_ca"]))
	assert.Contains(t, string(fields["subject"]), "CN=server.example.com")
	assert.Contains(t, string(fields["issuer"]), "CN=Test CA")
	assert.NotEmpty(t, string(fields["serial_number"]))
	assert.NotEmpty(t, string(fields["fingerprint_sha256"]))
	assert.Contains(t, string(fields["key_algorithm"]), "P-256")
	assert.Contains(t, string(fields["certificate"]), "BEGIN CERTIFICATE")
	assert.Contains(t, string(fields["private_key"]), "BEGIN EC PRIVATE KEY")

	// Verify the certificate chain: leaf signed by CA.
	leafBlock, _ := pem.Decode(fields["certificate"])
	require.NotNil(t, leafBlock)
	leafCert, err := x509.ParseCertificate(leafBlock.Bytes)
	require.NoError(t, err)

	caCertPEM, _ := pki.GetCACertificate(ctx, session)
	caBlock, _ := pem.Decode([]byte(caCertPEM))
	require.NotNil(t, caBlock)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	require.NoError(t, err)

	err = leafCert.CheckSignatureFrom(caCert)
	assert.NoError(t, err)

	// Verify SANs.
	assert.Contains(t, leafCert.DNSNames, "server.example.com")
	assert.Contains(t, leafCert.DNSNames, "*.example.com")
}

func TestIssueCertificate_IncrementSerial(t *testing.T) {
	ctx := t.Context()
	session := newTestSession(t)

	err := pki.InitCA(ctx, session, pkix.Name{CommonName: "Test CA"}, 10, false, nil)
	require.NoError(t, err)

	id1, err := pki.IssueCertificate(ctx, session, pki.IssueCertRequest{
		Subject:      pkix.Name{CommonName: "cert-1"},
		ValidityDays: 365,
	}, nil)
	require.NoError(t, err)

	id2, err := pki.IssueCertificate(ctx, session, pki.IssueCertRequest{
		Subject:      pkix.Name{CommonName: "cert-2"},
		ValidityDays: 365,
	}, nil)
	require.NoError(t, err)

	// Different item IDs.
	assert.NotEqual(t, id1, id2)

	// Different serial numbers.
	f1, _ := session.Get(ctx, id1)
	f2, _ := session.Get(ctx, id2)
	assert.NotEqual(t, string(f1["serial_number"]), string(f2["serial_number"]))

	// CA info shows cert count = 2.
	info, err := pki.GetCAInfo(ctx, session)
	require.NoError(t, err)
	assert.Equal(t, 2, info.CertCount)
	assert.Equal(t, int64(4), info.NextSerial) // 1=CA, 2=cert1, 3=cert2, next=4
}

func TestRevokeCertificate(t *testing.T) {
	ctx := t.Context()
	session := newTestSession(t)

	err := pki.InitCA(ctx, session, pkix.Name{CommonName: "Test CA"}, 10, false, nil)
	require.NoError(t, err)

	itemID, err := pki.IssueCertificate(ctx, session, pki.IssueCertRequest{
		Subject:      pkix.Name{CommonName: "leaf"},
		ValidityDays: 365,
	}, nil)
	require.NoError(t, err)

	// Revoke.
	err = pki.RevokeCertificate(ctx, session, itemID, 0)
	require.NoError(t, err)

	// Verify status changed.
	fields, err := session.Get(ctx, itemID)
	require.NoError(t, err)
	assert.Equal(t, "revoked", string(fields["status"]))
}

func TestRevokeCertificate_AlreadyRevoked(t *testing.T) {
	ctx := t.Context()
	session := newTestSession(t)

	err := pki.InitCA(ctx, session, pkix.Name{CommonName: "Test CA"}, 10, false, nil)
	require.NoError(t, err)

	itemID, err := pki.IssueCertificate(ctx, session, pki.IssueCertRequest{
		Subject:      pkix.Name{CommonName: "leaf"},
		ValidityDays: 365,
	}, nil)
	require.NoError(t, err)

	err = pki.RevokeCertificate(ctx, session, itemID, 0)
	require.NoError(t, err)

	err = pki.RevokeCertificate(ctx, session, itemID, 0)
	assert.ErrorIs(t, err, pki.ErrCertAlreadyRevoked)
}

func TestRenewCertificate(t *testing.T) {
	ctx := t.Context()
	session := newTestSession(t)

	err := pki.InitCA(ctx, session, pkix.Name{CommonName: "Test CA"}, 10, false, nil)
	require.NoError(t, err)

	oldID, err := pki.IssueCertificate(ctx, session, pki.IssueCertRequest{
		Subject:      pkix.Name{CommonName: "web.example.com"},
		ValidityDays: 365,
		DNSNames:     []string{"web.example.com"},
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, nil)
	require.NoError(t, err)

	// Renew.
	newID, err := pki.RenewCertificate(ctx, session, oldID, 730, nil)
	require.NoError(t, err)
	assert.NotEqual(t, oldID, newID)

	// Old cert should be revoked.
	oldFields, _ := session.Get(ctx, oldID)
	assert.Equal(t, "revoked", string(oldFields["status"]))

	// New cert should be active and link to old.
	newFields, err := session.Get(ctx, newID)
	require.NoError(t, err)
	assert.Equal(t, "active", string(newFields["status"]))
	assert.Equal(t, oldID, string(newFields["previous_item_id"]))
	assert.Contains(t, string(newFields["subject"]), "CN=web.example.com")

	// SANs should be preserved.
	newBlock, _ := pem.Decode(newFields["certificate"])
	require.NotNil(t, newBlock)
	newCert, _ := x509.ParseCertificate(newBlock.Bytes)
	assert.Contains(t, newCert.DNSNames, "web.example.com")
}

func TestGenerateCRL(t *testing.T) {
	ctx := t.Context()
	session := newTestSession(t)

	err := pki.InitCA(ctx, session, pkix.Name{CommonName: "Test CA"}, 10, false, nil)
	require.NoError(t, err)

	// Issue two certs, revoke one.
	id1, err := pki.IssueCertificate(ctx, session, pki.IssueCertRequest{
		Subject:      pkix.Name{CommonName: "cert-1"},
		ValidityDays: 365,
	}, nil)
	require.NoError(t, err)

	_, err = pki.IssueCertificate(ctx, session, pki.IssueCertRequest{
		Subject:      pkix.Name{CommonName: "cert-2"},
		ValidityDays: 365,
	}, nil)
	require.NoError(t, err)

	err = pki.RevokeCertificate(ctx, session, id1, 1) // KeyCompromise
	require.NoError(t, err)

	// Generate CRL.
	crlPEM, err := pki.GenerateCRL(ctx, session, nil)
	require.NoError(t, err)
	assert.Contains(t, string(crlPEM), "BEGIN X509 CRL")

	// Parse and verify.
	block, _ := pem.Decode(crlPEM)
	require.NotNil(t, block)
	crl, err := x509.ParseRevocationList(block.Bytes)
	require.NoError(t, err)
	assert.Len(t, crl.RevokedCertificateEntries, 1)

	// Verify CRL number incremented. InitCA auto-generates CRL #1, so the
	// explicit GenerateCRL call above produces CRL #2.
	info, _ := pki.GetCAInfo(ctx, session)
	assert.Equal(t, int64(2), info.CRLNumber)
}

// TestLoadCRL_ReturnsCachedCRL verifies that LoadCRL returns the most recently
// generated CRL without mutating state.
func TestLoadCRL_ReturnsCachedCRL(t *testing.T) {
	ctx := t.Context()
	session := newTestSession(t)

	// Before InitCA, LoadCRL should fail.
	_, err := pki.LoadCRL(ctx, session)
	require.Error(t, err)

	err = pki.InitCA(ctx, session, pkix.Name{CommonName: "Test CA"}, 10, false, nil)
	require.NoError(t, err)

	// InitCA auto-generates CRL #1; LoadCRL should return it.
	crlPEM, err := pki.LoadCRL(ctx, session)
	require.NoError(t, err)
	assert.Contains(t, string(crlPEM), "BEGIN X509 CRL")

	// Verify CRLNumber is still 1 (LoadCRL doesn't mutate).
	info1, _ := pki.GetCAInfo(ctx, session)
	require.Equal(t, int64(1), info1.CRLNumber)

	// Call LoadCRL again — still 1.
	_, err = pki.LoadCRL(ctx, session)
	require.NoError(t, err)
	info2, _ := pki.GetCAInfo(ctx, session)
	assert.Equal(t, int64(1), info2.CRLNumber, "LoadCRL must not increment CRLNumber")
}

func TestGetCACertificate(t *testing.T) {
	ctx := t.Context()
	session := newTestSession(t)

	// Before init, should fail.
	_, err := pki.GetCACertificate(ctx, session)
	assert.ErrorIs(t, err, pki.ErrNotCA)

	// Init and get.
	err = pki.InitCA(ctx, session, pkix.Name{CommonName: "Test CA"}, 10, false, nil)
	require.NoError(t, err)

	certPEM, err := pki.GetCACertificate(ctx, session)
	require.NoError(t, err)

	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.True(t, cert.IsCA)
	assert.Equal(t, "Test CA", cert.Subject.CommonName)
}

func TestGetCAInfo(t *testing.T) {
	ctx := t.Context()
	session := newTestSession(t)

	// Before init, should fail.
	_, err := pki.GetCAInfo(ctx, session)
	assert.ErrorIs(t, err, pki.ErrNotCA)

	// Init.
	err = pki.InitCA(ctx, session, pkix.Name{CommonName: "Test CA"}, 10, false, nil)
	require.NoError(t, err)

	// Issue 2 certs.
	for i := 0; i < 2; i++ {
		_, err := pki.IssueCertificate(ctx, session, pki.IssueCertRequest{
			Subject:      pkix.Name{CommonName: "cert"},
			ValidityDays: 365,
		}, nil)
		require.NoError(t, err)
	}

	info, err := pki.GetCAInfo(ctx, session)
	require.NoError(t, err)
	assert.True(t, info.IsCA)
	assert.Equal(t, 2, info.CertCount)
	assert.Equal(t, int64(4), info.NextSerial)
}

func TestParseCertificatePEM(t *testing.T) {
	ctx := t.Context()
	session := newTestSession(t)

	err := pki.InitCA(ctx, session, pkix.Name{
		CommonName:   "Parse Test CA",
		Organization: []string{"ParseOrg"},
		Country:      []string{"DE"},
	}, 5, false, nil)
	require.NoError(t, err)

	certPEM, _ := pki.GetCACertificate(ctx, session)
	fields, err := pki.ParseCertificatePEM(certPEM)
	require.NoError(t, err)
	assert.Contains(t, fields["subject"], "CN=Parse Test CA")
	assert.Contains(t, fields["subject"], "O=ParseOrg")
	assert.Contains(t, fields["subject"], "C=DE")
	assert.NotEmpty(t, fields["serial_number"])
	assert.NotEmpty(t, fields["not_before"])
	assert.NotEmpty(t, fields["not_after"])
	assert.NotEmpty(t, fields["fingerprint_sha256"])
	assert.Contains(t, fields["key_algorithm"], "P-256")
	assert.Equal(t, "active", fields["status"])

	// Invalid PEM.
	_, err = pki.ParseCertificatePEM("not valid pem")
	assert.ErrorIs(t, err, pki.ErrInvalidPEM)
}

func TestSignCSR(t *testing.T) {
	ctx := context.Background()
	session := newTestSession(t)

	err := pki.InitCA(ctx, session, pkix.Name{CommonName: "CSR Test CA"}, 10, false, nil)
	require.NoError(t, err)

	// Generate a CSR externally.
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "external.example.com",
			Organization: []string{"ExternalOrg"},
		},
		DNSNames: []string{"external.example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, csrKey)
	require.NoError(t, err)

	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))

	// Sign the CSR.
	itemID, err := pki.SignCSR(ctx, session, csrPEM, 365, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, itemID)

	// Verify the issued certificate.
	fields, err := session.Get(ctx, itemID)
	require.NoError(t, err)
	assert.Equal(t, "external.example.com", string(fields["_name"]))
	assert.Equal(t, "certificate", string(fields["_type"]))
	assert.Equal(t, "active", string(fields["status"]))
	assert.Equal(t, "true", string(fields["issued_by_ca"]))
	assert.Contains(t, string(fields["subject"]), "CN=external.example.com")

	// No private key should be stored (CSR requester keeps their key).
	assert.Empty(t, fields["private_key"])

	// The cert should be signed by the CA.
	leafBlock, _ := pem.Decode(fields["certificate"])
	require.NotNil(t, leafBlock)
	leafCert, _ := x509.ParseCertificate(leafBlock.Bytes)

	caCertPEM, _ := pki.GetCACertificate(ctx, session)
	caBlock, _ := pem.Decode([]byte(caCertPEM))
	caCert, _ := x509.ParseCertificate(caBlock.Bytes)

	err = leafCert.CheckSignatureFrom(caCert)
	assert.NoError(t, err)

	// The cert's public key should match the CSR key (not a new key).
	assert.Equal(t, csrKey.PublicKey, *leafCert.PublicKey.(*ecdsa.PublicKey))
}

// TestKeyStoreInterfaceContract verifies that the SoftwareKeyStore
// correctly implements the KeyStore interface contract.
func TestKeyStoreInterfaceContract(t *testing.T) {
	ks := pki.NewSoftwareKeyStore()

	// Generate a key.
	keyID, err := ks.GenerateKey()
	require.NoError(t, err)
	assert.NotEmpty(t, keyID)

	// Get signer.
	signer, err := ks.Signer(keyID)
	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.NotNil(t, signer.Public())

	// Export PEM.
	pemData, err := ks.ExportPEM(keyID)
	require.NoError(t, err)
	assert.Contains(t, pemData, "BEGIN EC PRIVATE KEY")

	// Import PEM.
	importedID, err := ks.ImportPEM(pemData)
	require.NoError(t, err)
	assert.NotEqual(t, keyID, importedID)

	// Imported key should produce the same public key.
	importedSigner, err := ks.Signer(importedID)
	require.NoError(t, err)
	origPub := signer.Public().(*ecdsa.PublicKey)
	importedPub := importedSigner.Public().(*ecdsa.PublicKey)
	assert.True(t, origPub.Equal(importedPub))

	// Delete.
	err = ks.Delete(keyID)
	require.NoError(t, err)

	// After delete, signer should fail.
	_, err = ks.Signer(keyID)
	assert.ErrorIs(t, err, pki.ErrKeyNotFound)
}

// TestKeyStoreImportPKCS8 verifies that PKCS8-encoded keys can be imported.
func TestKeyStoreImportPKCS8(t *testing.T) {
	ks := pki.NewSoftwareKeyStore()

	// Generate a key externally and marshal as PKCS8.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	pemData := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	keyID, err := ks.ImportPEM(pemData)
	require.NoError(t, err)

	signer, err := ks.Signer(keyID)
	require.NoError(t, err)
	assert.True(t, key.PublicKey.Equal(signer.Public()))
}

// TestKeyStoreImportInvalidPEM verifies error handling for invalid PEM.
func TestKeyStoreImportInvalidPEM(t *testing.T) {
	ks := pki.NewSoftwareKeyStore()

	_, err := ks.ImportPEM("not valid pem")
	assert.ErrorIs(t, err, pki.ErrInvalidPEM)
}

// TestInitCAWithExplicitKeyStore verifies that an explicit SoftwareKeyStore
// works end-to-end with InitCA.
func TestInitCAWithExplicitKeyStore(t *testing.T) {
	ctx := t.Context()
	session := newTestSession(t)

	ks := pki.NewSoftwareKeyStore()
	err := pki.InitCA(ctx, session, pkix.Name{CommonName: "KS Test CA"}, 5, false, ks)
	require.NoError(t, err)

	info, err := pki.GetCAInfo(ctx, session)
	require.NoError(t, err)
	assert.True(t, info.IsCA)
	assert.Contains(t, info.Subject, "CN=KS Test CA")

	// Issue a cert through the same keystore.
	itemID, err := pki.IssueCertificate(ctx, session, pki.IssueCertRequest{
		Subject:      pkix.Name{CommonName: "ks-leaf"},
		ValidityDays: 365,
	}, ks)
	require.NoError(t, err)

	fields, err := session.Get(ctx, itemID)
	require.NoError(t, err)
	assert.Contains(t, string(fields["certificate"]), "BEGIN CERTIFICATE")
	assert.Contains(t, string(fields["private_key"]), "BEGIN EC PRIVATE KEY")
}
