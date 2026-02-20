// Package pki provides Certificate Authority operations on top of an IronHand
// vault session. A vault can be initialised as a CA; certificates are then
// issued, revoked, renewed and tracked as regular vault items while CA state
// lives in reserved items protected from the normal CRUD API.
package pki

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/jmcleod/ironhand/internal/uuid"
	"github.com/jmcleod/ironhand/storage"
	"github.com/jmcleod/ironhand/vault"
)

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

var (
	// ErrNotCA is returned when a CA operation is attempted on a vault that
	// has not been initialised as a CA.
	ErrNotCA = errors.New("vault is not initialized as a CA")

	// ErrAlreadyCA is returned when InitCA is called on a vault that already
	// has CA state.
	ErrAlreadyCA = errors.New("vault is already initialized as a CA")

	// ErrCertNotFound is returned when the referenced certificate item does
	// not exist in the vault.
	ErrCertNotFound = errors.New("certificate item not found")

	// ErrCertAlreadyRevoked is returned when attempting to revoke a
	// certificate that is already revoked.
	ErrCertAlreadyRevoked = errors.New("certificate is already revoked")

	// ErrInvalidPEM is returned when PEM data cannot be decoded or parsed.
	ErrInvalidPEM = errors.New("invalid PEM data")

	// ErrNotCertificateItem is returned when an operation that requires a
	// certificate item is invoked on an item of a different type.
	ErrNotCertificateItem = errors.New("item is not a certificate")

	// ErrNoCRL is returned when no cached CRL has been generated yet.
	ErrNoCRL = errors.New("no CRL has been generated")
)

// ---------------------------------------------------------------------------
// Reserved item IDs (stored via session.Put, blocked from user CRUD by API)
// ---------------------------------------------------------------------------

const (
	caStateItemID       = "__ca_state"
	caCertItemID        = "__ca_cert"
	caKeyItemID         = "__ca_key"
	caRevocationsItemID = "__ca_revocations"
	caCRLItemID         = "__ca_crl"
)

// ReservedItemIDs returns the set of reserved item IDs used by the PKI
// subsystem. The API layer uses this to block user-facing CRUD access.
func ReservedItemIDs() []string {
	return []string{caStateItemID, caCertItemID, caKeyItemID, caRevocationsItemID, caCRLItemID}
}

// IsReservedItemID reports whether itemID is reserved by the PKI subsystem.
func IsReservedItemID(itemID string) bool {
	return strings.HasPrefix(itemID, "__ca_")
}

// ---------------------------------------------------------------------------
// Well-known field names for certificate items
// ---------------------------------------------------------------------------

const (
	FieldSubject           = "subject"
	FieldIssuer            = "issuer"
	FieldSerialNumber      = "serial_number"
	FieldNotBefore         = "not_before"
	FieldNotAfter          = "not_after"
	FieldCertificate       = "certificate"
	FieldPrivateKey        = "private_key"
	FieldChain             = "chain"
	FieldFingerprintSHA256 = "fingerprint_sha256"
	FieldKeyAlgorithm      = "key_algorithm"
	FieldStatus            = "status"
	FieldIssuedByCA        = "issued_by_ca"
	FieldPreviousItemID    = "previous_item_id"
	FieldNotes             = "notes"
)

// Metadata field names (matching the web/src/types/vault.ts conventions).
const (
	fieldName    = "_name"
	fieldType    = "_type"
	fieldCreated = "_created"
	fieldUpdated = "_updated"

	certItemType = "certificate"
)

// Certificate status values.
const (
	StatusActive  = "active"
	StatusExpired = "expired"
	StatusRevoked = "revoked"
)

// ---------------------------------------------------------------------------
// CA state types (JSON-serialized in reserved items)
// ---------------------------------------------------------------------------

// CAState is the persistent metadata for a CA vault.
type CAState struct {
	IsCA           bool   `json:"is_ca"`
	IsIntermediate bool   `json:"is_intermediate"`
	NextSerial     int64  `json:"next_serial"`
	Subject        string `json:"subject"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	CRLNumber      int64  `json:"crl_number"`
}

// RevocationEntry records a single revoked certificate.
type RevocationEntry struct {
	SerialNumber string `json:"serial_number"`
	RevokedAt    string `json:"revoked_at"`
	Reason       int    `json:"reason"`
	ItemID       string `json:"item_id"`
}

// CAInfo is the public information about a CA vault, returned to API callers.
type CAInfo struct {
	IsCA           bool   `json:"is_ca"`
	IsIntermediate bool   `json:"is_intermediate"`
	Subject        string `json:"subject"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	NextSerial     int64  `json:"next_serial"`
	CRLNumber      int64  `json:"crl_number"`
	CertCount      int    `json:"cert_count"`
}

// IssueCertRequest holds the parameters for issuing a new certificate.
type IssueCertRequest struct {
	Subject        pkix.Name
	ValidityDays   int
	KeyUsages      x509.KeyUsage
	ExtKeyUsages   []x509.ExtKeyUsage
	DNSNames       []string
	IPAddresses    []net.IP
	EmailAddresses []string
}

// ---------------------------------------------------------------------------
// Certificate PEM parsing
// ---------------------------------------------------------------------------

// ParseCertificatePEM decodes a PEM certificate and returns a map of
// well-known field values extracted from the parsed x509 certificate.
func ParseCertificatePEM(certPEM string) (map[string]string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, ErrInvalidPEM
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPEM, err)
	}

	fingerprint := sha256.Sum256(block.Bytes)

	m := map[string]string{
		FieldSubject:           subjectString(cert.Subject),
		FieldIssuer:            subjectString(cert.Issuer),
		FieldSerialNumber:      hex.EncodeToString(cert.SerialNumber.Bytes()),
		FieldNotBefore:         cert.NotBefore.UTC().Format(time.RFC3339),
		FieldNotAfter:          cert.NotAfter.UTC().Format(time.RFC3339),
		FieldFingerprintSHA256: hex.EncodeToString(fingerprint[:]),
		FieldKeyAlgorithm:      keyAlgorithmString(cert),
		FieldStatus:            certStatus(cert),
	}
	return m, nil
}

// subjectString formats a pkix.Name as a readable DN string.
func subjectString(name pkix.Name) string {
	var parts []string
	if name.CommonName != "" {
		parts = append(parts, "CN="+name.CommonName)
	}
	for _, ou := range name.OrganizationalUnit {
		parts = append(parts, "OU="+ou)
	}
	for _, o := range name.Organization {
		parts = append(parts, "O="+o)
	}
	for _, l := range name.Locality {
		parts = append(parts, "L="+l)
	}
	for _, p := range name.Province {
		parts = append(parts, "ST="+p)
	}
	for _, c := range name.Country {
		parts = append(parts, "C="+c)
	}
	return strings.Join(parts, ", ")
}

// certStatus returns "active" or "expired" based on the certificate's validity window.
func certStatus(cert *x509.Certificate) string {
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return StatusExpired
	}
	return StatusActive
}

// keyAlgorithmString returns a human-readable key algorithm description.
func keyAlgorithmString(cert *x509.Certificate) string {
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %s", pub.Curve.Params().Name)
	default:
		return cert.PublicKeyAlgorithm.String()
	}
}

// ---------------------------------------------------------------------------
// Internal helpers for CA state persistence
// ---------------------------------------------------------------------------

func loadCAState(ctx context.Context, session *vault.Session) (*CAState, error) {
	fields, err := session.Get(ctx, caStateItemID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrNotCA
		}
		return nil, fmt.Errorf("loading CA state: %w", err)
	}
	var state CAState
	if err := json.Unmarshal(fields["state"], &state); err != nil {
		return nil, fmt.Errorf("decoding CA state: %w", err)
	}
	return &state, nil
}

func saveCAState(ctx context.Context, session *vault.Session, state *CAState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encoding CA state: %w", err)
	}
	return session.Update(ctx, caStateItemID, vault.Fields{"state": data})
}

func loadCACert(ctx context.Context, session *vault.Session) (*x509.Certificate, error) {
	fields, err := session.Get(ctx, caCertItemID)
	if err != nil {
		return nil, fmt.Errorf("loading CA certificate: %w", err)
	}
	block, _ := pem.Decode(fields["certificate"])
	if block == nil {
		return nil, fmt.Errorf("CA certificate: %w", ErrInvalidPEM)
	}
	return x509.ParseCertificate(block.Bytes)
}

func loadCAKey(ctx context.Context, session *vault.Session) (*ecdsa.PrivateKey, error) {
	fields, err := session.Get(ctx, caKeyItemID)
	if err != nil {
		return nil, fmt.Errorf("loading CA private key: %w", err)
	}
	block, _ := pem.Decode(fields["private_key"])
	if block == nil {
		return nil, fmt.Errorf("CA private key: %w", ErrInvalidPEM)
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

// loadCASigner returns a crypto.Signer for the CA key. When a KeyStore is
// provided, it imports the stored PEM and returns the store's signer. When
// ks is nil (software-only legacy path), it falls back to loadCAKey.
func loadCASigner(ctx context.Context, session *vault.Session, ks KeyStore) (crypto.Signer, error) {
	if ks == nil {
		return loadCAKey(ctx, session)
	}
	fields, err := session.Get(ctx, caKeyItemID)
	if err != nil {
		return nil, fmt.Errorf("loading CA private key: %w", err)
	}
	keyPEM := string(fields["private_key"])
	keyID, err := ks.ImportPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("importing CA key into keystore: %w", err)
	}
	return ks.Signer(keyID)
}

// defaultKeyStore returns ks if non-nil, or a fresh SoftwareKeyStore.
func defaultKeyStore(ks KeyStore) KeyStore {
	if ks != nil {
		return ks
	}
	return NewSoftwareKeyStore()
}

func loadRevocations(ctx context.Context, session *vault.Session) ([]RevocationEntry, error) {
	fields, err := session.Get(ctx, caRevocationsItemID)
	if err != nil {
		return nil, fmt.Errorf("loading CA revocations: %w", err)
	}
	var entries []RevocationEntry
	if err := json.Unmarshal(fields["revocations"], &entries); err != nil {
		return nil, fmt.Errorf("decoding revocations: %w", err)
	}
	return entries, nil
}

func saveRevocations(ctx context.Context, session *vault.Session, entries []RevocationEntry) error {
	data, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("encoding revocations: %w", err)
	}
	return session.Update(ctx, caRevocationsItemID, vault.Fields{"revocations": data})
}

func encodeCertPEM(derBytes []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))
}

func encodeKeyPEM(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), nil
}

// ---------------------------------------------------------------------------
// CA Operations
// ---------------------------------------------------------------------------

// InitCA initialises a vault as a Certificate Authority. It generates a
// keypair via the provided KeyStore (or a default SoftwareKeyStore when ks
// is nil), creates a self-signed root CA certificate, and stores CA cert +
// key + state in reserved items.
func InitCA(ctx context.Context, session *vault.Session, subject pkix.Name, validityYears int, isIntermediate bool, ks KeyStore) error {
	ks = defaultKeyStore(ks)

	// Ensure not already a CA.
	if _, err := loadCAState(ctx, session); err == nil {
		return ErrAlreadyCA
	} else if !errors.Is(err, ErrNotCA) {
		return err
	}

	// Generate keypair via the key store.
	keyID, err := ks.GenerateKey()
	if err != nil {
		return fmt.Errorf("generating CA key: %w", err)
	}
	signer, err := ks.Signer(keyID)
	if err != nil {
		return fmt.Errorf("getting CA signer: %w", err)
	}

	now := time.Now().UTC()
	notAfter := now.AddDate(validityYears, 0, 0)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subject,
		NotBefore:             now,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        isIntermediate,
	}

	// Self-sign.
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return fmt.Errorf("creating CA certificate: %w", err)
	}

	certPEM := encodeCertPEM(derBytes)

	// Export key PEM for vault storage. HSM-backed stores may return
	// ErrKeyNotExportable; in that case we store a sentinel so the vault
	// knows the key is externally managed.
	keyPEM, err := ks.ExportPEM(keyID)
	if err != nil && !errors.Is(err, ErrKeyNotExportable) {
		return fmt.Errorf("exporting CA private key: %w", err)
	}
	if errors.Is(err, ErrKeyNotExportable) {
		keyPEM = "HSM-MANAGED"
	}

	state := &CAState{
		IsCA:           true,
		IsIntermediate: isIntermediate,
		NextSerial:     2, // serial 1 used by the CA cert itself
		Subject:        subjectString(subject),
		NotBefore:      now.Format(time.RFC3339),
		NotAfter:       notAfter.Format(time.RFC3339),
		CRLNumber:      0,
	}
	stateJSON, err := json.Marshal(state)
	if err != nil {
		return err
	}
	revocsJSON, _ := json.Marshal([]RevocationEntry{})

	// Store the four reserved items.
	if err := session.Put(ctx, caCertItemID, vault.Fields{
		"certificate": []byte(certPEM),
	}); err != nil {
		return fmt.Errorf("storing CA certificate: %w", err)
	}
	if err := session.Put(ctx, caKeyItemID, vault.Fields{
		"private_key": []byte(keyPEM),
	}); err != nil {
		return fmt.Errorf("storing CA private key: %w", err)
	}
	if err := session.Put(ctx, caStateItemID, vault.Fields{
		"state": stateJSON,
	}); err != nil {
		return fmt.Errorf("storing CA state: %w", err)
	}
	if err := session.Put(ctx, caRevocationsItemID, vault.Fields{
		"revocations": revocsJSON,
	}); err != nil {
		return fmt.Errorf("storing CA revocations: %w", err)
	}

	// Generate and cache an initial (empty) CRL so that GET /crl.pem works
	// immediately without requiring a separate POST to generate one first.
	if _, err := GenerateCRL(ctx, session, ks); err != nil {
		return fmt.Errorf("generating initial CRL: %w", err)
	}

	return nil
}

// IssueCertificate generates a new keypair via the provided KeyStore (or a
// default SoftwareKeyStore when ks is nil), creates a certificate signed by
// the vault's CA, stores it as a regular vault item, and returns the item ID.
func IssueCertificate(ctx context.Context, session *vault.Session, req IssueCertRequest, ks KeyStore) (string, error) {
	ks = defaultKeyStore(ks)

	state, err := loadCAState(ctx, session)
	if err != nil {
		return "", err
	}
	caCert, err := loadCACert(ctx, session)
	if err != nil {
		return "", err
	}
	caSigner, err := loadCASigner(ctx, session, ks)
	if err != nil {
		return "", err
	}

	// Generate leaf keypair via the key store.
	leafKeyID, err := ks.GenerateKey()
	if err != nil {
		return "", fmt.Errorf("generating leaf key: %w", err)
	}
	leafSigner, err := ks.Signer(leafKeyID)
	if err != nil {
		return "", fmt.Errorf("getting leaf signer: %w", err)
	}

	serial := big.NewInt(state.NextSerial)
	now := time.Now().UTC()
	notAfter := now.AddDate(0, 0, req.ValidityDays)

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               req.Subject,
		NotBefore:             now,
		NotAfter:              notAfter,
		KeyUsage:              req.KeyUsages,
		ExtKeyUsage:           req.ExtKeyUsages,
		BasicConstraintsValid: true,
		DNSNames:              req.DNSNames,
		IPAddresses:           req.IPAddresses,
		EmailAddresses:        req.EmailAddresses,
	}
	if template.KeyUsage == 0 {
		template.KeyUsage = x509.KeyUsageDigitalSignature
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, leafSigner.Public(), caSigner)
	if err != nil {
		return "", fmt.Errorf("signing leaf certificate: %w", err)
	}

	leafCertPEM := encodeCertPEM(derBytes)

	// Export leaf private key. HSM-backed stores may not allow export.
	leafKeyPEM, err := ks.ExportPEM(leafKeyID)
	if err != nil && !errors.Is(err, ErrKeyNotExportable) {
		return "", fmt.Errorf("exporting leaf private key: %w", err)
	}
	if errors.Is(err, ErrKeyNotExportable) {
		leafKeyPEM = "HSM-MANAGED"
	}

	// Parse the generated cert for field extraction.
	parsed, err := ParseCertificatePEM(leafCertPEM)
	if err != nil {
		return "", err
	}

	itemID := uuid.New()
	nowStr := now.Format(time.RFC3339)
	fields := vault.Fields{
		fieldName:              []byte(req.Subject.CommonName),
		fieldType:              []byte(certItemType),
		fieldCreated:           []byte(nowStr),
		fieldUpdated:           []byte(nowStr),
		FieldSubject:           []byte(parsed[FieldSubject]),
		FieldIssuer:            []byte(parsed[FieldIssuer]),
		FieldSerialNumber:      []byte(parsed[FieldSerialNumber]),
		FieldNotBefore:         []byte(parsed[FieldNotBefore]),
		FieldNotAfter:          []byte(parsed[FieldNotAfter]),
		FieldCertificate:       []byte(leafCertPEM),
		FieldPrivateKey:        []byte(leafKeyPEM),
		FieldFingerprintSHA256: []byte(parsed[FieldFingerprintSHA256]),
		FieldKeyAlgorithm:      []byte(parsed[FieldKeyAlgorithm]),
		FieldStatus:            []byte(StatusActive),
		FieldIssuedByCA:        []byte("true"),
	}

	if err := session.Put(ctx, itemID, fields); err != nil {
		return "", fmt.Errorf("storing issued certificate: %w", err)
	}

	// Update serial counter.
	state.NextSerial++
	if err := saveCAState(ctx, session, state); err != nil {
		return "", fmt.Errorf("updating CA state: %w", err)
	}

	return itemID, nil
}

// RevokeCertificate marks a certificate item as revoked and adds it to the
// CA's revocation list. The reason parameter is an x509 CRL reason code
// (0 = Unspecified, 1 = KeyCompromise, 4 = Superseded, etc.).
func RevokeCertificate(ctx context.Context, session *vault.Session, itemID string, reason int) error {
	fields, err := session.Get(ctx, itemID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrCertNotFound
		}
		return err
	}
	if string(fields[fieldType]) != certItemType {
		return ErrNotCertificateItem
	}
	if string(fields[FieldStatus]) == StatusRevoked {
		return ErrCertAlreadyRevoked
	}

	serialHex := string(fields[FieldSerialNumber])

	// Append to revocation list.
	revocs, err := loadRevocations(ctx, session)
	if err != nil {
		return err
	}
	revocs = append(revocs, RevocationEntry{
		SerialNumber: serialHex,
		RevokedAt:    time.Now().UTC().Format(time.RFC3339),
		Reason:       reason,
		ItemID:       itemID,
	})
	if err := saveRevocations(ctx, session, revocs); err != nil {
		return err
	}

	// Update item status.
	fields[FieldStatus] = []byte(StatusRevoked)
	fields[fieldUpdated] = []byte(time.Now().UTC().Format(time.RFC3339))
	return session.Update(ctx, itemID, fields)
}

// RenewCertificate re-issues a certificate with the same parameters but a
// new serial number and validity period. The old certificate is revoked with
// reason Superseded (4). Returns the new item ID. The KeyStore parameter
// may be nil to use the default SoftwareKeyStore.
func RenewCertificate(ctx context.Context, session *vault.Session, itemID string, validityDays int, ks KeyStore) (string, error) {
	fields, err := session.Get(ctx, itemID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return "", ErrCertNotFound
		}
		return "", err
	}
	if string(fields[fieldType]) != certItemType {
		return "", ErrNotCertificateItem
	}

	// Parse existing certificate to recover SANs and key usages.
	certPEMStr := string(fields[FieldCertificate])
	block, _ := pem.Decode([]byte(certPEMStr))
	if block == nil {
		return "", ErrInvalidPEM
	}
	oldCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parsing existing certificate: %w", err)
	}

	// Revoke old cert with reason Superseded.
	if string(fields[FieldStatus]) != StatusRevoked {
		if err := RevokeCertificate(ctx, session, itemID, 4); err != nil {
			return "", fmt.Errorf("revoking old certificate: %w", err)
		}
	}

	// Re-issue with same parameters.
	req := IssueCertRequest{
		Subject:        oldCert.Subject,
		ValidityDays:   validityDays,
		KeyUsages:      oldCert.KeyUsage,
		ExtKeyUsages:   oldCert.ExtKeyUsage,
		DNSNames:       oldCert.DNSNames,
		IPAddresses:    oldCert.IPAddresses,
		EmailAddresses: oldCert.EmailAddresses,
	}
	newItemID, err := IssueCertificate(ctx, session, req, ks)
	if err != nil {
		return "", err
	}

	// Set previous_item_id on new cert.
	newFields, err := session.Get(ctx, newItemID)
	if err != nil {
		return "", err
	}
	newFields[FieldPreviousItemID] = []byte(itemID)
	newFields[fieldUpdated] = []byte(time.Now().UTC().Format(time.RFC3339))
	if err := session.Update(ctx, newItemID, newFields); err != nil {
		return "", err
	}

	return newItemID, nil
}

// GenerateCRL creates a Certificate Revocation List from the CA's revocation
// entries. The CRL is signed with the CA key (via the provided KeyStore, or a
// default SoftwareKeyStore when ks is nil) and returned as PEM-encoded bytes.
func GenerateCRL(ctx context.Context, session *vault.Session, ks KeyStore) ([]byte, error) {
	ks = defaultKeyStore(ks)

	state, err := loadCAState(ctx, session)
	if err != nil {
		return nil, err
	}
	caCert, err := loadCACert(ctx, session)
	if err != nil {
		return nil, err
	}
	caSigner, err := loadCASigner(ctx, session, ks)
	if err != nil {
		return nil, err
	}
	revocs, err := loadRevocations(ctx, session)
	if err != nil {
		return nil, err
	}

	revokedCerts := make([]x509.RevocationListEntry, 0, len(revocs))
	for _, r := range revocs {
		serialBytes, err := hex.DecodeString(r.SerialNumber)
		if err != nil {
			continue
		}
		serial := new(big.Int).SetBytes(serialBytes)
		revokedAt, err := time.Parse(time.RFC3339, r.RevokedAt)
		if err != nil {
			revokedAt = time.Now()
		}
		revokedCerts = append(revokedCerts, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: revokedAt,
			ReasonCode:     r.Reason,
		})
	}

	state.CRLNumber++
	now := time.Now().UTC()
	template := &x509.RevocationList{
		Number:                    big.NewInt(state.CRLNumber),
		ThisUpdate:                now,
		NextUpdate:                now.Add(7 * 24 * time.Hour),
		RevokedCertificateEntries: revokedCerts,
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, template, caCert, caSigner)
	if err != nil {
		return nil, fmt.Errorf("creating CRL: %w", err)
	}

	// Persist updated CRL number.
	if err := saveCAState(ctx, session, state); err != nil {
		return nil, err
	}

	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})

	// Cache the generated CRL so that read-only retrieval (LoadCRL) does not
	// need to regenerate and therefore does not mutate state.
	if err := storeCRL(ctx, session, crlPEM); err != nil {
		return nil, fmt.Errorf("caching CRL: %w", err)
	}

	return crlPEM, nil
}

// LoadCRL returns the most recently generated (cached) CRL PEM bytes.
// It returns ErrNoCRL if no CRL has been generated yet, and ErrNotCA if
// the vault is not initialised as a CA.
func LoadCRL(ctx context.Context, session *vault.Session) ([]byte, error) {
	// Ensure the vault is actually a CA.
	if _, err := loadCAState(ctx, session); err != nil {
		return nil, err
	}

	fields, err := session.Get(ctx, caCRLItemID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrNoCRL
		}
		return nil, fmt.Errorf("loading cached CRL: %w", err)
	}
	data, ok := fields["crl"]
	if !ok || len(data) == 0 {
		return nil, ErrNoCRL
	}
	return data, nil
}

// storeCRL persists the PEM-encoded CRL to the reserved CRL item.
// It attempts an Update first (for existing vaults) and falls back to Put
// for vaults that were initialised before the cached-CRL item existed.
func storeCRL(ctx context.Context, session *vault.Session, crlPEM []byte) error {
	err := session.Update(ctx, caCRLItemID, vault.Fields{"crl": crlPEM})
	if err != nil && errors.Is(err, storage.ErrNotFound) {
		return session.Put(ctx, caCRLItemID, vault.Fields{"crl": crlPEM})
	}
	return err
}

// GetCACertificate returns the CA certificate PEM string.
func GetCACertificate(ctx context.Context, session *vault.Session) (string, error) {
	fields, err := session.Get(ctx, caCertItemID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return "", ErrNotCA
		}
		return "", fmt.Errorf("loading CA certificate: %w", err)
	}
	return string(fields["certificate"]), nil
}

// GetCAInfo returns public metadata about the CA vault.
func GetCAInfo(ctx context.Context, session *vault.Session) (*CAInfo, error) {
	state, err := loadCAState(ctx, session)
	if err != nil {
		return nil, err
	}

	// Count certificate items.
	items, err := session.List(ctx)
	if err != nil {
		return nil, err
	}
	certCount := 0
	for _, id := range items {
		if IsReservedItemID(id) || id == "__vault_meta" {
			continue
		}
		f, err := session.Get(ctx, id)
		if err != nil {
			continue
		}
		if string(f[fieldType]) == certItemType {
			certCount++
		}
	}

	return &CAInfo{
		IsCA:           state.IsCA,
		IsIntermediate: state.IsIntermediate,
		Subject:        state.Subject,
		NotBefore:      state.NotBefore,
		NotAfter:       state.NotAfter,
		NextSerial:     state.NextSerial,
		CRLNumber:      state.CRLNumber,
		CertCount:      certCount,
	}, nil
}

// SignCSR signs an externally-generated Certificate Signing Request with the
// CA's key (via the provided KeyStore, or a default SoftwareKeyStore when ks
// is nil), stores the issued certificate as a vault item (without a private
// key, since the requester keeps their own), and returns the item ID.
func SignCSR(ctx context.Context, session *vault.Session, csrPEM string, validityDays int, extKeyUsages []x509.ExtKeyUsage, ks KeyStore) (string, error) {
	ks = defaultKeyStore(ks)

	state, err := loadCAState(ctx, session)
	if err != nil {
		return "", err
	}
	caCert, err := loadCACert(ctx, session)
	if err != nil {
		return "", err
	}
	caSigner, err := loadCASigner(ctx, session, ks)
	if err != nil {
		return "", err
	}

	// Parse CSR.
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return "", fmt.Errorf("CSR: %w", ErrInvalidPEM)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parsing CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return "", fmt.Errorf("CSR signature invalid: %w", err)
	}

	serial := big.NewInt(state.NextSerial)
	now := time.Now().UTC()
	notAfter := now.AddDate(0, 0, validityDays)

	keyUsage := x509.KeyUsageDigitalSignature
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             now,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsages,
		BasicConstraintsValid: true,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caSigner)
	if err != nil {
		return "", fmt.Errorf("signing CSR: %w", err)
	}

	leafCertPEM := encodeCertPEM(derBytes)
	parsed, err := ParseCertificatePEM(leafCertPEM)
	if err != nil {
		return "", err
	}

	itemID := uuid.New()
	nowStr := now.Format(time.RFC3339)
	fields := vault.Fields{
		fieldName:              []byte(csr.Subject.CommonName),
		fieldType:              []byte(certItemType),
		fieldCreated:           []byte(nowStr),
		fieldUpdated:           []byte(nowStr),
		FieldSubject:           []byte(parsed[FieldSubject]),
		FieldIssuer:            []byte(parsed[FieldIssuer]),
		FieldSerialNumber:      []byte(parsed[FieldSerialNumber]),
		FieldNotBefore:         []byte(parsed[FieldNotBefore]),
		FieldNotAfter:          []byte(parsed[FieldNotAfter]),
		FieldCertificate:       []byte(leafCertPEM),
		FieldFingerprintSHA256: []byte(parsed[FieldFingerprintSHA256]),
		FieldKeyAlgorithm:      []byte(parsed[FieldKeyAlgorithm]),
		FieldStatus:            []byte(StatusActive),
		FieldIssuedByCA:        []byte("true"),
	}

	if err := session.Put(ctx, itemID, fields); err != nil {
		return "", fmt.Errorf("storing signed certificate: %w", err)
	}

	state.NextSerial++
	if err := saveCAState(ctx, session, state); err != nil {
		return "", err
	}

	return itemID, nil
}
