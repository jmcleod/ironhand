package vault

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/awnumar/memguard"
	"github.com/jmcleod/ironhand/crypto"
	"github.com/jmcleod/ironhand/internal/util"
	"github.com/jmcleod/ironhand/internal/uuid"
	"golang.org/x/crypto/curve25519"
)

const exportVersion = 1
const exportSaltLen = 16

// Credentials holds the identity and key material for a vault member.
// The MUK is stored in a memguard Enclave (encrypted at rest in memory).
// Call Destroy() when done to wipe sensitive key material.
type Credentials struct {
	memberID   string
	muk        *memguard.Enclave
	keypair    crypto.KeyPair
	secretKey  crypto.SecretKey
	kdfParams  Argon2idParams
	saltPass   []byte
	saltSecret []byte
	destroyed  bool
}

// CredentialProfile captures KDF settings used for deriving a member MUK.
type CredentialProfile struct {
	KDFParams  Argon2idParams
	SaltPass   []byte
	SaltSecret []byte
}

type credentialsOptions struct {
	profile   *CredentialProfile
	kdfParams *Argon2idParams // override KDF params only (salts are generated)
}

// CredentialsOption customizes credential creation/opening.
type CredentialsOption func(*credentialsOptions)

// WithCredentialProfile sets the KDF profile used for credential derivation.
// Both salts must be non-empty.
func WithCredentialProfile(profile CredentialProfile) CredentialsOption {
	return func(o *credentialsOptions) {
		cp := CredentialProfile{
			KDFParams:  profile.KDFParams,
			SaltPass:   util.CopyBytes(profile.SaltPass),
			SaltSecret: util.CopyBytes(profile.SaltSecret),
		}
		o.profile = &cp
	}
}

// WithCredentialKDFParams overrides only the Argon2id parameters for new
// credential creation. Fresh random salts are still generated automatically.
// This is ignored when WithCredentialProfile is also set (full profile takes
// precedence).
func WithCredentialKDFParams(params Argon2idParams) CredentialsOption {
	return func(o *credentialsOptions) {
		p := params
		o.kdfParams = &p
	}
}

func defaultCredentialProfile(kdfOverride *Argon2idParams) (CredentialProfile, error) {
	saltPass, err := util.RandomBytes(16)
	if err != nil {
		return CredentialProfile{}, fmt.Errorf("generating passphrase salt: %w", err)
	}
	saltSecret, err := util.RandomBytes(16)
	if err != nil {
		return CredentialProfile{}, fmt.Errorf("generating secret salt: %w", err)
	}
	params := crypto.DefaultArgon2idParams()
	if kdfOverride != nil {
		params = *kdfOverride
	}
	return CredentialProfile{
		KDFParams:  params,
		SaltPass:   saltPass,
		SaltSecret: saltSecret,
	}, nil
}

func profileFromOptions(opts ...CredentialsOption) (CredentialProfile, error) {
	o := credentialsOptions{}
	for _, opt := range opts {
		opt(&o)
	}
	if o.profile == nil {
		return defaultCredentialProfile(o.kdfParams)
	}
	if len(o.profile.SaltPass) == 0 || len(o.profile.SaltSecret) == 0 {
		return CredentialProfile{}, fmt.Errorf("credential profile requires non-empty salts")
	}
	return CredentialProfile{
		KDFParams:  o.profile.KDFParams,
		SaltPass:   util.CopyBytes(o.profile.SaltPass),
		SaltSecret: util.CopyBytes(o.profile.SaltSecret),
	}, nil
}

func profileFromOpenOptions(opts ...CredentialsOption) (CredentialProfile, error) {
	o := credentialsOptions{}
	for _, opt := range opts {
		opt(&o)
	}
	if o.profile == nil {
		return CredentialProfile{}, fmt.Errorf("opening credentials requires a credential profile")
	}
	return profileFromOptions(opts...)
}

// NewCredentials generates new credentials from a passphrase.
// It creates a new SecretKey, KeyPair, derives the MUK, and generates a member ID.
func NewCredentials(passphrase string, opts ...CredentialsOption) (*Credentials, error) {
	profile, err := profileFromOptions(opts...)
	if err != nil {
		return nil, err
	}
	sk, err := crypto.NewSecretKey()
	if err != nil {
		return nil, err
	}
	muk, err := crypto.DeriveMUK(sk.Bytes(), passphrase,
		crypto.WithArgonParams(profile.KDFParams),
		crypto.WithSaltPass(profile.SaltPass),
		crypto.WithSaltSecret(profile.SaltSecret),
	)
	if err != nil {
		return nil, err
	}
	mukEnclave := memguard.NewEnclave(muk)
	kp, err := crypto.GenerateX25519Keypair()
	if err != nil {
		return nil, err
	}
	return &Credentials{
		memberID:   uuid.New(),
		muk:        mukEnclave,
		keypair:    kp,
		secretKey:  sk,
		kdfParams:  profile.KDFParams,
		saltPass:   util.CopyBytes(profile.SaltPass),
		saltSecret: util.CopyBytes(profile.SaltSecret),
	}, nil
}

// OpenCredentials recreates credentials from existing key material for reopening a vault.
func OpenCredentials(secretKey crypto.SecretKey, passphrase string, memberID string, privateKey [32]byte, opts ...CredentialsOption) (*Credentials, error) {
	profile, err := profileFromOpenOptions(opts...)
	if err != nil {
		return nil, err
	}
	muk, err := crypto.DeriveMUK(secretKey.Bytes(), passphrase,
		crypto.WithArgonParams(profile.KDFParams),
		crypto.WithSaltPass(profile.SaltPass),
		crypto.WithSaltSecret(profile.SaltSecret),
	)
	if err != nil {
		return nil, err
	}
	mukEnclave := memguard.NewEnclave(muk)
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &privateKey)
	return &Credentials{
		memberID:   memberID,
		muk:        mukEnclave,
		keypair:    crypto.KeyPair{Private: privateKey, Public: pub},
		secretKey:  secretKey,
		kdfParams:  profile.KDFParams,
		saltPass:   util.CopyBytes(profile.SaltPass),
		saltSecret: util.CopyBytes(profile.SaltSecret),
	}, nil
}

// MemberID returns the member's unique identifier.
func (c *Credentials) MemberID() string {
	if c == nil || c.destroyed {
		return ""
	}
	return c.memberID
}

// PublicKey returns the member's X25519 public key.
func (c *Credentials) PublicKey() [32]byte {
	if c == nil || c.destroyed {
		return [32]byte{}
	}
	return c.keypair.Public
}

// PrivateKey returns the member's X25519 private key.
func (c *Credentials) PrivateKey() [32]byte {
	if c == nil || c.destroyed {
		return [32]byte{}
	}
	return c.keypair.Private
}

// SecretKey returns the secret key used in MUK derivation.
func (c *Credentials) SecretKey() crypto.SecretKey {
	if c == nil || c.destroyed {
		return nil
	}
	return c.secretKey
}

// Profile returns a copy of the KDF profile used to derive this credential's MUK.
func (c *Credentials) Profile() CredentialProfile {
	if c == nil || c.destroyed {
		return CredentialProfile{}
	}
	return CredentialProfile{
		KDFParams:  c.kdfParams,
		SaltPass:   util.CopyBytes(c.saltPass),
		SaltSecret: util.CopyBytes(c.saltSecret),
	}
}

// Destroy wipes sensitive key material held by the credentials.
// After calling Destroy, the Credentials must not be reused.
func (c *Credentials) Destroy() {
	if c == nil || c.destroyed {
		return
	}
	c.muk = nil
	c.memberID = ""
	util.WipeArray32(&c.keypair.Private)
	util.WipeArray32(&c.keypair.Public)
	c.secretKey = nil
	c.kdfParams = Argon2idParams{}
	util.WipeBytes(c.saltPass)
	util.WipeBytes(c.saltSecret)
	c.saltPass = nil
	c.saltSecret = nil
	c.destroyed = true
}

func (c *Credentials) matchesProfile(params Argon2idParams, saltPass, saltSecret []byte) bool {
	if c == nil || c.destroyed {
		return false
	}
	if c.kdfParams != params {
		return false
	}
	if !bytes.Equal(c.saltPass, saltPass) {
		return false
	}
	return bytes.Equal(c.saltSecret, saltSecret)
}

// lockedCredentials is the JSON-serializable form encrypted inside an export blob.
type lockedCredentials struct {
	MemberID   string         `json:"member_id"`
	SecretKey  string         `json:"secret_key"`
	PrivateKey [32]byte       `json:"private_key"`
	MUK        []byte         `json:"muk"`
	KDFParams  Argon2idParams `json:"kdf_params"`
	SaltPass   []byte         `json:"salt_pass"`
	SaltSecret []byte         `json:"salt_secret"`
}

// exportKDFParams uses the "sensitive" profile for credential export blobs
// because these are long-lived offline artifacts that may be stored on disk.
var exportKDFParams = func() util.Argon2idParams {
	p, _ := util.Argon2idProfile(util.KDFProfileSensitive)
	return p
}()

// ExportCredentials encrypts credentials into a portable byte blob protected
// by the given passphrase. The output format is:
//
//	version (1 byte) || salt (16 bytes) || AES-256-GCM ciphertext
//
// The encryption key is derived from the passphrase using Argon2id.
//
// SECURITY: The exported blob contains the MUK, private key, and all KDF
// parameters. Anyone who obtains the blob AND knows the passphrase can
// decrypt all vaults associated with these credentials. Treat exported
// blobs as highly sensitive — store them only in encrypted storage and
// delete them after import.
func ExportCredentials(creds *Credentials, passphrase string) ([]byte, error) {
	normalized := []byte(util.Normalize(passphrase))
	defer util.WipeBytes(normalized)
	return ExportCredentialsBytes(creds, normalized)
}

// ExportCredentialsBytes is like ExportCredentials but accepts the passphrase
// as []byte, avoiding an intermediate heap-allocated string. Use this when the
// passphrase originates from a memguard LockedBuffer. The passphrase bytes
// must already be NFKD-normalized if they may contain Unicode; ASCII-only
// passphrases (e.g., hex-encoded session passphrases) need no normalization.
// The caller should wipe the passphrase slice after this function returns.
func ExportCredentialsBytes(creds *Credentials, passphrase []byte) ([]byte, error) {
	if creds == nil {
		return nil, fmt.Errorf("credentials must not be nil")
	}
	if creds.destroyed {
		return nil, fmt.Errorf("credentials have been destroyed")
	}
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("passphrase must not be empty")
	}

	mukBuf, err := creds.muk.Open()
	if err != nil {
		return nil, fmt.Errorf("opening MUK enclave: %w", err)
	}
	defer mukBuf.Destroy()

	lc := lockedCredentials{
		MemberID:   creds.memberID,
		SecretKey:  creds.secretKey.String(),
		PrivateKey: creds.keypair.Private,
		MUK:        mukBuf.Bytes(),
		KDFParams:  creds.kdfParams,
		SaltPass:   creds.saltPass,
		SaltSecret: creds.saltSecret,
	}
	plaintext, err := json.Marshal(lc)
	if err != nil {
		return nil, fmt.Errorf("marshaling credentials: %w", err)
	}
	defer util.WipeBytes(plaintext)

	salt, err := util.RandomBytes(exportSaltLen)
	if err != nil {
		return nil, fmt.Errorf("generating export salt: %w", err)
	}

	// The string() conversion in a direct function argument is stack-allocated
	// in modern Go and avoids a heap copy.
	key, err := util.DeriveArgon2idKey(string(passphrase), salt, exportKDFParams)
	if err != nil {
		return nil, fmt.Errorf("deriving export key: %w", err)
	}
	defer util.WipeBytes(key)

	ciphertext, err := util.EncryptAES(plaintext, key)
	if err != nil {
		return nil, fmt.Errorf("encrypting credentials: %w", err)
	}

	// version || salt || ciphertext
	out := make([]byte, 0, 1+exportSaltLen+len(ciphertext))
	out = append(out, byte(exportVersion))
	out = append(out, salt...)
	out = append(out, ciphertext...)
	return out, nil
}

// ImportCredentials decrypts and reconstructs credentials from a blob
// previously created by ExportCredentials.
func ImportCredentials(data []byte, passphrase string) (*Credentials, error) {
	normalized := []byte(util.Normalize(passphrase))
	defer util.WipeBytes(normalized)
	return ImportCredentialsBytes(data, normalized)
}

// ImportCredentialsBytes is like ImportCredentials but accepts the passphrase
// as []byte. See ExportCredentialsBytes for normalization requirements.
// The caller should wipe the passphrase slice after this function returns.
func ImportCredentialsBytes(data []byte, passphrase []byte) (*Credentials, error) {
	if len(data) < 1+exportSaltLen {
		return nil, fmt.Errorf("export data too short")
	}
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("passphrase must not be empty")
	}

	version := data[0]
	if version != exportVersion {
		return nil, fmt.Errorf("unsupported export version: %d", version)
	}
	salt := data[1 : 1+exportSaltLen]
	ciphertext := data[1+exportSaltLen:]

	key, err := util.DeriveArgon2idKey(string(passphrase), salt, exportKDFParams)
	if err != nil {
		return nil, fmt.Errorf("deriving export key: %w", err)
	}
	defer util.WipeBytes(key)

	plaintext, err := util.DecryptAES(ciphertext, key)
	if err != nil {
		return nil, fmt.Errorf("decrypting credentials: %w", err)
	}
	defer util.WipeBytes(plaintext)

	var lc lockedCredentials
	if err := json.Unmarshal(plaintext, &lc); err != nil {
		return nil, fmt.Errorf("unmarshaling credentials: %w", err)
	}

	sk, err := crypto.ParseSecretKey(lc.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("parsing secret key: %w", err)
	}

	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &lc.PrivateKey)

	return &Credentials{
		memberID:   lc.MemberID,
		muk:        memguard.NewEnclave(lc.MUK),
		keypair:    crypto.KeyPair{Private: lc.PrivateKey, Public: pub},
		secretKey:  sk,
		kdfParams:  lc.KDFParams,
		saltPass:   util.CopyBytes(lc.SaltPass),
		saltSecret: util.CopyBytes(lc.SaltSecret),
	}, nil
}
