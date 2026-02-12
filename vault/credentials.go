package vault

import (
	"bytes"
	"fmt"

	"github.com/jmcleod/ironhand/crypto"
	"github.com/jmcleod/ironhand/internal/util"
	"github.com/jmcleod/ironhand/internal/uuid"
	"golang.org/x/crypto/curve25519"
)

// Credentials holds the identity and key material for a vault member.
type Credentials struct {
	memberID   string
	muk        []byte
	keypair    crypto.KeyPair
	secretKey  crypto.SecretKey
	kdfParams  Argon2idParams
	saltPass   []byte
	saltSecret []byte
}

// CredentialProfile captures KDF settings used for deriving a member MUK.
type CredentialProfile struct {
	KDFParams  Argon2idParams
	SaltPass   []byte
	SaltSecret []byte
}

type credentialsOptions struct {
	profile *CredentialProfile
}

// CredentialsOption customizes credential creation/opening.
type CredentialsOption func(*credentialsOptions)

// WithCredentialProfile sets the KDF profile used for credential derivation.
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

func defaultCredentialProfile() (CredentialProfile, error) {
	saltPass, err := util.RandomBytes(16)
	if err != nil {
		return CredentialProfile{}, fmt.Errorf("generating passphrase salt: %w", err)
	}
	saltSecret, err := util.RandomBytes(16)
	if err != nil {
		return CredentialProfile{}, fmt.Errorf("generating secret salt: %w", err)
	}
	return CredentialProfile{
		KDFParams:  crypto.DefaultArgon2idParams(),
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
		return defaultCredentialProfile()
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
	kp, err := crypto.GenerateX25519Keypair()
	if err != nil {
		return nil, err
	}
	return &Credentials{
		memberID:   uuid.New(),
		muk:        muk,
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
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &privateKey)
	return &Credentials{
		memberID:   memberID,
		muk:        muk,
		keypair:    crypto.KeyPair{Private: privateKey, Public: pub},
		secretKey:  secretKey,
		kdfParams:  profile.KDFParams,
		saltPass:   util.CopyBytes(profile.SaltPass),
		saltSecret: util.CopyBytes(profile.SaltSecret),
	}, nil
}

// MemberID returns the member's unique identifier.
func (c *Credentials) MemberID() string {
	return c.memberID
}

// PublicKey returns the member's X25519 public key.
func (c *Credentials) PublicKey() [32]byte {
	return c.keypair.Public
}

// PrivateKey returns the member's X25519 private key.
func (c *Credentials) PrivateKey() [32]byte {
	return c.keypair.Private
}

// SecretKey returns the secret key used in MUK derivation.
func (c *Credentials) SecretKey() crypto.SecretKey {
	return c.secretKey
}

// Profile returns a copy of the KDF profile used to derive this credential's MUK.
func (c *Credentials) Profile() CredentialProfile {
	return CredentialProfile{
		KDFParams:  c.kdfParams,
		SaltPass:   util.CopyBytes(c.saltPass),
		SaltSecret: util.CopyBytes(c.saltSecret),
	}
}

func (c *Credentials) matchesProfile(params Argon2idParams, saltPass, saltSecret []byte) bool {
	if c.kdfParams != params {
		return false
	}
	if !bytes.Equal(c.saltPass, saltPass) {
		return false
	}
	return bytes.Equal(c.saltSecret, saltSecret)
}
