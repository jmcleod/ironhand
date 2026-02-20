package crypto

import "github.com/jmcleod/ironhand/internal/util"

// Argon2idParams configures Argon2id key derivation.
type Argon2idParams = util.Argon2idParams

// KeyPair holds an X25519 public/private key pair.
type KeyPair = util.KeyPair

var mukInfo = []byte("vault:muk:v1")

// DeriveMUKOption is a functional option for DeriveMUK.
type DeriveMUKOption func(*deriveMUKOptions)

type deriveMUKOptions struct {
	saltPass   []byte
	params     Argon2idParams
	saltSecret []byte
	info       []byte
}

// WithSaltPass sets the salt used for passphrase derivation.
func WithSaltPass(salt []byte) DeriveMUKOption {
	return func(o *deriveMUKOptions) {
		o.saltPass = salt
	}
}

// WithArgonParams sets the Argon2id parameters.
func WithArgonParams(params Argon2idParams) DeriveMUKOption {
	return func(o *deriveMUKOptions) {
		o.params = params
	}
}

// WithSaltSecret sets the salt used for secret key derivation.
func WithSaltSecret(salt []byte) DeriveMUKOption {
	return func(o *deriveMUKOptions) {
		o.saltSecret = salt
	}
}

// WithInfo sets the info parameter for HKDF.
func WithInfo(info []byte) DeriveMUKOption {
	return func(o *deriveMUKOptions) {
		o.info = info
	}
}

// DeriveMUK derives a Master Unlock Key using the two-secret-key scheme
// (Argon2id + HKDF + XOR of passphrase-derived and secret-key-derived keys).
func DeriveMUK(secretKey []byte, passphrase string, opts ...DeriveMUKOption) ([]byte, error) {
	options := deriveMUKOptions{
		params: DefaultArgon2idParams(),
		info:   mukInfo,
	}
	for _, opt := range opts {
		opt(&options)
	}

	return util.NewTwoSecretKey(passphrase, options.saltPass, options.params, secretKey, options.saltSecret, options.info)
}

// Named KDF profiles for different deployment scenarios.
const (
	KDFProfileInteractive = util.KDFProfileInteractive // sub-second, dev/testing
	KDFProfileModerate    = util.KDFProfileModerate    // production default
	KDFProfileSensitive   = util.KDFProfileSensitive   // high-value secrets
)

// DefaultArgon2idParams returns the default Argon2id parameters (moderate profile).
func DefaultArgon2idParams() Argon2idParams {
	return util.DefaultArgon2idParams()
}

// Argon2idProfile returns the Argon2idParams for a named profile.
func Argon2idProfile(name string) (Argon2idParams, error) {
	return util.Argon2idProfile(name)
}

// ValidateArgon2idParams checks that the given parameters meet the minimum
// acceptable thresholds.
func ValidateArgon2idParams(p Argon2idParams) error {
	return util.ValidateArgon2idParams(p)
}

// GenerateX25519Keypair generates a new X25519 key pair for member identity.
func GenerateX25519Keypair() (KeyPair, error) {
	return util.GenerateX25519Keypair()
}
