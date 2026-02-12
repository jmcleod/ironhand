package icrypto

import (
	"crypto/rand"
	"fmt"

	"github.com/jmcleod/ironhand/internal/util"
)

// SealedWrap holds the result of sealing a KEK to a member's X25519 public key.
type SealedWrap struct {
	Ver        int      `json:"ver"`
	EphPub     [32]byte `json:"eph_pub"`
	Salt       []byte   `json:"salt"`
	Nonce      []byte   `json:"nonce"`
	Ciphertext []byte   `json:"ciphertext"`
}

// SealToMember encrypts a KEK to a recipient's X25519 public key using
// ephemeral ECDH + HKDF + AES-256-GCM.
func SealToMember(recipientPub [32]byte, plaintextKEK []byte, aad []byte) (*SealedWrap, error) {
	kp, err := util.GenerateX25519Keypair()
	if err != nil {
		return nil, err
	}
	defer util.WipeArray32(&kp.Private)

	shared, err := util.SharedSecret(kp.Private, recipientPub)
	if err != nil {
		return nil, err
	}
	defer util.WipeArray32(&shared)

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}

	wrapKey, err := util.HKDF(shared[:], salt, []byte("vault:kek-wrap:v1"))
	if err != nil {
		return nil, err
	}
	defer util.WipeBytes(wrapKey)

	ciphertext, err := util.EncryptAESWithAAD(plaintextKEK, wrapKey, aad)
	if err != nil {
		return nil, err
	}

	// util.EncryptAESWithAAD returns nonce || ciphertext; split for the struct.
	actualNonce := ciphertext[:12]
	actualCiphertext := ciphertext[12:]

	return &SealedWrap{
		Ver:        1,
		EphPub:     kp.Public,
		Salt:       salt,
		Nonce:      actualNonce,
		Ciphertext: actualCiphertext,
	}, nil
}

// OpenFromMember decrypts a KEK using the recipient's X25519 private key.
func OpenFromMember(recipientPriv [32]byte, wrap *SealedWrap, aad []byte) ([]byte, error) {
	if wrap.Ver != 1 {
		return nil, fmt.Errorf("unsupported sealed wrap version: %d", wrap.Ver)
	}

	shared, err := util.SharedSecret(recipientPriv, wrap.EphPub)
	if err != nil {
		return nil, err
	}
	defer util.WipeArray32(&shared)

	wrapKey, err := util.HKDF(shared[:], wrap.Salt, []byte("vault:kek-wrap:v1"))
	if err != nil {
		return nil, err
	}
	defer util.WipeBytes(wrapKey)

	// Reconstruct nonce || ciphertext without mutating wrap fields.
	fullCiphertext := make([]byte, len(wrap.Nonce)+len(wrap.Ciphertext))
	copy(fullCiphertext, wrap.Nonce)
	copy(fullCiphertext[len(wrap.Nonce):], wrap.Ciphertext)

	return util.DecryptAESWithAAD(fullCiphertext, wrapKey, aad)
}
