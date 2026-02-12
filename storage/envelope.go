package storage

import (
	"fmt"

	"github.com/jmcleod/ironhand/internal/util"
)

// Envelope is a sealed record containing AES-256-GCM encrypted data.
type Envelope struct {
	Ver        int    `json:"ver"`
	Scheme     string `json:"scheme"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
	Version    uint64 `json:"version,omitempty"`
}

// SealRecord encrypts plaintext into an Envelope using the given record key and AAD.
func SealRecord(recordKey, plaintext, aad []byte, version ...uint64) (*Envelope, error) {
	cipher, err := util.EncryptAESWithAAD(plaintext, recordKey, aad)
	if err != nil {
		return nil, err
	}

	// util.EncryptAESWithAAD returns nonce || ciphertext.
	nonce := cipher[:12]
	ciphertext := cipher[12:]

	env := &Envelope{
		Ver:        1,
		Scheme:     "aes256gcm",
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}
	if len(version) > 0 {
		env.Version = version[0]
	}
	return env, nil
}

// OpenRecord decrypts an Envelope using the given record key and AAD.
func OpenRecord(recordKey []byte, envelope *Envelope, aad []byte) ([]byte, error) {
	if envelope.Ver != 1 {
		return nil, fmt.Errorf("unsupported envelope version: %d", envelope.Ver)
	}
	if envelope.Scheme != "aes256gcm" {
		return nil, fmt.Errorf("unsupported envelope scheme: %s", envelope.Scheme)
	}

	// Reconstruct nonce || ciphertext without mutating envelope fields.
	fullCipher := make([]byte, len(envelope.Nonce)+len(envelope.Ciphertext))
	copy(fullCipher, envelope.Nonce)
	copy(fullCipher[len(envelope.Nonce):], envelope.Ciphertext)

	return util.DecryptAESWithAAD(fullCipher, recordKey, aad)
}
