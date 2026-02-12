package key

import (
	"fmt"

	"github.com/jmcleod/ironhand/internal/util"
)

// EncryptedKey is a key that has been encrypted by another key.
// It supports rotation to a different encrypting key.
type EncryptedKey interface {
	Encrypted
	Rotatable
	Type() Type
	Copy() EncryptedKey
}

type encryptedKey struct {
	keyID       string
	encryptedBy string
	keyType     Type
	bytes       []byte
}

func (ek *encryptedKey) ID() string {
	return ek.keyID
}

func (ek *encryptedKey) Type() Type {
	return ek.keyType
}

func (ek *encryptedKey) EncryptedBy() string {
	return ek.encryptedBy
}

func (ek *encryptedKey) Decrypter(d Decrypter) (Decrypter, error) {
	if ek.encryptedBy != d.ID() {
		return nil, fmt.Errorf("invalid key: expected %s but got %s", ek.keyID, d.ID())
	}

	bytes, err := d.Decrypt(ek.bytes)
	if err != nil {
		return nil, err
	}

	k := newWithIDAndTypeAndBytes(ek.keyID, ek.keyType, bytes)

	return k, nil
}

func (ek *encryptedKey) Rotate(d Decrypter, e Encrypter) error {
	bytes, err := d.Decrypt(ek.bytes)
	if err != nil {
		return fmt.Errorf("decrypting key for rotation: %w", err)
	}

	encBytes, err := e.Encrypt(bytes)
	if err != nil {
		return fmt.Errorf("encrypting key for rotation: %w", err)
	}

	ek.encryptedBy = e.ID()
	ek.bytes = encBytes

	return nil
}

func (ek *encryptedKey) Copy() EncryptedKey {
	return &encryptedKey{
		keyID:       ek.keyID,
		encryptedBy: ek.encryptedBy,
		keyType:     ek.keyType,
		bytes:       util.CopyBytes(ek.bytes),
	}
}

func newEncryptedKey(e Encrypter, id string, keyType Type, bytes []byte) (EncryptedKey, error) {
	encBytes, err := e.Encrypt(bytes)
	if err != nil {
		return nil, fmt.Errorf("encrypting key: %w", err)
	}

	return &encryptedKey{
		keyID:       id,
		encryptedBy: e.ID(),
		keyType:     keyType,
		bytes:       encBytes,
	}, nil
}

// EmptyEncryptedKey returns a nil EncryptedKey.
func EmptyEncryptedKey() EncryptedKey {
	return nil
}
