package key

import (
	"fmt"

	"github.com/jmcleod/ironhand/internal/util"
	"github.com/jmcleod/ironhand/internal/uuid"
)

// Encrypter can encrypt data and identify itself.
type Encrypter interface {
	ID() string
	Encrypt([]byte) ([]byte, error)
}

// Decrypter can decrypt data and identify itself.
type Decrypter interface {
	ID() string
	Decrypt([]byte) ([]byte, error)
}

// Key represents a symmetric encryption key that can both encrypt and decrypt.
type Key interface {
	Type() Type
	EncryptKey(Encrypter) (EncryptedKey, error)
	Copy() Key
	Encrypter
	Decrypter
}

type key struct {
	keyID   string
	keyType Type
	bytes   []byte
}

func (k *key) ID() string {
	return k.keyID
}

func (k *key) Type() Type {
	return k.keyType
}

func (k *key) EncryptKey(e Encrypter) (EncryptedKey, error) {
	return newEncryptedKey(e, k.keyID, k.keyType, k.bytes)
}

func (k *key) Encrypt(plainText []byte) ([]byte, error) {
	return util.EncryptAES(plainText, k.bytes)
}

func (k *key) Decrypt(cipherText []byte) ([]byte, error) {
	return util.DecryptAES(cipherText, k.bytes)
}

func (k *key) Copy() Key {
	return newWithIDAndTypeAndBytes(k.keyID, k.keyType, k.bytes)
}

func newWithIDAndTypeAndBytes(keyID string, t Type, bytes []byte) Key {
	return &key{
		keyID:   keyID,
		keyType: t,
		bytes:   util.CopyBytes(bytes),
	}
}

// NewSymmetricKey generates a new random 256-bit AES symmetric key.
func NewSymmetricKey() (Key, error) {
	rawKey, err := util.NewAESKey()
	if err != nil {
		return nil, fmt.Errorf("generating symmetric key: %w", err)
	}
	return newWithIDAndTypeAndBytes(uuid.New(), Symmetric, rawKey), nil
}
