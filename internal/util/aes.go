package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

const (
	AESKeySize = 32
)

func EncryptAES(plainText, rawKey []byte) ([]byte, error) {
	return EncryptAESWithAAD(plainText, rawKey, nil)
}

func EncryptAESWithAAD(plainText, rawKey, aad []byte) ([]byte, error) {
	if len(rawKey) != AESKeySize {
		return nil, fmt.Errorf("invalid AES key size: got %d, want %d", len(rawKey), AESKeySize)
	}

	block, err := aes.NewCipher(rawKey)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	cipherText := gcm.Seal(nonce, nonce, plainText, aad)

	return cipherText, nil
}

func DecryptAES(cipherText, rawKey []byte) ([]byte, error) {
	return DecryptAESWithAAD(cipherText, rawKey, nil)
}

func DecryptAESWithAAD(cipherText, rawKey, aad []byte) ([]byte, error) {
	if len(rawKey) != AESKeySize {
		return nil, fmt.Errorf("invalid AES key size: got %d, want %d", len(rawKey), AESKeySize)
	}

	block, err := aes.NewCipher(rawKey)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	if len(cipherText) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext shorter than nonce size")
	}

	nonce, cipherText := cipherText[:gcm.NonceSize()], cipherText[gcm.NonceSize():]

	plainText, err := gcm.Open(nil, nonce, cipherText, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypting ciphertext: %w", err)
	}

	return plainText, nil
}

func NewAESKey() ([]byte, error) {
	rawKey := make([]byte, AESKeySize)
	if _, err := rand.Read(rawKey); err != nil {
		return nil, fmt.Errorf("generating AES key: %w", err)
	}
	return rawKey, nil
}
