package util

import (
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/argon2"
)

type Argon2idParams struct {
	Time        uint32 `json:"time"`
	MemoryKiB   uint32 `json:"memory"`
	Parallelism uint8  `json:"parallelism"`
	KeyLen      uint32 `json:"key_len"`
}

func DefaultArgon2idParams() Argon2idParams {
	return Argon2idParams{
		Time:        1,
		MemoryKiB:   64 * 1024,
		Parallelism: 4,
		KeyLen:      32,
	}
}

func DeriveArgon2idKey(passphrase string, salt []byte, params Argon2idParams) ([]byte, error) {
	if params.KeyLen != 32 {
		return nil, fmt.Errorf("argon2id key length must be 32 bytes")
	}
	key := argon2.IDKey([]byte(passphrase), salt, params.Time, params.MemoryKiB, params.Parallelism, params.KeyLen)
	return key, nil
}

func CompareArgon2idKey(passphrase string, salt []byte, params Argon2idParams, expectedKey []byte) (bool, error) {
	key, err := DeriveArgon2idKey(passphrase, salt, params)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(key, expectedKey) == 1, nil
}
