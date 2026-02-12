package util

import "fmt"

func NewTwoSecretKey(passphrase string, saltPass []byte, argonParams Argon2idParams, secretKey []byte, saltSecret []byte, info []byte) ([]byte, error) {
	kPass, err := DeriveArgon2idKey(Normalize(passphrase), saltPass, argonParams)
	if err != nil {
		return nil, fmt.Errorf("deriving k_pass: %w", err)
	}

	kSecret, err := HKDF(secretKey, saltSecret, info)
	if err != nil {
		return nil, fmt.Errorf("deriving k_secret: %w", err)
	}

	result, err := Xor(kPass, kSecret)
	if err != nil {
		return nil, fmt.Errorf("combining keys: %w", err)
	}

	return result, nil
}
