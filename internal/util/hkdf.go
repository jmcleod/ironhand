package util

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const HKDFKeyLength = 32

func HKDF(seed []byte, salt []byte, info []byte) ([]byte, error) {
	h := hkdf.New(sha256.New, seed, salt, info)
	k := make([]byte, HKDFKeyLength)
	if _, err := io.ReadFull(h, k); err != nil {
		return nil, fmt.Errorf("reading from HKDF: %w", err)
	}
	return k, nil
}
