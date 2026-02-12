package util

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"strings"
)

var (
	allowedRandomChars = []rune("23456789ABCDEFGHJKLMNPQRSTVWXYZ")
)

func RandomChars(n int) (string, error) {
	var sb strings.Builder
	for i := 0; i < n; i++ {
		idx, err := RandomIntn(len(allowedRandomChars))
		if err != nil {
			return "", fmt.Errorf("generating random char index: %w", err)
		}
		sb.WriteRune(allowedRandomChars[idx])
	}
	return sb.String(), nil
}

func RandomInt() (int, error) {
	return RandomIntn(math.MaxInt)
}

func RandomIntn(max int) (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, fmt.Errorf("generating random number: %w", err)
	}
	return int(n.Int64()), nil
}

func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generating random bytes: %w", err)
	}
	return b, nil
}
