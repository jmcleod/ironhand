package util

import "fmt"

func CopyBytes(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

// WipeBytes best-effort zeroes the provided byte slice in place.
func WipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// WipeArray32 best-effort zeroes the provided 32-byte array in place.
func WipeArray32(a *[32]byte) {
	for i := range a {
		a[i] = 0
	}
}

func Xor(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("xor: mismatched lengths %d and %d", len(a), len(b))
	}
	c := make([]byte, len(a))
	for i := range a {
		c[i] = a[i] ^ b[i]
	}
	return c, nil
}
