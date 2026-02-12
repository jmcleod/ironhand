package util

import (
	"encoding/hex"
	"golang.org/x/text/unicode/norm"
)

func Normalize(s string) string {
	return norm.NFKD.String(s)
}

func HexEncode(b []byte) string {
	return hex.EncodeToString(b)
}

func HexDecode(s string) ([]byte, error) {
	return hex.DecodeString(s)
}
