package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	// recoveryCodeCount is the number of codes generated per batch.
	recoveryCodeCount = 8
	// recoveryCodeSegmentLen is the number of hex characters per segment.
	recoveryCodeSegmentLen = 4
	// recoveryCodeSegments is the number of dash-separated segments.
	recoveryCodeSegments = 3
	// recoveryCodeByteLen is the number of random bytes needed (6 bytes = 12 hex chars).
	recoveryCodeByteLen = 6
)

// generateRecoveryCodes creates a batch of single-use recovery codes.
// It returns the plaintext codes (to display to the user once) and their
// SHA-256 hashed counterparts (to persist in the account record).
func generateRecoveryCodes(count int) ([]string, []HashedRecoveryCode, error) {
	plaintext := make([]string, count)
	hashed := make([]HashedRecoveryCode, count)

	for i := 0; i < count; i++ {
		buf := make([]byte, recoveryCodeByteLen)
		if _, err := rand.Read(buf); err != nil {
			return nil, nil, fmt.Errorf("generating recovery code: %w", err)
		}
		hexStr := hex.EncodeToString(buf) // 12 hex chars
		// Format as XXXX-XXXX-XXXX
		code := hexStr[:4] + "-" + hexStr[4:8] + "-" + hexStr[8:12]
		plaintext[i] = code
		hashed[i] = HashedRecoveryCode{
			Hash: hashRecoveryCode(code),
			Used: false,
		}
	}
	return plaintext, hashed, nil
}

// hashRecoveryCode computes the hex-encoded SHA-256 hash of a recovery code.
// The code is normalised to lowercase with dashes removed before hashing.
func hashRecoveryCode(code string) string {
	normalised := strings.ToLower(strings.ReplaceAll(code, "-", ""))
	sum := sha256.Sum256([]byte(normalised))
	return hex.EncodeToString(sum[:])
}

// validateRecoveryCode checks a candidate code against the stored hashed codes.
// It uses constant-time comparison to prevent timing attacks. Returns the index
// of the matching (unused) code and whether a match was found.
func validateRecoveryCode(codes []HashedRecoveryCode, input string) (int, bool) {
	candidateHash := hashRecoveryCode(input)
	candidateBytes := []byte(candidateHash)

	for i, code := range codes {
		if code.Used {
			continue
		}
		storedBytes := []byte(code.Hash)
		if subtle.ConstantTimeCompare(candidateBytes, storedBytes) == 1 {
			return i, true
		}
	}
	return -1, false
}

// countUnusedRecoveryCodes returns the number of recovery codes that have not
// been consumed.
func countUnusedRecoveryCodes(codes []HashedRecoveryCode) int {
	n := 0
	for _, c := range codes {
		if !c.Used {
			n++
		}
	}
	return n
}
