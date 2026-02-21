package api

import (
	"strings"
	"testing"
)

func TestGenerateRecoveryCodes(t *testing.T) {
	plaintext, hashed, err := generateRecoveryCodes(8)
	if err != nil {
		t.Fatalf("generateRecoveryCodes: %v", err)
	}
	if len(plaintext) != 8 {
		t.Fatalf("expected 8 plaintext codes, got %d", len(plaintext))
	}
	if len(hashed) != 8 {
		t.Fatalf("expected 8 hashed codes, got %d", len(hashed))
	}

	// Verify format: XXXX-XXXX-XXXX
	for i, code := range plaintext {
		parts := strings.Split(code, "-")
		if len(parts) != 3 {
			t.Errorf("code %d: expected 3 segments, got %d: %q", i, len(parts), code)
			continue
		}
		for j, part := range parts {
			if len(part) != 4 {
				t.Errorf("code %d segment %d: expected 4 chars, got %d: %q", i, j, len(part), part)
			}
		}
	}

	// Verify all codes are unique.
	seen := make(map[string]bool)
	for _, code := range plaintext {
		if seen[code] {
			t.Errorf("duplicate code: %q", code)
		}
		seen[code] = true
	}

	// Verify no hashed code is pre-used.
	for i, h := range hashed {
		if h.Used {
			t.Errorf("hashed code %d is pre-used", i)
		}
		if h.Hash == "" {
			t.Errorf("hashed code %d has empty hash", i)
		}
	}
}

func TestValidateRecoveryCode_RoundTrip(t *testing.T) {
	plaintext, hashed, err := generateRecoveryCodes(4)
	if err != nil {
		t.Fatalf("generateRecoveryCodes: %v", err)
	}

	// Each plaintext code should match its hashed counterpart.
	for i, code := range plaintext {
		idx, ok := validateRecoveryCode(hashed, code)
		if !ok {
			t.Errorf("code %d: expected valid, got invalid", i)
			continue
		}
		if idx != i {
			t.Errorf("code %d: expected index %d, got %d", i, i, idx)
		}
	}
}

func TestValidateRecoveryCode_CaseInsensitive(t *testing.T) {
	plaintext, hashed, err := generateRecoveryCodes(1)
	if err != nil {
		t.Fatalf("generateRecoveryCodes: %v", err)
	}

	// Uppercase version should also validate.
	upper := strings.ToUpper(plaintext[0])
	idx, ok := validateRecoveryCode(hashed, upper)
	if !ok {
		t.Error("uppercase code should be valid")
	}
	if idx != 0 {
		t.Errorf("expected index 0, got %d", idx)
	}
}

func TestValidateRecoveryCode_WithoutDashes(t *testing.T) {
	plaintext, hashed, err := generateRecoveryCodes(1)
	if err != nil {
		t.Fatalf("generateRecoveryCodes: %v", err)
	}

	// Code without dashes should also validate.
	noDashes := strings.ReplaceAll(plaintext[0], "-", "")
	idx, ok := validateRecoveryCode(hashed, noDashes)
	if !ok {
		t.Error("code without dashes should be valid")
	}
	if idx != 0 {
		t.Errorf("expected index 0, got %d", idx)
	}
}

func TestValidateRecoveryCode_UsedCodeRejected(t *testing.T) {
	plaintext, hashed, err := generateRecoveryCodes(2)
	if err != nil {
		t.Fatalf("generateRecoveryCodes: %v", err)
	}

	// Mark the first code as used.
	hashed[0].Used = true

	_, ok := validateRecoveryCode(hashed, plaintext[0])
	if ok {
		t.Error("used code should be rejected")
	}

	// Second code should still work.
	idx, ok := validateRecoveryCode(hashed, plaintext[1])
	if !ok {
		t.Error("unused second code should be valid")
	}
	if idx != 1 {
		t.Errorf("expected index 1, got %d", idx)
	}
}

func TestValidateRecoveryCode_InvalidCode(t *testing.T) {
	_, hashed, err := generateRecoveryCodes(4)
	if err != nil {
		t.Fatalf("generateRecoveryCodes: %v", err)
	}

	_, ok := validateRecoveryCode(hashed, "0000-0000-0000")
	if ok {
		t.Error("bogus code should not validate (unless astronomically unlucky)")
	}

	_, ok = validateRecoveryCode(hashed, "")
	if ok {
		t.Error("empty code should not validate")
	}

	_, ok = validateRecoveryCode(hashed, "not-a-code")
	if ok {
		t.Error("garbage input should not validate")
	}
}

func TestCountUnusedRecoveryCodes(t *testing.T) {
	_, hashed, err := generateRecoveryCodes(8)
	if err != nil {
		t.Fatalf("generateRecoveryCodes: %v", err)
	}

	if n := countUnusedRecoveryCodes(hashed); n != 8 {
		t.Errorf("expected 8 unused, got %d", n)
	}

	hashed[0].Used = true
	hashed[3].Used = true
	if n := countUnusedRecoveryCodes(hashed); n != 6 {
		t.Errorf("expected 6 unused, got %d", n)
	}

	for i := range hashed {
		hashed[i].Used = true
	}
	if n := countUnusedRecoveryCodes(hashed); n != 0 {
		t.Errorf("expected 0 unused, got %d", n)
	}
}

func TestCountUnusedRecoveryCodes_Nil(t *testing.T) {
	if n := countUnusedRecoveryCodes(nil); n != 0 {
		t.Errorf("nil slice should return 0, got %d", n)
	}
}
