package crypto

import (
	"bytes"
	"testing"
)

func TestSecretKey(t *testing.T) {
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatalf("NewSecretKey failed: %v", err)
	}
	s := sk.String()
	parsed, err := ParseSecretKey(s)
	if err != nil {
		t.Fatalf("ParseSecretKey failed: %v", err)
	}

	if parsed.ID() != sk.ID() {
		t.Errorf("expected ID %s, got %s", sk.ID(), parsed.ID())
	}
	if !bytes.Equal(parsed.Bytes(), sk.Bytes()) {
		t.Errorf("expected secret %v, got %v", sk.Bytes(), parsed.Bytes())
	}
	if parsed.Version() != sk.Version() {
		t.Errorf("expected version %d, got %d", sk.Version(), parsed.Version())
	}
}

func TestParseSecretKey_Invalid(t *testing.T) {
	tests := []struct {
		name string
		str  string
	}{
		{"Empty", ""},
		{"WrongPrefix", "X1-ABCDEF-ABCDEF-ABCDE-ABCDE-ABCDE-ABCDE"},
		{"TooShortID", "V1-ABCDE-ABCDEF-ABCDE-ABCDE-ABCDE-ABCDE"},
		{"TooLongID", "V1-ABCDEFG-ABCDEF-ABCDE-ABCDE-ABCDE-ABCDE"},
		{"InvalidChars", "V1-ABC!@#-ABCDEF-ABCDE-ABCDE-ABCDE-ABCDE"},
		{"WrongSegmentCount", "V1-ABCDEF-ABCDEF-ABCDE-ABCDE-ABCDE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseSecretKey(tt.str)
			if err == nil {
				t.Errorf("ParseSecretKey(%q) expected error, got nil", tt.str)
			}
		})
	}
}

func TestDeriveMUK(t *testing.T) {
	secretKey := []byte("secret-key-material-32-bytes-!!!!")
	passphrase := "my-secure-passphrase"
	saltPass := []byte("salt-pass")
	saltSecret := []byte("salt-secret")
	info := []byte("custom-info")

	t.Run("DefaultOptions", func(t *testing.T) {
		muk1, err := DeriveMUK(secretKey, passphrase)
		if err != nil {
			t.Fatalf("DeriveMUK failed: %v", err)
		}
		muk2, err := DeriveMUK(secretKey, passphrase)
		if err != nil {
			t.Fatalf("DeriveMUK failed: %v", err)
		}
		if !bytes.Equal(muk1, muk2) {
			t.Error("DeriveMUK should be deterministic with same inputs")
		}
	})

	t.Run("WithAllOptions", func(t *testing.T) {
		params := DefaultArgon2idParams()
		params.Time = 1 // Speed up test

		muk1, err := DeriveMUK(secretKey, passphrase,
			WithSaltPass(saltPass),
			WithSaltSecret(saltSecret),
			WithArgonParams(params),
			WithInfo(info),
		)
		if err != nil {
			t.Fatalf("DeriveMUK failed: %v", err)
		}

		muk2, err := DeriveMUK(secretKey, passphrase,
			WithSaltPass(saltPass),
			WithSaltSecret(saltSecret),
			WithArgonParams(params),
			WithInfo(info),
		)
		if err != nil {
			t.Fatalf("DeriveMUK failed: %v", err)
		}

		if !bytes.Equal(muk1, muk2) {
			t.Error("DeriveMUK should be deterministic with same options")
		}

		// Verify that changing an option changes the MUK
		muk3, _ := DeriveMUK(secretKey, passphrase, WithSaltPass([]byte("other")))
		if bytes.Equal(muk1, muk3) {
			t.Error("MUK should change when saltPass changes")
		}
	})
}

func TestDefaultArgon2idParams(t *testing.T) {
	params := DefaultArgon2idParams()
	if params.MemoryKiB == 0 || params.Time == 0 || params.Parallelism == 0 {
		t.Errorf("DefaultArgon2idParams returned zeroed params: %+v", params)
	}
	// Default must be at least the moderate profile.
	if params.Time < 3 {
		t.Errorf("default Time=%d should be at least 3 (moderate profile)", params.Time)
	}
	if params.MemoryKiB < 64*1024 {
		t.Errorf("default MemoryKiB=%d should be at least 64 MiB (moderate profile)", params.MemoryKiB)
	}
}

func TestArgon2idProfile_ExposedThroughCryptoPackage(t *testing.T) {
	p, err := Argon2idProfile(KDFProfileSensitive)
	if err != nil {
		t.Fatalf("Argon2idProfile failed: %v", err)
	}
	if p.Time < 4 || p.MemoryKiB < 128*1024 {
		t.Errorf("sensitive profile params too low: %+v", p)
	}
}

func TestValidateArgon2idParams_ExposedThroughCryptoPackage(t *testing.T) {
	p := DefaultArgon2idParams()
	if err := ValidateArgon2idParams(p); err != nil {
		t.Errorf("default params should be valid: %v", err)
	}
	p.MemoryKiB = 1
	if err := ValidateArgon2idParams(p); err == nil {
		t.Error("expected error for extremely low memory")
	}
}

func TestGenerateX25519Keypair(t *testing.T) {
	kp, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("GenerateX25519Keypair failed: %v", err)
	}
	if len(kp.Public) == 0 || len(kp.Private) == 0 {
		t.Error("GenerateX25519Keypair returned empty keys")
	}
}
