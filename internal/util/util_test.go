package util

import (
	"bytes"
	"testing"
)

func TestAES(t *testing.T) {
	key, _ := NewAESKey()
	plainText := []byte("hello world")
	aad := []byte("context")

	t.Run("EncryptDecryptWithAAD", func(t *testing.T) {
		cipherText, err := EncryptAESWithAAD(plainText, key, aad)
		if err != nil {
			t.Fatalf("EncryptAESWithAAD failed: %v", err)
		}

		decrypted, err := DecryptAESWithAAD(cipherText, key, aad)
		if err != nil {
			t.Fatalf("DecryptAESWithAAD failed: %v", err)
		}

		if !bytes.Equal(plainText, decrypted) {
			t.Errorf("expected %s, got %s", plainText, decrypted)
		}
	})

	t.Run("TamperAAD", func(t *testing.T) {
		cipherText, _ := EncryptAESWithAAD(plainText, key, aad)
		_, err := DecryptAESWithAAD(cipherText, key, []byte("wrong context"))
		if err == nil {
			t.Error("expected error with wrong AAD, got nil")
		}
	})

	t.Run("TamperCipherText", func(t *testing.T) {
		cipherText, _ := EncryptAESWithAAD(plainText, key, aad)
		cipherText[len(cipherText)-1] ^= 0xFF
		_, err := DecryptAESWithAAD(cipherText, key, aad)
		if err == nil {
			t.Error("expected error with tampered ciphertext, got nil")
		}
	})

	t.Run("RejectBadKeySize", func(t *testing.T) {
		_, err := EncryptAESWithAAD(plainText, []byte("too short"), aad)
		if err == nil {
			t.Error("expected error with wrong key size, got nil")
		}
	})

	t.Run("EncryptDecryptLegacy", func(t *testing.T) {
		cipherText, err := EncryptAES(plainText, key)
		if err != nil {
			t.Fatalf("EncryptAES failed: %v", err)
		}

		decrypted, err := DecryptAES(cipherText, key)
		if err != nil {
			t.Fatalf("DecryptAES failed: %v", err)
		}

		if !bytes.Equal(plainText, decrypted) {
			t.Errorf("expected %s, got %s", plainText, decrypted)
		}
	})
}

func TestArgon2id(t *testing.T) {
	params := DefaultArgon2idParams()
	passphrase := "correct horse battery staple"
	salt := []byte("random salt")

	key, err := DeriveArgon2idKey(passphrase, salt, params)
	if err != nil {
		t.Fatalf("DeriveArgon2idKey failed: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("expected key length 32, got %d", len(key))
	}

	match, err := CompareArgon2idKey(passphrase, salt, params, key)
	if err != nil {
		t.Fatalf("CompareArgon2idKey failed: %v", err)
	}
	if !match {
		t.Error("expected CompareArgon2idKey to return true")
	}

	match, _ = CompareArgon2idKey("wrong passphrase", salt, params, key)
	if match {
		t.Error("expected CompareArgon2idKey to return false for wrong passphrase")
	}
}

func TestHKDF(t *testing.T) {
	seed := []byte("seed")
	salt := []byte("salt")
	info := []byte("info")

	key1, err := HKDF(seed, salt, info)
	if err != nil {
		t.Fatalf("HKDF failed: %v", err)
	}
	if len(key1) != 32 {
		t.Errorf("expected key length 32, got %d", len(key1))
	}

	key2, _ := HKDF(seed, salt, info)
	if !bytes.Equal(key1, key2) {
		t.Error("HKDF should be deterministic")
	}

	key3, _ := HKDF(seed, salt, []byte("different info"))
	if bytes.Equal(key1, key3) {
		t.Error("HKDF should produce different output with different info")
	}
}

func TestX25519(t *testing.T) {
	kpA, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("GenerateX25519Keypair A failed: %v", err)
	}

	kpB, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("GenerateX25519Keypair B failed: %v", err)
	}

	secretAB, err := SharedSecret(kpA.Private, kpB.Public)
	if err != nil {
		t.Fatalf("SharedSecret AB failed: %v", err)
	}

	secretBA, err := SharedSecret(kpB.Private, kpA.Public)
	if err != nil {
		t.Fatalf("SharedSecret BA failed: %v", err)
	}

	if !bytes.Equal(secretAB[:], secretBA[:]) {
		t.Error("Shared secrets should match")
	}
}

func TestBytes(t *testing.T) {
	a := []byte{0x01, 0x02, 0x03}
	b := []byte{0x10, 0x20, 0x30}
	expected := []byte{0x11, 0x22, 0x33}

	res, err := Xor(a, b)
	if err != nil {
		t.Fatalf("Xor failed: %v", err)
	}
	if !bytes.Equal(res, expected) {
		t.Errorf("Xor failed, expected %v, got %v", expected, res)
	}

	t.Run("Xor mismatched lengths", func(t *testing.T) {
		_, err := Xor([]byte{1, 2}, []byte{1})
		if err == nil {
			t.Error("expected error for mismatched lengths")
		}
	})

	copied := CopyBytes(a)
	if !bytes.Equal(copied, a) {
		t.Error("CopyBytes failed")
	}
	copied[0] = 0xFF
	if a[0] == 0xFF {
		t.Error("CopyBytes should return a new slice")
	}
}

func TestEncoding(t *testing.T) {
	s := "test string"
	encoded := HexEncode([]byte(s))
	decoded, err := HexDecode(encoded)
	if err != nil {
		t.Fatalf("HexDecode failed: %v", err)
	}
	if string(decoded) != s {
		t.Errorf("expected %s, got %s", s, string(decoded))
	}

	normalized := Normalize("cafe\u0301") // é in NFD
	if normalized != "cafe\u0301" {
		t.Errorf("Normalize failed, got %s", normalized)
	}
}

func TestRandom(t *testing.T) {
	t.Run("RandomBytes", func(t *testing.T) {
		b1, err := RandomBytes(32)
		if err != nil {
			t.Fatalf("RandomBytes failed: %v", err)
		}
		b2, err := RandomBytes(32)
		if err != nil {
			t.Fatalf("RandomBytes failed: %v", err)
		}
		if len(b1) != 32 {
			t.Errorf("expected 32 bytes, got %d", len(b1))
		}
		if bytes.Equal(b1, b2) {
			t.Error("RandomBytes should produce different outputs")
		}
	})

	t.Run("RandomChars", func(t *testing.T) {
		s1, err := RandomChars(10)
		if err != nil {
			t.Fatalf("RandomChars failed: %v", err)
		}
		s2, err := RandomChars(10)
		if err != nil {
			t.Fatalf("RandomChars failed: %v", err)
		}
		if len(s1) != 10 {
			t.Errorf("expected length 10, got %d", len(s1))
		}
		if s1 == s2 {
			t.Error("RandomChars should produce different outputs")
		}
	})

	t.Run("RandomInt", func(t *testing.T) {
		n, err := RandomInt()
		if err != nil {
			t.Fatalf("RandomInt failed: %v", err)
		}
		if n < 0 {
			t.Errorf("RandomInt returned negative number: %d", n)
		}
	})

	t.Run("RandomIntn", func(t *testing.T) {
		max := 100
		for i := 0; i < 100; i++ {
			n, err := RandomIntn(max)
			if err != nil {
				t.Fatalf("RandomIntn failed: %v", err)
			}
			if n < 0 || n >= max {
				t.Errorf("RandomIntn(%d) returned %d out of range", max, n)
			}
		}
	})
}

func TestDefaultArgon2idParams_MeetsOWASPMinimums(t *testing.T) {
	p := DefaultArgon2idParams()
	if p.Time < 3 {
		t.Errorf("default Time=%d is below OWASP recommended minimum of 3", p.Time)
	}
	if p.MemoryKiB < 64*1024 {
		t.Errorf("default MemoryKiB=%d is below OWASP recommended minimum of %d (64 MiB)", p.MemoryKiB, 64*1024)
	}
	if p.Parallelism < 1 {
		t.Errorf("default Parallelism=%d must be at least 1", p.Parallelism)
	}
	if p.KeyLen != 32 {
		t.Errorf("default KeyLen=%d must be 32", p.KeyLen)
	}
}

func TestArgon2idProfile_AllProfiles(t *testing.T) {
	profiles := []struct {
		name      string
		minTime   uint32
		minMemKiB uint32
	}{
		{KDFProfileInteractive, 2, 19 * 1024},
		{KDFProfileModerate, 3, 64 * 1024},
		{KDFProfileSensitive, 4, 128 * 1024},
	}

	for _, tc := range profiles {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Argon2idProfile(tc.name)
			if err != nil {
				t.Fatalf("Argon2idProfile(%q) failed: %v", tc.name, err)
			}
			if p.Time < tc.minTime {
				t.Errorf("profile %q: Time=%d, want at least %d", tc.name, p.Time, tc.minTime)
			}
			if p.MemoryKiB < tc.minMemKiB {
				t.Errorf("profile %q: MemoryKiB=%d, want at least %d", tc.name, p.MemoryKiB, tc.minMemKiB)
			}
			if p.Parallelism < 1 {
				t.Errorf("profile %q: Parallelism must be at least 1", tc.name)
			}
			if p.KeyLen != 32 {
				t.Errorf("profile %q: KeyLen=%d, want 32", tc.name, p.KeyLen)
			}
			// Every profile must pass validation.
			if err := ValidateArgon2idParams(p); err != nil {
				t.Errorf("profile %q failed validation: %v", tc.name, err)
			}
		})
	}
}

func TestArgon2idProfile_UnknownReturnsError(t *testing.T) {
	_, err := Argon2idProfile("nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown profile")
	}
}

func TestArgon2idProfile_Ordering(t *testing.T) {
	inter, _ := Argon2idProfile(KDFProfileInteractive)
	mod, _ := Argon2idProfile(KDFProfileModerate)
	sens, _ := Argon2idProfile(KDFProfileSensitive)

	// Profiles should be ordered by cost: interactive < moderate < sensitive.
	if inter.Time > mod.Time || inter.MemoryKiB > mod.MemoryKiB {
		t.Error("interactive profile should have lower or equal cost than moderate")
	}
	if mod.Time > sens.Time || mod.MemoryKiB > sens.MemoryKiB {
		t.Error("moderate profile should have lower or equal cost than sensitive")
	}
}

func TestValidateArgon2idParams(t *testing.T) {
	t.Run("ValidParams", func(t *testing.T) {
		p := DefaultArgon2idParams()
		if err := ValidateArgon2idParams(p); err != nil {
			t.Errorf("default params should be valid: %v", err)
		}
	})

	t.Run("KeyLenNot32", func(t *testing.T) {
		p := DefaultArgon2idParams()
		p.KeyLen = 16
		if err := ValidateArgon2idParams(p); err == nil {
			t.Error("expected error for KeyLen != 32")
		}
	})

	t.Run("TimeTooLow", func(t *testing.T) {
		p := DefaultArgon2idParams()
		p.Time = 0
		if err := ValidateArgon2idParams(p); err == nil {
			t.Error("expected error for Time=0")
		}
	})

	t.Run("MemoryTooLow", func(t *testing.T) {
		p := DefaultArgon2idParams()
		p.MemoryKiB = 1024 // 1 MiB — far below 19 MiB minimum
		if err := ValidateArgon2idParams(p); err == nil {
			t.Error("expected error for MemoryKiB=1024")
		}
	})

	t.Run("ParallelismTooLow", func(t *testing.T) {
		p := DefaultArgon2idParams()
		p.Parallelism = 0
		if err := ValidateArgon2idParams(p); err == nil {
			t.Error("expected error for Parallelism=0")
		}
	})

	t.Run("MinimumAcceptableParams", func(t *testing.T) {
		p := Argon2idParams{
			Time:        MinArgon2Time,
			MemoryKiB:   MinArgon2MemoryKiB,
			Parallelism: MinArgon2Parallel,
			KeyLen:      32,
		}
		if err := ValidateArgon2idParams(p); err != nil {
			t.Errorf("minimum acceptable params should be valid: %v", err)
		}
	})
}
