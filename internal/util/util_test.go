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
