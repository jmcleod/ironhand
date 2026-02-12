package key

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestKey(t *testing.T) {
	t.Run("Symmetric", func(t *testing.T) {
		k, err := NewSymmetricKey()
		if err != nil {
			t.Fatalf("NewSymmetricKey failed: %v", err)
		}
		plainText := []byte("hello")
		cipherText, err := k.Encrypt(plainText)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}
		decrypted, err := k.Decrypt(cipherText)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}
		if !bytes.Equal(plainText, decrypted) {
			t.Error("Decrypted text does not match plaintext")
		}
	})
}

func TestEncryptedKey(t *testing.T) {
	k, _ := NewSymmetricKey()
	master, _ := NewSymmetricKey()

	ek, err := k.EncryptKey(master)
	if err != nil {
		t.Fatalf("EncryptKey failed: %v", err)
	}

	if ek.EncryptedBy() != master.ID() {
		t.Errorf("expected encrypted by %s, got %s", master.ID(), ek.EncryptedBy())
	}

	dec, err := ek.Decrypter(master)
	if err != nil {
		t.Fatalf("Decrypter failed: %v", err)
	}
	if dec.ID() != k.ID() {
		t.Errorf("expected decrypter ID %s, got %s", k.ID(), dec.ID())
	}

	// Test Rotation
	newMaster, _ := NewSymmetricKey()
	err = ek.Rotate(master, newMaster)
	if err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}
	if ek.EncryptedBy() != newMaster.ID() {
		t.Errorf("expected new master ID %s, got %s", newMaster.ID(), ek.EncryptedBy())
	}

	_, err = ek.Decrypter(newMaster)
	if err != nil {
		t.Fatalf("Decrypter after rotation failed: %v", err)
	}
}

func TestJSON(t *testing.T) {
	t.Run("KeyJSON", func(t *testing.T) {
		k, _ := NewSymmetricKey()
		data, err := json.Marshal(k)
		if err != nil {
			t.Fatalf("Marshal failed: %v", err)
		}

		k2, err := UnmarshalKey(data)
		if err != nil {
			t.Fatalf("UnmarshalKey failed: %v", err)
		}

		if k2.ID() != k.ID() {
			t.Errorf("expected ID %s, got %s", k.ID(), k2.ID())
		}
	})

	t.Run("EncryptedKeyJSON", func(t *testing.T) {
		k, _ := NewSymmetricKey()
		master, _ := NewSymmetricKey()
		ek, _ := k.EncryptKey(master)

		data, err := json.Marshal(ek)
		if err != nil {
			t.Fatalf("Marshal failed: %v", err)
		}

		ek2, err := UnmarshalEncryptedKey(data)
		if err != nil {
			t.Fatalf("UnmarshalEncryptedKey failed: %v", err)
		}

		if ek2.ID() != ek.ID() {
			t.Errorf("expected ID %s, got %s", ek.ID(), ek2.ID())
		}
	})

	t.Run("TypeJSON", func(t *testing.T) {
		v := Symmetric
		data, err := v.MarshalJSON()
		if err != nil {
			t.Fatalf("Marshal failed for %v: %v", v, err)
		}
		var v2 Type
		if err := v2.UnmarshalJSON(data); err != nil {
			t.Fatalf("Unmarshal failed for %v: %v", v, err)
		}
		if v != v2 {
			t.Errorf("expected %v, got %v", v, v2)
		}
	})
}
