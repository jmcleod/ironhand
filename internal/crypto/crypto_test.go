package icrypto

import (
	"bytes"
	"testing"

	"github.com/jmcleod/ironhand/internal/util"
)

func TestAAD(t *testing.T) {
	vaultID := "vault-123"
	recordID := "record-456"
	epoch := uint64(1)
	ver := 1

	aad1 := AADRecord(vaultID, "ITEM", recordID, epoch, ver)
	aad2 := AADRecord(vaultID, "ITEM", recordID, epoch, ver)

	if !bytes.Equal(aad1, aad2) {
		t.Error("AADRecord should be deterministic")
	}

	aad3 := AADRecord(vaultID, "ITEM", "different-record", epoch, ver)
	if bytes.Equal(aad1, aad3) {
		t.Error("AADRecord should be different for different recordIDs")
	}

	aadField := AADFieldContent(vaultID, "item-1", "password", 10, 1, 1)
	if len(aadField) == 0 {
		t.Error("AADFieldContent produced empty AAD")
	}

	// Different field names must produce different AAD
	aadField2 := AADFieldContent(vaultID, "item-1", "username", 10, 1, 1)
	if bytes.Equal(aadField, aadField2) {
		t.Error("AADFieldContent should be different for different field names")
	}
}

func TestMemberWrap(t *testing.T) {
	kp, _ := util.GenerateX25519Keypair()
	kek := []byte("this-is-a-32-byte-kek-0123456789")
	aad := []byte("some-aad")

	wrap, err := SealToMember(kp.Public, kek, aad)
	if err != nil {
		t.Fatalf("SealToMember failed: %v", err)
	}

	if wrap.Ver != 1 {
		t.Errorf("expected version 1, got %d", wrap.Ver)
	}

	opened, err := OpenFromMember(kp.Private, wrap, aad)
	if err != nil {
		t.Fatalf("OpenFromMember failed: %v", err)
	}

	if !bytes.Equal(kek, opened) {
		t.Errorf("expected %x, got %x", kek, opened)
	}

	t.Run("TamperAAD", func(t *testing.T) {
		_, err := OpenFromMember(kp.Private, wrap, []byte("wrong-aad"))
		if err == nil {
			t.Error("expected error with wrong AAD, got nil")
		}
	})

	t.Run("TamperCiphertext", func(t *testing.T) {
		wrapCopy := *wrap
		wrapCopy.Ciphertext = bytes.Clone(wrap.Ciphertext)
		wrapCopy.Ciphertext[0] ^= 0xFF
		_, err := OpenFromMember(kp.Private, &wrapCopy, aad)
		if err == nil {
			t.Error("expected error with tampered ciphertext, got nil")
		}
	})
}

func TestRecordKeys(t *testing.T) {
	muk := []byte("muk-0123456789-0123456789-012345")
	vaultID := "vault-uuid"

	key1, err := DeriveRecordKey(muk, vaultID)
	if err != nil {
		t.Fatalf("DeriveRecordKey failed: %v", err)
	}

	key2, _ := DeriveRecordKey(muk, vaultID)
	if !bytes.Equal(key1, key2) {
		t.Error("DeriveRecordKey should be deterministic")
	}

	key3, _ := DeriveRecordKey(muk, "other-vault")
	if bytes.Equal(key1, key3) {
		t.Error("DeriveRecordKey should be different for different vaults")
	}
}
