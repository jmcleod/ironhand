package storage

import (
	"bytes"
	"testing"

	"github.com/jmcleod/ironhand/internal/util"
)

func TestEnvelope(t *testing.T) {
	key, _ := util.NewAESKey()
	plain := []byte("top secret")
	aad := []byte("context")

	env, err := SealRecord(key, plain, aad)
	if err != nil {
		t.Fatalf("SealRecord failed: %v", err)
	}

	if env.Ver != 1 {
		t.Errorf("expected version 1, got %d", env.Ver)
	}

	decrypted, err := OpenRecord(key, env, aad)
	if err != nil {
		t.Fatalf("OpenRecord failed: %v", err)
	}

	if !bytes.Equal(plain, decrypted) {
		t.Errorf("expected %s, got %s", plain, decrypted)
	}

	t.Run("WrongAAD", func(t *testing.T) {
		_, err := OpenRecord(key, env, []byte("wrong context"))
		if err == nil {
			t.Error("expected error with wrong AAD, got nil")
		}
	})

	t.Run("WrongKey", func(t *testing.T) {
		wrongKey, _ := util.NewAESKey()
		_, err := OpenRecord(wrongKey, env, aad)
		if err == nil {
			t.Error("expected error with wrong key, got nil")
		}
	})

	t.Run("UnsupportedVersion", func(t *testing.T) {
		badEnv := *env
		badEnv.Ver = 99
		_, err := OpenRecord(key, &badEnv, aad)
		if err == nil {
			t.Error("expected error with unsupported version, got nil")
		}
	})

	t.Run("UnsupportedScheme", func(t *testing.T) {
		badEnv := *env
		badEnv.Scheme = "unknown"
		_, err := OpenRecord(key, &badEnv, aad)
		if err == nil {
			t.Error("expected error with unsupported scheme, got nil")
		}
	})
}
