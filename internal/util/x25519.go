package util

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

type KeyPair struct {
	Private [32]byte
	Public  [32]byte
}

func GenerateX25519Keypair() (KeyPair, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return KeyPair{}, fmt.Errorf("error generating random bytes for X25519 private key: %w", err)
	}

	// Clamp the private key (though modern libraries might do this, it's good practice)
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)

	return KeyPair{
		Private: priv,
		Public:  pub,
	}, nil
}

func SharedSecret(priv [32]byte, pub [32]byte) ([32]byte, error) {
	secret, err := curve25519.X25519(priv[:], pub[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("error deriving shared secret: %w", err)
	}
	var res [32]byte
	copy(res[:], secret)
	return res, nil
}
