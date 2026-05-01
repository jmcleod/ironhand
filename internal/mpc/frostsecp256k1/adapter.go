package frostsecp256k1

import (
	"crypto"
	"fmt"

	"github.com/bytemare/frost"
)

const (
	Algorithm     = "frost-secp256k1-v1"
	Curve         = "secp256k1"
	Hash          = "SHA-256"
	ContextString = "FROST-secp256k1-SHA256-v1"
	Domain        = "mpc-frost-secp256k1-v1"
)

var chainCompatibility = []string{"evm-secp256k1", "bitcoin-secp256k1"}

type Descriptor struct {
	Algorithm          string
	Curve              string
	Hash               string
	ContextString      string
	Domain             string
	CiphersuiteID      byte
	ChainCompatibility []string
}

func NewDescriptor() (Descriptor, error) {
	if !frost.Secp256k1.Available() {
		return Descriptor{}, fmt.Errorf("FROST secp256k1 ciphersuite is unavailable")
	}
	group := frost.Secp256k1.Group()
	if !group.Available() {
		return Descriptor{}, fmt.Errorf("FROST secp256k1 group is unavailable")
	}
	if group.HashFunc() != crypto.SHA256 {
		return Descriptor{}, fmt.Errorf("FROST secp256k1 hash = %v, want SHA-256", group.HashFunc())
	}
	return Descriptor{
		Algorithm:          Algorithm,
		Curve:              Curve,
		Hash:               Hash,
		ContextString:      ContextString,
		Domain:             Domain,
		CiphersuiteID:      byte(frost.Secp256k1),
		ChainCompatibility: ChainCompatibility(),
	}, nil
}

func ChainCompatibility() []string {
	return append([]string(nil), chainCompatibility...)
}
