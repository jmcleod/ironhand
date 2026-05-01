package frostsecp256k1

import (
	"crypto"
	"fmt"

	"github.com/bytemare/ecc"
	"github.com/bytemare/frost"
)

const (
	Algorithm     = "frost-secp256k1-v1"
	Curve         = "secp256k1"
	Hash          = "SHA-256"
	Ciphersuite   = "FROST(secp256k1, SHA-256)"
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

func DecodeSignature(signature []byte) (*frost.Signature, error) {
	encoded := make([]byte, 0, len(signature)+1)
	encoded = append(encoded, byte(frost.Secp256k1))
	encoded = append(encoded, signature...)
	return DecodeEncodedSignature(encoded)
}

func DecodeEncodedSignature(encoded []byte) (*frost.Signature, error) {
	var sig frost.Signature
	if err := sig.Decode(encoded); err != nil {
		return nil, err
	}
	if sig.Group != frost.Secp256k1.Group() {
		return nil, fmt.Errorf("FROST signature group = %s, want %s", sig.Group, frost.Secp256k1.Group())
	}
	return &sig, nil
}

func DecodePublicKey(encoded []byte) (*ecc.Element, error) {
	publicKey := frost.Secp256k1.Group().NewElement()
	if err := publicKey.Decode(encoded); err != nil {
		return nil, err
	}
	return publicKey, nil
}

func VerifySignature(message, publicKey, signature []byte) error {
	decodedPublicKey, err := DecodePublicKey(publicKey)
	if err != nil {
		return err
	}
	decodedSignature, err := DecodeSignature(signature)
	if err != nil {
		return err
	}
	return frost.VerifySignature(frost.Secp256k1, message, decodedSignature, decodedPublicKey)
}
