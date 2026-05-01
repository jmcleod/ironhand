package frostsecp256k1

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/bytemare/frost"
)

type vectorHex []byte

func (h *vectorHex) UnmarshalJSON(data []byte) error {
	var encoded string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return err
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		return err
	}
	*h = decoded
	return nil
}

type secp256k1Vector struct {
	Config struct {
		Name  string `json:"name"`
		Group string `json:"group"`
		Hash  string `json:"hash"`
	} `json:"config"`
	Inputs struct {
		GroupPublicKey  vectorHex `json:"group_public_key"`
		Message         vectorHex `json:"message"`
		ParticipantList []uint16  `json:"participant_list"`
	} `json:"inputs"`
	RoundOneOutputs struct {
		Outputs []struct {
			Identifier             uint16    `json:"identifier"`
			HidingNonceCommitment  vectorHex `json:"hiding_nonce_commitment"`
			BindingNonceCommitment vectorHex `json:"binding_nonce_commitment"`
			HidingNonceRandomness  vectorHex `json:"hiding_nonce_randomness"`
			BindingNonceRandomness vectorHex `json:"binding_nonce_randomness"`
			BindingFactorInput     vectorHex `json:"binding_factor_input"`
			BindingFactor          vectorHex `json:"binding_factor"`
		} `json:"outputs"`
	} `json:"round_one_outputs"`
	RoundTwoOutputs struct {
		Outputs []struct {
			Identifier uint16    `json:"identifier"`
			Signature  vectorHex `json:"sig_share"`
		} `json:"outputs"`
	} `json:"round_two_outputs"`
	FinalOutput struct {
		Signature vectorHex `json:"sig"`
	} `json:"final_output"`
}

func loadSecp256k1Vector(t *testing.T) secp256k1Vector {
	t.Helper()
	data, err := os.ReadFile("testdata/rfc9591-frost-secp256k1-sha256.json")
	if err != nil {
		t.Fatalf("read vector fixture: %v", err)
	}
	var vector secp256k1Vector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatalf("decode vector fixture: %v", err)
	}
	return vector
}

func TestRFC9591Secp256k1VectorVerifiesFinalSignature(t *testing.T) {
	vector := loadSecp256k1Vector(t)
	if vector.Config.Name != "FROST(secp256k1, SHA-256)" {
		t.Fatalf("vector name = %q, want FROST(secp256k1, SHA-256)", vector.Config.Name)
	}
	if vector.Config.Group != Curve {
		t.Fatalf("vector group = %q, want %q", vector.Config.Group, Curve)
	}
	if vector.Config.Hash != Hash {
		t.Fatalf("vector hash = %q, want %q", vector.Config.Hash, Hash)
	}
	if err := VerifySignature(vector.Inputs.Message, vector.Inputs.GroupPublicKey, vector.FinalOutput.Signature); err != nil {
		t.Fatalf("VerifySignature() error = %v", err)
	}
}

func TestRFC9591Secp256k1VectorRejectsWrongMessage(t *testing.T) {
	vector := loadSecp256k1Vector(t)
	message := append([]byte(nil), vector.Inputs.Message...)
	message[0] ^= 0x01
	if err := VerifySignature(message, vector.Inputs.GroupPublicKey, vector.FinalOutput.Signature); err == nil {
		t.Fatal("VerifySignature() error = nil, want wrong-message rejection")
	}
}

func TestRFC9591Secp256k1VectorRejectsMalformedSignature(t *testing.T) {
	vector := loadSecp256k1Vector(t)
	signature := vector.FinalOutput.Signature[:len(vector.FinalOutput.Signature)-1]
	if _, err := DecodeSignature(signature); err == nil {
		t.Fatal("DecodeSignature() error = nil, want malformed-signature rejection")
	}
}

func TestRFC9591Secp256k1VectorRejectsMalformedCommitment(t *testing.T) {
	vector := loadSecp256k1Vector(t)
	group := frost.Secp256k1.Group()
	commitment := group.NewElement()
	malformed := vector.RoundOneOutputs.Outputs[0].HidingNonceCommitment[:len(vector.RoundOneOutputs.Outputs[0].HidingNonceCommitment)-1]
	if err := commitment.Decode(malformed); err == nil {
		t.Fatal("commitment.Decode() error = nil, want malformed-commitment rejection")
	}
}

func TestRFC9591Secp256k1VectorRejectsWrongCiphersuite(t *testing.T) {
	vector := loadSecp256k1Vector(t)
	encoded := append([]byte{byte(frost.P256)}, vector.FinalOutput.Signature...)
	if _, err := DecodeEncodedSignature(encoded); err == nil {
		t.Fatal("DecodeEncodedSignature() error = nil, want wrong-ciphersuite rejection")
	}
}

func TestRFC9591Secp256k1VectorDecodesCommitmentsAndShares(t *testing.T) {
	vector := loadSecp256k1Vector(t)
	group := frost.Secp256k1.Group()

	if len(vector.RoundOneOutputs.Outputs) != len(vector.Inputs.ParticipantList) {
		t.Fatalf("round one outputs = %d, want %d participants", len(vector.RoundOneOutputs.Outputs), len(vector.Inputs.ParticipantList))
	}
	for _, output := range vector.RoundOneOutputs.Outputs {
		hidingCommitment := group.NewElement()
		if err := hidingCommitment.Decode(output.HidingNonceCommitment); err != nil {
			t.Fatalf("decode hiding nonce commitment for participant %d: %v", output.Identifier, err)
		}
		bindingCommitment := group.NewElement()
		if err := bindingCommitment.Decode(output.BindingNonceCommitment); err != nil {
			t.Fatalf("decode binding nonce commitment for participant %d: %v", output.Identifier, err)
		}
		bindingFactor := group.NewScalar()
		if err := bindingFactor.Decode(output.BindingFactor); err != nil {
			t.Fatalf("decode binding factor for participant %d: %v", output.Identifier, err)
		}
		if len(output.HidingNonceRandomness) == 0 || len(output.BindingNonceRandomness) == 0 || len(output.BindingFactorInput) == 0 {
			t.Fatalf("participant %d has incomplete commitment transcript material", output.Identifier)
		}
	}

	for _, output := range vector.RoundTwoOutputs.Outputs {
		signatureShare := group.NewScalar()
		if err := signatureShare.Decode(output.Signature); err != nil {
			t.Fatalf("decode signature share for participant %d: %v", output.Identifier, err)
		}
	}
}
