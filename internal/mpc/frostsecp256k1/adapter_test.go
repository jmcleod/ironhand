package frostsecp256k1

import "testing"

func TestNewDescriptorSelectsSecp256k1SHA256(t *testing.T) {
	descriptor, err := NewDescriptor()
	if err != nil {
		t.Fatalf("NewDescriptor() error = %v", err)
	}
	if descriptor.Algorithm != Algorithm {
		t.Fatalf("Algorithm = %q, want %q", descriptor.Algorithm, Algorithm)
	}
	if descriptor.Curve != Curve {
		t.Fatalf("Curve = %q, want %q", descriptor.Curve, Curve)
	}
	if descriptor.Hash != Hash {
		t.Fatalf("Hash = %q, want %q", descriptor.Hash, Hash)
	}
	if descriptor.ContextString != ContextString {
		t.Fatalf("ContextString = %q, want %q", descriptor.ContextString, ContextString)
	}
	if descriptor.Domain != Domain {
		t.Fatalf("Domain = %q, want %q", descriptor.Domain, Domain)
	}
	if descriptor.CiphersuiteID == 0 {
		t.Fatal("CiphersuiteID = 0, want selected bytemare/frost ciphersuite")
	}
	if len(descriptor.ChainCompatibility) != len(ChainCompatibility()) {
		t.Fatalf("ChainCompatibility length = %d, want %d", len(descriptor.ChainCompatibility), len(ChainCompatibility()))
	}
}

func TestNewDescriptorReturnsCopyOfChainCompatibility(t *testing.T) {
	descriptor, err := NewDescriptor()
	if err != nil {
		t.Fatalf("NewDescriptor() error = %v", err)
	}
	descriptor.ChainCompatibility[0] = "mutated"

	next, err := NewDescriptor()
	if err != nil {
		t.Fatalf("NewDescriptor() second call error = %v", err)
	}
	if next.ChainCompatibility[0] == "mutated" {
		t.Fatal("ChainCompatibility shares backing storage with descriptor result")
	}
}
