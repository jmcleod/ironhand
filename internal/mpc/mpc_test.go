package mpc

import (
	"math/big"
	"testing"
	"time"
)

func TestDistributedKeyGenerationAndSignatureMath(t *testing.T) {
	parties := []PartyInfo{{ID: 1}, {ID: 2}, {ID: 3}}
	polys := make(map[int][]*big.Int)
	commitments := make([]PublicCommitment, 0, len(parties))

	for _, party := range parties {
		poly, err := GeneratePolynomial(2)
		if err != nil {
			t.Fatalf("GeneratePolynomial() error = %v", err)
		}
		polys[party.ID] = poly
		commitments = append(commitments, CommitmentsForPolynomial(party.ID, poly))
	}

	key, err := NewKeyMeta("test", 2, parties, commitments)
	if err != nil {
		t.Fatalf("NewKeyMeta() error = %v", err)
	}

	localShares := make(map[int]*big.Int)
	for _, receiver := range parties {
		localShares[receiver.ID] = big.NewInt(0)
		for _, dealer := range parties {
			share := EvalPolynomial(polys[dealer.ID], big.NewInt(int64(receiver.ID)))
			localShares[receiver.ID].Add(localShares[receiver.ID], share)
			localShares[receiver.ID].Mod(localShares[receiver.ID], curve().Params().N)
		}
	}

	participants := []int{1, 3}
	message := []byte("hello distributed threshold schnorr")
	commitmentsForSign := make([]Commitment, 0, len(participants))
	nonces := make(map[int]*big.Int)
	for _, partyID := range participants {
		nonce, err := RandomScalar()
		if err != nil {
			t.Fatalf("RandomScalar() error = %v", err)
		}
		nonces[partyID] = nonce
		commitmentsForSign = append(commitmentsForSign, Commitment{PartyID: partyID, R: ScalarBasePoint(nonce)})
	}

	r, err := AggregateCommitments(commitmentsForSign)
	if err != nil {
		t.Fatalf("AggregateCommitments() error = %v", err)
	}
	challenge, err := Challenge(key.PublicKey, r, message)
	if err != nil {
		t.Fatalf("Challenge() error = %v", err)
	}

	shares := make([]ShareProof, 0, len(participants))
	for _, partyID := range participants {
		z, err := SignShare(localShares[partyID], nonces[partyID], challenge, partyID, participants)
		if err != nil {
			t.Fatalf("SignShare() error = %v", err)
		}
		shares = append(shares, ShareProof{PartyID: partyID, Z: EncodeScalar(z)})
	}
	z, err := CombineSignatureShares(shares)
	if err != nil {
		t.Fatalf("CombineSignatureShares() error = %v", err)
	}

	sig := &Signature{
		Curve:       CurveName,
		R:           r,
		Z:           z,
		Commitments: commitmentsForSign,
		Shares:      shares,
	}
	if !key.Verify(message, sig) {
		t.Fatal("Verify() returned false for a valid signature")
	}
	if key.Verify([]byte("tampered"), sig) {
		t.Fatal("Verify() returned true for a tampered message")
	}
}

func TestExperimentalProviderIsNotProductionReady(t *testing.T) {
	provider, err := GetProvider(AlgorithmExperimentalP256Schnorr)
	if err != nil {
		t.Fatalf("GetProvider() error = %v", err)
	}
	info := provider.Info()
	if info.ProductionReady {
		t.Fatalf("%s must not be marked production ready", info.Algorithm)
	}
	if info.Status != ProviderStatusExperimental {
		t.Fatalf("%s status = %q, want %q", info.Algorithm, info.Status, ProviderStatusExperimental)
	}
	if len(info.ProductionBlockers) == 0 {
		t.Fatalf("%s must publish production blockers while experimental", info.Algorithm)
	}
	if info.SupportsReshare {
		t.Fatalf("%s must not advertise resharing support", info.Algorithm)
	}
	for _, chain := range info.ChainCompatibility {
		if chain == "evm-secp256k1" || chain == "bitcoin-secp256k1" {
			t.Fatalf("%s must not advertise production chain compatibility: %q", info.Algorithm, chain)
		}
	}
}

func TestFROSTSecp256k1ProviderIsReservedUntilImplemented(t *testing.T) {
	provider, err := GetProvider(AlgorithmFROSTSecp256k1)
	if err != nil {
		t.Fatalf("GetProvider() error = %v", err)
	}
	info := provider.Info()
	if info.ProductionReady {
		t.Fatalf("%s must not be marked production ready before implementation and review", info.Algorithm)
	}
	if info.SupportsKeygen || info.SupportsSigning || info.SupportsReshare {
		t.Fatalf("%s must not advertise usable capabilities before implementation", info.Algorithm)
	}
	if len(info.ProductionBlockers) == 0 {
		t.Fatalf("%s must publish production blockers while reserved", info.Algorithm)
	}
	if _, err := provider.NewKeyMeta("key-1", 2, nil, nil); err == nil {
		t.Fatalf("%s NewKeyMeta() error = nil, want unsupported error", info.Algorithm)
	}
}

func TestSupportedProvidersExposeExperimentalAndReservedProductionProvider(t *testing.T) {
	providers := SupportedProviders()
	got := make(map[string]ProviderInfo, len(providers))
	for _, provider := range providers {
		got[provider.Algorithm] = provider
	}
	if _, ok := got[AlgorithmExperimentalP256Schnorr]; !ok {
		t.Fatalf("SupportedProviders() missing %s", AlgorithmExperimentalP256Schnorr)
	}
	frost, ok := got[AlgorithmFROSTSecp256k1]
	if !ok {
		t.Fatalf("SupportedProviders() missing %s", AlgorithmFROSTSecp256k1)
	}
	if frost.Curve != "secp256k1" {
		t.Fatalf("%s curve = %q, want secp256k1", frost.Algorithm, frost.Curve)
	}
}

func TestNormalizeParticipantsRejectsDuplicates(t *testing.T) {
	_, err := NormalizeParticipants([]int{1, 1}, 2, []int{1, 2, 3})
	if err == nil {
		t.Fatal("NormalizeParticipants() error = nil, want duplicate error")
	}
}

func TestFragmentEnvelopeHashAndAttestationBindCiphertext(t *testing.T) {
	_, approvalPriv, identity, err := GenerateSignerIdentity(1, "party-1", "https://signer-1.test")
	if err != nil {
		t.Fatalf("GenerateSignerIdentity() error = %v", err)
	}
	fragment, err := EncryptFragment("key-1", 1, identity.EncryptionPublicKey, []byte("share"), Point{X: "x", Y: "y"})
	if err != nil {
		t.Fatalf("EncryptFragment() error = %v", err)
	}
	hash, err := FragmentEnvelopeHash(fragment)
	if err != nil {
		t.Fatalf("FragmentEnvelopeHash() error = %v", err)
	}
	attestation, err := SignFragmentAttestation(approvalPriv, FragmentAttestation{
		VaultID:               "vault-1",
		DKGSessionID:          "dkg-1",
		KeyID:                 fragment.KeyID,
		PartyID:               fragment.PartyID,
		PublicShareCommitment: fragment.PublicShareCommitment,
		CommitmentsHash:       "commitments",
		FragmentEnvelopeHash:  hash,
		ApprovalPublicKey:     identity.ApprovalPublicKey,
		CreatedAt:             time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("SignFragmentAttestation() error = %v", err)
	}
	if !VerifyFragmentAttestation(identity.ApprovalPublicKey, attestation) {
		t.Fatal("VerifyFragmentAttestation() returned false for valid attestation")
	}
	tampered := fragment
	tampered.Ciphertext = "different-ciphertext"
	tamperedHash, err := FragmentEnvelopeHash(tampered)
	if err != nil {
		t.Fatalf("FragmentEnvelopeHash(tampered) error = %v", err)
	}
	if tamperedHash == hash {
		t.Fatal("FragmentEnvelopeHash() did not change when ciphertext changed")
	}
	attestation.FragmentEnvelopeHash = tamperedHash
	if VerifyFragmentAttestation(identity.ApprovalPublicKey, attestation) {
		t.Fatal("VerifyFragmentAttestation() accepted a tampered envelope hash")
	}
}

func TestProviderValidateKeyFragmentsRejectsDuplicateAndUnexpectedParties(t *testing.T) {
	provider, err := GetProvider(AlgorithmExperimentalP256Schnorr)
	if err != nil {
		t.Fatalf("GetProvider() error = %v", err)
	}
	parties := []PartyInfo{{ID: 1}, {ID: 2}}
	commitments := []PublicCommitment{
		{PartyID: 1, Coefficients: []Point{ScalarBasePoint(big.NewInt(2)), ScalarBasePoint(big.NewInt(3))}},
		{PartyID: 2, Coefficients: []Point{ScalarBasePoint(big.NewInt(5)), ScalarBasePoint(big.NewInt(7))}},
	}
	makeFragment := func(partyID int) EncryptedFragment {
		share, err := PublicShareCommitment(commitments, partyID)
		if err != nil {
			t.Fatalf("PublicShareCommitment(%d) error = %v", partyID, err)
		}
		return EncryptedFragment{
			KeyID:                 "key-1",
			PartyID:               partyID,
			Algorithm:             FragmentEnvelope,
			Nonce:                 "nonce",
			Ciphertext:            "ciphertext",
			PublicShareCommitment: share,
		}
	}
	_, _, identity, err := GenerateSignerIdentity(1, "party-1", "")
	if err != nil {
		t.Fatalf("GenerateSignerIdentity() error = %v", err)
	}
	valid1, err := EncryptFragment("key-1", 1, identity.EncryptionPublicKey, []byte("share-1"), makeFragment(1).PublicShareCommitment)
	if err != nil {
		t.Fatalf("EncryptFragment() error = %v", err)
	}
	_, _, identity2, err := GenerateSignerIdentity(2, "party-2", "")
	if err != nil {
		t.Fatalf("GenerateSignerIdentity() error = %v", err)
	}
	valid2, err := EncryptFragment("key-1", 2, identity2.EncryptionPublicKey, []byte("share-2"), makeFragment(2).PublicShareCommitment)
	if err != nil {
		t.Fatalf("EncryptFragment() error = %v", err)
	}
	if err := provider.ValidateKeyFragments("key-1", parties, commitments, []EncryptedFragment{valid1, valid2}); err != nil {
		t.Fatalf("ValidateKeyFragments(valid) error = %v", err)
	}
	if err := provider.ValidateKeyFragments("key-1", parties, commitments, []EncryptedFragment{valid1, valid1}); err == nil {
		t.Fatal("ValidateKeyFragments() accepted duplicate party fragments")
	}
	unexpected := valid2
	unexpected.PartyID = 3
	if err := provider.ValidateKeyFragments("key-1", parties, commitments, []EncryptedFragment{valid1, unexpected}); err == nil {
		t.Fatal("ValidateKeyFragments() accepted an unexpected party")
	}
}
