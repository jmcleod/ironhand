package mpc

import (
	"math/big"
	"testing"
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
}

func TestNormalizeParticipantsRejectsDuplicates(t *testing.T) {
	_, err := NormalizeParticipants([]int{1, 1}, 2, []int{1, 2, 3})
	if err == nil {
		t.Fatal("NormalizeParticipants() error = nil, want duplicate error")
	}
}
