package vault

import (
	"math/big"
	"testing"
	"time"

	"github.com/jmcleod/ironhand/crypto"
	"github.com/jmcleod/ironhand/internal/mpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVaultMPCKeyAndSigningSession(t *testing.T) {
	ctx := t.Context()
	_, session, creds := createTestVault(t)

	bobKP, err := crypto.GenerateX25519Keypair()
	require.NoError(t, err)
	carolKP, err := crypto.GenerateX25519Keypair()
	require.NoError(t, err)

	require.NoError(t, session.AddMember(ctx, "bob", bobKP.Public, RoleWriter))
	require.NoError(t, session.AddMember(ctx, "carol", carolKP.Public, RoleWriter))

	type signerMaterial struct {
		memberID string
		partyID  int
		identity mpc.SignerIdentity
		approval []byte
	}
	signers := make([]signerMaterial, 0, 3)
	for _, cfg := range []struct {
		memberID string
		partyID  int
	}{
		{creds.MemberID(), 1},
		{"bob", 2},
		{"carol", 3},
	} {
		_, approvalPriv, identity, err := mpc.GenerateSignerIdentity(cfg.partyID, cfg.memberID, "https://"+cfg.memberID+".signer.test")
		require.NoError(t, err)
		require.NoError(t, session.RegisterMPCSigner(ctx, cfg.memberID, MPCSignerRegistration{
			URL:                 identity.URL,
			EncryptionPublicKey: identity.EncryptionPublicKey,
			ApprovalPublicKey:   identity.ApprovalPublicKey,
		}))
		signers = append(signers, signerMaterial{memberID: cfg.memberID, partyID: cfg.partyID, identity: identity, approval: approvalPriv})
	}

	polys := make(map[int][]*big.Int)
	commitments := make([]mpc.PublicCommitment, 0, len(signers))
	for _, signer := range signers {
		poly, err := mpc.GeneratePolynomial(2)
		require.NoError(t, err)
		polys[signer.partyID] = poly
		commitments = append(commitments, mpc.CommitmentsForPolynomial(signer.partyID, poly))
	}

	localShares := make(map[int]*big.Int)
	fragments := make(map[string]mpc.EncryptedFragment, len(signers))
	for _, receiver := range signers {
		localShare := big.NewInt(0)
		for _, dealer := range signers {
			share := mpc.EvalPolynomial(polys[dealer.partyID], big.NewInt(int64(receiver.partyID)))
			localShare.Add(localShare, share)
			localShare.Mod(localShare, mpc.CurveOrder())
		}
		localShares[receiver.partyID] = localShare
		publicShare, err := mpc.PublicShareCommitment(commitments, receiver.partyID)
		require.NoError(t, err)
		fragment, err := mpc.EncryptFragment("mpc-key-1", receiver.partyID, receiver.identity.EncryptionPublicKey, []byte(mpc.EncodeScalar(localShare)), publicShare)
		require.NoError(t, err)
		fragments[receiver.memberID] = fragment
	}

	key, err := session.CreateMPCKey(ctx, MPCKeyCreate{
		KeyID:       "mpc-key-1",
		Threshold:   2,
		MemberIDs:   []string{creds.MemberID(), "bob", "carol"},
		Commitments: commitments,
		Fragments:   fragments,
	})
	require.NoError(t, err)
	assert.Equal(t, MPCAlgorithmExperimentalP256Schnorr, key.Algorithm)
	assert.Equal(t, 2, key.Threshold)
	assert.Len(t, key.Participants, 3)

	keys, err := session.ListMPCKeys(ctx)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, "mpc-key-1", keys[0].KeyID)

	signSession, err := session.CreateMPCSigningSession(ctx, key.KeyID, []byte("threshold signing payload"), []uint32{1, 3}, time.Minute)
	require.NoError(t, err)
	assert.Equal(t, []uint32{1, 3}, signSession.Participants)

	participants := []int{1, 3}
	signCommitments := make([]mpc.Commitment, 0, len(participants))
	nonces := make(map[int]*big.Int, len(participants))
	for _, partyID := range participants {
		nonce, err := mpc.RandomScalar()
		require.NoError(t, err)
		nonces[partyID] = nonce
		signCommitments = append(signCommitments, mpc.Commitment{PartyID: partyID, R: mpc.ScalarBasePoint(nonce)})
	}
	r, err := mpc.AggregateCommitments(signCommitments)
	require.NoError(t, err)
	challenge, err := mpc.Challenge(key.PublicKeyPoint(), r, signSession.Message)
	require.NoError(t, err)
	shares := make([]mpc.ShareProof, 0, len(participants))
	for _, partyID := range participants {
		z, err := mpc.SignShare(localShares[partyID], nonces[partyID], challenge, partyID, participants)
		require.NoError(t, err)
		shares = append(shares, mpc.ShareProof{PartyID: partyID, Z: mpc.EncodeScalar(z)})
	}
	z, err := mpc.CombineSignatureShares(shares)
	require.NoError(t, err)
	sig := &mpc.Signature{Curve: mpc.CurveName, R: r, Z: z, Commitments: signCommitments, Shares: shares}

	for _, signer := range signers {
		if signer.partyID != 1 && signer.partyID != 3 {
			continue
		}
		approval, err := mpc.SignApproval(signer.approval, mpc.Approval{
			SessionID:   signSession.SessionID,
			KeyID:       signSession.KeyID,
			PartyID:     signer.partyID,
			MessageHash: signSession.MessageHash,
			ExpiresAt:   signSession.ExpiresAt,
		})
		require.NoError(t, err)
		_, err = session.AddMPCApproval(ctx, signSession.SessionID, approval)
		require.NoError(t, err)
	}

	completed, err := session.CompleteMPCSigningSession(ctx, signSession.SessionID, signCommitments, sig)
	require.NoError(t, err)
	assert.Equal(t, MPCSigningSessionCompleted, completed.Status)
	require.NotNil(t, completed.Signature)
	assert.True(t, mpc.Verify(signSession.Message, key.PublicKeyPoint(), completed.Signature))
}
