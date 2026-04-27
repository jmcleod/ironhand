package vault

import (
	"math/big"
	"strings"
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

	badFragments := make(map[string]mpc.EncryptedFragment, len(fragments))
	for memberID, fragment := range fragments {
		badFragments[memberID] = fragment
	}
	badFragment := badFragments["bob"]
	badFragment.PublicShareCommitment = mpc.Point{X: "bad", Y: "bad"}
	badFragments["bob"] = badFragment
	_, err = session.CreateMPCKey(ctx, MPCKeyCreate{
		KeyID:       "mpc-key-1",
		Threshold:   2,
		MemberIDs:   []string{creds.MemberID(), "bob", "carol"},
		Commitments: commitments,
		Fragments:   badFragments,
	})
	require.ErrorContains(t, err, "public share commitment")

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
			VaultID:           signSession.VaultID,
			SessionID:         signSession.SessionID,
			KeyID:             signSession.KeyID,
			PartyID:           signer.partyID,
			Threshold:         key.Threshold,
			Participants:      participants,
			MessageHash:       signSession.MessageHash,
			MessageType:       signSession.MessageType,
			TransactionDigest: signSession.Transaction.Digest,
			ExpiresAt:         signSession.ExpiresAt,
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

	thresholdSession, err := session.CreateMPCSigningSession(ctx, key.KeyID, []byte("threshold subset payload"), []uint32{1, 2, 3}, time.Minute)
	require.NoError(t, err)
	subsetParticipants := []int{1, 2}
	subsetCommitments := make([]mpc.Commitment, 0, len(subsetParticipants))
	subsetNonces := make(map[int]*big.Int, len(subsetParticipants))
	for _, partyID := range subsetParticipants {
		nonce, err := mpc.RandomScalar()
		require.NoError(t, err)
		subsetNonces[partyID] = nonce
		subsetCommitments = append(subsetCommitments, mpc.Commitment{PartyID: partyID, R: mpc.ScalarBasePoint(nonce)})
	}
	subsetR, err := mpc.AggregateCommitments(subsetCommitments)
	require.NoError(t, err)
	subsetChallenge, err := mpc.Challenge(key.PublicKeyPoint(), subsetR, thresholdSession.Message)
	require.NoError(t, err)
	subsetShares := make([]mpc.ShareProof, 0, len(subsetParticipants))
	for _, partyID := range subsetParticipants {
		z, err := mpc.SignShare(localShares[partyID], subsetNonces[partyID], subsetChallenge, partyID, subsetParticipants)
		require.NoError(t, err)
		subsetShares = append(subsetShares, mpc.ShareProof{PartyID: partyID, Z: mpc.EncodeScalar(z)})
	}
	subsetZ, err := mpc.CombineSignatureShares(subsetShares)
	require.NoError(t, err)
	subsetSig := &mpc.Signature{Curve: mpc.CurveName, R: subsetR, Z: subsetZ, Commitments: subsetCommitments, Shares: subsetShares}
	for _, signer := range signers {
		if signer.partyID != 1 && signer.partyID != 2 {
			continue
		}
		approval, err := mpc.SignApproval(signer.approval, mpc.Approval{
			VaultID:           thresholdSession.VaultID,
			SessionID:         thresholdSession.SessionID,
			KeyID:             thresholdSession.KeyID,
			PartyID:           signer.partyID,
			Threshold:         key.Threshold,
			Participants:      []int{1, 2, 3},
			MessageHash:       thresholdSession.MessageHash,
			MessageType:       thresholdSession.MessageType,
			TransactionDigest: thresholdSession.Transaction.Digest,
			ExpiresAt:         thresholdSession.ExpiresAt,
		})
		require.NoError(t, err)
		_, err = session.AddMPCApproval(ctx, thresholdSession.SessionID, approval)
		require.NoError(t, err)
	}
	completedThreshold, err := session.CompleteMPCSigningSession(ctx, thresholdSession.SessionID, subsetCommitments, subsetSig)
	require.NoError(t, err)
	assert.Equal(t, MPCSigningSessionCompleted, completedThreshold.Status)

	expiredSession, err := session.CreateMPCSigningSession(ctx, key.KeyID, []byte("expired payload"), []uint32{1, 2}, time.Nanosecond)
	require.NoError(t, err)
	time.Sleep(time.Millisecond)
	_, err = session.CompleteMPCSigningSession(ctx, expiredSession.SessionID, nil, nil)
	require.ErrorContains(t, err, "expired")

	updatedKey, err := session.SetMPCKeyStatus(ctx, key.KeyID, MPCKeyStatusDisabled)
	require.NoError(t, err)
	assert.Equal(t, MPCKeyStatusDisabled, updatedKey.Status)
	_, err = session.CreateMPCSigningSession(ctx, key.KeyID, []byte("disabled payload"), []uint32{1, 2}, time.Minute)
	require.ErrorContains(t, err, "is not active")
	updatedKey, err = session.SetMPCKeyStatus(ctx, key.KeyID, MPCKeyStatusActive)
	require.NoError(t, err)
	assert.Equal(t, MPCKeyStatusActive, updatedKey.Status)

	require.NoError(t, session.RevokeMember(ctx, "bob"))
	updatedKey, err = session.GetMPCKey(ctx, key.KeyID)
	require.NoError(t, err)
	assert.Equal(t, MPCKeyStatusReshareRequired, updatedKey.Status)
}

func TestEvaluateMPCPolicyMaxValue(t *testing.T) {
	key := &MPCKey{
		Policy:       MPCPolicy{ApprovalMode: MPCApprovalModeThreshold, MaxValue: "1000"},
		Participants: []MPCParticipant{{PartyID: 1, Role: RoleOwner}, {PartyID: 2, Role: RoleWriter}},
	}
	tests := []struct {
		name    string
		policy  MPCPolicy
		value   string
		allowed bool
		reason  string
	}{
		{name: "under limit", value: "999", allowed: true},
		{name: "equal limit", value: "1000", allowed: true},
		{name: "over limit", value: "1001", allowed: false, reason: "exceeds max_value"},
		{name: "missing transaction value", value: "", allowed: false, reason: "required by max_value"},
		{name: "invalid transaction value", value: "1.5", allowed: false, reason: "invalid transaction value"},
		{name: "invalid policy value", policy: MPCPolicy{ApprovalMode: MPCApprovalModeThreshold, MaxValue: "abc"}, value: "1", allowed: false, reason: "invalid max_value"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := tt.policy
			if policy.MaxValue == "" {
				policy = key.Policy
			}
			key.Policy = policy
			decision := evaluateMPCPolicy(key, []uint32{1, 2}, MPCTransactionMetadata{Value: tt.value})
			require.Equal(t, tt.allowed, decision.Allowed)
			if tt.reason != "" {
				require.NotEmpty(t, decision.Reasons)
				assert.Contains(t, strings.Join(decision.Reasons, "\n"), tt.reason)
			}
		})
	}
}

func TestValidateMPCCompletionTranscript(t *testing.T) {
	session := &MPCSigningSession{Participants: []uint32{1, 2, 3}}
	key := &MPCKey{Threshold: 2}
	c1 := mpc.Commitment{PartyID: 1, R: mpc.Point{X: "1", Y: "2"}}
	c2 := mpc.Commitment{PartyID: 2, R: mpc.Point{X: "3", Y: "4"}}
	validCommitments := []mpc.Commitment{c1, c2}
	validSignature := &mpc.Signature{
		Commitments: validCommitments,
		Shares:      []mpc.ShareProof{{PartyID: 1, Z: "a"}, {PartyID: 2, Z: "b"}},
	}

	require.NoError(t, validateMPCCompletionTranscript(session, key, validCommitments, validSignature))

	tests := []struct {
		name        string
		commitments []mpc.Commitment
		signature   *mpc.Signature
		err         string
	}{
		{
			name:        "mismatched caller commitments",
			commitments: []mpc.Commitment{c2, c1},
			signature:   validSignature,
			err:         "do not match",
		},
		{
			name:        "too few commitments",
			commitments: []mpc.Commitment{c1},
			signature:   &mpc.Signature{Commitments: []mpc.Commitment{c1}, Shares: []mpc.ShareProof{{PartyID: 1, Z: "a"}}},
			err:         "needs at least 2",
		},
		{
			name:        "unselected party",
			commitments: []mpc.Commitment{c1, {PartyID: 4, R: mpc.Point{X: "5", Y: "6"}}},
			signature:   &mpc.Signature{Commitments: []mpc.Commitment{c1, {PartyID: 4, R: mpc.Point{X: "5", Y: "6"}}}, Shares: []mpc.ShareProof{{PartyID: 1, Z: "a"}, {PartyID: 4, Z: "d"}}},
			err:         "was not selected",
		},
		{
			name:        "duplicate commitment",
			commitments: []mpc.Commitment{c1, c1},
			signature:   &mpc.Signature{Commitments: []mpc.Commitment{c1, c1}, Shares: []mpc.ShareProof{{PartyID: 1, Z: "a"}, {PartyID: 1, Z: "b"}}},
			err:         "duplicate commitment",
		},
		{
			name:        "share without commitment",
			commitments: validCommitments,
			signature:   &mpc.Signature{Commitments: validCommitments, Shares: []mpc.ShareProof{{PartyID: 1, Z: "a"}, {PartyID: 3, Z: "c"}}},
			err:         "no matching commitment",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMPCCompletionTranscript(session, key, tt.commitments, tt.signature)
			require.ErrorContains(t, err, tt.err)
		})
	}
}
