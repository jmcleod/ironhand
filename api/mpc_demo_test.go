package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ihcrypto "github.com/jmcleod/ironhand/crypto"
	"github.com/jmcleod/ironhand/internal/mpcsigner"
	"github.com/jmcleod/ironhand/storage/memory"
	"github.com/jmcleod/ironhand/vault"
	"github.com/stretchr/testify/require"
)

type demoSigner struct {
	memberID string
	partyID  uint32
	store    string
	service  *mpcsigner.Service
	server   *httptest.Server
}

func TestMPCDemoHarness(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewRepository()
	epochCache := vault.NewMemoryEpochCache()
	api := New(repo, epochCache, WithExperimentalMPC(true), WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))

	creds, err := vault.NewCredentials("mpc-demo-passphrase")
	require.NoError(t, err)
	defer creds.Destroy()
	v := vault.New("mpc-demo-vault", repo, vault.WithEpochCache(epochCache))
	session, err := v.Create(ctx, creds)
	require.NoError(t, err)
	defer session.Close()

	bobKP, err := ihcrypto.GenerateX25519Keypair()
	require.NoError(t, err)
	carolKP, err := ihcrypto.GenerateX25519Keypair()
	require.NoError(t, err)
	require.NoError(t, session.AddMember(ctx, "bob", bobKP.Public, vault.RoleWriter))
	require.NoError(t, session.AddMember(ctx, "carol", carolKP.Public, vault.RoleWriter))

	signers := []*demoSigner{
		newDemoSigner(t, creds.MemberID(), 1),
		newDemoSigner(t, "bob", 2),
		newDemoSigner(t, "carol", 3),
	}
	for _, signer := range signers {
		identity := signer.service.Identity()
		require.NoError(t, session.RegisterMPCSigner(ctx, signer.memberID, vault.MPCSignerRegistration{
			URL:                 signer.server.URL,
			EncryptionPublicKey: identity.EncryptionPublicKey,
			ApprovalPublicKey:   identity.ApprovalPublicKey,
			Status:              vault.MPCSignerStatusActive,
		}))
	}

	prepared, dkg, err := api.orchestrateMPCDKG(ctx, session, v.ID(), CreateMPCKeyRequest{KeyID: "demo-mpc-key", Threshold: 2})
	require.NoError(t, err)
	require.NotNil(t, dkg)
	key, err := session.CreateMPCKey(ctx, vault.MPCKeyCreate{
		KeyID:       prepared.KeyID,
		Algorithm:   prepared.Algorithm,
		Threshold:   prepared.Threshold,
		MemberIDs:   prepared.MemberIDs,
		Commitments: prepared.Commitments,
		Fragments:   prepared.Fragments,
		Policy:      prepared.Policy,
	})
	require.NoError(t, err)
	api.commitMPCDKG(ctx, dkg)
	attempt, err := session.GetMPCDKGAttempt(ctx, dkg.SessionID)
	require.NoError(t, err)
	attempt.Status = vault.MPCDKGStatusCommitted
	_, err = session.SaveMPCDKGAttempt(ctx, *attempt)
	require.NoError(t, err)

	signingSession, err := session.CreateMPCSigningSession(ctx, key.KeyID, []byte("ironhand mpc demo payload"), []uint32{1, 2}, time.Minute)
	require.NoError(t, err)
	for _, partyID := range []uint32{1, 2} {
		_, err := api.requestMPCSessionApprovalWithSigner(ctx, session, signingSession.SessionID, partyID)
		require.NoError(t, err)
		approveDemoRequest(t, signers[partyID-1].server.URL, signingSession.SessionID, partyID)
	}
	completed, err := api.completeMPCSessionWithSigners(ctx, session, signingSession.SessionID)
	require.NoError(t, err)
	require.Equal(t, vault.MPCSigningSessionCompleted, completed.Status)
	require.NotNil(t, completed.Signature)

	dkgAttempt, err := session.GetMPCDKGAttempt(ctx, dkg.SessionID)
	require.NoError(t, err)
	t.Logf("MPC demo complete: key=%s threshold=%d participants=%d provider=%s", key.KeyID, key.Threshold, len(key.Participants), key.Provider.Algorithm)
	t.Logf("DKG attempt: session=%s status=%s commitments=%d fragments=%d", dkgAttempt.DKGSessionID, dkgAttempt.Status, len(dkgAttempt.Commitments), len(dkgAttempt.Fragments))
	t.Logf("Signing session: session=%s approvals=%d signature_curve=%s", completed.SessionID, len(completed.Approvals), completed.Signature.Curve)
}

func newDemoSigner(t *testing.T, memberID string, partyID uint32) *demoSigner {
	t.Helper()
	return newDemoSignerWithStore(t, memberID, partyID, t.TempDir()+"/signer.sealed")
}

func newDemoSignerWithStore(t *testing.T, memberID string, partyID uint32, storePath string) *demoSigner {
	t.Helper()
	signer := &demoSigner{memberID: memberID, partyID: partyID, store: storePath}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signer.service.Handler().ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	store, err := mpcsigner.NewFileStore(storePath, "demo-signer-state-passphrase")
	require.NoError(t, err)
	service, err := mpcsigner.NewWithStore(memberID, partyID, memberID, server.URL, nil, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	signer.service = service
	signer.server = server
	return signer
}

func restartDemoSigner(t *testing.T, signer *demoSigner) *demoSigner {
	t.Helper()
	store, err := mpcsigner.NewFileStore(signer.store, "demo-signer-state-passphrase")
	require.NoError(t, err)
	service, err := mpcsigner.NewWithStore(signer.memberID, signer.partyID, signer.memberID, signer.server.URL, nil, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	signer.service = service
	return signer
}

func approveDemoRequest(t *testing.T, signerURL, sessionID string, partyID uint32) {
	t.Helper()
	body, err := json.Marshal(map[string]string{})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, signerURL+"/signer/approval-requests/"+fmt.Sprintf("%s-%d", sessionID, partyID)+"/approve", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("approve signer request: status=%d body=%s", resp.StatusCode, string(data))
	}
}

type demoKeyEnv struct {
	api     *API
	session *vault.Session
	vault   *vault.Vault
	key     *vault.MPCKey
	signers []*demoSigner
}

func TestMPCSignerDurableRestartCompletesSigning(t *testing.T) {
	env := newDemoKeyEnv(t, "restart")
	restarted := restartDemoSigner(t, env.signers[1])
	env.signers[1] = restarted
	identity := restarted.service.Identity()
	require.NoError(t, env.session.RegisterMPCSigner(context.Background(), restarted.memberID, vault.MPCSignerRegistration{
		URL:                 restarted.server.URL,
		EncryptionPublicKey: identity.EncryptionPublicKey,
		ApprovalPublicKey:   identity.ApprovalPublicKey,
		Status:              vault.MPCSignerStatusActive,
	}))

	signingSession, err := env.session.CreateMPCSigningSession(context.Background(), env.key.KeyID, []byte("restart signing payload"), []uint32{1, 2}, time.Minute)
	require.NoError(t, err)
	for _, partyID := range []uint32{1, 2} {
		_, err := env.api.requestMPCSessionApprovalWithSigner(context.Background(), env.session, signingSession.SessionID, partyID)
		require.NoError(t, err)
		approveDemoRequest(t, env.signers[partyID-1].server.URL, signingSession.SessionID, partyID)
	}
	completed, err := env.api.completeMPCSessionWithSigners(context.Background(), env.session, signingSession.SessionID)
	require.NoError(t, err)
	require.Equal(t, vault.MPCSigningSessionCompleted, completed.Status)
}

func TestMPCDKGFailureRecordsAttempt(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewRepository()
	epochCache := vault.NewMemoryEpochCache()
	api := New(repo, epochCache, WithExperimentalMPC(true), WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	creds, err := vault.NewCredentials("mpc-failure-passphrase")
	require.NoError(t, err)
	defer creds.Destroy()
	v := vault.New("mpc-failure-vault", repo, vault.WithEpochCache(epochCache))
	session, err := v.Create(ctx, creds)
	require.NoError(t, err)
	defer session.Close()
	bobKP, err := ihcrypto.GenerateX25519Keypair()
	require.NoError(t, err)
	require.NoError(t, session.AddMember(ctx, "bob", bobKP.Public, vault.RoleWriter))
	signers := []*demoSigner{newDemoSigner(t, creds.MemberID(), 1), newDemoSigner(t, "bob", 2)}
	for _, signer := range signers {
		identity := signer.service.Identity()
		require.NoError(t, session.RegisterMPCSigner(ctx, signer.memberID, vault.MPCSignerRegistration{
			URL:                 signer.server.URL,
			EncryptionPublicKey: identity.EncryptionPublicKey,
			ApprovalPublicKey:   identity.ApprovalPublicKey,
			Status:              vault.MPCSignerStatusActive,
		}))
	}
	signers[1].server.Close()
	_, _, err = api.orchestrateMPCDKG(ctx, session, v.ID(), CreateMPCKeyRequest{KeyID: "failed-key", Threshold: 2})
	require.Error(t, err)
	attempts, err := session.ListMPCDKGAttempts(ctx)
	require.NoError(t, err)
	require.Len(t, attempts, 1)
	require.Equal(t, vault.MPCDKGStatusFailed, attempts[0].Status)
	require.NotEmpty(t, attempts[0].LastError)
}

func TestMPCKeyLifecycleBlocksAndRevocationMarksReshare(t *testing.T) {
	env := newDemoKeyEnv(t, "lifecycle")
	_, err := env.session.SetMPCKeyStatus(context.Background(), env.key.KeyID, vault.MPCKeyStatusDisabled)
	require.NoError(t, err)
	_, err = env.session.CreateMPCSigningSession(context.Background(), env.key.KeyID, []byte("disabled payload"), []uint32{1, 2}, time.Minute)
	require.ErrorContains(t, err, "is not active")
	_, err = env.session.SetMPCKeyStatus(context.Background(), env.key.KeyID, vault.MPCKeyStatusActive)
	require.NoError(t, err)
	require.NoError(t, env.session.RevokeMember(context.Background(), "bob"))
	key, err := env.session.GetMPCKey(context.Background(), env.key.KeyID)
	require.NoError(t, err)
	require.Equal(t, vault.MPCKeyStatusReshareRequired, key.Status)
}

func newDemoKeyEnv(t *testing.T, name string) *demoKeyEnv {
	t.Helper()
	ctx := context.Background()
	repo := memory.NewRepository()
	epochCache := vault.NewMemoryEpochCache()
	api := New(repo, epochCache, WithExperimentalMPC(true), WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	creds, err := vault.NewCredentials("mpc-" + name + "-passphrase")
	require.NoError(t, err)
	t.Cleanup(creds.Destroy)
	v := vault.New("mpc-"+name+"-vault", repo, vault.WithEpochCache(epochCache))
	session, err := v.Create(ctx, creds)
	require.NoError(t, err)
	t.Cleanup(session.Close)
	bobKP, err := ihcrypto.GenerateX25519Keypair()
	require.NoError(t, err)
	carolKP, err := ihcrypto.GenerateX25519Keypair()
	require.NoError(t, err)
	require.NoError(t, session.AddMember(ctx, "bob", bobKP.Public, vault.RoleWriter))
	require.NoError(t, session.AddMember(ctx, "carol", carolKP.Public, vault.RoleWriter))
	signers := []*demoSigner{newDemoSigner(t, creds.MemberID(), 1), newDemoSigner(t, "bob", 2), newDemoSigner(t, "carol", 3)}
	for _, signer := range signers {
		identity := signer.service.Identity()
		require.NoError(t, session.RegisterMPCSigner(ctx, signer.memberID, vault.MPCSignerRegistration{
			URL:                 signer.server.URL,
			EncryptionPublicKey: identity.EncryptionPublicKey,
			ApprovalPublicKey:   identity.ApprovalPublicKey,
			Status:              vault.MPCSignerStatusActive,
		}))
	}
	prepared, dkg, err := api.orchestrateMPCDKG(ctx, session, v.ID(), CreateMPCKeyRequest{KeyID: "demo-" + name + "-key", Threshold: 2})
	require.NoError(t, err)
	key, err := session.CreateMPCKey(ctx, vault.MPCKeyCreate{KeyID: prepared.KeyID, Algorithm: prepared.Algorithm, Threshold: prepared.Threshold, MemberIDs: prepared.MemberIDs, Commitments: prepared.Commitments, Fragments: prepared.Fragments, Policy: prepared.Policy})
	require.NoError(t, err)
	api.commitMPCDKG(ctx, dkg)
	return &demoKeyEnv{api: api, session: session, vault: v, key: key, signers: signers}
}
