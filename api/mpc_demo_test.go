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
	var service *mpcsigner.Service
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		service.Handler().ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	store, err := mpcsigner.NewFileStore(t.TempDir()+"/signer.sealed", "demo-signer-state-passphrase")
	require.NoError(t, err)
	service, err = mpcsigner.NewWithStore(memberID, partyID, memberID, server.URL, nil, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	return &demoSigner{memberID: memberID, partyID: partyID, service: service, server: server}
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
