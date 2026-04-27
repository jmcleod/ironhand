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

	"github.com/go-chi/chi/v5"
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
	for _, fragment := range prepared.Fragments {
		require.NotNil(t, fragment.Attestation)
		require.Equal(t, v.ID(), fragment.Attestation.VaultID)
		require.Equal(t, dkg.SessionID, fragment.Attestation.DKGSessionID)
	}
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
	require.NoError(t, api.commitMPCDKG(ctx, dkg))
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
	metrics, err := session.MPCMetrics(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, metrics.KeysByStatus[vault.MPCKeyStatusActive])
	require.Equal(t, 1, metrics.SigningSessionsByStatus[vault.MPCSigningSessionCompleted])

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
	creds   *vault.Credentials
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

func TestMPCCreateKeyDisablesKeyWhenSignerCommitFails(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewRepository()
	epochCache := vault.NewMemoryEpochCache()
	api := New(repo, epochCache, WithExperimentalMPC(true), WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	creds, err := vault.NewCredentials("mpc-create-commit-failure-passphrase")
	require.NoError(t, err)
	defer creds.Destroy()
	v := vault.New("mpc-create-commit-failure-vault", repo, vault.WithEpochCache(epochCache))
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
	failingSigner := signers[1]
	failingCommitServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/signer/dkg/commit" {
			writeError(w, http.StatusInternalServerError, "forced signer commit failure")
			return
		}
		failingSigner.service.Handler().ServeHTTP(w, r)
	}))
	t.Cleanup(failingCommitServer.Close)
	identity := failingSigner.service.Identity()
	require.NoError(t, session.RegisterMPCSigner(ctx, failingSigner.memberID, vault.MPCSignerRegistration{
		URL:                 failingCommitServer.URL,
		EncryptionPublicKey: identity.EncryptionPublicKey,
		ApprovalPublicKey:   identity.ApprovalPublicKey,
		Status:              vault.MPCSignerStatusActive,
	}))
	require.NoError(t, api.saveAccountRecord(creds.SecretKey().String(), accountRecord{
		SecretKeyID: creds.SecretKey().ID(),
		CreatedAt:   time.Now().UTC(),
	}))

	const failedKeyID = "create-commit-failed-key"
	req := httptest.NewRequest(http.MethodPost, "/vaults/"+v.ID()+"/mpc/keys", bytes.NewReader([]byte(`{"key_id":"`+failedKeyID+`","threshold":2}`)))
	req.Header.Set("Content-Type", "application/json")
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("vaultID", v.ID())
	reqCtx := context.WithValue(req.Context(), credentialsKey, creds)
	reqCtx = context.WithValue(reqCtx, chi.RouteCtxKey, routeCtx)
	rec := httptest.NewRecorder()

	api.CreateMPCKey(rec, req.WithContext(reqCtx))
	require.NotEqual(t, http.StatusCreated, rec.Code, rec.Body.String())
	key, err := session.GetMPCKey(ctx, failedKeyID)
	require.NoError(t, err)
	require.Equal(t, vault.MPCKeyStatusDisabled, key.Status)
	attempts, err := session.ListMPCDKGAttempts(ctx)
	require.NoError(t, err)
	require.Len(t, attempts, 1)
	require.Equal(t, vault.MPCDKGStatusFailed, attempts[0].Status)
}

func TestMPCCreateKeyRejectsManualArtifactsWithoutRecoveryMode(t *testing.T) {
	env := newDemoKeyEnv(t, "manual-import-mode")
	require.NoError(t, env.api.saveAccountRecord(env.creds.SecretKey().String(), accountRecord{
		SecretKeyID: env.creds.SecretKey().ID(),
		CreatedAt:   time.Now().UTC(),
	}))

	req := httptest.NewRequest(http.MethodPost, "/vaults/"+env.vault.ID()+"/mpc/keys", bytes.NewReader([]byte(`{
		"key_id":"manual-key",
		"threshold":2,
		"commitments":[{"partyId":1}],
		"fragments":{"member":{"key_id":"manual-key","party_id":1}}
	}`)))
	req.Header.Set("Content-Type", "application/json")
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("vaultID", env.vault.ID())
	reqCtx := context.WithValue(req.Context(), credentialsKey, env.creds)
	reqCtx = context.WithValue(reqCtx, chi.RouteCtxKey, routeCtx)
	rec := httptest.NewRecorder()

	env.api.CreateMPCKey(rec, req.WithContext(reqCtx))
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "import_mode")
}

func TestMPCProductionModeRejectsExperimentalProvider(t *testing.T) {
	api := New(memory.NewRepository(), vault.NewMemoryEpochCache(), WithExperimentalMPC(true), WithMPCProductionMode(true))
	err := api.validateMPCProviderForUse("")
	require.ErrorContains(t, err, "not production ready")
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

func TestMPCRotateHandlerCreatesReplacementKey(t *testing.T) {
	env := newDemoKeyEnv(t, "rotate")
	require.NoError(t, env.session.RevokeMember(context.Background(), "bob"))
	require.NoError(t, env.api.saveAccountRecord(env.creds.SecretKey().String(), accountRecord{
		SecretKeyID: env.creds.SecretKey().ID(),
		CreatedAt:   time.Now().UTC(),
	}))

	const failedReplacementKeyID = "failed-replacement-key"
	req := httptest.NewRequest(http.MethodPost, "/vaults/"+env.vault.ID()+"/mpc/keys/"+env.key.KeyID+"/rotate", bytes.NewReader([]byte(`{"key_id":"`+failedReplacementKeyID+`"}`)))
	req.Header.Set("Content-Type", "application/json")
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("vaultID", env.vault.ID())
	routeCtx.URLParams.Add("keyID", env.key.KeyID)
	ctx := context.WithValue(req.Context(), credentialsKey, env.creds)
	ctx = context.WithValue(ctx, chi.RouteCtxKey, routeCtx)
	rec := httptest.NewRecorder()

	env.api.RotateMPCKey(rec, req.WithContext(ctx))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var replacement vault.MPCKey
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &replacement))
	require.Equal(t, env.key.KeyID, replacement.ReplacesKeyID)
	require.Len(t, replacement.Participants, 2)
	oldKey, err := env.session.GetMPCKey(context.Background(), env.key.KeyID)
	require.NoError(t, err)
	require.Equal(t, vault.MPCKeyStatusArchived, oldKey.Status)
	require.Equal(t, replacement.KeyID, oldKey.ReplacedByKeyID)
}

func TestMPCRotateHandlerKeepsOldKeyWhenSignerCommitFails(t *testing.T) {
	env := newDemoKeyEnv(t, "rotate-commit-fail")
	require.NoError(t, env.session.RevokeMember(context.Background(), "bob"))
	require.NoError(t, env.api.saveAccountRecord(env.creds.SecretKey().String(), accountRecord{
		SecretKeyID: env.creds.SecretKey().ID(),
		CreatedAt:   time.Now().UTC(),
	}))

	carol := env.signers[2]
	failingCommitServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/signer/dkg/commit" {
			writeError(w, http.StatusInternalServerError, "forced signer commit failure")
			return
		}
		carol.service.Handler().ServeHTTP(w, r)
	}))
	t.Cleanup(failingCommitServer.Close)
	identity := carol.service.Identity()
	require.NoError(t, env.session.RegisterMPCSigner(context.Background(), carol.memberID, vault.MPCSignerRegistration{
		URL:                 failingCommitServer.URL,
		EncryptionPublicKey: identity.EncryptionPublicKey,
		ApprovalPublicKey:   identity.ApprovalPublicKey,
		Status:              vault.MPCSignerStatusActive,
	}))

	const failedReplacementKeyID = "failed-replacement-key"
	req := httptest.NewRequest(http.MethodPost, "/vaults/"+env.vault.ID()+"/mpc/keys/"+env.key.KeyID+"/rotate", bytes.NewReader([]byte(`{"key_id":"`+failedReplacementKeyID+`"}`)))
	req.Header.Set("Content-Type", "application/json")
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("vaultID", env.vault.ID())
	routeCtx.URLParams.Add("keyID", env.key.KeyID)
	ctx := context.WithValue(req.Context(), credentialsKey, env.creds)
	ctx = context.WithValue(ctx, chi.RouteCtxKey, routeCtx)
	rec := httptest.NewRecorder()

	env.api.RotateMPCKey(rec, req.WithContext(ctx))
	require.NotEqual(t, http.StatusCreated, rec.Code, rec.Body.String())
	oldKey, err := env.session.GetMPCKey(context.Background(), env.key.KeyID)
	require.NoError(t, err)
	require.Equal(t, vault.MPCKeyStatusReshareRequired, oldKey.Status)
	require.Empty(t, oldKey.ReplacedByKeyID)
	attempts, err := env.session.ListMPCDKGAttempts(context.Background())
	require.NoError(t, err)
	var failedAttempt *vault.MPCDKGAttempt
	for i := range attempts {
		if attempts[i].KeyID == failedReplacementKeyID {
			failedAttempt = &attempts[i]
			break
		}
	}
	require.NotNil(t, failedAttempt)
	require.Equal(t, vault.MPCDKGStatusFailed, failedAttempt.Status)
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
	require.NoError(t, api.commitMPCDKG(ctx, dkg))
	return &demoKeyEnv{api: api, session: session, vault: v, creds: creds, key: key, signers: signers}
}
