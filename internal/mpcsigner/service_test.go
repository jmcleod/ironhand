package mpcsigner

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jmcleod/ironhand/internal/mpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignerApprovalRequiresKnownBoundKey(t *testing.T) {
	service := newTestSignerService(t)

	resp := postSignerJSON(t, service, "/signer/approval-requests", ApprovalRequest{
		VaultID:      "vault-1",
		KeyID:        "missing",
		SessionID:    "session-1",
		Threshold:    2,
		Participants: []int{1, 2},
		MessageHash:  "hash",
		ExpiresAt:    time.Now().Add(time.Minute),
	})

	assert.Equal(t, http.StatusNotFound, resp.Code)
}

func TestSignerApprovalBindsSessionContext(t *testing.T) {
	service := newTestSignerService(t)
	installTestSignerKey(service, "vault-1", "key-1")

	req := ApprovalRequest{
		VaultID:      "vault-1",
		KeyID:        "key-1",
		SessionID:    "session-1",
		Threshold:    2,
		Participants: []int{1, 2},
		MessageHash:  "hash",
		ExpiresAt:    time.Now().Add(time.Minute).UTC(),
	}
	resp := postSignerJSON(t, service, "/signer/approval-requests", req)
	require.Equal(t, http.StatusAccepted, resp.Code)
	var created CreateApprovalRequestResponse
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &created))
	assert.Equal(t, ApprovalRequestPending, created.Request.Status)

	resp = postSignerJSON(t, service, "/signer/approval-requests/"+created.Request.RequestID+"/approve", map[string]string{})
	require.Equal(t, http.StatusOK, resp.Code)
	var approved CreateApprovalRequestResponse
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &approved))
	require.NotNil(t, approved.Request.Approval)
	approval := *approved.Request.Approval
	assert.Equal(t, req.VaultID, approval.VaultID)
	assert.Equal(t, req.KeyID, approval.KeyID)
	assert.Equal(t, req.SessionID, approval.SessionID)
	assert.Equal(t, req.Threshold, approval.Threshold)
	assert.Equal(t, req.Participants, approval.Participants)
	assert.True(t, mpc.VerifyApproval(service.Identity().ApprovalPublicKey, approval, time.Now().UTC()))
}

func TestSignerRejectsExpiredAndConflictingApprovalRequests(t *testing.T) {
	service := newTestSignerService(t)
	installTestSignerKey(service, "vault-1", "key-1")

	expired := postSignerJSON(t, service, "/signer/approval-requests", ApprovalRequest{
		VaultID:      "vault-1",
		KeyID:        "key-1",
		SessionID:    "expired-session",
		Threshold:    2,
		Participants: []int{1, 2},
		MessageHash:  "hash",
		ExpiresAt:    time.Now().Add(-time.Minute),
	})
	require.Equal(t, http.StatusBadRequest, expired.Code)

	req := ApprovalRequest{
		VaultID:      "vault-1",
		KeyID:        "key-1",
		SessionID:    "session-1",
		Threshold:    2,
		Participants: []int{1, 2},
		MessageHash:  "hash-1",
		ExpiresAt:    time.Now().Add(time.Minute).UTC(),
	}
	first := postSignerJSON(t, service, "/signer/approval-requests", req)
	require.Equal(t, http.StatusAccepted, first.Code)
	req.MessageHash = "hash-2"
	conflict := postSignerJSON(t, service, "/signer/approval-requests", req)
	require.Equal(t, http.StatusConflict, conflict.Code)
}

func TestNonceCommitIsIdempotentAndTranscriptBound(t *testing.T) {
	service := newTestSignerService(t)
	installTestSignerKey(service, "vault-1", "key-1")

	req := NonceCommitRequest{KeyID: "key-1", SessionID: "session-1", MessageHash: "hash-1"}
	first := postSignerJSON(t, service, "/signer/sign/commit", req)
	require.Equal(t, http.StatusOK, first.Code)
	second := postSignerJSON(t, service, "/signer/sign/commit", req)
	require.Equal(t, http.StatusOK, second.Code)
	assert.JSONEq(t, first.Body.String(), second.Body.String())

	conflict := postSignerJSON(t, service, "/signer/sign/commit", NonceCommitRequest{KeyID: "key-1", SessionID: "session-1", MessageHash: "hash-2"})
	assert.Equal(t, http.StatusConflict, conflict.Code)
}

func TestSignerRejectsWrongPartySignShare(t *testing.T) {
	service := newTestSignerService(t)
	installTestSignerKey(service, "vault-1", "key-1")

	resp := postSignerJSON(t, service, "/signer/sign/share", SignShareRequest{
		KeyID:     "key-1",
		SessionID: "session-1",
		Fragment:  mpc.EncryptedFragment{KeyID: "key-1", PartyID: 2},
		Approval:  mpc.Approval{KeyID: "key-1", SessionID: "session-1", PartyID: 1},
	})
	require.Equal(t, http.StatusBadRequest, resp.Code)
}

func TestSignerHealthAndReadyExposeOperationalState(t *testing.T) {
	service := newTestSignerService(t)
	installTestSignerKey(service, "vault-1", "key-1")

	req := httptest.NewRequest(http.MethodGet, "/signer/health", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	service.Handler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var health map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &health))
	assert.Equal(t, "ok", health["status"])
	assert.Equal(t, "member-1", health["member_id"])
	assert.Equal(t, float64(1), health["keys"])

	req = httptest.NewRequest(http.MethodGet, "/signer/ready", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec = httptest.NewRecorder()
	service.Handler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}

func newTestSignerService(t *testing.T) *Service {
	t.Helper()
	service, err := New("member-1", 1, "member-1", "http://signer-1.test", nil, nil)
	require.NoError(t, err)
	return service
}

func installTestSignerKey(service *Service, vaultID, keyID string) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.keys[keyID] = &keyState{
		vaultID:     vaultID,
		dkgStatus:   "committed",
		threshold:   2,
		members:     []Member{{MemberID: "member-1", PartyID: 1}, {MemberID: "member-2", PartyID: 2}},
		commitments: make(map[int]mpc.PublicCommitment),
		inbox:       make(map[int]string),
		publicKey:   mpc.Point{X: "test-x", Y: "test-y"},
		nonces:      make(map[string]*nonceState),
	}
}

func postSignerJSON(t *testing.T, service *Service, path string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	service.Handler().ServeHTTP(rec, req)
	return rec
}
