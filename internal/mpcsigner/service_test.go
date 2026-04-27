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

	resp := postSignerJSON(t, service, "/signer/approve", ApprovalRequest{
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
	resp := postSignerJSON(t, service, "/signer/approve", req)
	require.Equal(t, http.StatusOK, resp.Code)

	var approval mpc.Approval
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &approval))
	assert.Equal(t, req.VaultID, approval.VaultID)
	assert.Equal(t, req.KeyID, approval.KeyID)
	assert.Equal(t, req.SessionID, approval.SessionID)
	assert.Equal(t, req.Threshold, approval.Threshold)
	assert.Equal(t, req.Participants, approval.Participants)
	assert.True(t, mpc.VerifyApproval(service.Identity().ApprovalPublicKey, approval, time.Now().UTC()))
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
	rec := httptest.NewRecorder()
	service.Handler().ServeHTTP(rec, req)
	return rec
}
