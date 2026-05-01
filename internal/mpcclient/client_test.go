package mpcclient

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignedRequestIncludesReplayNonce(t *testing.T) {
	shared := []byte("shared-secret")
	body := []byte(`{"ok":true}`)
	req := httptest.NewRequest(http.MethodPost, "https://signer-1.internal/sign", bytes.NewReader(body))
	req.RemoteAddr = "10.0.0.2:12345"
	SignRequest(req, shared, body, time.Now())

	cache := NewReplayCache(2 * time.Minute)
	_, ok, err := VerifyRequestWithReplay(req, shared, 2*time.Minute, cache)
	require.NoError(t, err)
	assert.True(t, ok)

	req.Body = ioNopCloser(body)
	_, ok, err = VerifyRequestWithReplay(req, shared, 2*time.Minute, cache)
	require.NoError(t, err)
	assert.False(t, ok, "same signed request nonce must not verify twice")
}

func TestUnsignedRequestRequiresLoopback(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://signer.local/sign", bytes.NewReader(nil))
	req.RemoteAddr = "127.0.0.1:12345"
	_, ok, err := VerifyRequest(req, nil, 2*time.Minute)
	require.NoError(t, err)
	assert.True(t, ok)

	req = httptest.NewRequest(http.MethodPost, "http://signer.local/sign", bytes.NewReader(nil))
	req.RemoteAddr = "10.0.0.2:12345"
	_, ok, err = VerifyRequest(req, nil, 2*time.Minute)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestSignedRequestBindsBodyAndHost(t *testing.T) {
	shared := []byte("shared-secret")
	body := []byte(`{"ok":true}`)
	req := httptest.NewRequest(http.MethodPost, "https://signer-1.internal/sign", bytes.NewReader(body))
	req.RemoteAddr = "10.0.0.2:12345"
	SignRequest(req, shared, body, time.Now())

	req.Body = ioNopCloser([]byte(`{"ok":false}`))
	_, ok, err := VerifyRequest(req, shared, 2*time.Minute)
	require.NoError(t, err)
	assert.False(t, ok)

	req = httptest.NewRequest(http.MethodPost, "https://signer-1.internal/sign", bytes.NewReader(body))
	req.RemoteAddr = "10.0.0.2:12345"
	SignRequest(req, shared, body, time.Now())
	req.URL.Host = "signer-2.internal"
	_, ok, err = VerifyRequest(req, shared, 2*time.Minute)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestSignedRequestBindsMethodPathAndQuery(t *testing.T) {
	shared := []byte("shared-secret")
	body := []byte(`{"ok":true}`)
	req := httptest.NewRequest(http.MethodPost, "https://signer-1.internal/sign?session=one", bytes.NewReader(body))
	req.RemoteAddr = "10.0.0.2:12345"
	SignRequest(req, shared, body, time.Now())

	req.Method = http.MethodGet
	_, ok, err := VerifyRequest(req, shared, 2*time.Minute)
	require.NoError(t, err)
	assert.False(t, ok)

	req = httptest.NewRequest(http.MethodPost, "https://signer-1.internal/sign?session=one", bytes.NewReader(body))
	req.RemoteAddr = "10.0.0.2:12345"
	SignRequest(req, shared, body, time.Now())
	req.URL.Path = "/sign/share"
	_, ok, err = VerifyRequest(req, shared, 2*time.Minute)
	require.NoError(t, err)
	assert.False(t, ok)

	req = httptest.NewRequest(http.MethodPost, "https://signer-1.internal/sign?session=one", bytes.NewReader(body))
	req.RemoteAddr = "10.0.0.2:12345"
	SignRequest(req, shared, body, time.Now())
	req.URL.RawQuery = "session=two"
	_, ok, err = VerifyRequest(req, shared, 2*time.Minute)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestSignedRequestRejectsStaleTimestamp(t *testing.T) {
	shared := []byte("shared-secret")
	body := []byte(`{"ok":true}`)
	req := httptest.NewRequest(http.MethodPost, "https://signer-1.internal/sign", bytes.NewReader(body))
	req.RemoteAddr = "10.0.0.2:12345"
	SignRequest(req, shared, body, time.Now().Add(-10*time.Minute))

	_, ok, err := VerifyRequest(req, shared, 2*time.Minute)
	require.NoError(t, err)
	assert.False(t, ok)
}

func ioNopCloser(body []byte) *readCloser {
	return &readCloser{bytes.NewReader(body)}
}

type readCloser struct {
	*bytes.Reader
}

func (r *readCloser) Close() error { return nil }
