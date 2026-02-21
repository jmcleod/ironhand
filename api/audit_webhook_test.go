package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebhook_SuccessfulDelivery(t *testing.T) {
	var received webhookEvent
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh := newAuditWebhook(srv.URL, "")
	wh.enqueue(webhookEvent{
		Event:      "login_success",
		AccountID:  "acct-1",
		RemoteAddr: "127.0.0.1:1234",
		Timestamp:  "2025-01-01T00:00:00Z",
		Attrs:      map[string]string{"key": "value"},
	})
	wh.close()

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "login_success", received.Event)
	assert.Equal(t, "acct-1", received.AccountID)
	assert.Equal(t, "127.0.0.1:1234", received.RemoteAddr)
	assert.Equal(t, "value", received.Attrs["key"])
}

func TestWebhook_RetryOn500(t *testing.T) {
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := attempts.Add(1)
		if count == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh := newAuditWebhook(srv.URL, "")
	wh.enqueue(webhookEvent{Event: "test_event", Timestamp: "2025-01-01T00:00:00Z"})
	wh.close()

	assert.Equal(t, int32(2), attempts.Load(), "should have retried once after 500")
}

func TestWebhook_NoRetryOn400(t *testing.T) {
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	wh := newAuditWebhook(srv.URL, "")
	wh.enqueue(webhookEvent{Event: "test_event", Timestamp: "2025-01-01T00:00:00Z"})
	wh.close()

	assert.Equal(t, int32(1), attempts.Load(), "should not retry on 4xx")
}

func TestWebhook_AuthHeader(t *testing.T) {
	var gotAuth string
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh := newAuditWebhook(srv.URL, "Authorization: Bearer my-token-123")
	wh.enqueue(webhookEvent{Event: "test_event", Timestamp: "2025-01-01T00:00:00Z"})
	wh.close()

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "Bearer my-token-123", gotAuth)
}

func TestWebhook_ContentType(t *testing.T) {
	var gotContentType string
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotContentType = r.Header.Get("Content-Type")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh := newAuditWebhook(srv.URL, "")
	wh.enqueue(webhookEvent{Event: "test_event", Timestamp: "2025-01-01T00:00:00Z"})
	wh.close()

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "application/json", gotContentType)
}

func TestWebhook_QueueFullNonBlocking(t *testing.T) {
	// Create a webhook that never reads (no server, just a blocking handler).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block forever to simulate slow consumer.
		select {}
	}))
	defer srv.Close()

	wh := &auditWebhook{
		url:    srv.URL,
		client: &http.Client{Timeout: 100 * time.Millisecond},
		events: make(chan webhookEvent, 2), // tiny buffer
	}
	wh.wg.Add(1)
	go wh.loop()

	// Fill the queue.
	for i := 0; i < 10; i++ {
		wh.enqueue(webhookEvent{Event: "flood", Timestamp: "2025-01-01T00:00:00Z"})
	}

	// If we get here without blocking, the test passes.
	// Clean up by closing.
	close(wh.events)
	// Don't wait for wg — the goroutine is stuck in the blocking handler.
}

func TestWebhook_GracefulShutdownDrains(t *testing.T) {
	var count atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh := newAuditWebhook(srv.URL, "")
	for i := 0; i < 5; i++ {
		wh.enqueue(webhookEvent{Event: "drain_test", Timestamp: "2025-01-01T00:00:00Z"})
	}
	wh.close() // should block until all 5 are sent

	assert.Equal(t, int32(5), count.Load(), "all queued events should be delivered on close")
}

func TestWebhook_JSONPayloadStructure(t *testing.T) {
	var body []byte
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		body, _ = io.ReadAll(r.Body)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh := newAuditWebhook(srv.URL, "")
	wh.enqueue(webhookEvent{
		Event:      "vault_exported",
		AccountID:  "acct-42",
		RemoteAddr: "10.0.0.1:5555",
		Timestamp:  "2025-06-15T12:00:00Z",
		Attrs:      map[string]string{"vault_id": "v-1"},
	})
	wh.close()

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, body)

	var parsed map[string]interface{}
	err := json.Unmarshal(body, &parsed)
	require.NoError(t, err)

	assert.Equal(t, "vault_exported", parsed["event"])
	assert.Equal(t, "acct-42", parsed["account_id"])
	assert.Equal(t, "10.0.0.1:5555", parsed["remote_addr"])
	assert.Equal(t, "2025-06-15T12:00:00Z", parsed["timestamp"])

	attrs, ok := parsed["attrs"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "v-1", attrs["vault_id"])
}
