package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// webhookQueueSize is the bounded channel capacity for outbound audit events.
const webhookQueueSize = 1024

// webhookEvent is the JSON payload POSTed to the external endpoint.
type webhookEvent struct {
	Event      string            `json:"event"`
	AccountID  string            `json:"account_id,omitempty"`
	RemoteAddr string            `json:"remote_addr,omitempty"`
	Timestamp  string            `json:"timestamp"`
	Attrs      map[string]string `json:"attrs,omitempty"`
}

// auditWebhook dispatches audit events to an external HTTP endpoint.
// Events are enqueued non-blockingly into a bounded channel and sent
// by a background goroutine. If the channel is full, events are dropped.
type auditWebhook struct {
	url        string
	authHeader string // "Header: Value" format, e.g., "Authorization: Bearer xxx"
	client     *http.Client
	events     chan webhookEvent
	wg         sync.WaitGroup
}

// newAuditWebhook creates a webhook dispatcher and starts its background loop.
func newAuditWebhook(url, authHeader string) *auditWebhook {
	w := &auditWebhook{
		url:        url,
		authHeader: authHeader,
		client:     &http.Client{Timeout: 10 * time.Second},
		events:     make(chan webhookEvent, webhookQueueSize),
	}
	w.wg.Add(1)
	go w.loop()
	return w
}

// enqueue adds an event to the dispatch queue. If the queue is full, the
// event is dropped and a warning is logged. This method never blocks.
func (w *auditWebhook) enqueue(evt webhookEvent) {
	select {
	case w.events <- evt:
	default:
		slog.Warn("audit webhook: queue full, dropping event", "event", evt.Event)
	}
}

// close shuts down the webhook dispatcher, draining any remaining events.
func (w *auditWebhook) close() {
	close(w.events)
	w.wg.Wait()
}

// loop reads from the event channel and sends each event.
func (w *auditWebhook) loop() {
	defer w.wg.Done()
	for evt := range w.events {
		w.send(evt)
	}
}

// send POSTs the event to the configured URL with one retry on 5xx.
func (w *auditWebhook) send(evt webhookEvent) {
	body, err := json.Marshal(evt)
	if err != nil {
		slog.Warn("audit webhook: marshal failed", "error", err)
		return
	}

	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(1 * time.Second)
		}

		req, err := http.NewRequest("POST", w.url, bytes.NewReader(body))
		if err != nil {
			slog.Warn("audit webhook: request creation failed", "error", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "IronHand-Audit-Webhook/1.0")

		if w.authHeader != "" {
			parts := strings.SplitN(w.authHeader, ":", 2)
			if len(parts) == 2 {
				req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
		}

		resp, err := w.client.Do(req)
		if err != nil {
			slog.Warn("audit webhook: request failed", "error", err, "attempt", attempt+1)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return // success
		}
		if resp.StatusCode >= 500 {
			slog.Warn("audit webhook: server error", "status", resp.StatusCode, "attempt", attempt+1)
			continue // retry on 5xx
		}
		// 4xx: log and do not retry (client error).
		slog.Warn("audit webhook: client error", "status", resp.StatusCode)
		return
	}
}
