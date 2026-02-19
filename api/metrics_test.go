package api

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoginFailureSpikeAlert(t *testing.T) {
	var mu sync.Mutex
	var alerts []AlertEvent
	collector := newMetricsCollector(func(e AlertEvent) {
		mu.Lock()
		alerts = append(alerts, e)
		mu.Unlock()
	})
	// Override threshold for fast testing.
	collector.loginThreshold = 5

	// Record failures below threshold — no alert.
	for i := 0; i < 4; i++ {
		collector.recordEvent(AuditLoginFailure)
	}
	mu.Lock()
	assert.Empty(t, alerts, "no alert below threshold")
	mu.Unlock()

	// The 5th failure should trigger an alert.
	collector.recordEvent(AuditLoginFailure)
	mu.Lock()
	require.Len(t, alerts, 1)
	assert.Equal(t, AlertLoginFailureSpike, alerts[0].Type)
	assert.Equal(t, 5, alerts[0].Count)
	mu.Unlock()
}

func TestBulkExportAlert(t *testing.T) {
	var mu sync.Mutex
	var alerts []AlertEvent
	collector := newMetricsCollector(func(e AlertEvent) {
		mu.Lock()
		alerts = append(alerts, e)
		mu.Unlock()
	})
	collector.exportThreshold = 3

	// Record exports.
	for i := 0; i < 2; i++ {
		collector.recordEvent(AuditVaultExported)
	}
	mu.Lock()
	assert.Empty(t, alerts, "no alert below threshold")
	mu.Unlock()

	collector.recordEvent(AuditVaultExported)
	mu.Lock()
	require.Len(t, alerts, 1)
	assert.Equal(t, AlertBulkExport, alerts[0].Type)
	assert.Equal(t, 3, alerts[0].Count)
	mu.Unlock()
}

func TestMetricsNoAlertWithoutCallback(t *testing.T) {
	// A nil alertFn should not panic.
	collector := newMetricsCollector(nil)
	collector.recordEvent(AuditLoginFailure)
	// Should not panic.
}

func TestMetricsNilCollector(t *testing.T) {
	// A nil collector should not panic.
	var collector *metricsCollector
	collector.recordEvent(AuditLoginFailure)
}

func TestMetricsSlidingWindowExpiry(t *testing.T) {
	var mu sync.Mutex
	var alerts []AlertEvent
	collector := newMetricsCollector(func(e AlertEvent) {
		mu.Lock()
		alerts = append(alerts, e)
		mu.Unlock()
	})
	collector.loginThreshold = 5
	collector.loginWindow = 100 * time.Millisecond

	// Record 4 failures.
	for i := 0; i < 4; i++ {
		collector.recordEvent(AuditLoginFailure)
	}

	// Wait for them to slide out of the window.
	time.Sleep(150 * time.Millisecond)

	// Record 1 more — should NOT trigger alert because old ones expired.
	collector.recordEvent(AuditLoginFailure)
	mu.Lock()
	assert.Empty(t, alerts, "old failures should not count after window expiry")
	mu.Unlock()
}

func TestMetricsResetAfterAlert(t *testing.T) {
	var mu sync.Mutex
	var alerts []AlertEvent
	collector := newMetricsCollector(func(e AlertEvent) {
		mu.Lock()
		alerts = append(alerts, e)
		mu.Unlock()
	})
	collector.loginThreshold = 3

	// Trigger first alert.
	for i := 0; i < 3; i++ {
		collector.recordEvent(AuditLoginFailure)
	}
	mu.Lock()
	require.Len(t, alerts, 1, "first alert triggered")
	mu.Unlock()

	// Counter was reset — need 3 more to trigger again.
	for i := 0; i < 2; i++ {
		collector.recordEvent(AuditLoginFailure)
	}
	mu.Lock()
	assert.Len(t, alerts, 1, "no second alert yet")
	mu.Unlock()

	collector.recordEvent(AuditLoginFailure)
	mu.Lock()
	assert.Len(t, alerts, 2, "second alert triggered")
	mu.Unlock()
}
