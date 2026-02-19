package api

import (
	"sync"
	"time"
)

// AlertType identifies the kind of anomaly detected.
type AlertType string

const (
	AlertLoginFailureSpike AlertType = "login_failure_spike"
	AlertBulkExport        AlertType = "bulk_export"
)

// AlertEvent describes an anomaly that triggered an alert.
type AlertEvent struct {
	Type      AlertType `json:"type"`
	Message   string    `json:"message"`
	Count     int       `json:"count"`
	Threshold int       `json:"threshold"`
	Timestamp time.Time `json:"timestamp"`
}

// AlertFunc is the callback invoked when an anomaly is detected.
type AlertFunc func(AlertEvent)

// metricsCollector tracks sliding window counters for anomaly detection.
type metricsCollector struct {
	mu sync.Mutex

	// Sliding window for login failures.
	loginFailures  []time.Time
	loginWindow    time.Duration
	loginThreshold int

	// Sliding window for vault exports.
	exports         []time.Time
	exportWindow    time.Duration
	exportThreshold int

	alertFn AlertFunc
}

const (
	defaultLoginFailureWindow    = 1 * time.Minute
	defaultLoginFailureThreshold = 50
	defaultExportWindow          = 5 * time.Minute
	defaultExportThreshold       = 10
)

func newMetricsCollector(alertFn AlertFunc) *metricsCollector {
	return &metricsCollector{
		loginWindow:     defaultLoginFailureWindow,
		loginThreshold:  defaultLoginFailureThreshold,
		exportWindow:    defaultExportWindow,
		exportThreshold: defaultExportThreshold,
		alertFn:         alertFn,
	}
}

// recordEvent inspects an audit event and updates the relevant counters.
func (m *metricsCollector) recordEvent(event AuditEvent) {
	if m == nil || m.alertFn == nil {
		return
	}
	switch event {
	case AuditLoginFailure:
		m.recordLoginFailure()
	case AuditVaultExported:
		m.recordExport()
	}
}

func (m *metricsCollector) recordLoginFailure() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	m.loginFailures = append(m.loginFailures, now)
	m.loginFailures = trimWindow(m.loginFailures, now, m.loginWindow)

	if len(m.loginFailures) >= m.loginThreshold {
		m.alertFn(AlertEvent{
			Type:      AlertLoginFailureSpike,
			Message:   "login failure rate exceeds threshold",
			Count:     len(m.loginFailures),
			Threshold: m.loginThreshold,
			Timestamp: now,
		})
		// Reset to avoid repeated alerts within the same spike.
		m.loginFailures = m.loginFailures[:0]
	}
}

func (m *metricsCollector) recordExport() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	m.exports = append(m.exports, now)
	m.exports = trimWindow(m.exports, now, m.exportWindow)

	if len(m.exports) >= m.exportThreshold {
		m.alertFn(AlertEvent{
			Type:      AlertBulkExport,
			Message:   "vault export rate exceeds threshold",
			Count:     len(m.exports),
			Threshold: m.exportThreshold,
			Timestamp: now,
		})
		m.exports = m.exports[:0]
	}
}

// trimWindow removes entries older than (now - window) from the sorted slice.
func trimWindow(times []time.Time, now time.Time, window time.Duration) []time.Time {
	cutoff := now.Add(-window)
	start := 0
	for start < len(times) && times[start].Before(cutoff) {
		start++
	}
	return times[start:]
}
