package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRateLimiter_AllowsBeforeThreshold(t *testing.T) {
	rl := newLoginRateLimiter()

	// Under the threshold, requests should not be blocked.
	for i := 0; i < maxFailures-1; i++ {
		rl.recordFailure("acct-1")
		blocked, _ := rl.check("acct-1")
		assert.False(t, blocked, "should not block before reaching maxFailures")
	}
}

func TestRateLimiter_BlocksAfterThreshold(t *testing.T) {
	rl := newLoginRateLimiter()

	// Reach and exceed the threshold.
	for i := 0; i < maxFailures; i++ {
		rl.recordFailure("acct-1")
	}

	blocked, retryAfter := rl.check("acct-1")
	require.True(t, blocked, "should block after maxFailures")
	assert.Greater(t, retryAfter, time.Duration(0), "retry-after should be positive")
}

func TestRateLimiter_ExponentialBackoff(t *testing.T) {
	rl := newLoginRateLimiter()

	// Hit the threshold.
	for i := 0; i < maxFailures; i++ {
		rl.recordFailure("acct-1")
	}
	_, first := rl.check("acct-1")

	// One more failure should double the lockout.
	rl.recordFailure("acct-1")
	_, second := rl.check("acct-1")
	assert.Greater(t, second, first, "lockout should increase with more failures")
}

func TestRateLimiter_SuccessResetsCounter(t *testing.T) {
	rl := newLoginRateLimiter()

	for i := 0; i < maxFailures; i++ {
		rl.recordFailure("acct-1")
	}
	blocked, _ := rl.check("acct-1")
	require.True(t, blocked)

	// A successful login should clear the state.
	rl.recordSuccess("acct-1")

	blocked, _ = rl.check("acct-1")
	assert.False(t, blocked, "should not block after successful login")
}

func TestRateLimiter_IsolatesAccounts(t *testing.T) {
	rl := newLoginRateLimiter()

	// Lock out acct-1.
	for i := 0; i < maxFailures; i++ {
		rl.recordFailure("acct-1")
	}
	blocked, _ := rl.check("acct-1")
	require.True(t, blocked)

	// acct-2 should be unaffected.
	blocked, _ = rl.check("acct-2")
	assert.False(t, blocked, "rate limit for one account should not affect another")
}

func TestRateLimiter_UnknownAccountNotBlocked(t *testing.T) {
	rl := newLoginRateLimiter()

	blocked, _ := rl.check("unknown")
	assert.False(t, blocked)
}

func TestRateLimiter_SweepRemovesExpired(t *testing.T) {
	rl := newLoginRateLimiter()

	// Manually create an expired record.
	rl.mu.Lock()
	rl.attempts["old"] = &attemptRecord{
		failures:    maxFailures + 1,
		lastFailure: time.Now().Add(-2 * attemptExpiry),
		lockedUntil: time.Now().Add(-attemptExpiry),
	}
	rl.mu.Unlock()

	rl.sweep()

	rl.mu.Lock()
	_, exists := rl.attempts["old"]
	rl.mu.Unlock()
	assert.False(t, exists, "sweep should remove expired records")
}

func TestRateLimiter_MaxLockoutCap(t *testing.T) {
	rl := newLoginRateLimiter()

	// Add many failures to hit the cap.
	for i := 0; i < maxFailures+20; i++ {
		rl.recordFailure("acct-1")
	}

	_, retryAfter := rl.check("acct-1")
	assert.LessOrEqual(t, retryAfter, maxLockout+time.Second, "lockout should not exceed maxLockout")
}

// ---------------------------------------------------------------------------
// Per-IP rate limiter tests
// ---------------------------------------------------------------------------

func TestIPRateLimiter_AllowsBeforeThreshold(t *testing.T) {
	rl := newIPRateLimiter()

	for i := 0; i < ipMaxFailures-1; i++ {
		rl.recordFailure("192.168.1.1")
		blocked, _ := rl.check("192.168.1.1")
		assert.False(t, blocked, "should not block before ipMaxFailures")
	}
}

func TestIPRateLimiter_BlocksAfterThreshold(t *testing.T) {
	rl := newIPRateLimiter()

	for i := 0; i < ipMaxFailures; i++ {
		rl.recordFailure("192.168.1.1")
	}

	blocked, retryAfter := rl.check("192.168.1.1")
	require.True(t, blocked, "should block after ipMaxFailures")
	assert.Greater(t, retryAfter, time.Duration(0))
}

func TestIPRateLimiter_IsolatesIPs(t *testing.T) {
	rl := newIPRateLimiter()

	for i := 0; i < ipMaxFailures; i++ {
		rl.recordFailure("192.168.1.1")
	}
	blocked, _ := rl.check("192.168.1.1")
	require.True(t, blocked)

	// A different IP should be unaffected.
	blocked2, _ := rl.check("10.0.0.1")
	assert.False(t, blocked2, "different IP should not be blocked")
}

func TestIPRateLimiter_SuccessClears(t *testing.T) {
	rl := newIPRateLimiter()

	for i := 0; i < ipMaxFailures; i++ {
		rl.recordFailure("192.168.1.1")
	}
	blocked, _ := rl.check("192.168.1.1")
	require.True(t, blocked)

	rl.recordSuccess("192.168.1.1")
	blocked2, _ := rl.check("192.168.1.1")
	assert.False(t, blocked2, "should not be blocked after success")
}

func TestIPRateLimiter_MaxLockoutCap(t *testing.T) {
	rl := newIPRateLimiter()

	for i := 0; i < ipMaxFailures+20; i++ {
		rl.recordFailure("192.168.1.1")
	}

	_, retryAfter := rl.check("192.168.1.1")
	assert.LessOrEqual(t, retryAfter, ipMaxLockout+time.Second)
}

// ---------------------------------------------------------------------------
// Global rate limiter tests
// ---------------------------------------------------------------------------

func TestGlobalRateLimiter_AllowsBeforeThreshold(t *testing.T) {
	rl := newGlobalRateLimiter()

	for i := 0; i < globalMaxFailures-1; i++ {
		rl.recordFailure()
		blocked, _ := rl.check()
		assert.False(t, blocked, "should not block before globalMaxFailures")
	}
}

func TestGlobalRateLimiter_BlocksAfterThreshold(t *testing.T) {
	rl := newGlobalRateLimiter()

	for i := 0; i < globalMaxFailures; i++ {
		rl.recordFailure()
	}

	blocked, retryAfter := rl.check()
	require.True(t, blocked, "should block after globalMaxFailures in window")
	assert.Greater(t, retryAfter, time.Duration(0))
	// Lockout should be approximately globalLockout.
	assert.LessOrEqual(t, retryAfter, globalLockout+time.Second)
}

func TestGlobalRateLimiter_SlidingWindowExpiry(t *testing.T) {
	rl := newGlobalRateLimiter()

	// Inject old failures outside the sliding window.
	rl.mu.Lock()
	for i := 0; i < globalMaxFailures; i++ {
		rl.failures = append(rl.failures, time.Now().Add(-2*globalWindow))
	}
	rl.mu.Unlock()

	// One new failure should NOT trigger lockout — old ones are outside the window.
	rl.recordFailure()
	blocked, _ := rl.check()
	assert.False(t, blocked, "expired failures outside window should not count")
}

// ---------------------------------------------------------------------------
// extractClientIP tests
// ---------------------------------------------------------------------------

func TestExtractClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{
			name:       "remote ipv4",
			remoteAddr: "192.168.1.1:12345",
			want:       "192.168.1.1",
		},
		{
			name:       "remote ipv6",
			remoteAddr: "[::1]:8080",
			want:       "::1",
		},
		{
			name:       "xff first valid wins",
			remoteAddr: "10.0.0.1:80",
			headers: map[string]string{
				"X-Forwarded-For": "198.51.100.25, 203.0.113.9",
			},
			want: "198.51.100.25",
		},
		{
			name:       "xff skips invalid entries",
			remoteAddr: "10.0.0.1:80",
			headers: map[string]string{
				"X-Forwarded-For": "unknown, not-an-ip, 203.0.113.7",
			},
			want: "203.0.113.7",
		},
		{
			name:       "forwarded fallback",
			remoteAddr: "10.0.0.1:80",
			headers: map[string]string{
				"Forwarded": `for=198.51.100.1;proto=https;by=203.0.113.43`,
			},
			want: "198.51.100.1",
		},
		{
			name:       "x-real-ip fallback",
			remoteAddr: "10.0.0.1:80",
			headers: map[string]string{
				"X-Real-IP": "203.0.113.11",
			},
			want: "203.0.113.11",
		},
		{
			name:       "empty when nothing parseable",
			remoteAddr: "not-a-hostport",
			want:       "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{RemoteAddr: tt.remoteAddr}
			r.Header = make(http.Header)
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			got := extractClientIP(r)
			assert.Equal(t, tt.want, got)
		})
	}
}
