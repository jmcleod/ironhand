package api

import (
	"crypto/tls"
	"net/http"
	"net/netip"
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
// Registration IP rate limiter tests
// ---------------------------------------------------------------------------

func TestRegIPLimiter_AllowsBeforeThreshold(t *testing.T) {
	rl := newRegistrationIPLimiter()

	for i := 0; i < regIPMaxRequests-1; i++ {
		rl.record("192.168.1.1")
		blocked, _ := rl.check("192.168.1.1")
		assert.False(t, blocked, "should not block before regIPMaxRequests")
	}
}

func TestRegIPLimiter_BlocksAfterThreshold(t *testing.T) {
	rl := newRegistrationIPLimiter()

	for i := 0; i < regIPMaxRequests; i++ {
		rl.record("192.168.1.1")
	}

	blocked, retryAfter := rl.check("192.168.1.1")
	require.True(t, blocked, "should block after regIPMaxRequests")
	assert.Greater(t, retryAfter, time.Duration(0), "retry-after should be positive")
}

func TestRegIPLimiter_IsolatesIPs(t *testing.T) {
	rl := newRegistrationIPLimiter()

	for i := 0; i < regIPMaxRequests; i++ {
		rl.record("192.168.1.1")
	}
	blocked, _ := rl.check("192.168.1.1")
	require.True(t, blocked)

	blocked2, _ := rl.check("10.0.0.1")
	assert.False(t, blocked2, "different IP should not be blocked")
}

func TestRegIPLimiter_ExponentialBackoff(t *testing.T) {
	rl := newRegistrationIPLimiter()

	// Hit the threshold.
	for i := 0; i < regIPMaxRequests; i++ {
		rl.record("192.168.1.1")
	}
	_, first := rl.check("192.168.1.1")

	// One more request should increase the lockout.
	rl.record("192.168.1.1")
	_, second := rl.check("192.168.1.1")
	assert.Greater(t, second, first, "lockout should increase with more requests")
}

func TestRegIPLimiter_MaxLockoutCap(t *testing.T) {
	rl := newRegistrationIPLimiter()

	for i := 0; i < regIPMaxRequests+20; i++ {
		rl.record("192.168.1.1")
	}

	_, retryAfter := rl.check("192.168.1.1")
	assert.LessOrEqual(t, retryAfter, regIPMaxLockout+time.Second, "lockout should not exceed cap")
}

func TestRegIPLimiter_ExpiresOldRecords(t *testing.T) {
	rl := newRegistrationIPLimiter()

	// Manually inject an old record.
	rl.mu.Lock()
	rl.requests["192.168.1.1"] = &attemptRecord{
		failures:    regIPMaxRequests + 1,
		lastFailure: time.Now().Add(-2 * regIPExpiry),
		lockedUntil: time.Now().Add(-regIPExpiry),
	}
	rl.mu.Unlock()

	blocked, _ := rl.check("192.168.1.1")
	assert.False(t, blocked, "expired record should be garbage-collected on check")
}

// ---------------------------------------------------------------------------
// Registration global rate limiter tests
// ---------------------------------------------------------------------------

func TestRegGlobalLimiter_AllowsBeforeThreshold(t *testing.T) {
	rl := newRegistrationGlobalLimiter()

	for i := 0; i < regGlobalMaxRequests-1; i++ {
		rl.record()
		blocked, _ := rl.check()
		assert.False(t, blocked, "should not block before regGlobalMaxRequests")
	}
}

func TestRegGlobalLimiter_BlocksAfterThreshold(t *testing.T) {
	rl := newRegistrationGlobalLimiter()

	for i := 0; i < regGlobalMaxRequests; i++ {
		rl.record()
	}

	blocked, retryAfter := rl.check()
	require.True(t, blocked, "should block after regGlobalMaxRequests in window")
	assert.Greater(t, retryAfter, time.Duration(0))
	assert.LessOrEqual(t, retryAfter, regGlobalLockout+time.Second)
}

func TestRegGlobalLimiter_SlidingWindowExpiry(t *testing.T) {
	rl := newRegistrationGlobalLimiter()

	// Inject old requests outside the sliding window.
	rl.mu.Lock()
	for i := 0; i < regGlobalMaxRequests; i++ {
		rl.requests = append(rl.requests, time.Now().Add(-2*regGlobalWindow))
	}
	rl.mu.Unlock()

	// One new request should NOT trigger lockout — old ones are outside the window.
	rl.record()
	blocked, _ := rl.check()
	assert.False(t, blocked, "expired requests outside window should not count")
}

// ---------------------------------------------------------------------------
// extractClientIP tests
// ---------------------------------------------------------------------------

func TestExtractClientIP(t *testing.T) {
	// The package-level extractClientIP passes nil trustedProxies, which
	// means proxy headers are NEVER trusted (fail-safe default). Only
	// RemoteAddr is used.
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
			name:       "xff ignored without trusted proxies",
			remoteAddr: "10.0.0.1:80",
			headers: map[string]string{
				"X-Forwarded-For": "198.51.100.25, 203.0.113.9",
			},
			want: "10.0.0.1",
		},
		{
			name:       "forwarded ignored without trusted proxies",
			remoteAddr: "10.0.0.1:80",
			headers: map[string]string{
				"Forwarded": `for=198.51.100.1;proto=https;by=203.0.113.43`,
			},
			want: "10.0.0.1",
		},
		{
			name:       "x-real-ip ignored without trusted proxies",
			remoteAddr: "10.0.0.1:80",
			headers: map[string]string{
				"X-Real-IP": "203.0.113.11",
			},
			want: "10.0.0.1",
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

// ---------------------------------------------------------------------------
// extractClientIPWithProxies (trusted proxy) tests
// ---------------------------------------------------------------------------

func TestExtractClientIPWithTrustedProxies(t *testing.T) {
	trustedCIDR := netip.MustParsePrefix("10.0.0.0/8")

	tests := []struct {
		name           string
		remoteAddr     string
		headers        map[string]string
		trustedProxies []netip.Prefix
		want           string
	}{
		{
			name:           "trusted proxy honors XFF",
			remoteAddr:     "10.0.0.1:80",
			headers:        map[string]string{"X-Forwarded-For": "198.51.100.25"},
			trustedProxies: []netip.Prefix{trustedCIDR},
			want:           "198.51.100.25",
		},
		{
			name:           "untrusted peer ignores XFF",
			remoteAddr:     "192.168.1.1:80",
			headers:        map[string]string{"X-Forwarded-For": "198.51.100.25"},
			trustedProxies: []netip.Prefix{trustedCIDR},
			want:           "192.168.1.1",
		},
		{
			name:           "untrusted peer ignores Forwarded",
			remoteAddr:     "192.168.1.1:80",
			headers:        map[string]string{"Forwarded": "for=198.51.100.25"},
			trustedProxies: []netip.Prefix{trustedCIDR},
			want:           "192.168.1.1",
		},
		{
			name:           "untrusted peer ignores X-Real-IP",
			remoteAddr:     "192.168.1.1:80",
			headers:        map[string]string{"X-Real-IP": "198.51.100.25"},
			trustedProxies: []netip.Prefix{trustedCIDR},
			want:           "192.168.1.1",
		},
		{
			name:           "no trusted proxies configured - trust none (fail-safe)",
			remoteAddr:     "192.168.1.1:80",
			headers:        map[string]string{"X-Forwarded-For": "198.51.100.25"},
			trustedProxies: nil,
			want:           "192.168.1.1",
		},
		{
			name:           "empty trusted proxies - trust none (fail-safe)",
			remoteAddr:     "192.168.1.1:80",
			headers:        map[string]string{"X-Forwarded-For": "198.51.100.25"},
			trustedProxies: []netip.Prefix{},
			want:           "192.168.1.1",
		},
		{
			name:           "trusted proxy with no headers falls back to remote",
			remoteAddr:     "10.0.0.1:80",
			trustedProxies: []netip.Prefix{trustedCIDR},
			want:           "10.0.0.1",
		},
		{
			name:           "multiple CIDRs - second matches",
			remoteAddr:     "172.16.0.1:80",
			headers:        map[string]string{"X-Forwarded-For": "198.51.100.25"},
			trustedProxies: []netip.Prefix{trustedCIDR, netip.MustParsePrefix("172.16.0.0/12")},
			want:           "198.51.100.25",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{RemoteAddr: tt.remoteAddr}
			r.Header = make(http.Header)
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			got := extractClientIPWithProxies(r, tt.trustedProxies)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWithTrustedProxies(t *testing.T) {
	t.Run("valid CIDRs", func(t *testing.T) {
		opt, err := WithTrustedProxies([]string{"10.0.0.0/8", "172.16.0.0/12"})
		require.NoError(t, err)
		require.NotNil(t, opt)
	})

	t.Run("bare IP treated as /32", func(t *testing.T) {
		opt, err := WithTrustedProxies([]string{"10.0.0.1"})
		require.NoError(t, err)
		require.NotNil(t, opt)
	})

	t.Run("bare IPv6 treated as /128", func(t *testing.T) {
		opt, err := WithTrustedProxies([]string{"::1"})
		require.NoError(t, err)
		require.NotNil(t, opt)
	})

	t.Run("invalid CIDR returns error", func(t *testing.T) {
		_, err := WithTrustedProxies([]string{"not-a-cidr"})
		require.Error(t, err)
	})

	t.Run("mixed valid and invalid returns error", func(t *testing.T) {
		_, err := WithTrustedProxies([]string{"10.0.0.0/8", "garbage"})
		require.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// Extended trusted proxy edge cases
// ---------------------------------------------------------------------------

func TestExtractClientIPWithTrustedProxies_IPv6(t *testing.T) {
	trustedIPv6 := netip.MustParsePrefix("fd00::/8")

	tests := []struct {
		name           string
		remoteAddr     string
		headers        map[string]string
		trustedProxies []netip.Prefix
		want           string
	}{
		{
			name:           "trusted IPv6 proxy honors XFF",
			remoteAddr:     "[fd00::1]:80",
			headers:        map[string]string{"X-Forwarded-For": "2001:db8::42"},
			trustedProxies: []netip.Prefix{trustedIPv6},
			want:           "2001:db8::42",
		},
		{
			name:           "untrusted IPv6 peer ignores XFF",
			remoteAddr:     "[2001:db8::99]:80",
			headers:        map[string]string{"X-Forwarded-For": "198.51.100.25"},
			trustedProxies: []netip.Prefix{trustedIPv6},
			want:           "2001:db8::99",
		},
		{
			name:           "trusted IPv6 proxy with Forwarded quoted IPv6",
			remoteAddr:     "[fd00::1]:80",
			headers:        map[string]string{"Forwarded": `for="[2001:db8::42]:1234"`},
			trustedProxies: []netip.Prefix{trustedIPv6},
			want:           "2001:db8::42",
		},
		{
			name:           "loopback IPv6 trusted",
			remoteAddr:     "[::1]:80",
			headers:        map[string]string{"X-Forwarded-For": "198.51.100.25"},
			trustedProxies: []netip.Prefix{netip.MustParsePrefix("::1/128")},
			want:           "198.51.100.25",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{RemoteAddr: tt.remoteAddr}
			r.Header = make(http.Header)
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			got := extractClientIPWithProxies(r, tt.trustedProxies)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExtractClientIPWithTrustedProxies_MultiHopXFF(t *testing.T) {
	// When there are multiple hops, X-Forwarded-For contains:
	//   <original-client>, <proxy-1>, <proxy-2>
	// extractClientIPWithProxies returns the first valid IP (the original client).
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}

	r := &http.Request{
		RemoteAddr: "10.0.0.5:80",
		Header: http.Header{
			"X-Forwarded-For": []string{"203.0.113.50, 10.0.0.3, 10.0.0.4"},
		},
	}
	got := extractClientIPWithProxies(r, trusted)
	assert.Equal(t, "203.0.113.50", got, "should extract the original client IP from multi-hop chain")
}

func TestExtractClientIPWithTrustedProxies_AllHeaderTypes(t *testing.T) {
	// When trusted, test priority: XFF > Forwarded > X-Real-IP.
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}

	t.Run("XFF takes priority over Forwarded and X-Real-IP", func(t *testing.T) {
		r := &http.Request{
			RemoteAddr: "10.0.0.1:80",
			Header: http.Header{
				"X-Forwarded-For": []string{"198.51.100.10"},
				"Forwarded":       []string{"for=198.51.100.20"},
				"X-Real-Ip":       []string{"198.51.100.30"},
			},
		}
		got := extractClientIPWithProxies(r, trusted)
		assert.Equal(t, "198.51.100.10", got)
	})

	t.Run("Forwarded takes priority over X-Real-IP when no XFF", func(t *testing.T) {
		r := &http.Request{
			RemoteAddr: "10.0.0.1:80",
			Header: http.Header{
				"Forwarded": []string{"for=198.51.100.20"},
				"X-Real-Ip": []string{"198.51.100.30"},
			},
		}
		got := extractClientIPWithProxies(r, trusted)
		assert.Equal(t, "198.51.100.20", got)
	})

	t.Run("X-Real-IP used when no XFF or Forwarded", func(t *testing.T) {
		r := &http.Request{
			RemoteAddr: "10.0.0.1:80",
			Header: http.Header{
				"X-Real-Ip": []string{"198.51.100.30"},
			},
		}
		got := extractClientIPWithProxies(r, trusted)
		assert.Equal(t, "198.51.100.30", got)
	})
}

// TestAPIExtractClientIP_MethodWithTrustedProxies tests the API-method-level
// extractClientIP that reads the trustedProxies from the API struct.
func TestAPIExtractClientIP_MethodWithTrustedProxies(t *testing.T) {
	a := &API{
		trustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}

	t.Run("trusted peer uses XFF", func(t *testing.T) {
		r := &http.Request{
			RemoteAddr: "10.0.0.1:80",
			Header: http.Header{
				"X-Forwarded-For": []string{"198.51.100.25"},
			},
		}
		got := a.extractClientIP(r)
		assert.Equal(t, "198.51.100.25", got)
	})

	t.Run("untrusted peer ignores XFF", func(t *testing.T) {
		r := &http.Request{
			RemoteAddr: "192.168.1.1:80",
			Header: http.Header{
				"X-Forwarded-For": []string{"198.51.100.25"},
			},
		}
		got := a.extractClientIP(r)
		assert.Equal(t, "192.168.1.1", got)
	})
}

func TestAPIExtractClientIP_MethodWithoutTrustedProxies(t *testing.T) {
	a := &API{} // trustedProxies is nil — fail-safe: trust no proxy headers

	r := &http.Request{
		RemoteAddr: "192.168.1.1:80",
		Header: http.Header{
			"X-Forwarded-For": []string{"198.51.100.25"},
		},
	}
	got := a.extractClientIP(r)
	assert.Equal(t, "192.168.1.1", got, "should ignore proxy headers when no trusted proxies configured")
}

func TestExtractClientIPWithTrustedProxies_SpoofAttempt(t *testing.T) {
	// An attacker directly connecting (not through a proxy) tries to spoof
	// their IP via X-Forwarded-For. With trusted proxies configured, the
	// header should be ignored.
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}

	r := &http.Request{
		RemoteAddr: "203.0.113.99:12345",
		Header: http.Header{
			"X-Forwarded-For": []string{"10.0.0.1"}, // trying to look internal
			"Forwarded":       []string{"for=10.0.0.2"},
			"X-Real-Ip":       []string{"10.0.0.3"},
		},
	}
	got := extractClientIPWithProxies(r, trusted)
	assert.Equal(t, "203.0.113.99", got, "should use TCP peer, not spoofed headers")
}

func TestExtractClientIPWithTrustedProxies_NarrowCIDR(t *testing.T) {
	// Only a single IP is trusted (the exact load balancer).
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")}

	t.Run("exact match trusted", func(t *testing.T) {
		r := &http.Request{
			RemoteAddr: "10.0.0.1:80",
			Header: http.Header{
				"X-Forwarded-For": []string{"198.51.100.25"},
			},
		}
		got := extractClientIPWithProxies(r, trusted)
		assert.Equal(t, "198.51.100.25", got)
	})

	t.Run("adjacent IP not trusted", func(t *testing.T) {
		r := &http.Request{
			RemoteAddr: "10.0.0.2:80",
			Header: http.Header{
				"X-Forwarded-For": []string{"198.51.100.25"},
			},
		}
		got := extractClientIPWithProxies(r, trusted)
		assert.Equal(t, "10.0.0.2", got, "10.0.0.2 is not in 10.0.0.1/32")
	})
}

// ---------------------------------------------------------------------------
// requestIsSecureWithProxies — forwarded-proto trust model
// ---------------------------------------------------------------------------

func TestRequestIsSecure_DirectTLSAlwaysSecure(t *testing.T) {
	// When the connection is direct TLS, result is always true regardless of
	// proxy configuration or headers.
	r := &http.Request{
		TLS:        &tls.ConnectionState{},
		RemoteAddr: "1.2.3.4:443",
	}
	assert.True(t, requestIsSecureWithProxies(r, nil))
}

func TestRequestIsSecure_NoTrustedProxies_IgnoresForwardedProtoHeaders(t *testing.T) {
	// Without trusted proxies configured (nil/empty), forwarded-proto headers
	// must be ignored — fail-safe default.
	t.Run("XForwardedProto", func(t *testing.T) {
		r := &http.Request{
			RemoteAddr: "10.0.0.1:80",
			Header:     http.Header{"X-Forwarded-Proto": []string{"https"}},
		}
		assert.False(t, requestIsSecureWithProxies(r, nil), "should ignore X-Forwarded-Proto without trusted proxies")
		assert.False(t, requestIsSecureWithProxies(r, []netip.Prefix{}), "should ignore X-Forwarded-Proto with empty trusted proxies")
	})
	t.Run("Forwarded", func(t *testing.T) {
		r := &http.Request{
			RemoteAddr: "10.0.0.1:80",
			Header:     http.Header{"Forwarded": []string{"proto=https"}},
		}
		assert.False(t, requestIsSecureWithProxies(r, nil), "should ignore Forwarded header without trusted proxies")
	})
}

func TestRequestIsSecure_UntrustedPeer_IgnoresForwardedProtoHeaders(t *testing.T) {
	// Even with trusted proxies configured, a peer outside the trusted range
	// must not have its forwarded-proto headers honored.
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}

	t.Run("XForwardedProto_UntrustedPeer", func(t *testing.T) {
		r := &http.Request{
			RemoteAddr: "192.168.1.1:80",
			Header:     http.Header{"X-Forwarded-Proto": []string{"https"}},
		}
		assert.False(t, requestIsSecureWithProxies(r, trusted), "untrusted peer's X-Forwarded-Proto must be ignored")
	})
	t.Run("Forwarded_UntrustedPeer", func(t *testing.T) {
		r := &http.Request{
			RemoteAddr: "192.168.1.1:80",
			Header:     http.Header{"Forwarded": []string{"proto=https"}},
		}
		assert.False(t, requestIsSecureWithProxies(r, trusted), "untrusted peer's Forwarded header must be ignored")
	})
}

func TestRequestIsSecure_TrustedPeer_HonorsForwardedProtoHeaders(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}

	t.Run("XForwardedProto_HTTPS", func(t *testing.T) {
		r := &http.Request{
			RemoteAddr: "10.0.0.5:80",
			Header:     http.Header{"X-Forwarded-Proto": []string{"https"}},
		}
		assert.True(t, requestIsSecureWithProxies(r, trusted))
	})
	t.Run("XForwardedProto_HTTP", func(t *testing.T) {
		r := &http.Request{
			RemoteAddr: "10.0.0.5:80",
			Header:     http.Header{"X-Forwarded-Proto": []string{"http"}},
		}
		assert.False(t, requestIsSecureWithProxies(r, trusted))
	})
	t.Run("Forwarded_HTTPS", func(t *testing.T) {
		r := &http.Request{
			RemoteAddr: "10.0.0.5:80",
			Header:     http.Header{"Forwarded": []string{"proto=https"}},
		}
		assert.True(t, requestIsSecureWithProxies(r, trusted))
	})
	t.Run("Forwarded_HTTP", func(t *testing.T) {
		r := &http.Request{
			RemoteAddr: "10.0.0.5:80",
			Header:     http.Header{"Forwarded": []string{"proto=http"}},
		}
		assert.False(t, requestIsSecureWithProxies(r, trusted))
	})
}

func TestRequestIsSecure_TrustedPeer_NoHeaders_NotSecure(t *testing.T) {
	// Trusted peer but no forwarded-proto headers → not secure (no TLS).
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
	r := &http.Request{
		RemoteAddr: "10.0.0.5:80",
	}
	assert.False(t, requestIsSecureWithProxies(r, trusted))
}

func TestRequestIsSecure_PackageLevelFunction_FailSafe(t *testing.T) {
	// The package-level requestIsSecure (no proxies) must always ignore
	// forwarded-proto headers.
	r := &http.Request{
		RemoteAddr: "10.0.0.1:80",
		Header:     http.Header{"X-Forwarded-Proto": []string{"https"}},
	}
	assert.False(t, requestIsSecure(r), "package-level requestIsSecure must be fail-safe")
}
