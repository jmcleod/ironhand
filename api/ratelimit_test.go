package api

import (
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
