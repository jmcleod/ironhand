package api

import (
	"net/http"
	"strconv"
	"sync"
	"time"
)

// loginRateLimiter tracks failed login attempts per account and enforces
// exponential backoff. The key is the account lookup ID (SHA-256 of the
// secret key), NOT the raw secret key — so even rate-limit state doesn't
// leak credential material.
type loginRateLimiter struct {
	mu       sync.Mutex
	attempts map[string]*attemptRecord
}

type attemptRecord struct {
	failures    int
	lastFailure time.Time
	lockedUntil time.Time
}

const (
	// maxFailures is the number of consecutive failures before lockout begins.
	maxFailures = 5
	// baseLockout is the initial lockout duration after maxFailures is reached.
	baseLockout = 1 * time.Minute
	// maxLockout caps the exponential backoff.
	maxLockout = 15 * time.Minute
	// attemptExpiry is how long after the last failure before the record is
	// garbage-collected.
	attemptExpiry = 1 * time.Hour
)

func newLoginRateLimiter() *loginRateLimiter {
	return &loginRateLimiter{
		attempts: make(map[string]*attemptRecord),
	}
}

// check returns true if the account is currently locked out, along with how
// long the caller should wait. A zero duration means the request may proceed.
func (rl *loginRateLimiter) check(accountID string) (blocked bool, retryAfter time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rec, ok := rl.attempts[accountID]
	if !ok {
		return false, 0
	}
	// Expire stale records.
	if time.Since(rec.lastFailure) > attemptExpiry {
		delete(rl.attempts, accountID)
		return false, 0
	}
	if time.Now().Before(rec.lockedUntil) {
		return true, time.Until(rec.lockedUntil)
	}
	return false, 0
}

// recordFailure increments the failure counter and applies exponential
// backoff once maxFailures is exceeded.
func (rl *loginRateLimiter) recordFailure(accountID string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rec, ok := rl.attempts[accountID]
	if !ok {
		rec = &attemptRecord{}
		rl.attempts[accountID] = rec
	}
	rec.failures++
	rec.lastFailure = time.Now()

	if rec.failures >= maxFailures {
		// Exponential backoff: baseLockout * 2^(failures - maxFailures)
		shift := rec.failures - maxFailures
		lockout := baseLockout
		for i := 0; i < shift; i++ {
			lockout *= 2
			if lockout > maxLockout {
				lockout = maxLockout
				break
			}
		}
		rec.lockedUntil = time.Now().Add(lockout)
	}
}

// recordSuccess resets the failure counter on a successful login.
func (rl *loginRateLimiter) recordSuccess(accountID string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.attempts, accountID)
}

// sweep removes expired records. Call periodically from a background goroutine.
func (rl *loginRateLimiter) sweep() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for id, rec := range rl.attempts {
		if now.Sub(rec.lastFailure) > attemptExpiry {
			delete(rl.attempts, id)
		}
	}
}

// writeRateLimited sends a 429 Too Many Requests response.
func writeRateLimited(w http.ResponseWriter, retryAfter time.Duration) {
	w.Header().Set("Retry-After", retryAfterString(retryAfter))
	writeError(w, http.StatusTooManyRequests, "too many failed login attempts; try again later")
}

func retryAfterString(d time.Duration) string {
	secs := int(d.Seconds())
	if secs < 1 {
		secs = 1
	}
	return strconv.Itoa(secs)
}
