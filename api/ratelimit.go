package api

import (
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
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

// ---------------------------------------------------------------------------
// Per-IP rate limiter
// ---------------------------------------------------------------------------

const (
	ipMaxFailures = 20
	ipBaseLockout = 1 * time.Minute
	ipMaxLockout  = 30 * time.Minute
)

// ipRateLimiter tracks failed login attempts per source IP.
type ipRateLimiter struct {
	mu       sync.Mutex
	attempts map[string]*attemptRecord
}

func newIPRateLimiter() *ipRateLimiter {
	return &ipRateLimiter{
		attempts: make(map[string]*attemptRecord),
	}
}

func (rl *ipRateLimiter) check(ip string) (blocked bool, retryAfter time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rec, ok := rl.attempts[ip]
	if !ok {
		return false, 0
	}
	if time.Since(rec.lastFailure) > attemptExpiry {
		delete(rl.attempts, ip)
		return false, 0
	}
	if time.Now().Before(rec.lockedUntil) {
		return true, time.Until(rec.lockedUntil)
	}
	return false, 0
}

func (rl *ipRateLimiter) recordFailure(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rec, ok := rl.attempts[ip]
	if !ok {
		rec = &attemptRecord{}
		rl.attempts[ip] = rec
	}
	rec.failures++
	rec.lastFailure = time.Now()

	if rec.failures >= ipMaxFailures {
		shift := rec.failures - ipMaxFailures
		lockout := ipBaseLockout
		for i := 0; i < shift; i++ {
			lockout *= 2
			if lockout > ipMaxLockout {
				lockout = ipMaxLockout
				break
			}
		}
		rec.lockedUntil = time.Now().Add(lockout)
	}
}

func (rl *ipRateLimiter) recordSuccess(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.attempts, ip)
}

// ---------------------------------------------------------------------------
// Global rate limiter (sliding window)
// ---------------------------------------------------------------------------

const (
	globalWindow      = 1 * time.Minute
	globalMaxFailures = 100
	globalLockout     = 5 * time.Minute
)

// globalRateLimiter tracks total failed login attempts across all accounts
// using a sliding window.
type globalRateLimiter struct {
	mu          sync.Mutex
	failures    []time.Time
	lockedUntil time.Time
}

func newGlobalRateLimiter() *globalRateLimiter {
	return &globalRateLimiter{}
}

func (rl *globalRateLimiter) check() (blocked bool, retryAfter time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if time.Now().Before(rl.lockedUntil) {
		return true, time.Until(rl.lockedUntil)
	}
	return false, 0
}

func (rl *globalRateLimiter) recordFailure() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	rl.failures = append(rl.failures, now)

	// Trim failures outside the window.
	cutoff := now.Add(-globalWindow)
	start := 0
	for start < len(rl.failures) && rl.failures[start].Before(cutoff) {
		start++
	}
	rl.failures = rl.failures[start:]

	if len(rl.failures) >= globalMaxFailures {
		rl.lockedUntil = now.Add(globalLockout)
	}
}

// ---------------------------------------------------------------------------
// Helper: extract client IP
// ---------------------------------------------------------------------------

// extractClientIP returns the client IP for rate limiting. It delegates to
// extractClientIPWithProxies using the API's configured trusted proxies.
func (a *API) extractClientIP(r *http.Request) string {
	return extractClientIPWithProxies(r, a.trustedProxies)
}

// extractClientIPWithProxies returns the best-effort client IP address.
//
// When trustedProxies is non-empty, proxy headers (X-Forwarded-For,
// Forwarded, X-Real-IP) are only honored if the request's RemoteAddr
// falls within one of the trusted CIDR ranges. This prevents untrusted
// clients from spoofing their source IP via headers.
//
// When trustedProxies is empty (the default), the legacy behaviour is
// preserved: proxy headers are consulted unconditionally.
//
// Priority when proxy headers are trusted:
// 1. First valid entry in X-Forwarded-For
// 2. First valid "for=" value in Forwarded
// 3. X-Real-IP
// 4. RemoteAddr
func extractClientIPWithProxies(r *http.Request, trustedProxies []netip.Prefix) string {
	remoteIP, _ := parseIPCandidate(r.RemoteAddr)

	// Determine whether the direct peer is trusted.
	proxyTrusted := len(trustedProxies) == 0 // empty = trust all (legacy)
	if !proxyTrusted && remoteIP != "" {
		if addr, err := netip.ParseAddr(remoteIP); err == nil {
			for _, prefix := range trustedProxies {
				if prefix.Contains(addr) {
					proxyTrusted = true
					break
				}
			}
		}
	}

	if proxyTrusted {
		if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
			for _, part := range strings.Split(xff, ",") {
				if ip, ok := parseIPCandidate(part); ok {
					return ip
				}
			}
		}

		if fwd := strings.TrimSpace(r.Header.Get("Forwarded")); fwd != "" {
			for _, elem := range strings.Split(fwd, ",") {
				for _, param := range strings.Split(elem, ";") {
					param = strings.TrimSpace(param)
					if !strings.HasPrefix(strings.ToLower(param), "for=") {
						continue
					}
					raw := strings.TrimSpace(param[4:])
					if ip, ok := parseIPCandidate(raw); ok {
						return ip
					}
				}
			}
		}

		if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
			if ip, ok := parseIPCandidate(xrip); ok {
				return ip
			}
		}
	}

	if remoteIP != "" {
		return remoteIP
	}
	return ""
}

// extractClientIP is the package-level function for use in tests and
// contexts without an API instance. It uses the legacy behaviour of
// trusting all proxy headers unconditionally.
func extractClientIP(r *http.Request) string {
	return extractClientIPWithProxies(r, nil)
}

func parseIPCandidate(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	s = strings.Trim(s, "\"")
	if s == "" {
		return "", false
	}

	// RFC 7239 quoted IPv6 may appear as [::1]:1234.
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}

	// Remove IPv6 brackets if present.
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	// Drop zone if any (e.g. fe80::1%eth0).
	if i := strings.IndexByte(s, '%'); i >= 0 {
		s = s[:i]
	}

	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.String(), true
	}
	// As a fallback, allow net.ParseIP normalization.
	if ip := net.ParseIP(s); ip != nil {
		return ip.String(), true
	}
	return "", false
}
