package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
)

// cspNonceKey is the context key used to pass the per-request CSP nonce from
// the SecurityHeaders middleware to downstream handlers (e.g. the web handler
// that injects the nonce into served HTML).
type cspNonceKeyType struct{}

var cspNonceKey = cspNonceKeyType{}

// CSPNonce retrieves the per-request CSP nonce from the request context.
// Returns an empty string if the middleware has not run.
func CSPNonce(ctx context.Context) string {
	if v, ok := ctx.Value(cspNonceKey).(string); ok {
		return v
	}
	return ""
}

// SecurityHeaders returns middleware that sets standard security response
// headers on every response. It should be placed early in the middleware chain.
//
// A per-request cryptographic nonce is generated for style-src, replacing
// 'unsafe-inline'. The nonce is stored in the request context so that the
// web handler can inject it into served HTML pages (via a <meta> tag) and
// downstream components can apply it to dynamically created <style> elements.
//
// HSTS (Strict-Transport-Security) is only set when the request is determined
// to be secure. Forwarded-protocol headers (X-Forwarded-Proto, Forwarded) are
// only honored if the direct peer's RemoteAddr falls within the API's
// configured --trusted-proxies CIDR ranges, matching the same trust model used
// for client IP extraction.
func (a *API) SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := generateCSPNonce()
		ctx := context.WithValue(r.Context(), cspNonceKey, nonce)
		r = r.WithContext(ctx)

		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

		csp := fmt.Sprintf(
			"default-src 'self'; script-src 'self'; style-src 'self' 'nonce-%s'; "+
				"img-src 'self' data:; connect-src 'self'; "+
				"object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
			nonce,
		)
		w.Header().Set("Content-Security-Policy", csp)

		if requestIsSecureWithProxies(r, a.trustedProxies) {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}

		next.ServeHTTP(w, r)
	})
}

// generateCSPNonce returns a 16-byte base64-encoded cryptographic nonce.
func generateCSPNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback should never happen with a working OS CSPRNG.
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawStdEncoding.EncodeToString(b)
}

// noCacheHeaders is middleware that prevents caching of API responses.
// It sets Cache-Control: no-store to prevent browsers and intermediate
// proxies from persisting sensitive data (secret keys, vault items,
// credentials, private keys, etc.) to disk.
//
// Pragma: no-cache is included for HTTP/1.0 backward compatibility.
func noCacheHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		next.ServeHTTP(w, r)
	})
}
