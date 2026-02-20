package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/awnumar/memguard"
	"github.com/jmcleod/ironhand/internal/util"
	"github.com/jmcleod/ironhand/vault"
)

type contextKey int

const credentialsKey contextKey = iota

const sessionCookieName = "ironhand_session"
const sessionSecretCookieName = "ironhand_session_key"

// AuthMiddleware authenticates either a session cookie or explicit credentials
// and stores imported credentials on the request context.
func (a *API) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if creds, ok := a.credentialsFromSessionCookie(r); ok {
			defer creds.Destroy()
			ctx := context.WithValue(r.Context(), credentialsKey, creds)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		if !a.headerAuthEnabled {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}

		credsHeader := r.Header.Get("X-Credentials")
		if credsHeader == "" {
			writeError(w, http.StatusUnauthorized, "missing X-Credentials header")
			return
		}

		passphrase := r.Header.Get("X-Passphrase")
		if passphrase == "" {
			writeError(w, http.StatusUnauthorized, "missing X-Passphrase header")
			return
		}
		defer func() { passphrase = "" }() // best-effort: remove string reference

		blob, err := base64.StdEncoding.DecodeString(credsHeader)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid X-Credentials encoding")
			return
		}
		defer util.WipeBytes(blob)

		creds, err := vault.ImportCredentials(blob, passphrase)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		defer creds.Destroy()

		ctx := context.WithValue(r.Context(), credentialsKey, creds)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *API) credentialsFromSessionCookie(r *http.Request) (*vault.Credentials, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil, false
	}
	token := cookie.Value

	secretCookie, err := r.Cookie(sessionSecretCookieName)
	if err != nil || secretCookie.Value == "" {
		return nil, false
	}

	session, ok := a.sessions.Get(token)
	if !ok {
		return nil, false
	}

	blob, err := base64.StdEncoding.DecodeString(session.CredentialsBlob)
	if err != nil {
		return nil, false
	}
	defer util.WipeBytes(blob)

	passBuf := deriveSessionPassphrase(token, secretCookie.Value)
	defer passBuf.Destroy()
	creds, err := vault.ImportCredentialsBytes(blob, passBuf.Bytes())
	if err != nil {
		return nil, false
	}

	// Update last accessed timestamp.
	session.LastAccessedAt = time.Now()
	a.sessions.Put(token, session)

	return creds, true
}

func writeSessionCookie(w http.ResponseWriter, r *http.Request, token string, expiresAt time.Time, trustedProxies []netip.Prefix) {
	secure := requestIsSecureWithProxies(r, trustedProxies)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  expiresAt,
	})
}

func writeSessionSecretCookie(w http.ResponseWriter, r *http.Request, secret string, expiresAt time.Time, trustedProxies []netip.Prefix) {
	secure := requestIsSecureWithProxies(r, trustedProxies)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionSecretCookieName,
		Value:    secret,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		Expires:  expiresAt,
	})
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request, trustedProxies []netip.Prefix) {
	secure := requestIsSecureWithProxies(r, trustedProxies)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     sessionSecretCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

// combineLoginPassphrase combines a passphrase and secret key into a single
// login passphrase stored in a memguard LockedBuffer (mlock'd, wiped on
// Destroy). The caller must call Destroy() on the returned buffer when done.
func combineLoginPassphrase(passphrase, secretKey string) *memguard.LockedBuffer {
	combined := []byte(passphrase + ":" + secretKey)
	return memguard.NewBufferFromBytes(combined) // NewBufferFromBytes wipes combined
}

// deriveSessionPassphrase derives a session passphrase from the session ID
// (stored in the ironhand_session cookie) and the session secret (stored in
// the ironhand_session_key cookie) using HMAC-SHA256. The result is returned
// in a memguard LockedBuffer (mlock'd, wiped on Destroy). This ensures that
// neither the server-side session store nor the client cookie alone is
// sufficient to reconstruct the credentials passphrase. The caller must call
// Destroy() on the returned buffer when done.
func deriveSessionPassphrase(sessionID, sessionSecret string) *memguard.LockedBuffer {
	keyBytes := []byte(sessionSecret)
	mac := hmac.New(sha256.New, keyBytes)
	util.WipeBytes(keyBytes)
	mac.Write([]byte("ironhand:session_passphrase:v1:" + sessionID))
	raw := mac.Sum(nil)
	hexBytes := []byte(hex.EncodeToString(raw))
	util.WipeBytes(raw)
	return memguard.NewBufferFromBytes(hexBytes) // NewBufferFromBytes wipes hexBytes
}

// requestIsSecureWithProxies reports whether the original client connection
// uses TLS.
//
// Forwarded-protocol headers (X-Forwarded-Proto, Forwarded) are only honored
// when trustedProxies is non-empty AND the request's RemoteAddr falls within
// one of the trusted CIDR ranges — the same trust model used by
// extractClientIPWithProxies. When trustedProxies is nil or empty (the
// default), only the direct TLS state (r.TLS) is checked.
func requestIsSecureWithProxies(r *http.Request, trustedProxies []netip.Prefix) bool {
	if r.TLS != nil {
		return true
	}

	if !isPeerTrusted(r, trustedProxies) {
		return false
	}

	if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Forwarded")), "proto=https")
}

// requestIsSecure is the package-level convenience function for contexts
// without an API instance. It trusts no proxy headers and only checks r.TLS
// (fail-safe default).
func requestIsSecure(r *http.Request) bool {
	return requestIsSecureWithProxies(r, nil)
}

// isPeerTrusted reports whether the request's direct peer (RemoteAddr) falls
// within one of the configured trusted proxy CIDR ranges. Returns false when
// trustedProxies is nil or empty (fail-safe default).
func isPeerTrusted(r *http.Request, trustedProxies []netip.Prefix) bool {
	if len(trustedProxies) == 0 {
		return false
	}
	remoteIP, _ := parseIPCandidate(r.RemoteAddr)
	if remoteIP == "" {
		return false
	}
	addr, err := netip.ParseAddr(remoteIP)
	if err != nil {
		return false
	}
	for _, prefix := range trustedProxies {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func credentialsFromContext(ctx context.Context) *vault.Credentials {
	creds, _ := ctx.Value(credentialsKey).(*vault.Credentials)
	return creds
}
