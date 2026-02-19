package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/jmcleod/ironhand/vault"
)

type contextKey int

const credentialsKey contextKey = iota

const sessionCookieName = "ironhand_session"

type authSession struct {
	SecretKeyID           string
	SessionPassphrase     string
	CredentialsBlob       string
	ExpiresAt             time.Time
	LastAccessedAt        time.Time
	PendingTOTPSecret     string
	PendingTOTPExpiry     time.Time
	WebAuthnSessionData   string
	WebAuthnSessionExpiry time.Time
}

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

		blob, err := base64.StdEncoding.DecodeString(credsHeader)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid X-Credentials encoding")
			return
		}

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

	a.sessions.mu.RLock()
	session, ok := a.sessions.data[token]
	a.sessions.mu.RUnlock()
	if !ok || time.Now().After(session.ExpiresAt) {
		return nil, false
	}

	// Check idle timeout.
	if a.idleTimeout > 0 && time.Since(session.LastAccessedAt) > a.idleTimeout {
		a.sessions.mu.Lock()
		delete(a.sessions.data, token)
		a.sessions.mu.Unlock()
		return nil, false
	}

	blob, err := base64.StdEncoding.DecodeString(session.CredentialsBlob)
	if err != nil {
		return nil, false
	}
	creds, err := vault.ImportCredentials(blob, session.SessionPassphrase)
	if err != nil {
		return nil, false
	}

	// Update last accessed timestamp.
	session.LastAccessedAt = time.Now()
	a.sessions.mu.Lock()
	a.sessions.data[token] = session
	a.sessions.mu.Unlock()

	return creds, true
}

func writeSessionCookie(w http.ResponseWriter, r *http.Request, token string, expiresAt time.Time) {
	secure := requestIsSecure(r)
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

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	secure := requestIsSecure(r)
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
}

func combineLoginPassphrase(passphrase, secretKey string) string {
	return passphrase + ":" + secretKey
}

func requestIsSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Forwarded")), "proto=https")
}

func credentialsFromContext(ctx context.Context) *vault.Credentials {
	creds, _ := ctx.Value(credentialsKey).(*vault.Credentials)
	return creds
}
