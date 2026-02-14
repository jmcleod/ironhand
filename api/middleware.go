package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/jmcleod/ironhand/crypto"
	"github.com/jmcleod/ironhand/vault"
)

type contextKey int

const credentialsKey contextKey = iota

const sessionCookieName = "ironhand_session"

type authSession struct {
	SecretKeyID     string
	LoginPassphrase string
	ExpiresAt       time.Time
}

// AuthMiddleware extracts X-Credentials and X-Passphrase headers, imports
// the credentials, and stores them on the request context. The credentials
// are destroyed after the next handler returns.
func (a *API) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if creds, ok := a.credentialsFromSessionCookie(r); ok {
			defer creds.Destroy()
			ctx := context.WithValue(r.Context(), credentialsKey, creds)
			next.ServeHTTP(w, r.WithContext(ctx))
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
			writeError(w, http.StatusUnauthorized, "credential import failed: "+err.Error())
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

	record, err := a.loadAccountRecord(session.SecretKeyID)
	if err != nil {
		return nil, false
	}
	blob, err := base64.StdEncoding.DecodeString(record.CredentialsBlob)
	if err != nil {
		return nil, false
	}
	creds, err := vault.ImportCredentials(blob, session.LoginPassphrase)
	if err != nil {
		return nil, false
	}
	return creds, true
}

func writeSessionCookie(w http.ResponseWriter, r *http.Request, token string, expiresAt time.Time) {
	secure := r.TLS != nil
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
	secure := r.TLS != nil
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

func parseSecretKeyID(secretKey string) (string, error) {
	sk, err := crypto.ParseSecretKey(secretKey)
	if err != nil {
		return "", err
	}
	return sk.ID(), nil
}

func credentialsFromContext(ctx context.Context) *vault.Credentials {
	creds, _ := ctx.Value(credentialsKey).(*vault.Credentials)
	return creds
}
