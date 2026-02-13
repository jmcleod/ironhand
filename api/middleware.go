package api

import (
	"context"
	"encoding/base64"
	"net/http"

	"github.com/jmcleod/ironhand/vault"
)

type contextKey int

const credentialsKey contextKey = iota

// AuthMiddleware extracts X-Credentials and X-Passphrase headers, imports
// the credentials, and stores them on the request context. The credentials
// are destroyed after the next handler returns.
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func credentialsFromContext(ctx context.Context) *vault.Credentials {
	creds, _ := ctx.Value(credentialsKey).(*vault.Credentials)
	return creds
}
