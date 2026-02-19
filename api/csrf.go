package api

import (
	"crypto/subtle"
	"net/http"
	"time"

	"github.com/jmcleod/ironhand/internal/uuid"
)

const (
	csrfCookieName = "ironhand_csrf"
	csrfHeaderName = "X-CSRF-Token"
)

// CSRFMiddleware enforces double-submit cookie CSRF protection for
// cookie-authenticated mutating requests. Safe methods (GET, HEAD, OPTIONS)
// and header-authenticated requests are exempt.
func (a *API) CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Safe methods do not need CSRF protection.
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		// If no session cookie is present the request is either
		// header-authenticated or unauthenticated — both cases are
		// immune to CSRF because cross-origin requests cannot set
		// custom headers.
		if _, err := r.Cookie(sessionCookieName); err != nil {
			next.ServeHTTP(w, r)
			return
		}

		// Validate the CSRF token.
		cookie, err := r.Cookie(csrfCookieName)
		if err != nil || cookie.Value == "" {
			writeError(w, http.StatusForbidden, "missing CSRF token")
			return
		}
		header := r.Header.Get(csrfHeaderName)
		if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) != 1 {
			writeError(w, http.StatusForbidden, "invalid CSRF token")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// writeCSRFCookie sets the CSRF double-submit cookie. It is intentionally
// NOT HttpOnly so that the browser-side SPA can read it and include it as a
// request header on mutating requests.
func writeCSRFCookie(w http.ResponseWriter, r *http.Request) {
	token := uuid.New()
	secure := requestIsSecure(r)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearCSRFCookie removes the CSRF cookie on logout.
func clearCSRFCookie(w http.ResponseWriter, r *http.Request) {
	secure := requestIsSecure(r)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}
