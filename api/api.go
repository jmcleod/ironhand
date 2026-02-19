package api

import (
	"context"
	_ "embed"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/jmcleod/ironhand/pki"
	"github.com/jmcleod/ironhand/storage"
	"github.com/jmcleod/ironhand/vault"
)

// API holds the dependencies needed by the REST handlers.
type API struct {
	repo               storage.Repository
	epochCache         vault.EpochCache
	sessions           *sessionStore
	rateLimiter        *loginRateLimiter
	ipLimiter          *ipRateLimiter
	globalLimiter      *globalRateLimiter
	audit              *auditLogger
	metrics            *metricsCollector
	headerAuthEnabled  bool
	idleTimeout        time.Duration
	keyStore           pki.KeyStore
	webauthn           *webauthn.WebAuthn
	webauthnCeremonies map[string]webauthnCeremonyState
	webauthnCeremonyMu sync.Mutex
}

const defaultIdleTimeout = 30 * time.Minute

type sessionStore struct {
	mu   sync.RWMutex
	data map[string]authSession
}

//go:embed openapi.yaml
var openapiSpec []byte

// Option configures the API instance.
type Option func(*API)

// WithLogger sets the structured logger for audit events.
// If not set, a default JSON logger writing to stderr is used.
func WithLogger(logger *slog.Logger) Option {
	return func(a *API) {
		a.audit = newAuditLogger(logger)
	}
}

// WithHeaderAuth enables or disables X-Credentials/X-Passphrase header-based
// authentication. This is disabled by default for security. Enable it only
// for non-browser API clients that cannot use cookie-based sessions.
func WithHeaderAuth(enabled bool) Option {
	return func(a *API) {
		a.headerAuthEnabled = enabled
	}
}

// WithIdleTimeout sets the session idle timeout. If a session is not used
// within this duration, it is automatically invalidated. The default is
// 30 minutes.
func WithIdleTimeout(d time.Duration) Option {
	return func(a *API) {
		a.idleTimeout = d
	}
}

// WithAlerting enables anomaly detection and invokes the callback when a
// suspicious pattern is detected (e.g., login failure spike, bulk exports).
func WithAlerting(fn AlertFunc) Option {
	return func(a *API) {
		a.metrics = newMetricsCollector(fn)
	}
}

// WithWebAuthn enables WebAuthn/passkey MFA for the API.
func WithWebAuthn(wa *webauthn.WebAuthn) Option {
	return func(a *API) {
		a.webauthn = wa
		a.webauthnCeremonies = make(map[string]webauthnCeremonyState)
	}
}

// WithKeyStore configures an alternative PKI key store (e.g. HSM or cloud
// KMS). When nil (the default), a SoftwareKeyStore is used — keys are
// generated in software and stored in the vault like before.
func WithKeyStore(ks pki.KeyStore) Option {
	return func(a *API) {
		a.keyStore = ks
	}
}

// New creates a new API instance.
func New(repo storage.Repository, epochCache vault.EpochCache, opts ...Option) *API {
	a := &API{
		repo:       repo,
		epochCache: epochCache,
		sessions: &sessionStore{
			data: make(map[string]authSession),
		},
		rateLimiter:   newLoginRateLimiter(),
		ipLimiter:     newIPRateLimiter(),
		globalLimiter: newGlobalRateLimiter(),
		idleTimeout:   defaultIdleTimeout,
	}
	for _, opt := range opts {
		opt(a)
	}
	if a.audit == nil {
		a.audit = newAuditLogger(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	}
	// Wire metrics collector into the audit logger if alerting is configured.
	if a.metrics != nil {
		a.audit.metrics = a.metrics
	}
	return a
}

// Router returns a chi.Router with all API routes mounted.
func (a *API) Router() chi.Router {
	r := chi.NewRouter()

	r.Get("/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/yaml")
		w.Write(openapiSpec)
	})

	r.Handle("/docs*", middleware.SwaggerUI(middleware.SwaggerUIOpts{
		SpecURL: "/api/v1/openapi.yaml",
		Path:    "api/v1/docs",
	}, nil))

	r.Handle("/redoc*", middleware.Redoc(middleware.RedocOpts{
		SpecURL: "/api/v1/openapi.yaml",
		Path:    "api/v1/redoc",
	}, nil))

	r.Post("/auth/register", a.Register)
	r.Post("/auth/login", a.Login)
	r.Post("/auth/logout", a.Logout)
	r.With(a.AuthMiddleware).Get("/auth/2fa", a.TwoFactorStatus)
	r.With(a.AuthMiddleware, a.CSRFMiddleware).Post("/auth/2fa/setup", a.SetupTwoFactor)
	r.With(a.AuthMiddleware, a.CSRFMiddleware).Post("/auth/2fa/enable", a.EnableTwoFactor)

	// WebAuthn routes (registration + status require auth; login does not).
	r.With(a.AuthMiddleware).Get("/auth/webauthn/status", a.WebAuthnStatus)
	r.With(a.AuthMiddleware, a.CSRFMiddleware).Post("/auth/webauthn/register/begin", a.BeginWebAuthnRegistration)
	r.With(a.AuthMiddleware, a.CSRFMiddleware).Post("/auth/webauthn/register/finish", a.FinishWebAuthnRegistration)
	r.Post("/auth/webauthn/login/begin", a.BeginWebAuthnLogin)
	r.Post("/auth/webauthn/login/finish", a.FinishWebAuthnLogin)

	r.With(a.AuthMiddleware, a.CSRFMiddleware).Post("/vaults", a.CreateVault)
	r.With(a.AuthMiddleware).Get("/vaults", a.ListVaults)

	// All other vault routes require auth middleware.
	r.Route("/vaults/{vaultID}", func(r chi.Router) {
		r.Use(a.AuthMiddleware)
		r.Use(a.CSRFMiddleware)
		r.Delete("/", a.DeleteVault)
		r.Post("/open", a.OpenVault)
		r.Get("/items", a.ListItems)
		r.Post("/items/{itemID}", a.PutItem)
		r.Get("/items/{itemID}", a.GetItem)
		r.Put("/items/{itemID}", a.UpdateItem)
		r.Delete("/items/{itemID}", a.DeleteItem)
		r.Get("/items/{itemID}/history", a.GetItemHistory)
		r.Get("/items/{itemID}/history/{version}", a.GetHistoryVersion)
		r.Get("/items/{itemID}/private-key", a.GetItemPrivateKey)
		r.Get("/audit", a.ListAuditLogs)
		r.Get("/audit/export", a.ExportAuditLog)
		r.Post("/members", a.AddMember)
		r.Delete("/members/{memberID}", a.RevokeMember)
		r.Post("/export", a.ExportVault)
		r.Post("/import", a.ImportVault)

		// PKI / Certificate Authority routes
		r.Route("/pki", func(r chi.Router) {
			r.Post("/init", a.InitCA)
			r.Get("/info", a.GetCAInfo)
			r.Get("/ca.pem", a.GetCACert)
			r.Post("/issue", a.IssueCert)
			r.Get("/crl.pem", a.GetCRL)
			r.Post("/sign-csr", a.SignCSR)
			r.Post("/items/{itemID}/revoke", a.RevokeCert)
			r.Post("/items/{itemID}/renew", a.RenewCert)
		})
	})

	return r
}

// openSession creates a Vault and opens a session with the given credentials.
func (a *API) openSession(ctx context.Context, vaultID string, creds *vault.Credentials) (*vault.Session, error) {
	v := vault.New(vaultID, a.repo, vault.WithEpochCache(a.epochCache))
	return v.Open(ctx, creds)
}
