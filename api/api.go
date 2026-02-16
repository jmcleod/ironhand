package api

import (
	"context"
	_ "embed"
	"log/slog"
	"net/http"
	"os"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/go-openapi/runtime/middleware"

	"github.com/jmcleod/ironhand/storage"
	"github.com/jmcleod/ironhand/vault"
)

// API holds the dependencies needed by the REST handlers.
type API struct {
	repo        storage.Repository
	epochCache  vault.EpochCache
	sessions    *sessionStore
	rateLimiter *loginRateLimiter
	audit       *auditLogger
}

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

// New creates a new API instance.
func New(repo storage.Repository, epochCache vault.EpochCache, opts ...Option) *API {
	a := &API{
		repo:       repo,
		epochCache: epochCache,
		sessions: &sessionStore{
			data: make(map[string]authSession),
		},
		rateLimiter: newLoginRateLimiter(),
	}
	for _, opt := range opts {
		opt(a)
	}
	if a.audit == nil {
		a.audit = newAuditLogger(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
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
	r.With(a.AuthMiddleware).Post("/auth/2fa/setup", a.SetupTwoFactor)
	r.With(a.AuthMiddleware).Post("/auth/2fa/enable", a.EnableTwoFactor)

	r.With(a.AuthMiddleware).Post("/vaults", a.CreateVault)
	r.With(a.AuthMiddleware).Get("/vaults", a.ListVaults)

	// All other vault routes require auth middleware.
	r.Route("/vaults/{vaultID}", func(r chi.Router) {
		r.Use(a.AuthMiddleware)
		r.Delete("/", a.DeleteVault)
		r.Post("/open", a.OpenVault)
		r.Get("/items", a.ListItems)
		r.Post("/items/{itemID}", a.PutItem)
		r.Get("/items/{itemID}", a.GetItem)
		r.Put("/items/{itemID}", a.UpdateItem)
		r.Delete("/items/{itemID}", a.DeleteItem)
		r.Get("/items/{itemID}/history", a.GetItemHistory)
		r.Get("/items/{itemID}/history/{version}", a.GetHistoryVersion)
		r.Get("/audit", a.ListAuditLogs)
		r.Post("/members", a.AddMember)
		r.Delete("/members/{memberID}", a.RevokeMember)
	})

	return r
}

// openSession creates a Vault and opens a session with the given credentials.
func (a *API) openSession(ctx context.Context, vaultID string, creds *vault.Credentials) (*vault.Session, error) {
	v := vault.New(vaultID, a.repo, vault.WithEpochCache(a.epochCache))
	return v.Open(ctx, creds)
}
