package api

import (
	"context"
	_ "embed"
	"net/http"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/go-openapi/runtime/middleware"

	"github.com/jmcleod/ironhand/storage"
	"github.com/jmcleod/ironhand/vault"
)

// API holds the dependencies needed by the REST handlers.
type API struct {
	repo       storage.Repository
	epochCache vault.EpochCache
	sessions   *sessionStore
}

type sessionStore struct {
	mu   sync.RWMutex
	data map[string]authSession
}

//go:embed openapi.yaml
var openapiSpec []byte

// New creates a new API instance.
func New(repo storage.Repository, epochCache vault.EpochCache) *API {
	return &API{
		repo:       repo,
		epochCache: epochCache,
		sessions: &sessionStore{
			data: make(map[string]authSession),
		},
	}
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
	r.Post("/auth/reveal-secret-key", a.RevealSecretKey)

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
