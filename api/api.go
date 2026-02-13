package api

import (
	"context"

	"github.com/go-chi/chi/v5"

	"github.com/jmcleod/ironhand/storage"
	"github.com/jmcleod/ironhand/vault"
)

// API holds the dependencies needed by the REST handlers.
type API struct {
	repo       storage.Repository
	epochCache vault.EpochCache
}

// New creates a new API instance.
func New(repo storage.Repository, epochCache vault.EpochCache) *API {
	return &API{
		repo:       repo,
		epochCache: epochCache,
	}
}

// Router returns a chi.Router with all API routes mounted.
func (a *API) Router() chi.Router {
	r := chi.NewRouter()

	// Create vault does not require auth headers (credentials are generated).
	r.Post("/vaults", a.CreateVault)

	// All other vault routes require auth middleware.
	r.Route("/vaults/{vaultID}", func(r chi.Router) {
		r.Use(AuthMiddleware)
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
