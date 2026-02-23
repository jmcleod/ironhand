package api

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/jmcleod/ironhand/internal/util"
	"github.com/jmcleod/ironhand/pki"
	"github.com/jmcleod/ironhand/storage"
	"github.com/jmcleod/ironhand/vault"
)

// API holds the dependencies needed by the REST handlers.
type API struct {
	repo                       storage.Repository
	epochCache                 vault.EpochCache
	sessions                   SessionStore
	rateLimiter                *loginRateLimiter
	ipLimiter                  *ipRateLimiter
	globalLimiter              *globalRateLimiter
	regIPLimiter               *registrationIPLimiter
	regGlobalLimiter           *registrationGlobalLimiter
	audit                      *auditLogger
	metrics                    *metricsCollector
	headerAuthEnabled          bool
	idleTimeout                time.Duration
	keyStore                   pki.KeyStore
	webauthn                   *webauthn.WebAuthn
	webauthnCeremonies         map[string]webauthnCeremonyState
	webauthnCeremonyMu         sync.Mutex
	invites                    *inviteStore
	trustedProxies             []netip.Prefix       // CIDR ranges for trusted reverse proxies; nil = trust none (fail-safe)
	kdfParams                  *util.Argon2idParams // nil = use DefaultArgon2idParams(); overridden by --kdf-profile
	auditMu                    vaultMutex           // serialises audit appends per vault
	auditMaxAge                time.Duration
	auditMaxEntries            int
	auditAppendsSinceRetention atomic.Int64  // counts appends since last retention check
	webhook                    *auditWebhook // nil when not configured
	noRateLimit                bool          // disables all rate limiters (for E2E testing only)
}

// DefaultIdleTimeout is the default session idle timeout (30 minutes).
const DefaultIdleTimeout = 30 * time.Minute

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

// WithSessionStore sets a custom SessionStore implementation. When not set,
// an in-memory session store is used (sessions are lost on restart).
func WithSessionStore(s SessionStore) Option {
	return func(a *API) {
		a.sessions = s
	}
}

// WithAuditRetention configures automatic per-vault audit retention.
// maxAge <= 0 disables time-based pruning.
// maxEntries <= 0 disables count-based pruning.
func WithAuditRetention(maxAge time.Duration, maxEntries int) Option {
	return func(a *API) {
		a.auditMaxAge = maxAge
		a.auditMaxEntries = maxEntries
	}
}

// WithAuditWebhook configures an HTTP endpoint to receive all audit events
// as JSON POST requests. Events are dispatched asynchronously via a bounded
// queue (capacity 1024). Dropped events (queue full) are logged as warnings.
//
// The optional authHeader is sent with each request in "Header: Value"
// format (e.g., "Authorization: Bearer xxx").
func WithAuditWebhook(url, authHeader string) Option {
	return func(a *API) {
		a.webhook = newAuditWebhook(url, authHeader)
	}
}

// WithTrustedProxies configures the CIDR ranges of trusted reverse proxies.
// Proxy headers (X-Forwarded-For, Forwarded, X-Real-IP) are only honored
// if the request's RemoteAddr falls within one of these ranges.
//
// When not configured (the default), proxy headers are never consulted and
// the TCP peer address (RemoteAddr) is always used. This fail-safe default
// prevents IP spoofing when the server is deployed without a reverse proxy.
func WithTrustedProxies(cidrs []string) (Option, error) {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			// Try as a bare IP address (add /32 or /128).
			addr, addrErr := netip.ParseAddr(cidr)
			if addrErr != nil {
				return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", cidr, err)
			}
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			prefix = netip.PrefixFrom(addr, bits)
		}
		prefixes = append(prefixes, prefix)
	}
	return func(a *API) {
		a.trustedProxies = prefixes
	}, nil
}

// WithKDFProfile sets the Argon2id KDF profile used for new vault and
// credential creation. The profile name must be one of: "interactive",
// "moderate", "sensitive". When not set, the "moderate" profile is used
// (Time=3, Memory=64 MiB, Parallelism=4).
//
// This does NOT affect existing vaults — they store their KDF parameters
// in vault state at creation time and continue using those parameters.
func WithKDFProfile(name string) (Option, error) {
	p, err := util.Argon2idProfile(name)
	if err != nil {
		return nil, err
	}
	return func(a *API) {
		a.kdfParams = &p
	}, nil
}

// WithNoRateLimit disables all rate limiters. This is intended exclusively
// for automated E2E testing where many accounts are created in rapid
// succession from the same IP. Do NOT use in production.
func WithNoRateLimit() Option {
	return func(a *API) {
		a.noRateLimit = true
	}
}

// kdfParamsForNewVault returns the Argon2id parameters to use when creating
// new vaults or credentials. Returns the configured profile or the default.
func (a *API) kdfParamsForNewVault() util.Argon2idParams {
	if a.kdfParams != nil {
		return *a.kdfParams
	}
	return util.DefaultArgon2idParams()
}

// New creates a new API instance.
func New(repo storage.Repository, epochCache vault.EpochCache, opts ...Option) *API {
	a := &API{
		repo:             repo,
		epochCache:       epochCache,
		rateLimiter:      newLoginRateLimiter(),
		ipLimiter:        newIPRateLimiter(),
		globalLimiter:    newGlobalRateLimiter(),
		regIPLimiter:     newRegistrationIPLimiter(),
		regGlobalLimiter: newRegistrationGlobalLimiter(),
		idleTimeout:      DefaultIdleTimeout,
	}
	for _, opt := range opts {
		opt(a)
	}
	// Default to in-memory sessions if no store was provided.
	if a.sessions == nil {
		a.sessions = NewMemorySessionStore(a.idleTimeout)
	}
	if a.audit == nil {
		a.audit = newAuditLogger(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	}
	// Default to a logging-based alert handler so anomaly detection is
	// always active, even when no custom callback is provided.
	if a.metrics == nil {
		a.metrics = newMetricsCollector(func(e AlertEvent) {
			a.audit.logger.Warn("anomaly detected",
				slog.String("alert_type", string(e.Type)),
				slog.String("message", e.Message),
				slog.Int("count", e.Count),
				slog.Int("threshold", e.Threshold),
			)
		})
	}
	a.audit.metrics = a.metrics
	if a.webhook != nil {
		a.audit.webhook = a.webhook
	}
	a.invites = newInviteStore()
	return a
}

// Close releases resources held by the API instance.
// Must be called on server shutdown to drain the audit webhook queue.
func (a *API) Close() {
	if a.webhook != nil {
		a.webhook.close()
	}
}

// Router returns a chi.Router with all API routes mounted.
func (a *API) Router() chi.Router {
	r := chi.NewRouter()

	// Prevent caching of all API responses. Auth endpoints return secret
	// keys, vault endpoints return decrypted items, and PKI endpoints
	// return private keys — none of this should persist in browser or
	// proxy caches.
	r.Use(noCacheHeaders)

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
	r.With(a.AuthMiddleware, a.CSRFMiddleware).Post("/auth/2fa/disable", a.DisableTwoFactor)

	// WebAuthn routes (registration + status require auth; login does not).
	r.With(a.AuthMiddleware).Get("/auth/webauthn/status", a.WebAuthnStatus)
	r.With(a.AuthMiddleware, a.CSRFMiddleware).Post("/auth/webauthn/register/begin", a.BeginWebAuthnRegistration)
	r.With(a.AuthMiddleware, a.CSRFMiddleware).Post("/auth/webauthn/register/finish", a.FinishWebAuthnRegistration)
	r.Post("/auth/webauthn/login/begin", a.BeginWebAuthnLogin)
	r.Post("/auth/webauthn/login/finish", a.FinishWebAuthnLogin)
	r.With(a.AuthMiddleware).Get("/auth/webauthn/credentials", a.ListPasskeys)
	r.With(a.AuthMiddleware, a.CSRFMiddleware).Put("/auth/webauthn/credentials/{credentialID}", a.LabelPasskey)
	r.With(a.AuthMiddleware, a.CSRFMiddleware).Delete("/auth/webauthn/credentials/{credentialID}", a.DeletePasskey)

	// Recovery code routes.
	r.With(a.AuthMiddleware).Get("/auth/recovery-codes", a.RecoveryCodesStatus)
	r.With(a.AuthMiddleware, a.CSRFMiddleware).Post("/auth/recovery-codes", a.GenerateRecoveryCodes)

	// Auth settings routes.
	r.With(a.AuthMiddleware).Get("/auth/settings", a.GetAuthSettings)
	r.With(a.AuthMiddleware, a.CSRFMiddleware).Put("/auth/settings", a.UpdateAuthSettings)

	// Step-up authentication routes.
	r.With(a.AuthMiddleware, a.CSRFMiddleware).Post("/auth/step-up", a.StepUpTOTP)
	r.With(a.AuthMiddleware, a.CSRFMiddleware).Post("/auth/step-up/passkey/begin", a.BeginStepUpPasskey)
	r.With(a.AuthMiddleware, a.CSRFMiddleware).Post("/auth/step-up/passkey/finish", a.FinishStepUpPasskey)

	r.With(a.AuthMiddleware, a.CSRFMiddleware).Post("/vaults", a.CreateVault)
	r.With(a.AuthMiddleware).Get("/vaults", a.ListVaults)

	// Invite routes (outside vault group — auth required, no vault membership check).
	r.With(a.AuthMiddleware).Get("/invites/{token}", a.GetInviteInfo)
	r.With(a.AuthMiddleware, a.CSRFMiddleware).Post("/invites/{token}/accept", a.AcceptInvite)

	// Cross-vault search.
	r.With(a.AuthMiddleware).Get("/search", a.SearchItems)

	// All other vault routes require auth middleware.
	r.Route("/vaults/{vaultID}", func(r chi.Router) {
		r.Use(a.AuthMiddleware)
		r.Use(a.CSRFMiddleware)
		r.Delete("/", a.DeleteVault)
		r.Post("/open", a.OpenVault)
		r.Get("/items", a.ListItems)
		r.Get("/items/versions", a.ListItemVersions)
		r.Post("/items/{itemID}", a.PutItem)
		r.Get("/items/{itemID}", a.GetItem)
		r.Put("/items/{itemID}", a.UpdateItem)
		r.Delete("/items/{itemID}", a.DeleteItem)
		r.Get("/items/{itemID}/history", a.GetItemHistory)
		r.Get("/items/{itemID}/history/{version}", a.GetHistoryVersion)
		r.Get("/items/{itemID}/private-key", a.GetItemPrivateKey)
		r.Get("/audit", a.ListAuditLogs)
		r.Get("/audit/export", a.ExportAuditLog)
		r.Get("/members", a.ListMembers)
		r.Post("/members", a.AddMember)
		r.Put("/members/{memberID}", a.ChangeMemberRole)
		r.Delete("/members/{memberID}", a.RevokeMember)
		r.Post("/invites", a.CreateInvite)
		r.Get("/invites", a.ListInvites)
		r.Delete("/invites/{token}", a.CancelInvite)
		r.Post("/export", a.ExportVault)
		r.Post("/import", a.ImportVault)

		// PKI / Certificate Authority routes
		r.Route("/pki", func(r chi.Router) {
			r.Post("/init", a.InitCA)
			r.Get("/info", a.GetCAInfo)
			r.Get("/ca.pem", a.GetCACert)
			r.Post("/issue", a.IssueCert)
			r.Get("/crl.pem", a.GetCRL)   // read-only: returns cached CRL
			r.Post("/crl", a.GenerateCRL) // state-mutating: regenerate & cache CRL
			r.Post("/sign-csr", a.SignCSR)
			r.Post("/items/{itemID}/revoke", a.RevokeCert)
			r.Post("/items/{itemID}/renew", a.RenewCert)
		})
	})

	return r
}

// openSession creates a Vault and opens a session with the given credentials.
// If the primary credentials fail to open the vault (e.g. the user was invited
// to a vault created with different KDF params / salts, so the derived record
// key cannot decrypt the vault state), it transparently falls back to
// vault-specific credentials stored in the account record.
func (a *API) openSession(ctx context.Context, vaultID string, creds *vault.Credentials) (*vault.Session, error) {
	v := vault.New(vaultID, a.repo, vault.WithEpochCache(a.epochCache))
	session, err := v.Open(ctx, creds)
	if err == nil {
		return session, nil
	}

	// Always attempt fallback to vault-specific credentials. When the
	// invitee's MUK differs from the vault creator's, vault.Open fails at
	// loadVaultState (AES-GCM decryption error) — not at the profile
	// comparison step — so we cannot rely on error string matching.
	// If no vault-specific credentials exist, loadVaultCredentials fails
	// and we return the original Open error.
	vaultCreds, loadErr := a.loadVaultCredentials(creds, vaultID)
	if loadErr != nil {
		return nil, err // return the original error, not the load error
	}
	defer vaultCreds.Destroy()

	v2 := vault.New(vaultID, a.repo, vault.WithEpochCache(a.epochCache))
	return v2.Open(ctx, vaultCreds)
}
