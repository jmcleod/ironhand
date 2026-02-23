package cmd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/spf13/cobra"

	"github.com/jmcleod/ironhand/api"
	"github.com/jmcleod/ironhand/internal/util"
	"github.com/jmcleod/ironhand/pki"
	"github.com/jmcleod/ironhand/storage"
	bboltstorage "github.com/jmcleod/ironhand/storage/bbolt"
	pgstorage "github.com/jmcleod/ironhand/storage/postgres"
	"github.com/jmcleod/ironhand/vault"
	"github.com/jmcleod/ironhand/web"
)

var (
	port               int
	dataDir            string
	tlsCert            string
	tlsKey             string
	storageBackend     string
	postgresDSN        string
	enableHeaderAuth   bool
	sessionStorage     string
	webauthnRPID       string
	webauthnRPOrigin   string
	webauthnRPName     string
	sessionKey         string
	sessionKeyFile     string
	pkiKeystore        string
	pkcs11Module       string
	pkcs11Token        string
	pkcs11PIN          string
	kdfProfile         string
	auditRetentionDays int
	auditMaxEntries    int
	auditWebhookURL    string
	auditWebhookHeader string
	trustedProxies     []string
	noRateLimit        bool
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the encryption service server",
	RunE: func(cmd *cobra.Command, args []string) error {
		var (
			repo       storage.Repository
			epochCache vault.EpochCache
			closeFn    func()
		)

		switch storageBackend {
		case "bbolt":
			if err := os.MkdirAll(dataDir, 0o700); err != nil {
				return fmt.Errorf("failed to create data directory: %w", err)
			}
			boltRepo, err := bboltstorage.NewRepositoryFromFile(dataDir+"/vault.db", nil)
			if err != nil {
				return fmt.Errorf("failed to open vault storage: %w", err)
			}
			boltEpochCache, err := vault.NewBoltEpochCacheFromFile(dataDir+"/epoch.db", nil)
			if err != nil {
				boltRepo.Close()
				return fmt.Errorf("failed to open epoch cache: %w", err)
			}
			repo = boltRepo
			epochCache = boltEpochCache
			closeFn = func() { boltRepo.Close() }

		case "postgres":
			dsn := postgresDSN
			if dsn == "" {
				dsn = os.Getenv("IRONHAND_POSTGRES_DSN")
			}
			if dsn == "" {
				return fmt.Errorf("--postgres-dsn or IRONHAND_POSTGRES_DSN required when --storage=postgres")
			}
			ctx := context.Background()
			pgStore, err := pgstorage.NewRepositoryFromDSN(ctx, dsn)
			if err != nil {
				return fmt.Errorf("failed to connect to postgres: %w", err)
			}
			pgEpoch, err := pgstorage.NewEpochCache(ctx, pgStore.Pool())
			if err != nil {
				pgStore.Close()
				return fmt.Errorf("failed to initialize epoch cache: %w", err)
			}
			repo = pgStore
			epochCache = pgEpoch
			closeFn = func() { pgStore.Close() }

		default:
			return fmt.Errorf("unknown storage backend: %q (supported: bbolt, postgres)", storageBackend)
		}
		defer closeFn()

		printBanner()

		// Configure WebAuthn/passkey support.
		rpOrigin := webauthnRPOrigin
		if rpOrigin == "" {
			rpOrigin = fmt.Sprintf("https://localhost:%d", port)
		}
		wa, err := webauthn.New(&webauthn.Config{
			RPDisplayName: webauthnRPName,
			RPID:          webauthnRPID,
			RPOrigins:     []string{rpOrigin},
		})
		if err != nil {
			return fmt.Errorf("failed to configure webauthn: %w", err)
		}

		// Configure PKI key store.
		keyStore, closeKS, err := resolvePKIKeyStore()
		if err != nil {
			return fmt.Errorf("PKI key store: %w", err)
		}
		defer closeKS()

		// Configure API options.
		apiOpts := []api.Option{
			api.WithHeaderAuth(enableHeaderAuth),
			api.WithWebAuthn(wa),
		}
		if noRateLimit {
			apiOpts = append(apiOpts, api.WithNoRateLimit())
			fmt.Println("WARNING: Rate limiting is disabled (--no-rate-limit)")
		}
		if kdfProfile != "" {
			kdfOpt, err := api.WithKDFProfile(kdfProfile)
			if err != nil {
				return fmt.Errorf("--kdf-profile: %w", err)
			}
			apiOpts = append(apiOpts, kdfOpt)
			fmt.Printf("KDF profile: %s\n", kdfProfile)
		}
		if auditRetentionDays > 0 || auditMaxEntries > 0 {
			apiOpts = append(apiOpts, api.WithAuditRetention(time.Duration(auditRetentionDays)*24*time.Hour, auditMaxEntries))
		}
		if len(trustedProxies) > 0 {
			proxyOpt, err := api.WithTrustedProxies(trustedProxies)
			if err != nil {
				return err
			}
			apiOpts = append(apiOpts, proxyOpt)
			fmt.Printf("Trusted proxy CIDRs: %v\n", trustedProxies)
		} else {
			fmt.Println("No trusted proxies configured — proxy headers (X-Forwarded-For, etc.) will be ignored")
		}
		if keyStore != nil {
			apiOpts = append(apiOpts, api.WithKeyStore(keyStore))
			fmt.Printf("Using PKCS#11 key store (module: %s, token: %s)\n", pkcs11Module, pkcs11Token)
		}
		if auditWebhookURL != "" {
			apiOpts = append(apiOpts, api.WithAuditWebhook(auditWebhookURL, auditWebhookHeader))
			fmt.Printf("Audit webhook: %s\n", auditWebhookURL)
		}
		switch sessionStorage {
		case "memory":
			// Default — MemorySessionStore is created automatically by api.New().
		case "persistent":
			wrappingKey, wkErr := resolveSessionWrappingKey()
			if wkErr != nil {
				return fmt.Errorf("session wrapping key: %w", wkErr)
			}
			if wrappingKey == nil {
				return fmt.Errorf("--session-storage=persistent requires a wrapping key; provide one via --session-key, IRONHAND_SESSION_KEY, or --session-key-file")
			}
			sessStore, err := api.NewPersistentSessionStore(repo, api.DefaultIdleTimeout, wrappingKey)
			util.WipeBytes(wrappingKey) // store has copied the key internally
			if err != nil {
				return fmt.Errorf("failed to initialize persistent session store: %w", err)
			}
			defer sessStore.Close()
			apiOpts = append(apiOpts, api.WithSessionStore(sessStore))
			fmt.Println("Using persistent session storage")
		default:
			return fmt.Errorf("unknown session-storage: %q (supported: memory, persistent)", sessionStorage)
		}

		a := api.New(repo, epochCache, apiOpts...)

		r := chi.NewRouter()
		r.Use(middleware.Logger)
		r.Use(middleware.Recoverer)
		r.Use(a.SecurityHeaders)

		r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("OK"))
		})

		r.Mount("/api/v1", a.Router())

		webHandler, err := web.Handler(func(r *http.Request) string {
			return api.CSPNonce(r.Context())
		})
		if err != nil {
			return err
		}
		r.Handle("/*", webHandler)

		var tlsConfig *tls.Config
		if tlsCert != "" && tlsKey != "" {
			cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
			if err != nil {
				return fmt.Errorf("failed to load TLS key pair: %w", err)
			}
			tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}
		} else {
			cert, err := util.GenerateSelfSignedCert()
			if err != nil {
				return fmt.Errorf("failed to generate self-signed certificate: %w", err)
			}
			tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}
			fmt.Println("Using self-signed runtime generated certificate for TLS")
		}

		server := &http.Server{
			Addr:              fmt.Sprintf(":%d", port),
			Handler:           r,
			TLSConfig:         tlsConfig,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		}

		// Graceful shutdown on SIGINT/SIGTERM.
		done := make(chan error, 1)
		go func() {
			if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				done <- fmt.Errorf("server failed: %w", err)
				return
			}
			done <- nil
		}()

		fmt.Printf("Starting server on port %d (storage: %s)...\n", port, storageBackend)

		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

		select {
		case sig := <-quit:
			fmt.Printf("\nReceived %s, shutting down...\n", sig)
			a.Close() // drain audit webhook queue before stopping HTTP
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := server.Shutdown(ctx); err != nil {
				return fmt.Errorf("server shutdown failed: %w", err)
			}
			return nil
		case err := <-done:
			a.Close()
			return err
		}
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
	serverCmd.Flags().IntVarP(&port, "port", "p", 8443, "Port to listen on")
	serverCmd.Flags().StringVar(&dataDir, "data-dir", "./data", "Directory for persistent data")
	serverCmd.Flags().StringVar(&tlsCert, "tls-cert", "", "Path to TLS certificate file")
	serverCmd.Flags().StringVar(&tlsKey, "tls-key", "", "Path to TLS key file")
	serverCmd.Flags().StringVar(&storageBackend, "storage", "bbolt", "Storage backend: bbolt or postgres")
	serverCmd.Flags().StringVar(&postgresDSN, "postgres-dsn", "", "PostgreSQL connection string (required when --storage=postgres)")
	serverCmd.Flags().BoolVar(&enableHeaderAuth, "enable-header-auth", false, "Allow X-Credentials/X-Passphrase header-based authentication (disabled by default)")
	serverCmd.Flags().StringVar(&sessionStorage, "session-storage", "memory", "Session storage: memory (default, lost on restart) or persistent (stored in backing storage)")
	serverCmd.Flags().StringVar(&webauthnRPID, "webauthn-rp-id", "localhost", "WebAuthn Relying Party ID (domain)")
	serverCmd.Flags().StringVar(&webauthnRPOrigin, "webauthn-rp-origin", "", "WebAuthn Relying Party origin (default: https://localhost:<port>)")
	serverCmd.Flags().StringVar(&webauthnRPName, "webauthn-rp-name", "IronHand", "WebAuthn Relying Party display name")
	serverCmd.Flags().StringVar(&sessionKey, "session-key", "", "Hex-encoded 32-byte wrapping key for persistent session storage")
	serverCmd.Flags().StringVar(&sessionKeyFile, "session-key-file", "", "Path to file containing raw 32-byte wrapping key for persistent session storage")
	serverCmd.Flags().StringVar(&pkiKeystore, "pki-keystore", "software", "PKI key store backend: software (default) or pkcs11")
	serverCmd.Flags().StringVar(&pkcs11Module, "pkcs11-module", "", "Path to PKCS#11 shared library (e.g., /usr/lib/softhsm/libsofthsm2.so)")
	serverCmd.Flags().StringVar(&pkcs11Token, "pkcs11-token-label", "", "PKCS#11 token label")
	serverCmd.Flags().StringVar(&pkcs11PIN, "pkcs11-pin", "", "PKCS#11 user PIN (also via IRONHAND_PKCS11_PIN env var)")
	serverCmd.Flags().StringVar(&kdfProfile, "kdf-profile", "moderate", "Argon2id KDF profile for new accounts: interactive, moderate (default), sensitive")
	serverCmd.Flags().IntVar(&auditRetentionDays, "audit-retention-days", 0, "Automatically prune per-vault audit entries older than this many days (0 disables)")
	serverCmd.Flags().IntVar(&auditMaxEntries, "audit-max-entries", 0, "Automatically keep only the newest N per-vault audit entries (0 disables)")
	serverCmd.Flags().StringVar(&auditWebhookURL, "audit-webhook-url", "", "HTTP(S) URL to POST audit events to (SIEM/webhook integration)")
	serverCmd.Flags().StringVar(&auditWebhookHeader, "audit-webhook-header", "", "Auth header for audit webhook in 'Header: Value' format (e.g., 'Authorization: Bearer xxx')")
	serverCmd.Flags().StringSliceVar(&trustedProxies, "trusted-proxies", nil, "CIDR ranges of trusted reverse proxies (e.g., 10.0.0.0/8,172.16.0.0/12); proxy headers are ignored unless this is set")
	serverCmd.Flags().BoolVar(&noRateLimit, "no-rate-limit", false, "Disable all rate limiters (for E2E testing only — do NOT use in production)")
}

// resolveSessionWrappingKey resolves the session wrapping key from the
// available sources in priority order: --session-key flag, IRONHAND_SESSION_KEY
// environment variable, --session-key-file flag. Returns (nil, nil) if no
// source is configured.
func resolveSessionWrappingKey() ([]byte, error) {
	// 1. --session-key flag or IRONHAND_SESSION_KEY env var (hex-encoded).
	raw := sessionKey
	if raw == "" {
		raw = os.Getenv("IRONHAND_SESSION_KEY")
	}
	if raw != "" {
		key, err := util.HexDecode(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid session wrapping key (hex decode failed): %w", err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("session wrapping key must be exactly 32 bytes, got %d", len(key))
		}
		return key, nil
	}

	// 2. --session-key-file flag (raw 32 bytes).
	if sessionKeyFile != "" {
		key, err := os.ReadFile(sessionKeyFile)
		if err != nil {
			return nil, fmt.Errorf("reading session key file: %w", err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("session key file must contain exactly 32 bytes, got %d", len(key))
		}
		return key, nil
	}

	return nil, nil
}

// resolvePKIKeyStore creates the configured PKI key store. Returns
// (nil, noop, nil) for the default software store. The caller must
// call the returned close function when done.
func resolvePKIKeyStore() (pki.KeyStore, func(), error) {
	noop := func() {}

	switch pkiKeystore {
	case "software", "":
		return nil, noop, nil

	case "pkcs11":
		module := pkcs11Module
		if module == "" {
			module = os.Getenv("IRONHAND_PKCS11_MODULE")
		}
		if module == "" {
			return nil, nil, fmt.Errorf("--pkcs11-module or IRONHAND_PKCS11_MODULE required when --pki-keystore=pkcs11")
		}

		token := pkcs11Token
		if token == "" {
			token = os.Getenv("IRONHAND_PKCS11_TOKEN_LABEL")
		}
		if token == "" {
			return nil, nil, fmt.Errorf("--pkcs11-token-label or IRONHAND_PKCS11_TOKEN_LABEL required when --pki-keystore=pkcs11")
		}

		pin := pkcs11PIN
		if pin == "" {
			pin = os.Getenv("IRONHAND_PKCS11_PIN")
		}
		if pin == "" {
			return nil, nil, fmt.Errorf("--pkcs11-pin or IRONHAND_PKCS11_PIN required when --pki-keystore=pkcs11")
		}

		cfg := pki.PKCS11Config{
			ModulePath: module,
			TokenLabel: token,
			PIN:        pin,
		}

		ks, err := pki.NewPKCS11KeyStore(cfg)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to initialize PKCS#11 key store: %w", err)
		}
		return ks, func() { _ = ks.Close() }, nil

	default:
		return nil, nil, fmt.Errorf("unknown pki-keystore: %q (supported: software, pkcs11)", pkiKeystore)
	}
}
