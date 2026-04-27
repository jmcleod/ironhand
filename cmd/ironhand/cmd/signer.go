package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jmcleod/ironhand/internal/mpcsigner"
)

var (
	signerListen    string
	signerMemberID  string
	signerPartyID   uint32
	signerName      string
	signerURL       string
	signerShared    string
	signerTLSCert   string
	signerTLSKey    string
	signerClientCA  string
	signerStateFile string
	signerStatePass string
)

var signerCmd = &cobra.Command{
	Use:   "signer",
	Short: "Start an MPC signer service",
	RunE: func(cmd *cobra.Command, args []string) error {
		if signerMemberID == "" {
			return fmt.Errorf("--member-id is required")
		}
		if signerPartyID == 0 {
			return fmt.Errorf("--party-id is required")
		}
		if signerURL == "" {
			signerURL = "http://" + signerListen
		}
		shared := signerShared
		if shared == "" {
			shared = os.Getenv("IRONHAND_MPC_SHARED_KEY")
		}
		if shared == "" {
			fmt.Println("WARNING: MPC signer request signing is disabled; set --mpc-shared-key or IRONHAND_MPC_SHARED_KEY")
		}
		statePass := signerStatePass
		if statePass == "" {
			statePass = os.Getenv("IRONHAND_MPC_SIGNER_STATE_KEY")
		}
		var store *mpcsigner.FileStore
		var err error
		if signerStateFile != "" {
			if statePass == "" {
				return fmt.Errorf("--state-file requires --state-passphrase or IRONHAND_MPC_SIGNER_STATE_KEY")
			}
			store, err = mpcsigner.NewFileStore(signerStateFile, statePass)
			if err != nil {
				return err
			}
		}
		service, err := mpcsigner.NewWithStore(signerMemberID, signerPartyID, signerName, signerURL, []byte(shared), store, slog.Default())
		if err != nil {
			return err
		}
		identity := service.Identity()
		fmt.Printf("Signer identity: member=%s party=%d url=%s\n", signerMemberID, signerPartyID, identity.URL)
		fmt.Printf("  encryption_public_key=%s\n", identity.EncryptionPublicKey)
		fmt.Printf("  approval_public_key=%s\n", identity.ApprovalPublicKey)
		server := &http.Server{
			Addr:              signerListen,
			Handler:           service.Handler(),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		if signerTLSCert != "" || signerTLSKey != "" {
			if signerTLSCert == "" || signerTLSKey == "" {
				return fmt.Errorf("--tls-cert and --tls-key must be provided together")
			}
			cert, err := tls.LoadX509KeyPair(signerTLSCert, signerTLSKey)
			if err != nil {
				return fmt.Errorf("load signer TLS key pair: %w", err)
			}
			cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
			if signerClientCA != "" {
				pem, err := os.ReadFile(signerClientCA)
				if err != nil {
					return fmt.Errorf("read client CA: %w", err)
				}
				pool := x509.NewCertPool()
				if !pool.AppendCertsFromPEM(pem) {
					return fmt.Errorf("client CA file did not contain a PEM certificate")
				}
				cfg.ClientCAs = pool
				cfg.ClientAuth = tls.RequireAndVerifyClientCert
			}
			server.TLSConfig = cfg
		}

		done := make(chan error, 1)
		go func() {
			var err error
			if server.TLSConfig != nil {
				err = server.ListenAndServeTLS("", "")
			} else {
				err = server.ListenAndServe()
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				done <- err
				return
			}
			done <- nil
		}()
		fmt.Printf("Starting MPC signer on %s as member %s party %d\n", signerListen, signerMemberID, signerPartyID)
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		select {
		case sig := <-quit:
			fmt.Printf("\nReceived %s, shutting down signer...\n", sig)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return server.Shutdown(ctx)
		case err := <-done:
			return err
		}
	},
}

func init() {
	rootCmd.AddCommand(signerCmd)
	signerCmd.Flags().StringVar(&signerListen, "listen", "127.0.0.1:8081", "Address for the signer service to listen on")
	signerCmd.Flags().StringVar(&signerMemberID, "member-id", "", "IronHand vault member ID represented by this signer")
	signerCmd.Flags().Uint32Var(&signerPartyID, "party-id", 0, "Stable MPC party ID for this signer")
	signerCmd.Flags().StringVar(&signerName, "name", "IronHand MPC Signer", "Human-readable signer name")
	signerCmd.Flags().StringVar(&signerURL, "url", "", "Externally reachable signer URL registered with the vault")
	signerCmd.Flags().StringVar(&signerShared, "mpc-shared-key", "", "Shared HMAC key for internal MPC calls (or IRONHAND_MPC_SHARED_KEY)")
	signerCmd.Flags().StringVar(&signerTLSCert, "tls-cert", "", "Path to signer TLS certificate")
	signerCmd.Flags().StringVar(&signerTLSKey, "tls-key", "", "Path to signer TLS private key")
	signerCmd.Flags().StringVar(&signerClientCA, "client-ca", "", "CA bundle for requiring/verifying coordinator mTLS client certificates")
	signerCmd.Flags().StringVar(&signerStateFile, "state-file", "", "Path to a sealed signer state file for durable identity and key metadata")
	signerCmd.Flags().StringVar(&signerStatePass, "state-passphrase", "", "Passphrase for sealing signer state (or IRONHAND_MPC_SIGNER_STATE_KEY)")
}
