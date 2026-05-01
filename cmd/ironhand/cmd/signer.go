package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jmcleod/ironhand/internal/mpcsigner"
)

var (
	signerListen           string
	signerMemberID         string
	signerPartyID          uint32
	signerName             string
	signerURL              string
	signerShared           string
	signerTLSCert          string
	signerTLSKey           string
	signerClientCA         string
	signerStateFile        string
	signerStatePass        string
	signerDevMemory        bool
	signerAllowInsecureDev bool
	signerOperatorToken    string
	signerApprovalURL      string
	signerApprovalReason   string
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
		statePass := signerStatePass
		if statePass == "" {
			statePass = os.Getenv("IRONHAND_MPC_SIGNER_STATE_KEY")
		}
		var store *mpcsigner.FileStore
		var err error
		operatorToken := signerOperatorToken
		if operatorToken == "" {
			operatorToken = os.Getenv("IRONHAND_MPC_SIGNER_OPERATOR_TOKEN")
		}
		if err := validateSignerDeployment(signerDeploymentConfig{
			Listen:           signerListen,
			URL:              signerURL,
			SharedKey:        shared,
			TLSCert:          signerTLSCert,
			TLSKey:           signerTLSKey,
			ClientCA:         signerClientCA,
			StateFile:        signerStateFile,
			StatePassphrase:  statePass,
			DevMemory:        signerDevMemory,
			AllowInsecureDev: signerAllowInsecureDev,
			OperatorToken:    operatorToken,
		}); err != nil {
			return err
		}
		if shared == "" {
			fmt.Println("WARNING: MPC signer request signing is disabled for loopback-only local development")
		}
		if signerStateFile != "" {
			store, err = mpcsigner.NewFileStore(signerStateFile, statePass)
			if err != nil {
				return err
			}
		}
		if signerDevMemory {
			fmt.Println("WARNING: signer state is in-memory only; identity and MPC key metadata will be lost on restart")
		}
		service, err := mpcsigner.NewWithStore(signerMemberID, signerPartyID, signerName, signerURL, []byte(shared), store, slog.Default())
		if err != nil {
			return err
		}
		service.SetOperatorToken([]byte(operatorToken))
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

var signerApprovalsCmd = &cobra.Command{
	Use:   "approvals",
	Short: "Manage local MPC signer approval requests",
}

var signerApprovalsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List pending local signer approval requests",
	RunE: func(cmd *cobra.Command, args []string) error {
		var resp mpcsigner.ListApprovalRequestsResponse
		if err := signerApprovalJSON(http.MethodGet, "/signer/approval-requests", nil, &resp); err != nil {
			return err
		}
		for _, request := range resp.Requests {
			fmt.Printf("%s\t%s\tkey=%s\tsession=%s\texpires=%s\tmessage_type=%s\n",
				request.RequestID,
				request.Status,
				request.Request.KeyID,
				request.Request.SessionID,
				request.Request.ExpiresAt.Format(time.RFC3339),
				request.Request.MessageType)
		}
		return nil
	},
}

var signerApprovalsApproveCmd = &cobra.Command{
	Use:   "approve <request_id>",
	Short: "Approve a local signer approval request",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var resp mpcsigner.CreateApprovalRequestResponse
		if err := signerApprovalJSON(http.MethodPost, "/signer/approval-requests/"+args[0]+"/approve", map[string]string{}, &resp); err != nil {
			return err
		}
		fmt.Printf("approved %s for session %s\n", resp.Request.RequestID, resp.Request.Request.SessionID)
		return nil
	},
}

var signerApprovalsRejectCmd = &cobra.Command{
	Use:   "reject <request_id>",
	Short: "Reject a local signer approval request",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var resp mpcsigner.CreateApprovalRequestResponse
		payload := mpcsigner.RejectApprovalRequest{Reason: signerApprovalReason}
		if err := signerApprovalJSON(http.MethodPost, "/signer/approval-requests/"+args[0]+"/reject", payload, &resp); err != nil {
			return err
		}
		fmt.Printf("rejected %s for session %s\n", resp.Request.RequestID, resp.Request.Request.SessionID)
		return nil
	},
}

type signerDeploymentConfig struct {
	Listen           string
	URL              string
	SharedKey        string
	TLSCert          string
	TLSKey           string
	ClientCA         string
	StateFile        string
	StatePassphrase  string
	DevMemory        bool
	AllowInsecureDev bool
	OperatorToken    string
}

func validateSignerDeployment(cfg signerDeploymentConfig) error {
	if cfg.StateFile == "" && !cfg.DevMemory {
		return fmt.Errorf("MPC signer requires --state-file for durable sealed identity and key state; use --dev-in-memory only with --allow-insecure-mpc-local-dev")
	}
	if cfg.StateFile != "" && cfg.StatePassphrase == "" {
		return fmt.Errorf("--state-file requires --state-passphrase or IRONHAND_MPC_SIGNER_STATE_KEY")
	}
	if cfg.DevMemory && !cfg.AllowInsecureDev {
		return fmt.Errorf("--dev-in-memory requires --allow-insecure-mpc-local-dev")
	}
	if cfg.SharedKey == "" && !cfg.AllowInsecureDev {
		return fmt.Errorf("MPC signer requires --mpc-shared-key or IRONHAND_MPC_SHARED_KEY; use --allow-insecure-mpc-local-dev only for loopback development")
	}
	if cfg.OperatorToken == "" && !cfg.AllowInsecureDev {
		return fmt.Errorf("MPC signer requires --operator-token or IRONHAND_MPC_SIGNER_OPERATOR_TOKEN for local approval actions")
	}
	if cfg.AllowInsecureDev {
		if !isLoopbackEndpoint(cfg.Listen) || !isLoopbackEndpoint(cfg.URL) {
			return fmt.Errorf("--allow-insecure-mpc-local-dev requires loopback-only --listen and --url")
		}
		return nil
	}
	if cfg.TLSCert == "" || cfg.TLSKey == "" {
		return fmt.Errorf("MPC signer production mode requires --tls-cert and --tls-key")
	}
	if cfg.ClientCA == "" {
		return fmt.Errorf("MPC signer production mode requires --client-ca for coordinator mTLS")
	}
	return nil
}

func isLoopbackEndpoint(value string) bool {
	host := value
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil {
			return false
		}
		host = parsed.Hostname()
	} else {
		splitHost, _, err := net.SplitHostPort(value)
		if err == nil {
			host = splitHost
		} else if strings.Contains(value, ":") {
			return false
		}
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func init() {
	rootCmd.AddCommand(signerCmd)
	signerCmd.AddCommand(signerApprovalsCmd)
	signerApprovalsCmd.AddCommand(signerApprovalsListCmd, signerApprovalsApproveCmd, signerApprovalsRejectCmd)
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
	signerCmd.Flags().BoolVar(&signerDevMemory, "dev-in-memory", false, "Run signer with volatile in-memory state for tests only")
	signerCmd.Flags().BoolVar(&signerAllowInsecureDev, "allow-insecure-mpc-local-dev", false, "Allow unsigned MPC signer calls from loopback clients only")
	signerCmd.Flags().StringVar(&signerOperatorToken, "operator-token", "", "Local operator token for approving/rejecting signer approval requests (or IRONHAND_MPC_SIGNER_OPERATOR_TOKEN)")
	signerApprovalsCmd.PersistentFlags().StringVar(&signerApprovalURL, "url", "http://127.0.0.1:8081", "Local signer URL")
	signerApprovalsCmd.PersistentFlags().StringVar(&signerOperatorToken, "operator-token", "", "Local operator token (or IRONHAND_MPC_SIGNER_OPERATOR_TOKEN)")
	signerApprovalsRejectCmd.Flags().StringVar(&signerApprovalReason, "reason", "", "Optional rejection reason")
}

func signerApprovalJSON(method, path string, in any, out any) error {
	token := signerOperatorToken
	if token == "" {
		token = os.Getenv("IRONHAND_MPC_SIGNER_OPERATOR_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("--operator-token or IRONHAND_MPC_SIGNER_OPERATOR_TOKEN is required")
	}
	var body []byte
	var err error
	if in != nil {
		body, err = json.Marshal(in)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequest(method, mpcsigner.NormalizeURL(signerApprovalURL)+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Ironhand-Signer-Operator-Token", token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("signer returned status %d: %s", resp.StatusCode, string(data))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
