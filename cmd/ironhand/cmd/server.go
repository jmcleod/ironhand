package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/spf13/cobra"

	"github.com/jmcleod/ironhand/api"
	bboltstorage "github.com/jmcleod/ironhand/storage/bbolt"
	"github.com/jmcleod/ironhand/vault"
	"github.com/jmcleod/ironhand/web"
)

var (
	port    int
	dataDir string
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the encryption service server",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := os.MkdirAll(dataDir, 0o700); err != nil {
			return fmt.Errorf("failed to create data directory: %w", err)
		}

		repo, err := bboltstorage.NewRepositoryFromFile(dataDir+"/vault.db", nil)
		if err != nil {
			return fmt.Errorf("failed to open vault storage: %w", err)
		}
		defer repo.Close()

		epochCache, err := vault.NewBoltEpochCacheFromFile(dataDir+"/epoch.db", nil)
		if err != nil {
			return fmt.Errorf("failed to open epoch cache: %w", err)
		}

		a := api.New(repo, epochCache)

		r := chi.NewRouter()
		r.Use(middleware.Logger)
		r.Use(middleware.Recoverer)

		r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("OK"))
		})

		r.Mount("/api/v1", a.Router())

		webHandler, err := web.Handler()
		if err != nil {
			return err
		}
		r.Handle("/*", webHandler)

		server := &http.Server{
			Addr:              fmt.Sprintf(":%d", port),
			Handler:           r,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		}

		// Graceful shutdown on SIGINT/SIGTERM.
		done := make(chan error, 1)
		go func() {
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				done <- fmt.Errorf("server failed: %w", err)
				return
			}
			done <- nil
		}()

		fmt.Printf("Starting server on port %d (data: %s)...\n", port, dataDir)

		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

		select {
		case sig := <-quit:
			fmt.Printf("\nReceived %s, shutting down...\n", sig)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := server.Shutdown(ctx); err != nil {
				return fmt.Errorf("server shutdown failed: %w", err)
			}
			return nil
		case err := <-done:
			return err
		}
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
	serverCmd.Flags().IntVarP(&port, "port", "p", 8080, "Port to listen on")
	serverCmd.Flags().StringVar(&dataDir, "data-dir", "./data", "Directory for persistent data")
}
