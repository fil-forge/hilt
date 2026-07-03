package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
	"go.uber.org/zap"

	"github.com/fil-forge/hilt/pkg/config"
	appfx "github.com/fil-forge/hilt/pkg/fx"
)

var cfgFile string

func main() {
	rootCmd := &cobra.Command{
		Use:   "hilt",
		Short: "Hilt tenant management service",
		Long:  "Hilt manages tenants of Ingot and their secret keys.",
	}

	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the hilt service",
		RunE:  runServe,
	}

	// identity config (UCAN RPC service identity)
	serveCmd.Flags().String("identity-key-file", "", "path to a PEM-encoded Ed25519 private key for the Hilt service identity (an ephemeral key is generated if unset)")
	serveCmd.Flags().String("identity-service-id", "", "optional did:web service identity to wrap the key with, e.g. did:web:hilt.example.com")

	// http server config
	serveCmd.Flags().String("host", "127.0.0.1", "host to bind the server to")
	serveCmd.Flags().Int("port", 8080, "port to bind the server to")

	// storage config
	serveCmd.Flags().String("storage", "postgres", "storage backend (memory or postgres)")
	serveCmd.Flags().String("postgres-dsn", "", "postgres connection string (used when storage=postgres)")
	serveCmd.Flags().Bool("skip-migrations", false, "skip running postgres migrations on startup")

	// vault config
	serveCmd.Flags().String("vault", "hashicorp", "vault backend for private keys (hashicorp or memory)")
	serveCmd.Flags().String("hashicorp-address", "http://127.0.0.1:8200", "hashicorp vault server address")
	serveCmd.Flags().String("hashicorp-mount", "secret", "hashicorp vault KV v2 secrets engine mount path")
	serveCmd.Flags().String("hashicorp-auth-method", "approle", "hashicorp vault auth method (approle or token)")
	serveCmd.Flags().String("hashicorp-token", "", "hashicorp vault token (auth-method=token; prefer HILT_VAULT_HASHICORP_TOKEN env var or config file to avoid exposing via process args)")
	serveCmd.Flags().String("hashicorp-approle-role-id", "", "hashicorp vault AppRole role ID (auth-method=approle; prefer HILT_VAULT_HASHICORP_APPROLE_ROLE_ID env var or config file)")
	serveCmd.Flags().String("hashicorp-approle-secret-id", "", "hashicorp vault AppRole secret ID (auth-method=approle; prefer HILT_VAULT_HASHICORP_APPROLE_SECRET_ID env var or config file)")
	serveCmd.Flags().String("hashicorp-approle-mount", "approle", "hashicorp vault AppRole auth mount path")

	// plc config
	serveCmd.Flags().String("plc-directory", "https://plc.directory", "did:plc directory endpoint")

	// auth config
	serveCmd.Flags().String("partner-key", "", "partner bearer key required on Tenant API requests (prefer HILT_AUTH_PARTNER_KEY env var or config file to avoid exposing via process args)")

	// upload service config
	serveCmd.Flags().String("upload-service-id", "did:web:upload.forgery.network", "Upload service DID")
	serveCmd.Flags().String("upload-service-url", "https://upload.forgery.network", "Upload service HTTP endpoint")
	serveCmd.Flags().String("upload-product-id", "did:web:hilt.forgery.network", "Upload service product/plan DID that tenants are registered under")
	serveCmd.Flags().String("upload-proofs", "", "Upload service proofs: an encoded UCAN container or a path to a file containing one")

	rootCmd.AddCommand(serveCmd)

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file path (default: looks for config.yaml in current dir)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runServe(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(cfgFile, config.WithFlagSet(cmd.Flags()))
	if err != nil {
		return err
	}
	app := fx.New(
		appfx.AppModule(cfg),
		// Suppress fx's default logging and use our own zap logger.
		fx.WithLogger(func(log *zap.Logger) fxevent.Logger {
			return &fxevent.ZapLogger{Logger: log}
		}),
	)
	app.Run()

	return nil
}
