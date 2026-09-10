package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
	"go.uber.org/zap"

	"github.com/fil-forge/hilt/cmd/client"
	"github.com/fil-forge/hilt/pkg/config"
	appfx "github.com/fil-forge/hilt/pkg/fx"
	"github.com/fil-forge/hilt/pkg/iammigrate"
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
	serveCmd.Flags().Bool("insecure-did-resolution", false, "resolve did:web DIDs over HTTP instead of HTTPS on the UCAN RPC server (insecure; development only)")

	addStorageFlags(serveCmd)
	serveCmd.Flags().Bool("skip-migrations", false, "skip running postgres migrations on startup")
	addVaultFlags(serveCmd)

	// plc config
	serveCmd.Flags().String("plc-directory", "https://plc.directory", "did:plc directory endpoint")

	// auth config
	serveCmd.Flags().String("partner-key", "", "CSV partner bearer key(s) required on Tenant API requests (prefer HILT_AUTH_PARTNER_KEY env var or config file to avoid exposing via process args)")

	// upload service config
	serveCmd.Flags().String("upload-service-id", "did:web:upload.fil-forge.com", "Upload service DID")
	serveCmd.Flags().String("upload-service-url", "https://upload.fil-forge.com", "Upload service HTTP endpoint")
	serveCmd.Flags().String("upload-product-id", "did:web:hilt.fil-forge.com", "Upload service product/plan DID that tenants are registered under")
	serveCmd.Flags().String("upload-proofs", "", "Upload service proofs: an encoded UCAN container or a path to a file containing one")

	addRevocationFlags(serveCmd)

	migrateCmd := &cobra.Command{
		Use:   "migrate",
		Short: "One-shot data migrations run against a Hilt database",
	}
	migrateIAMCmd := &cobra.Command{
		Use:   "iam",
		Short: "Remove the access keys that predate the tenant IAM model",
		Long: "Remove every access key from the database ahead of the Hilt release that " +
			"introduces principals, bucket policies and service credentials. For each key " +
			"it publishes a revocation for the key's unexpired delegations, signed by the " +
			"tenant, then deletes the delegations, the vault entry and the row. A revocation " +
			"failure leaves the key intact and the command can be rerun.\n\n" +
			"Run it against the network's database before deploying that release: its " +
			"schema migration refuses to run while any access key remains.",
		RunE: runMigrateIAM,
	}
	addStorageFlags(migrateIAMCmd)
	addVaultFlags(migrateIAMCmd)
	addRevocationFlags(migrateIAMCmd)
	migrateCmd.AddCommand(migrateIAMCmd)

	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(migrateCmd)
	rootCmd.AddCommand(client.Cmd)

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file path (default: looks for config.yaml in current dir)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// addStorageFlags registers the storage backend flags shared by the commands
// that open the database.
func addStorageFlags(cmd *cobra.Command) {
	cmd.Flags().String("storage", "postgres", "storage backend (memory or postgres)")
	cmd.Flags().String("postgres-dsn", "", "postgres connection string (used when storage=postgres)")
}

// addVaultFlags registers the vault backend flags shared by the commands that
// read private keys.
func addVaultFlags(cmd *cobra.Command) {
	cmd.Flags().String("vault", "openbao", "vault backend for private keys (openbao or memory)")
	cmd.Flags().String("openbao-address", "http://127.0.0.1:8200", "openbao server address")
	cmd.Flags().String("openbao-mount", "secret", "openbao KV v2 secrets engine mount path")
	cmd.Flags().String("openbao-auth-method", "approle", "openbao auth method (approle or token)")
	cmd.Flags().String("openbao-token", "", "openbao token (auth-method=token; prefer HILT_VAULT_OPENBAO_TOKEN env var or config file to avoid exposing via process args)")
	cmd.Flags().String("openbao-approle-role-id", "", "openbao AppRole role ID (auth-method=approle; prefer HILT_VAULT_OPENBAO_APPROLE_ROLE_ID env var or config file)")
	cmd.Flags().String("openbao-approle-secret-id", "", "openbao AppRole secret ID (auth-method=approle; prefer HILT_VAULT_OPENBAO_APPROLE_SECRET_ID env var or config file)")
	cmd.Flags().String("openbao-approle-mount", "approle", "openbao AppRole auth mount path")
}

// addRevocationFlags registers the revocation service (Swarf) flags shared by
// the commands that publish revocations.
func addRevocationFlags(cmd *cobra.Command) {
	cmd.Flags().String("revocation-service-id", "did:web:revoke.fil-forge.com", "Revocation service DID")
	cmd.Flags().String("revocation-service-url", "https://revoke.fil-forge.com", "Revocation service HTTP endpoint")
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

// runMigrateIAM boots the reduced fx graph (database, vault, revocation client),
// runs the access key migration once, and stops the graph. Interrupting the
// process cancels the run between keys; the keys already removed stay removed.
func runMigrateIAM(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(cfgFile, config.WithFlagSet(cmd.Flags()))
	if err != nil {
		return err
	}

	// fx's own event log is left off: a one-shot command has nothing to report
	// beyond what the migrator logs, and a configuration error then surfaces as
	// itself rather than as a missing logger dependency.
	var migrator *iammigrate.Migrator
	app := fx.New(appfx.IAMMigrateModule(cfg), fx.Populate(&migrator), fx.NopLogger)
	if err := app.Err(); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	startCtx, cancel := context.WithTimeout(ctx, app.StartTimeout())
	defer cancel()
	if err := app.Start(startCtx); err != nil {
		return fmt.Errorf("starting: %w", err)
	}

	report, runErr := migrator.Run(ctx)

	stopCtx, cancel := context.WithTimeout(context.Background(), app.StopTimeout())
	defer cancel()
	if err := app.Stop(stopCtx); err != nil && runErr == nil {
		runErr = fmt.Errorf("stopping: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Removed %d access key(s), published %d revocation(s)\n", report.Keys, report.Revocations)
	return runErr
}
