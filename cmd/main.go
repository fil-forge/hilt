package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
	serveCmd.Flags().String("host", "127.0.0.1", "host to bind the server to")
	cobra.CheckErr(viper.BindPFlag("server.host", serveCmd.Flags().Lookup("host")))

	serveCmd.Flags().Int("port", 8080, "port to bind the server to")
	cobra.CheckErr(viper.BindPFlag("server.port", serveCmd.Flags().Lookup("port")))

	serveCmd.Flags().String("storage", "postgres", "storage backend (memory or postgres)")
	cobra.CheckErr(viper.BindPFlag("storage.type", serveCmd.Flags().Lookup("storage")))

	serveCmd.Flags().String("postgres-dsn", "", "postgres connection string (used when storage=postgres)")
	cobra.CheckErr(viper.BindPFlag("storage.postgres.dsn", serveCmd.Flags().Lookup("postgres-dsn")))

	serveCmd.Flags().Bool("skip-migrations", false, "skip running postgres migrations on startup")
	cobra.CheckErr(viper.BindPFlag("storage.postgres.skip_migrations", serveCmd.Flags().Lookup("skip-migrations")))

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
