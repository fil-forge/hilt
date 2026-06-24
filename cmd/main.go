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
	serveCmd.Flags().String("host", "0.0.0.0", "host to bind the server to")
	serveCmd.Flags().Int("port", 8080, "port to bind the server to")

	rootCmd.AddCommand(serveCmd)

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file path (default: looks for config.yaml in current dir)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runServe(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(cfgFile, config.WithFlagSet(cmd.Flags()))
	cobra.CheckErr(err)

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
