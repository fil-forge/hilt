// Package lib holds shared helpers for the `hilt client` command tree.
package lib

import (
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/fil-forge/hilt/pkg/client"
	"github.com/fil-forge/hilt/pkg/config"
	appfx "github.com/fil-forge/hilt/pkg/fx"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// InitAdminClient loads the Hilt config, builds the service identity (the signing
// key) and an admin client targeting the running Hilt server. The command must be
// run with the service's identity config so the signed invocation's issuer matches
// the server's service DID.
func InitAdminClient(cmd *cobra.Command) (*client.AdminClient, *zap.Logger, error) {
	cfg, err := config.Load(inheritedString(cmd, "config"))
	if err != nil {
		return nil, nil, fmt.Errorf("loading config: %w", err)
	}
	logger, err := appfx.NewLogger(cfg.Log)
	if err != nil {
		return nil, nil, fmt.Errorf("creating logger: %w", err)
	}
	id, err := appfx.NewIdentity(cfg.Identity, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("loading service identity: %w", err)
	}
	endpoint, err := serverURL(cmd, cfg)
	if err != nil {
		return nil, nil, err
	}
	c, err := client.NewAdminClient(id.DID(), endpoint, id, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("creating admin client: %w", err)
	}
	return c, logger, nil
}

// serverURL resolves the Hilt server URL: an explicit --url wins, otherwise it is
// derived from the configured server host/port (a wildcard bind host is treated as
// loopback for the client).
func serverURL(cmd *cobra.Command, cfg *config.Config) (url.URL, error) {
	if raw := inheritedString(cmd, "url"); raw != "" {
		u, err := url.Parse(raw)
		if err != nil {
			return url.URL{}, fmt.Errorf("parsing --url: %w", err)
		}
		return *u, nil
	}
	host := cfg.Server.Host
	if host == "" {
		host = "127.0.0.1"
	}
	return url.URL{Scheme: "http", Host: net.JoinHostPort(host, strconv.Itoa(cfg.Server.Port))}, nil
}

func inheritedString(cmd *cobra.Command, name string) string {
	if f := cmd.InheritedFlags().Lookup(name); f != nil {
		return f.Value.String()
	}
	return ""
}
