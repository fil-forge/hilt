// Package lib holds shared helpers for the `hilt client` command tree.
package lib

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/fil-forge/hilt/pkg/client"
	"github.com/fil-forge/hilt/pkg/client/management"
	"github.com/fil-forge/hilt/pkg/config"
	appfx "github.com/fil-forge/hilt/pkg/fx"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// partnerKeyEnvVar configures the partner key when no config is available, so
// the tenant API commands work as a standalone tool.
const partnerKeyEnvVar = "HILT_PARTNER_KEY"

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
	c, err := client.NewAdminClient(id, endpoint, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("creating admin client: %w", err)
	}
	return c, logger, nil
}

// InitManagementClient loads the Hilt config (if available) and builds a partner
// REST client for the Tenant API. Config is optional: when it does not load, the
// partner key is read from the HILT_PARTNER_KEY env var and the server URL must
// be supplied with --url, so the command works as a standalone tool.
func InitManagementClient(cmd *cobra.Command) (*management.Client, *zap.Logger, error) {
	logger := zap.NewNop()
	cfg, err := config.Load(inheritedString(cmd, "config"))
	if err != nil {
		// Standalone mode: fall back to flags + env vars.
		cfg = nil
	} else {
		if logger, err = appfx.NewLogger(cfg.Log); err != nil {
			return nil, nil, fmt.Errorf("creating logger: %w", err)
		}
	}
	endpoint, err := serverURL(cmd, cfg)
	if err != nil {
		return nil, nil, err
	}
	partnerKey := resolvePartnerKey(cfg)
	if partnerKey == "" {
		return nil, nil, fmt.Errorf("partner key required: set auth.partner_key in the config file or the %s env var", partnerKeyEnvVar)
	}
	return management.NewClient(endpoint, partnerKey, management.WithLogger(logger)), logger, nil
}

// resolvePartnerKey returns the partner key to authenticate Tenant API requests
// with: the first entry of the config's (possibly CSV) auth.partner_key when set,
// otherwise the HILT_PARTNER_KEY env var. Returns "" when neither is set.
func resolvePartnerKey(cfg *config.Config) string {
	if cfg != nil {
		// The server accepts a CSV of keys to support rotation; the client
		// authenticates with one.
		if key := strings.TrimSpace(strings.Split(cfg.Auth.PartnerKey, ",")[0]); key != "" {
			return key
		}
	}
	return os.Getenv(partnerKeyEnvVar)
}

// PrintJSON pretty-prints v as JSON to the command's stdout.
func PrintJSON(cmd *cobra.Command, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding response: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), string(data))
	return nil
}

// serverURL resolves the Hilt server URL: an explicit --url wins, otherwise it is
// derived from the configured server host/port (a wildcard bind host is treated as
// loopback for the client). cfg may be nil (standalone mode), in which case --url
// is required.
func serverURL(cmd *cobra.Command, cfg *config.Config) (url.URL, error) {
	if raw := inheritedString(cmd, "url"); raw != "" {
		// Accept host[:port][/path] without an explicit scheme. A schemeless URL
		// either fails to parse ("127.0.0.1:8080" — colon in the first path
		// segment) or parses without a host ("localhost:8080" is scheme
		// "localhost"; "localhost" is a bare path), so retry with http://.
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			u, err = url.Parse("http://" + raw)
			if err != nil {
				return url.URL{}, fmt.Errorf("parsing --url: %w", err)
			}
		}
		return *u, nil
	}
	if cfg == nil {
		return url.URL{}, fmt.Errorf("no config loaded: --url is required")
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
