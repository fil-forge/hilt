package fx

import (
	"fmt"
	"net/url"
	"time"

	"github.com/fil-forge/hilt/pkg/config"
	"github.com/fil-forge/ucantone/did/plc"
	"go.uber.org/fx"
)

// PLCModule provides a did:plc directory client.
var PLCModule = fx.Module("plc",
	fx.Provide(NewPLCClient),
)

// NewPLCClient builds a did:plc directory client from configuration.
func NewPLCClient(cfg config.PLCConfig) (*plc.DirectoryClient, error) {
	if cfg.Directory == "" {
		return nil, fmt.Errorf("plc.directory is required")
	}
	u, err := url.Parse(cfg.Directory)
	if err != nil {
		return nil, fmt.Errorf("parsing plc.directory %q: %w", cfg.Directory, err)
	}
	return plc.NewDirectoryClient(*u, plc.WithTimeout(time.Second*10))
}
