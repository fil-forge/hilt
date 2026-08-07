package fx

import (
	"fmt"
	"net/url"

	accesskeysvc "github.com/fil-forge/hilt/pkg/api/service/accesskey"
	"github.com/fil-forge/hilt/pkg/config"
	bucketsvc "github.com/fil-forge/hilt/pkg/rpc/service/bucket"
	swarfclient "github.com/fil-forge/swarf/pkg/client"
	"github.com/fil-forge/ucantone/did"
	"go.uber.org/fx"
)

// RevocationModule provides the Swarf revocation-service client, published as the
// narrow interface each consumer declares as well as the concrete type. Both the
// REST access-key service and the UCAN bucket service revoke delegations, so the
// client is shared rather than owned by either module.
var RevocationModule = fx.Module("revocation",
	fx.Provide(
		fx.Annotate(
			NewRevocationClient,
			fx.As(fx.Self()),
			fx.As(new(accesskeysvc.RevocationClient)),
			fx.As(new(bucketsvc.RevocationClient)),
		),
	),
)

// NewRevocationClient builds the Swarf revocation-service client from
// configuration. It takes no issuer: revocations are signed by the tenant that
// issued the revoked delegation, which is passed per Publish call.
func NewRevocationClient(cfg config.RevocationConfig) (*swarfclient.Client, error) {
	serviceID, err := did.Parse(cfg.ServiceID)
	if err != nil {
		return nil, fmt.Errorf("parsing revocation.service_id %q: %w", cfg.ServiceID, err)
	}
	serviceURL, err := url.Parse(cfg.ServiceURL)
	if err != nil {
		return nil, fmt.Errorf("parsing revocation.service_url %q: %w", cfg.ServiceURL, err)
	}
	return swarfclient.New(serviceID, *serviceURL)
}
