package fx

import (
	"fmt"
	"net/url"

	"github.com/fil-forge/hilt/pkg/config"
	"github.com/fil-forge/hilt/pkg/grant"
	swarfclient "github.com/fil-forge/swarf/pkg/client"
	"github.com/fil-forge/ucantone/did"
	"go.uber.org/fx"
)

// RevocationModule provides the Swarf revocation-service client, published as
// [grant.RevocationPublisher] as well as the concrete type. The REST access-key
// service, the UCAN bucket service and the grant rotator all revoke delegations
// through it, so the client is shared rather than owned by any of their modules.
var RevocationModule = fx.Module("revocation",
	fx.Provide(
		fx.Annotate(
			NewRevocationClient,
			fx.As(fx.Self()),
			fx.As(new(grant.RevocationPublisher)),
		),
		grant.NewRotator,
	),
)

// NewRevocationClient builds the Swarf revocation-service client from
// configuration. It takes no issuer: revocations are signed by the tenant that
// issued the revoked delegations, which is passed per publish call.
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
