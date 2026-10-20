package fx

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/fil-forge/hilt/pkg/config"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/tracing"
	swarfclient "github.com/fil-forge/swarf/pkg/client"
	"github.com/fil-forge/ucantone/did"
	"go.uber.org/fx"
)

// RevocationModule provides the Swarf revocation-service client, published as
// [grant.RevocationPublisher] as well as the concrete type. The REST access-key
// service and the UCAN bucket service both revoke delegations through it, so
// the client is shared rather than owned by either module.
var RevocationModule = fx.Module("revocation",
	fx.Provide(
		fx.Annotate(
			NewRevocationClient,
			fx.As(fx.Self()),
			fx.As(new(grant.RevocationPublisher)),
		),
	),
)

// NewRevocationClient builds the Swarf revocation-service client from
// configuration. It takes no issuer: revocations are signed by the tenant that
// issued the revoked delegations, which is passed per publish call.
//
// Both settings are required. Neither has a default, so a deployment that
// forgets them fails at startup rather than publishing to another stage's
// Swarf.
func NewRevocationClient(cfg config.RevocationConfig) (*swarfclient.Client, error) {
	if cfg.ServiceID == "" {
		return nil, errors.New("revocation.service_id is required: set HILT_REVOCATION_SERVICE_ID or --revocation-service-id")
	}
	if cfg.ServiceURL == "" {
		return nil, errors.New("revocation.service_url is required: set HILT_REVOCATION_SERVICE_URL or --revocation-service-url")
	}
	serviceID, err := did.Parse(cfg.ServiceID)
	if err != nil {
		return nil, fmt.Errorf("parsing revocation.service_id %q: %w", cfg.ServiceID, err)
	}
	serviceURL, err := url.Parse(cfg.ServiceURL)
	if err != nil {
		return nil, fmt.Errorf("parsing revocation.service_url %q: %w", cfg.ServiceURL, err)
	}
	return swarfclient.New(serviceID, *serviceURL, swarfclient.WithHTTPClient(tracing.NewHTTPClient()))
}
