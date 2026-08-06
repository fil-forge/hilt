package fx

import (
	"fmt"
	"net/url"

	"github.com/fil-forge/hilt/pkg/config"
	swarfclient "github.com/fil-forge/swarf/pkg/client"
	"github.com/fil-forge/ucantone/did"
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
