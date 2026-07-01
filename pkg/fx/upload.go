package fx

import (
	"fmt"
	"net/url"

	"github.com/fil-forge/hilt/pkg/client"
	"github.com/fil-forge/hilt/pkg/config"
	delegationstore "github.com/fil-forge/hilt/pkg/store/delegation"
	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/ucantone/did"
	"go.uber.org/zap"
)

// NewUploadClient builds the Sprue upload-service client from configuration. The
// delegation store doubles as the client's proof store (it satisfies
// ucanlib.ProofStore); ProvisionSpace is self-issued and does not consult it.
func NewUploadClient(id identity.Identity, cfg config.UploadConfig, delegations delegationstore.Store, logger *zap.Logger) (*client.UploadClient, error) {
	serviceID, err := did.Parse(cfg.ServiceID)
	if err != nil {
		return nil, fmt.Errorf("parsing upload.service_id %q: %w", cfg.ServiceID, err)
	}
	serviceURL, err := url.Parse(cfg.ServiceURL)
	if err != nil {
		return nil, fmt.Errorf("parsing upload.service_url %q: %w", cfg.ServiceURL, err)
	}
	// The product DID is optional here: it is only consumed when registering
	// tenants as customers. Leave it undefined when unset so the client remains
	// usable for the bucket-provisioning flows that do not need it.
	var product did.DID
	if cfg.ProductID != "" {
		product, err = did.Parse(cfg.ProductID)
		if err != nil {
			return nil, fmt.Errorf("parsing upload.product_id %q: %w", cfg.ProductID, err)
		}
	}
	return client.NewUploadClient(serviceID, *serviceURL, id, delegations,
		client.WithProduct(product), client.WithLogger(logger))
}
