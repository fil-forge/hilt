package fx

import (
	"errors"
	"fmt"
	"net/url"
	"os"

	"github.com/fil-forge/hilt/pkg/client/upload"
	"github.com/fil-forge/hilt/pkg/config"
	"github.com/fil-forge/hilt/pkg/tracing"
	"github.com/fil-forge/libforge/identity"
	ucanlib "github.com/fil-forge/libforge/ucan"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan/container"
	"go.uber.org/zap"
)

// NewUploadClient builds the Sprue upload-service client from configuration. Its
// proof store — the delegations it presents to Sprue — is loaded from
// upload.proofs (see [uploadProofs]).
//
// The service DID, URL and product DID are required. None has a default, so a
// deployment that forgets one fails at startup rather than provisioning on
// another stage's Sprue.
func NewUploadClient(id identity.Identity, cfg config.UploadConfig, logger *zap.Logger) (*upload.Client, error) {
	if cfg.ServiceID == "" {
		return nil, errors.New("upload.service_id is required: set HILT_UPLOAD_SERVICE_ID or --upload-service-id")
	}
	if cfg.ServiceURL == "" {
		return nil, errors.New("upload.service_url is required: set HILT_UPLOAD_SERVICE_URL or --upload-service-url")
	}
	if cfg.ProductID == "" {
		return nil, errors.New("upload.product_id is required: set HILT_UPLOAD_PRODUCT_ID or --upload-product-id")
	}
	serviceID, err := did.Parse(cfg.ServiceID)
	if err != nil {
		return nil, fmt.Errorf("parsing upload.service_id %q: %w", cfg.ServiceID, err)
	}
	serviceURL, err := url.Parse(cfg.ServiceURL)
	if err != nil {
		return nil, fmt.Errorf("parsing upload.service_url %q: %w", cfg.ServiceURL, err)
	}
	product, err := did.Parse(cfg.ProductID)
	if err != nil {
		return nil, fmt.Errorf("parsing upload.product_id %q: %w", cfg.ProductID, err)
	}
	proofs, err := uploadProofs(cfg.Proofs)
	if err != nil {
		return nil, fmt.Errorf("loading upload.proofs: %w", err)
	}
	return upload.NewClient(
		serviceID,
		*serviceURL,
		id,
		upload.WithBaseProofs(proofs),
		upload.WithProduct(product),
		upload.WithLogger(logger),
		upload.WithHTTPClient(tracing.NewHTTPClient()),
	)
}

// uploadProofs builds the upload client's proof store from cfg.Proofs, which is
// either an inline (codec-prefixed) encoded UCAN container or a path to a file
// containing one. The inline form is tried first so a file whose name happens to
// be a valid container string does not shadow it. Empty yields an empty store.
func uploadProofs(proofs string) (ucanlib.ProofStore, error) {
	if proofs == "" {
		return ucanlib.NewContainerProofStore(container.New()), nil
	}
	ct, err := container.Decode([]byte(proofs))
	if err != nil {
		data, ferr := os.ReadFile(proofs)
		if ferr != nil {
			return nil, fmt.Errorf("upload.proofs is neither a valid container (%v) nor a readable file: %w", err, ferr)
		}
		if ct, err = container.Decode(data); err != nil {
			return nil, fmt.Errorf("decoding upload.proofs file %q: %w", proofs, err)
		}
	}
	return ucanlib.NewContainerProofStore(ct), nil
}
