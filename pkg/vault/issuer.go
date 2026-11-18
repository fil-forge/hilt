package vault

import (
	"context"
	"fmt"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
)

// TenantIssuer loads the tenant's secp256k1 signing key from v and returns an
// issuer that signs as the tenant.
func TenantIssuer(ctx context.Context, v Vault, tenantID did.DID) (ucan.Issuer, error) {
	keyBytes, err := v.Read(ctx, TenantKeyPath(tenantID))
	if err != nil {
		return nil, fmt.Errorf("reading tenant key: %w", err)
	}
	signer, err := secp256k1.Decode(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("decoding tenant key: %w", err)
	}
	return multikey.NewIssuer(tenantID, signer), nil
}
