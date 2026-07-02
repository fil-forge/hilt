// Package vault defines a KMS-agnostic interface for storing the private key
// material Hilt manages (tenant keys, bucket keys, S3 access keys). Keys are
// opaque string paths and values are raw private-key bytes. Implementations may
// be backed by any KMS; an in-memory implementation lives in vault/memory.
package vault

import "context"

// Vault stores secret key material by opaque string key.
type Vault interface {
	// Read returns the value stored at key. It returns [ErrNotFound] if no value
	// exists for the key.
	Read(ctx context.Context, key string) ([]byte, error)
	// Write stores value at key, overwriting any existing value.
	Write(ctx context.Context, key string, value []byte) error
	// Delete removes the value at key. It is idempotent: deleting an absent key
	// returns nil.
	Delete(ctx context.Context, key string) error
}
