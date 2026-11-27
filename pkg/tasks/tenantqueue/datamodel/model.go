// Package datamodel holds the stored form of the arguments of queue-tenant's
// tasks that carry more than one value. A task's arguments are kept in
// Postgres with the task, so no model here has a field for a secret.
package datamodel

import "github.com/fil-forge/ucantone/did"

// CreateKeyArgs is the arguments of a queue-tenant.create-key task: the
// access key to create for the task's subject tenant. The key's secret is
// not among them.
type CreateKeyArgs struct {
	// Key is the access key's did:key.
	Key did.DID `cborgen:"key"`
	// Name is the key's human readable name.
	Name string `cborgen:"name"`
	// Permissions are the S3 permissions of a service key. Empty for a
	// principal-bound key.
	Permissions []string `cborgen:"permissions"`
	// Buckets are the DIDs of the buckets a service key is scoped to. Empty
	// means every bucket of the tenant.
	Buckets []did.DID `cborgen:"buckets"`
	// Principal is the principal a principal-bound key belongs to. Nil for a
	// service key.
	Principal *string `cborgen:"principal"`
	// ExpiresAt is when the key expires, in microseconds since the Unix
	// epoch. Nil means it never expires.
	ExpiresAt *int64 `cborgen:"expiresAt"`
	// CreatedAt is the key's creation time, in microseconds since the Unix
	// epoch.
	CreatedAt int64 `cborgen:"createdAt"`
}
