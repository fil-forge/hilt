// Package datamodel holds the stored form of the arguments of queue-tenant's
// tasks that carry more than one value, and of the results of those that
// return one. A task's arguments and result are kept in Postgres with the
// task, so no model here has a field for a secret.
package datamodel

import (
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/fil-forge/ucantone/did"
)

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

// PutPolicyArgs is the arguments of a queue-tenant.put-policy task: the
// policy to store for a bucket of the task's subject tenant, and the
// condition the write was sent with.
type PutPolicyArgs struct {
	// Bucket is the DID of the bucket the policy applies to.
	Bucket did.DID `cborgen:"bucket"`
	// Name is the name the bucket is addressed by, which the document's
	// resources must name.
	Name string `cborgen:"name"`
	// Document is the policy to store.
	Document s3bkt.PolicyDocument `cborgen:"document"`
	// Conditional makes the write check IfMatch. Unset, the write replaces
	// whatever is stored and creates when nothing is.
	Conditional bool `cborgen:"conditional"`
	// IfMatch is the ETag the bucket's current policy must carry for a
	// Conditional write to proceed (If-Match). Nil means the bucket must
	// have no policy (If-None-Match: *).
	IfMatch *string `cborgen:"ifMatch"`
}

// PutPolicyResult is the result of a queue-tenant.put-policy task.
type PutPolicyResult struct {
	// ETag is the entity tag of the policy the task stored.
	ETag string `cborgen:"etag"`
	// Created is whether the bucket had no policy before.
	Created bool `cborgen:"created"`
}

// DeletePolicyArgs is the arguments of a queue-tenant.delete-policy task:
// the bucket of the task's subject tenant whose policy to remove, and the
// condition the removal was sent with.
type DeletePolicyArgs struct {
	// Bucket is the DID of the bucket whose policy is removed.
	Bucket did.DID `cborgen:"bucket"`
	// Name is the name the bucket is addressed by.
	Name string `cborgen:"name"`
	// IfMatch is the ETag the bucket's current policy must carry for the
	// removal to proceed (If-Match). Nil removes whatever is stored.
	IfMatch *string `cborgen:"ifMatch"`
}
