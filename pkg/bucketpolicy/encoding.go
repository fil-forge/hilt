package bucketpolicy

import (
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
)

// Canonical returns the canonical JSON encoding of d: the [s3bkt.Normalize]d
// document in the AWS shape, compact, Version before Statement and the fields
// of each statement in the order Sid (omitted when empty), Effect, Principal,
// Action, Resource. It is what Hilt stores, and the JSON Ingot writes for the
// policy `/s3/bucket/policy` returns.
func Canonical(d s3bkt.BucketPolicy) []byte {
	return encodeJSON(s3bkt.Normalize(d))
}
