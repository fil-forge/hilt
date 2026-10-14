package bucketpolicy

import (
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
)

// Canonical returns the canonical JSON encoding of d: the AWS shape, compact,
// Version before Statement, the statements deduplicated and in CID order (see
// [s3bkt.StatementSet]) and the fields of each in the order Sid (omitted when
// empty), Effect, Principal, Action, Resource. It is what Hilt stores, and
// the JSON Ingot writes for the policy `/s3/bucket/policy` returns.
func Canonical(d s3bkt.PolicyDocument) []byte {
	return encodeJSON(d)
}
