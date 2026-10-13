package bucketpolicy

import (
	"bytes"
	"slices"
	"strings"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	"github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

// statementCID returns the CID of st's DAG-JSON encoding: its sets as maps
// with sorted keys, so nothing about how the caller built them reaches it.
func statementCID(st s3bkt.Statement) cid.Cid {
	var buf bytes.Buffer
	if err := st.MarshalDagJSON(&buf); err != nil {
		panic(err) // the sets are bounded by s3bkt.MaxSetSize, within the encoder's map limit
	}
	return dagJSONCID(buf.Bytes())
}

// dagJSONCID returns the CIDv1 (dag-json, sha2-256) of raw.
func dagJSONCID(raw []byte) cid.Cid {
	sum, err := mh.Sum(raw, mh.SHA2_256, -1)
	if err != nil {
		panic(err) // sha2-256 with the default length cannot fail
	}
	return cid.NewCidV1(cid.DagJSON, sum)
}

// normalize returns a copy of d in canonical form, its Version kept: the
// statements deduplicated and ordered by their CID. The principal, action and
// resource sets need nothing, being sets. Two policies that differ only in
// statement order or in duplicate statements normalize to the same value.
func normalize(d s3bkt.BucketPolicy) s3bkt.BucketPolicy {
	type keyed struct {
		key string
		st  s3bkt.Statement
	}
	keyedStatements := make([]keyed, 0, len(d.Statements))
	for _, st := range d.Statements {
		keyedStatements = append(keyedStatements, keyed{key: statementCID(st).String(), st: st})
	}
	slices.SortFunc(keyedStatements, func(a, b keyed) int { return strings.Compare(a.key, b.key) })
	keyedStatements = slices.CompactFunc(keyedStatements, func(a, b keyed) bool { return a.key == b.key })
	statements := make([]s3bkt.Statement, len(keyedStatements))
	for i, k := range keyedStatements {
		statements[i] = k.st
	}
	return s3bkt.BucketPolicy{Version: d.Version, Statements: statements}
}

// Canonical returns the canonical JSON encoding of d: the [normalize]d
// document in the AWS shape, compact, Version before Statement and the fields
// of each statement in the order Sid (omitted when empty), Effect, Principal,
// Action, Resource. It is what Hilt stores, and the JSON Ingot writes for the
// policy `/s3/bucket/policy` returns.
func Canonical(d s3bkt.BucketPolicy) []byte {
	return encodeJSON(normalize(d))
}

// ETag returns the entity tag of d: the CID of the DAG-JSON encoding of the
// [normalize]d document (CIDv1, dag-json, sha2-256), its statements in CID
// order and each statement's sets as maps, in double quotes as HTTP carries
// it. Callers treat it as opaque.
func ETag(d s3bkt.BucketPolicy) string {
	n := normalize(d)
	var buf bytes.Buffer
	if err := n.MarshalDagJSON(&buf); err != nil {
		panic(err) // see statementCID
	}
	return `"` + dagJSONCID(buf.Bytes()).String() + `"`
}
