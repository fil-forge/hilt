// Package dagjson is the DAG-JSON form of a bucket policy, which the ETag is
// computed over and the canonical order derived from. It follows the schema
// from the IAM RFC: the statement, principal and action lists are sets, a set
// being a map from its members to Empty, and a policy's statements are the set
// of their CIDs. The generated encoder (json_gen.go, from gen/main.go) writes
// map keys and struct fields in sorted order, so neither the order the caller
// wrote things in nor any duplicate can reach the bytes.
//
// Nothing serves these types; the document Hilt stores and returns keeps the
// AWS shape. The package imports nothing of Hilt's so that the generator can
// build it with the codegen tag.
package dagjson

// Empty is the value of a set member.
type Empty struct{}

// Statement is the DAG-JSON form of a policy statement. The wildcard
// principal is the set {"*"}, which cannot collide with an id because a list
// holding "*" is refused while parsing.
type Statement struct {
	Sid       string `dagjsongen:"omitempty"`
	Effect    string
	Principal map[string]Empty
	Action    map[string]Empty
}

// Policy is the DAG-JSON form of a policy: the set of its statements' CIDs.
type Policy struct {
	Statement map[string]Empty
}
