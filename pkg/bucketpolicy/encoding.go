package bucketpolicy

import (
	"bytes"
	"slices"
	"strings"

	"github.com/fil-forge/hilt/pkg/bucketpolicy/internal/dagjson"
	"github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

// encode returns the DAG-JSON form of st (see [dagjson]): its lists as sets.
func encode(st Statement) dagjson.Statement {
	e := dagjson.Statement{
		Sid:       st.Sid,
		Effect:    string(st.Effect),
		Principal: make(map[string]dagjson.Empty, len(st.Principal.IDs)),
		Action:    make(map[string]dagjson.Empty, len(st.Actions)),
	}
	if st.Principal.All {
		e.Principal[Wildcard] = dagjson.Empty{}
	} else {
		for _, id := range st.Principal.IDs {
			e.Principal[id] = dagjson.Empty{}
		}
	}
	for _, a := range st.Actions {
		e.Action[a] = dagjson.Empty{}
	}
	return e
}

// decode returns the AWS-shaped statement of e: principals and actions in
// sorted order, never nil.
func decode(e dagjson.Statement) Statement {
	st := Statement{Sid: e.Sid, Effect: Effect(e.Effect), Actions: members(e.Action)}
	if _, all := e.Principal[Wildcard]; all {
		st.Principal = Everyone()
	} else {
		st.Principal = Only(members(e.Principal)...)
	}
	return st
}

// members returns the set's members, sorted, never nil.
func members(set map[string]dagjson.Empty) []string {
	out := make([]string, 0, len(set))
	for m := range set {
		out = append(out, m)
	}
	slices.Sort(out)
	return out
}

// statementCID returns the CID of e's DAG-JSON encoding.
func statementCID(e dagjson.Statement) cid.Cid {
	var buf bytes.Buffer
	if err := e.MarshalDagJSON(&buf); err != nil {
		panic(err) // the sets are bounded by maxSetSize, the only failure the encoder has
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

// normalize returns a copy of d in canonical form. The statement, principal
// and action lists are sets: each is deduplicated and sorted, a wildcard
// principal drops any stray ids, nil lists become empty lists, and the
// statements are ordered by their CID. Two policies that differ only in order
// or in duplicates normalize to the same value.
func normalize(d Policy) Policy {
	type keyed struct {
		key string
		st  Statement
	}
	keyedStatements := make([]keyed, 0, len(d.Statements))
	for _, st := range d.Statements {
		e := encode(st)
		keyedStatements = append(keyedStatements, keyed{key: statementCID(e).String(), st: decode(e)})
	}
	slices.SortFunc(keyedStatements, func(a, b keyed) int { return strings.Compare(a.key, b.key) })
	keyedStatements = slices.CompactFunc(keyedStatements, func(a, b keyed) bool { return a.key == b.key })
	statements := make([]Statement, len(keyedStatements))
	for i, k := range keyedStatements {
		statements[i] = k.st
	}
	return Policy{Statements: statements}
}

// Canonical returns the canonical JSON encoding of d: the [normalize]d
// document in the AWS shape, compact, with the fields of each statement in
// the order Sid (omitted when empty), Effect, Principal, Action. It is what
// Hilt stores and returns.
func Canonical(d Policy) []byte {
	return encodeJSON(normalize(d))
}

// ETag returns the entity tag of d: the CID of the DAG-JSON encoding of the
// policy as sets (CIDv1, dag-json, sha2-256; each statement by the CID of its
// own encoding), in double quotes as HTTP carries it. Callers treat it as
// opaque.
func ETag(d Policy) string {
	p := dagjson.Policy{Statement: make(map[string]dagjson.Empty, len(d.Statements))}
	for _, st := range d.Statements {
		p.Statement[statementCID(encode(st)).String()] = dagjson.Empty{}
	}
	var buf bytes.Buffer
	if err := p.MarshalDagJSON(&buf); err != nil {
		panic(err) // see statementCID
	}
	return `"` + dagJSONCID(buf.Bytes()).String() + `"`
}
