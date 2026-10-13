// Package bucketpolicy defines the bucket policy and its evaluation: which
// actions a principal holds on a bucket, how a policy is canonicalized (its
// lists are sets) and tagged for compare-and-set, and which principals a
// change to it affects. It
// has no store or transport dependencies; the bucket policy store persists
// policies and the management API validates them with the rules here.
//
// The document is an AWS bucket policy, reduced to what Forge evaluates:
//
//	{
//	  "Version": "2012-10-17",                       // "2012-10-17" | "2008-10-17"
//	  "Statement": [
//	    {
//	      "Sid": "owners",                             // optional label, never evaluated
//	      "Effect": "Allow",                           // "Allow" | "Deny"
//	      "Principal": {"AWS": ["arn:aws:iam:::user/8f2c..."]}, // or "*" or {"AWS": "*"}
//	      "Action": ["s3:GetObject", "s3:ListBucket"], // policy actions, or "s3:*"
//	      "Resource": ["arn:aws:s3:::photos", "arn:aws:s3:::photos/*"]
//	    }
//	  ]
//	}
//
// A principal is a tenant principal, named by the user ARN of its id; in Go
// the [Principal] holds the bare ids. Action and Resource may each be a
// string or a list. Every resource names the policy's bucket, as the bucket
// (arn:aws:s3:::<bucket>) or its objects (arn:aws:s3:::<bucket>/*): an object
// action needs the objects ARN in its statement, a bucket action the bucket
// ARN, and "s3:*" both. Any other field, Condition and NotPrincipal included,
// is refused.
package bucketpolicy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/fil-forge/hilt/pkg/s3perm"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/fil-forge/ucantone/errors"
)

// Effect is whether a statement grants or withholds its actions.
type Effect = s3bkt.Effect

const (
	Allow = s3bkt.Allow
	Deny  = s3bkt.Deny
)

// Version2012 and Version2008 are the policy language versions a document
// may declare. Forge evaluates both the same way.
const (
	Version2012 = "2012-10-17"
	Version2008 = "2008-10-17"
)

// Wildcard is the principal value that names every principal of the tenant.
// It is carried as the bare JSON string "*" or as {"AWS": "*"}; inside a list
// it is rejected.
const Wildcard = s3bkt.Wildcard

// s3ARNPrefix begins the policy bucket's ARNs, the only resources a document
// names.
const (
	s3ARNPrefix   = "arn:aws:s3:::"
	objectsSuffix = "/*"
)

// UserARN returns the ARN a document names principal id by.
func UserARN(id string) string { return s3bkt.UserARN(id) }

// BucketARN returns the ARN of bucket itself, which bucket actions need.
func BucketARN(bucket string) string { return s3ARNPrefix + bucket }

// ObjectsARN returns the ARN of every object in bucket, which object actions
// need.
func ObjectsARN(bucket string) string { return s3ARNPrefix + bucket + objectsSuffix }

// Principal is the set of principals a statement applies to: every principal
// of the tenant (All), or the listed ids. It encodes as the string "*" or as
// {"AWS": [user ARNs]}.
type Principal = s3bkt.Principal

// Everyone returns the principal set naming every principal of the tenant.
func Everyone() Principal { return s3bkt.Everyone() }

// Only returns the principal set naming exactly the given ids.
func Only(ids ...string) Principal { return s3bkt.Only(ids...) }

// stringOrList is a JSON field AWS allows as a string or a list of strings.
type stringOrList []string

func (l *stringOrList) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) > 0 && data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return fmt.Errorf("%v: %w", err, ErrInvalidPolicy)
		}
		*l = stringOrList{s}
		return nil
	}
	var ss []string
	if err := json.Unmarshal(data, &ss); err != nil {
		return fmt.Errorf("must be a string or a list of strings: %w", ErrInvalidPolicy)
	}
	*l = ss
	return nil
}

// Statement grants (Allow) or withholds (Deny) actions on the bucket's
// resources to principals. Sid is an optional label the caller chooses; Hilt
// stores and returns it and never reads it.
type Statement = s3bkt.Statement

// Policy is a bucket policy. It is the wire type of `/s3/bucket/policy`, with
// the strict decoding below.
type Policy s3bkt.BucketPolicy

// InvalidPolicyErrorName is the name of [ErrInvalidPolicy].
const InvalidPolicyErrorName = "InvalidBucketPolicy"

// ErrInvalidPolicy is returned by [Decode] and [Validate] for a policy the API
// rejects with 422. The returned error wraps it with the reason.
var ErrInvalidPolicy = errors.New(InvalidPolicyErrorName, "invalid bucket policy")

// Decode parses a policy document: [Policy.UnmarshalJSON]'s checks, plus
// trailing data after the document is an error wrapping [ErrInvalidPolicy].
// The result is in canonical form. Whether its principals exist is left to
// [Validate].
func Decode(data []byte) (Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	var d Policy
	if err := dec.Decode(&d); err != nil {
		if errors.Is(err, ErrInvalidPolicy) {
			return Policy{}, err
		}
		return Policy{}, fmt.Errorf("decoding policy: %v: %w", err, ErrInvalidPolicy)
	}
	if _, err := dec.Token(); err != io.EOF {
		return Policy{}, fmt.Errorf("decoding policy: trailing data after the document: %w", ErrInvalidPolicy)
	}
	return d, nil
}

// UnmarshalJSON parses a policy document strictly and refuses one that is not
// well formed, so an invalid policy never comes into existence: a field the
// schema does not define, a property name that differs from the schema in
// case, a malformed principal, or a document [wellFormed] rejects is an error
// wrapping [ErrInvalidPolicy]. The result is in canonical form.
func (p *Policy) UnmarshalJSON(data []byte) error {
	if err := strictKeys(data); err != nil {
		return err
	}
	// The wire form takes Action and Resource as a string or a list.
	var w struct {
		Version   string
		Statement []struct {
			Sid       string
			Effect    Effect
			Principal Principal
			Action    stringOrList
			Resource  stringOrList
		}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		if errors.Is(err, ErrInvalidPolicy) {
			return fmt.Errorf("decoding policy: %w", err)
		}
		return fmt.Errorf("decoding policy: %v: %w", err, ErrInvalidPolicy)
	}
	d := Policy{Version: w.Version, Statements: make([]Statement, len(w.Statement))}
	for i, st := range w.Statement {
		d.Statements[i] = Statement{Sid: st.Sid, Effect: st.Effect, Principal: st.Principal, Actions: st.Action, Resources: st.Resource}
	}
	if err := wellFormed(d); err != nil {
		return err
	}
	*p = normalize(d)
	return nil
}

// strictKeys rejects any property name that is not spelled exactly as the
// schema defines it, and a null Sid. encoding/json matches field names
// case-insensitively, so DisallowUnknownFields alone would accept "statement",
// "effect" or "ACTION".
// A document this cannot parse is left to the decoder, which reports it.
func strictKeys(data []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil
	}
	for k := range top {
		if k != "Version" && k != "Statement" {
			return fmt.Errorf("decoding policy: unknown field %q: %w", k, ErrInvalidPolicy)
		}
	}
	var statements []map[string]json.RawMessage
	if err := json.Unmarshal(top["Statement"], &statements); err != nil {
		return nil
	}
	for _, st := range statements {
		for k, v := range st {
			switch k {
			case "Sid":
				// encoding/json decodes null into "" without error, which would
				// read as an absent Sid.
				if string(bytes.TrimSpace(v)) == "null" {
					return fmt.Errorf("decoding policy: Sid must be a string: %w", ErrInvalidPolicy)
				}
			case "Effect", "Principal", "Action", "Resource":
			default:
				return fmt.Errorf("decoding policy: unknown field %q: %w", k, ErrInvalidPolicy)
			}
		}
	}
	return nil
}

// maxSetSize bounds the statements of a policy and the principals of a
// statement. It is the generated DAG-JSON encoder's map limit, so a document
// within it always encodes; a real policy is far smaller.
const maxSetSize = 4096

// wellFormed is the structural check every decoded document passes: a
// recognized Version, at least one statement and at most maxSetSize, each
// with a recognized effect, naming [Wildcard] or at least one principal and
// at most maxSetSize (and never [Wildcard] inside the list), holding at least
// one action, each in the policy vocabulary (see [s3perm.PolicyAction]) or
// [s3perm.PolicyWildcard], and at least one resource, each an ARN of the one
// bucket every resource in the document names, covering what its actions act
// on (see the package doc). It returns an error wrapping [ErrInvalidPolicy]
// otherwise.
func wellFormed(d Policy) error {
	if d.Version != Version2012 && d.Version != Version2008 {
		return fmt.Errorf("policy Version %q must be %q or %q: %w", d.Version, Version2012, Version2008, ErrInvalidPolicy)
	}
	if len(d.Statements) == 0 {
		return fmt.Errorf("Statement must not be empty: %w", ErrInvalidPolicy)
	}
	if len(d.Statements) > maxSetSize {
		return fmt.Errorf("Statement holds %d statements, at most %d are allowed: %w", len(d.Statements), maxSetSize, ErrInvalidPolicy)
	}
	bucket := ""
	for i, st := range d.Statements {
		if st.Effect != Allow && st.Effect != Deny {
			return fmt.Errorf("statement %d: Effect %q must be %q or %q: %w", i, st.Effect, Allow, Deny, ErrInvalidPolicy)
		}
		if !st.Principal.All {
			if len(st.Principal.IDs) == 0 {
				return fmt.Errorf("statement %d: Principal must not be empty: %w", i, ErrInvalidPolicy)
			}
			if len(st.Principal.IDs) > maxSetSize {
				return fmt.Errorf("statement %d: Principal names %d principals, at most %d are allowed: %w", i, len(st.Principal.IDs), maxSetSize, ErrInvalidPolicy)
			}
			if slices.Contains(st.Principal.IDs, Wildcard) {
				return fmt.Errorf("statement %d: Principal %q must be the bare string, not a list entry: %w", i, Wildcard, ErrInvalidPolicy)
			}
		}
		if len(st.Actions) == 0 {
			return fmt.Errorf("statement %d: Action must not be empty: %w", i, ErrInvalidPolicy)
		}
		for _, a := range st.Actions {
			if a != s3perm.PolicyWildcard && !s3perm.PolicyAction(a) {
				return fmt.Errorf("statement %d: Action %q is not a policy action: %w", i, a, ErrInvalidPolicy)
			}
		}
		if len(st.Resources) == 0 {
			return fmt.Errorf("statement %d: Resource must not be empty: %w", i, ErrInvalidPolicy)
		}
		var hasBucket, hasObjects bool
		for _, r := range st.Resources {
			b, objects, ok := parseS3ARN(r)
			if !ok {
				return fmt.Errorf("statement %d: Resource %q must be %q or %q: %w", i, r, BucketARN("<bucket>"), ObjectsARN("<bucket>"), ErrInvalidPolicy)
			}
			if bucket == "" {
				bucket = b
			}
			if b != bucket {
				return fmt.Errorf("statement %d: Resource %q names bucket %q, the policy names %q: %w", i, r, b, bucket, ErrInvalidPolicy)
			}
			hasBucket = hasBucket || !objects
			hasObjects = hasObjects || objects
		}
		for _, a := range st.Actions {
			wildcard := a == s3perm.PolicyWildcard
			if (wildcard || objectAction(a)) && !hasObjects {
				return fmt.Errorf("statement %d: Action %q needs Resource %q: %w", i, a, ObjectsARN(bucket), ErrInvalidPolicy)
			}
			if (wildcard || !objectAction(a)) && !hasBucket {
				return fmt.Errorf("statement %d: Action %q needs Resource %q: %w", i, a, BucketARN(bucket), ErrInvalidPolicy)
			}
		}
	}
	return nil
}

// parseS3ARN splits arn:aws:s3:::<bucket> or arn:aws:s3:::<bucket>/* into the
// bucket and whether it names the bucket's objects. Any other shape, a key
// prefix or a wildcard in the bucket name included, is not ok.
func parseS3ARN(arn string) (bucket string, objects bool, ok bool) {
	rest, ok := strings.CutPrefix(arn, s3ARNPrefix)
	if !ok {
		return "", false, false
	}
	bucket, objects = strings.CutSuffix(rest, objectsSuffix)
	if bucket == "" || strings.ContainsAny(bucket, "/*?") {
		return "", false, false
	}
	return bucket, objects, true
}

// bucketActions are the policy actions that act on the bucket rather than on
// its objects; every other policy action is an object action. The split is
// versitygw's, which evaluates the policy against these ARNs.
var bucketActions = []string{
	"s3:ListBucket",
	"s3:ListBucketMultipartUploads",
	"s3:ListBucketVersions",
}

// objectAction reports whether policy action a acts on objects.
func objectAction(a string) bool { return !slices.Contains(bucketActions, a) }

// Validate checks that d may be stored as the policy of bucket: it is
// [wellFormed], every resource names bucket, and every named principal
// exists per principalExists. A document that came through [Decode] is well
// formed already; the check is repeated here for documents built in code. It
// returns an error wrapping [ErrInvalidPolicy] otherwise.
func Validate(d Policy, bucket string, principalExists func(string) bool) error {
	if err := wellFormed(d); err != nil {
		return err
	}
	for i, st := range d.Statements {
		for _, r := range st.Resources {
			if b, _, _ := parseS3ARN(r); b != bucket {
				return fmt.Errorf("statement %d: Resource %q must name bucket %q: %w", i, r, bucket, ErrInvalidPolicy)
			}
		}
		if st.Principal.All {
			continue
		}
		for _, p := range st.Principal.IDs {
			if p == "" || !principalExists(p) {
				return fmt.Errorf("statement %d: unknown principal %q: %w", i, p, ErrInvalidPolicy)
			}
		}
	}
	return nil
}

// encodeJSON is json.Marshal for the policy types, whose encoding cannot fail:
// struct fields are written in declaration order without whitespace, so the
// struct definitions in libforge's commands/s3/bucket fix the layout.
func encodeJSON(v any) []byte {
	out, _ := json.Marshal(v)
	return out
}

// Effective returns the actions principal p holds under d: the actions of the
// allow statements naming p or [Wildcard], minus the actions of the deny
// statements naming p or [Wildcard], with [s3perm.PolicyWildcard] standing for
// every policy action. The result is sorted and deduplicated, and nil when it
// is empty or d is nil (a bucket with no policy). It is also nil for
// p == [Wildcard], which is not a principal: expanding the wildcard to the
// tenant's principals is [Changed]'s job.
func Effective(d *Policy, p string) []string {
	if d == nil {
		return nil
	}
	allowed := map[string]bool{}
	denied := map[string]bool{}
	for _, st := range d.Statements {
		if !names(st, p) {
			continue
		}
		set := allowed
		if st.Effect == Deny {
			set = denied
		}
		for _, a := range expand(st.Actions) {
			set[a] = true
		}
	}
	var out []string
	for a := range allowed {
		if !denied[a] {
			out = append(out, a)
		}
	}
	slices.Sort(out)
	return out
}

// Named returns the principals d names explicitly, sorted and deduplicated,
// and whether any statement names [Wildcard].
func Named(d Policy) (principals []string, wildcard bool) {
	seen := map[string]bool{}
	for _, st := range d.Statements {
		if st.Principal.All {
			wildcard = true
			continue
		}
		for _, p := range st.Principal.IDs {
			if !seen[p] {
				seen[p] = true
				principals = append(principals, p)
			}
		}
	}
	slices.Sort(principals)
	return principals, wildcard
}

// RemovePrincipal returns d with principalID removed from every statement
// naming it, dropping statements left with no principal, and reports whether
// anything changed. A wildcard statement names no principal and is kept as is.
func RemovePrincipal(d Policy, principalID string) (Policy, bool) {
	var statements []Statement
	changed := false
	for _, st := range d.Statements {
		if !st.Principal.All {
			ids := slices.DeleteFunc(slices.Clone(st.Principal.IDs), func(p string) bool { return p == principalID })
			if len(ids) != len(st.Principal.IDs) {
				changed = true
			}
			if len(ids) == 0 {
				continue
			}
			st.Principal = Only(ids...)
		}
		statements = append(statements, st)
	}
	return Policy{Version: d.Version, Statements: statements}, changed
}

// Changed returns the principals whose effective set differs between old and
// new, either of which may be nil for "no policy". It considers every
// principal either policy names, with [Wildcard] expanding to
// tenantPrincipals. The result is sorted and deduplicated.
func Changed(old, new *Policy, tenantPrincipals []string) []string {
	candidates := map[string]bool{}
	for _, d := range []*Policy{old, new} {
		if d == nil {
			continue
		}
		named, wildcard := Named(*d)
		for _, p := range named {
			candidates[p] = true
		}
		if wildcard {
			for _, p := range tenantPrincipals {
				candidates[p] = true
			}
		}
	}
	var out []string
	for p := range candidates {
		if !slices.Equal(Effective(old, p), Effective(new, p)) {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out
}

// names reports whether st applies to principal p. [Wildcard] is never a
// principal, so no statement applies to it.
func names(st Statement, p string) bool {
	if p == Wildcard {
		return false
	}
	return st.Principal.All || slices.Contains(st.Principal.IDs, p)
}

// expand replaces [s3perm.PolicyWildcard] with every policy action.
func expand(actions []string) []string {
	if !slices.Contains(actions, s3perm.PolicyWildcard) {
		return actions
	}
	out := make([]string, 0, len(actions)+16)
	for _, a := range actions {
		if a == s3perm.PolicyWildcard {
			out = append(out, s3perm.PolicyActions()...)
		} else {
			out = append(out, a)
		}
	}
	return out
}
