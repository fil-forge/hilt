// Package bucketpolicy evaluates bucket policies: which actions a principal
// holds on a bucket, how a policy is canonicalized (its lists are sets) and
// tagged for compare-and-set, and which principals a change to it affects.
// The document type, its JSON form and its structural checks are libforge's
// [s3bkt.BucketPolicy]; [Decode] and [Validate] add Hilt's canonical form and
// its checks against the bucket and the tenant's principals. It has no store
// or transport dependencies.
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
// the [s3bkt.Principal] holds the bare ids. Action and Resource may each be a
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
	"maps"
	"slices"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/fil-forge/ucantone/errors"
)

// Decode parses a policy document: [s3bkt.BucketPolicy.UnmarshalJSON]'s
// checks, plus trailing data after the document is an error wrapping
// [s3bkt.ErrInvalidPolicy]. The result is in canonical form (see
// [s3bkt.Normalize]).
// Whether its principals exist is left to [Validate].
func Decode(data []byte) (s3bkt.BucketPolicy, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	var d s3bkt.BucketPolicy
	if err := dec.Decode(&d); err != nil {
		if errors.Is(err, s3bkt.ErrInvalidPolicy) {
			return s3bkt.BucketPolicy{}, err
		}
		return s3bkt.BucketPolicy{}, fmt.Errorf("decoding policy: %v: %w", err, s3bkt.ErrInvalidPolicy)
	}
	if _, err := dec.Token(); err != io.EOF {
		return s3bkt.BucketPolicy{}, fmt.Errorf("decoding policy: trailing data after the document: %w", s3bkt.ErrInvalidPolicy)
	}
	return s3bkt.Normalize(d), nil
}

// Validate checks that d may be stored as the policy of bucket: it is
// [s3bkt.WellFormed], every resource names bucket, and every named principal
// exists per principalExists. A document that came through [Decode] is well
// formed already; the check is repeated here for documents built in code. It
// returns an error wrapping [s3bkt.ErrInvalidPolicy] otherwise.
func Validate(d s3bkt.BucketPolicy, bucket string, principalExists func(string) bool) error {
	if err := s3bkt.WellFormed(d); err != nil {
		return err
	}
	for i, st := range d.Statements {
		for _, r := range st.Resources.Members() {
			if b, _, _ := s3bkt.ParseS3ARN(r); b != bucket {
				return fmt.Errorf("statement %d: Resource %q must name bucket %q: %w", i, r, bucket, s3bkt.ErrInvalidPolicy)
			}
		}
		if st.Principal.All() {
			continue
		}
		for _, p := range st.Principal.Members() {
			if p == "" || !principalExists(p) {
				return fmt.Errorf("statement %d: unknown principal %q: %w", i, p, s3bkt.ErrInvalidPolicy)
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
// allow statements naming p or [s3bkt.Wildcard], minus the actions of the deny
// statements naming p or [s3bkt.Wildcard], with [s3bkt.PolicyWildcard] standing for
// every policy action. The result is sorted and deduplicated, and nil when it
// is empty or d is nil (a bucket with no policy). It is also nil for
// p == [s3bkt.Wildcard], which is not a principal: expanding the wildcard to the
// tenant's principals is [Changed]'s job.
func Effective(d *s3bkt.BucketPolicy, p string) []string {
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
		if st.Effect == s3bkt.Deny {
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
// and whether any statement names [s3bkt.Wildcard].
func Named(d s3bkt.BucketPolicy) (principals []string, wildcard bool) {
	seen := map[string]bool{}
	for _, st := range d.Statements {
		if st.Principal.All() {
			wildcard = true
			continue
		}
		for _, p := range st.Principal.Members() {
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
func RemovePrincipal(d s3bkt.BucketPolicy, principalID string) (s3bkt.BucketPolicy, bool) {
	var statements []s3bkt.Statement
	changed := false
	for _, st := range d.Statements {
		if _, named := st.Principal[principalID]; named && !st.Principal.All() {
			changed = true
			ids := maps.Clone(st.Principal)
			delete(ids, principalID)
			if len(ids) == 0 {
				continue
			}
			st.Principal = ids
		}
		statements = append(statements, st)
	}
	return s3bkt.BucketPolicy{Version: d.Version, Statements: statements}, changed
}

// Changed returns the principals whose effective set differs between old and
// new, either of which may be nil for "no policy". It considers every
// principal either policy names, with [s3bkt.Wildcard] expanding to
// tenantPrincipals. The result is sorted and deduplicated.
func Changed(old, new *s3bkt.BucketPolicy, tenantPrincipals []string) []string {
	candidates := map[string]bool{}
	for _, d := range []*s3bkt.BucketPolicy{old, new} {
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

// names reports whether st applies to principal p. [s3bkt.Wildcard] is never a
// principal, so no statement applies to it.
func names(st s3bkt.Statement, p string) bool {
	if p == s3bkt.Wildcard {
		return false
	}
	_, named := st.Principal[p]
	return st.Principal.All() || named
}

// expand returns the actions, sorted, with [s3bkt.PolicyWildcard] replaced by
// every policy action.
func expand(actions s3bkt.StringSet) []string {
	if _, ok := actions[s3bkt.PolicyWildcard]; !ok {
		return actions.Members()
	}
	out := make([]string, 0, len(actions)+16)
	for _, a := range actions.Members() {
		if a == s3bkt.PolicyWildcard {
			out = append(out, s3bkt.PolicyActions()...)
		} else {
			out = append(out, a)
		}
	}
	return out
}
