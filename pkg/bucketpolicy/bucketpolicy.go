// Package bucketpolicy defines the bucket policy and its evaluation: which
// actions a principal holds on a bucket, how a policy is canonicalized and
// tagged for compare-and-set, and which principals a change to it affects. It
// has no store or transport dependencies; the bucket policy store persists
// policies and the management API validates them with the rules here.
package bucketpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/fil-forge/ucantone/errors"
)

// Effect is whether a statement grants or withholds its actions.
type Effect string

const (
	Allow Effect = "Allow"
	Deny  Effect = "Deny"
)

// Wildcard is the principal entry that names every principal of the tenant.
const Wildcard = "*"

// Statement grants (Allow) or withholds (Deny) actions to principals. A
// principal entry is a console userId, or [Wildcard] for every principal of
// the tenant.
type Statement struct {
	Effect     Effect   `json:"effect"`
	Principals []string `json:"principals"`
	Actions    []string `json:"actions"`
}

// Policy is a bucket policy.
type Policy struct {
	Statements []Statement `json:"statements"`
}

// InvalidPolicyErrorName is the name of [ErrInvalidPolicy].
const InvalidPolicyErrorName = "InvalidBucketPolicy"

// ErrInvalidPolicy is returned by [Validate] for a policy the API rejects
// with 422. The returned error wraps it with the reason.
var ErrInvalidPolicy = errors.New(InvalidPolicyErrorName, "invalid bucket policy")

// Validate checks that d may be stored: it has at least one statement, every
// statement has a recognized effect and at least one principal and one action,
// every action is in the policy vocabulary (see [s3perm.PolicyAction]), and
// every named principal exists per principalExists ([Wildcard] is not looked
// up). It returns an error wrapping [ErrInvalidPolicy] otherwise.
func Validate(d Policy, principalExists func(string) bool) error {
	if len(d.Statements) == 0 {
		return fmt.Errorf("statements must not be empty: %w", ErrInvalidPolicy)
	}
	for i, st := range d.Statements {
		if st.Effect != Allow && st.Effect != Deny {
			return fmt.Errorf("statement %d: effect %q must be %q or %q: %w", i, st.Effect, Allow, Deny, ErrInvalidPolicy)
		}
		if len(st.Principals) == 0 {
			return fmt.Errorf("statement %d: principals must not be empty: %w", i, ErrInvalidPolicy)
		}
		if len(st.Actions) == 0 {
			return fmt.Errorf("statement %d: actions must not be empty: %w", i, ErrInvalidPolicy)
		}
		for _, p := range st.Principals {
			if p == Wildcard {
				continue
			}
			if p == "" || !principalExists(p) {
				return fmt.Errorf("statement %d: unknown principal %q: %w", i, p, ErrInvalidPolicy)
			}
		}
		for _, a := range st.Actions {
			if !s3perm.PolicyAction(a) {
				return fmt.Errorf("statement %d: action %q is not a policy action: %w", i, a, ErrInvalidPolicy)
			}
		}
	}
	return nil
}

// Canonical returns the canonical encoding of d: compact JSON with the fields
// of each statement in the order effect, principals, actions, and every list
// in the order given. Nil lists encode as empty lists. Two policies with the
// same statements in the same order have the same canonical form.
func Canonical(d Policy) []byte {
	statements := make([]Statement, len(d.Statements))
	for i, st := range d.Statements {
		statements[i] = Statement{
			Effect:     st.Effect,
			Principals: nonNil(st.Principals),
			Actions:    nonNil(st.Actions),
		}
	}
	// json.Marshal writes struct fields in declaration order without whitespace,
	// so the struct definitions above fix the layout; a marshalling error is
	// impossible for these types.
	out, err := json.Marshal(Policy{Statements: statements})
	if err != nil {
		panic(fmt.Sprintf("bucketpolicy: marshalling canonical policy: %v", err))
	}
	return out
}

// ETag returns the strong entity tag of d: the hex SHA-256 of its canonical
// encoding, in double quotes as HTTP carries it.
func ETag(d Policy) string {
	sum := sha256.Sum256(Canonical(d))
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

// Effective returns the actions principal p holds under d: the actions of the
// Allow statements naming p or [Wildcard], minus the actions of the Deny
// statements naming p or [Wildcard]. The result is sorted and deduplicated,
// and nil when it is empty or d is nil (a bucket with no policy). It is also
// nil for p == [Wildcard], which is not a principal: expanding the wildcard to
// the tenant's principals is [Changed]'s job.
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
		for _, a := range st.Actions {
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
		for _, p := range st.Principals {
			if p == Wildcard {
				wildcard = true
				continue
			}
			if !seen[p] {
				seen[p] = true
				principals = append(principals, p)
			}
		}
	}
	slices.Sort(principals)
	return principals, wildcard
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
	return slices.Contains(st.Principals, p) || slices.Contains(st.Principals, Wildcard)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
