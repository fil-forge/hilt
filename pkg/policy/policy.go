// Package policy defines the bucket policy document and its evaluation: which
// actions a principal holds on a bucket, how a document is canonicalized and
// tagged for compare-and-set, and which principals a change to it affects. It
// has no store or transport dependencies; the policy store persists documents
// and the management API validates them with the rules here.
package policy

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

// Document is a bucket policy.
type Document struct {
	Statements []Statement `json:"statements"`
}

// InvalidDocumentErrorName is the name of [ErrInvalidDocument].
const InvalidDocumentErrorName = "InvalidPolicyDocument"

// ErrInvalidDocument is returned by [Validate] for a document the API rejects
// with 422. The returned error wraps it with the reason.
var ErrInvalidDocument = errors.New(InvalidDocumentErrorName, "invalid policy document")

// Validate checks that d may be stored: it has at least one statement, every
// statement has a recognized effect and at least one principal and one action,
// every action is in the policy vocabulary (see [s3perm.PolicyAction]), and
// every named principal exists per principalExists ([Wildcard] is not looked
// up). It returns an error wrapping [ErrInvalidDocument] otherwise.
func Validate(d Document, principalExists func(string) bool) error {
	if len(d.Statements) == 0 {
		return fmt.Errorf("statements must not be empty: %w", ErrInvalidDocument)
	}
	for i, st := range d.Statements {
		if st.Effect != Allow && st.Effect != Deny {
			return fmt.Errorf("statement %d: effect %q must be %q or %q: %w", i, st.Effect, Allow, Deny, ErrInvalidDocument)
		}
		if len(st.Principals) == 0 {
			return fmt.Errorf("statement %d: principals must not be empty: %w", i, ErrInvalidDocument)
		}
		if len(st.Actions) == 0 {
			return fmt.Errorf("statement %d: actions must not be empty: %w", i, ErrInvalidDocument)
		}
		for _, p := range st.Principals {
			if p == Wildcard {
				continue
			}
			if p == "" || !principalExists(p) {
				return fmt.Errorf("statement %d: unknown principal %q: %w", i, p, ErrInvalidDocument)
			}
		}
		for _, a := range st.Actions {
			if !s3perm.PolicyAction(a) {
				return fmt.Errorf("statement %d: action %q is not a policy action: %w", i, a, ErrInvalidDocument)
			}
		}
	}
	return nil
}

// Canonical returns the canonical encoding of d: compact JSON with the fields
// of each statement in the order effect, principals, actions, and every list
// in the order given. Nil lists encode as empty lists. Two documents with the
// same statements in the same order have the same canonical form.
func Canonical(d Document) []byte {
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
	out, err := json.Marshal(Document{Statements: statements})
	if err != nil {
		panic(fmt.Sprintf("policy: marshalling canonical document: %v", err))
	}
	return out
}

// ETag returns the strong entity tag of d: the hex SHA-256 of its canonical
// encoding, in double quotes as HTTP carries it.
func ETag(d Document) string {
	sum := sha256.Sum256(Canonical(d))
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

// Effective returns the actions principal p holds under d: the actions of the
// Allow statements naming p or [Wildcard], minus the actions of the Deny
// statements naming p or [Wildcard]. The result is sorted and deduplicated,
// and nil when it is empty or d is nil (a bucket with no policy).
func Effective(d *Document, p string) []string {
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
func Named(d Document) (principals []string, wildcard bool) {
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
// principal either document names, with [Wildcard] expanding to
// tenantPrincipals. The result is sorted and deduplicated.
func Changed(old, new *Document, tenantPrincipals []string) []string {
	candidates := map[string]bool{}
	for _, d := range []*Document{old, new} {
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

// names reports whether st applies to principal p.
func names(st Statement, p string) bool {
	return slices.Contains(st.Principals, p) || slices.Contains(st.Principals, Wildcard)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
