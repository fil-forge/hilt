package policy_test

import (
	"encoding/json"
	"testing"

	"github.com/fil-forge/hilt/pkg/policy"
	"github.com/stretchr/testify/require"
)

func allow(principals []string, actions ...string) policy.Statement {
	return policy.Statement{Effect: policy.Allow, Principals: principals, Actions: actions}
}

func deny(principals []string, actions ...string) policy.Statement {
	return policy.Statement{Effect: policy.Deny, Principals: principals, Actions: actions}
}

func doc(statements ...policy.Statement) *policy.Document {
	return &policy.Document{Statements: statements}
}

func TestValidate(t *testing.T) {
	known := func(p string) bool { return p == "alice" || p == "bob" }

	valid := []struct {
		name string
		doc  policy.Document
	}{
		{"one allow", *doc(allow([]string{"alice"}, "s3:GetObject"))},
		{"wildcard is not looked up", *doc(allow([]string{"*"}, "s3:GetObject"))},
		{"deny naming wildcard", *doc(deny([]string{"*"}, "s3:DeleteObject"))},
		{"several statements", *doc(
			allow([]string{"alice", "bob"}, "s3:GetObject", "s3:ListBucket"),
			deny([]string{"bob"}, "s3:ListBucket"),
		)},
		{"bucket-configuration reads", *doc(allow([]string{"alice"}, "s3:GetBucketVersioning", "s3:GetBucketObjectLockConfiguration"))},
		{"multipart actions", *doc(allow([]string{"alice"}, "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts", "s3:ListBucketMultipartUploads"))},
	}
	for _, tt := range valid {
		t.Run("accepts "+tt.name, func(t *testing.T) {
			require.NoError(t, policy.Validate(tt.doc, known))
		})
	}

	invalid := []struct {
		name string
		doc  policy.Document
		want string
	}{
		{"empty statements", policy.Document{}, "statements must not be empty"},
		{"nil statements slice", policy.Document{Statements: nil}, "statements must not be empty"},
		{"unknown effect", *doc(policy.Statement{Effect: "Permit", Principals: []string{"alice"}, Actions: []string{"s3:GetObject"}}), `effect "Permit"`},
		{"lowercase effect", *doc(policy.Statement{Effect: "allow", Principals: []string{"alice"}, Actions: []string{"s3:GetObject"}}), `effect "allow"`},
		{"empty principals", *doc(allow(nil, "s3:GetObject")), "principals must not be empty"},
		{"empty actions", *doc(allow([]string{"alice"})), "actions must not be empty"},
		{"unknown principal", *doc(allow([]string{"alice", "mallory"}, "s3:GetObject")), `unknown principal "mallory"`},
		{"empty principal", *doc(allow([]string{""}, "s3:GetObject")), `unknown principal ""`},
		{"create bucket", *doc(allow([]string{"alice"}, "s3:CreateBucket")), `action "s3:CreateBucket"`},
		{"delete bucket", *doc(allow([]string{"alice"}, "s3:DeleteBucket")), `action "s3:DeleteBucket"`},
		{"list all my buckets", *doc(allow([]string{"alice"}, "s3:ListAllMyBuckets")), `action "s3:ListAllMyBuckets"`},
		{"unknown action", *doc(allow([]string{"alice"}, "s3:Frobnicate")), `action "s3:Frobnicate"`},
		{"invalid action in a later statement", *doc(
			allow([]string{"alice"}, "s3:GetObject"),
			deny([]string{"*"}, "s3:ListAllMyBuckets"),
		), `statement 1: action "s3:ListAllMyBuckets"`},
	}
	for _, tt := range invalid {
		t.Run("rejects "+tt.name, func(t *testing.T) {
			err := policy.Validate(tt.doc, known)
			require.ErrorIs(t, err, policy.ErrInvalidDocument)
			require.ErrorContains(t, err, tt.want)
		})
	}
}

func TestCanonical(t *testing.T) {
	t.Run("compact JSON with fixed field order and input order kept", func(t *testing.T) {
		d := *doc(
			allow([]string{"bob", "alice"}, "s3:PutObject", "s3:GetObject"),
			deny([]string{"*"}, "s3:DeleteObject"),
		)
		require.Equal(t,
			`{"statements":[{"effect":"Allow","principals":["bob","alice"],"actions":["s3:PutObject","s3:GetObject"]},{"effect":"Deny","principals":["*"],"actions":["s3:DeleteObject"]}]}`,
			string(policy.Canonical(d)))
	})

	t.Run("is valid JSON that decodes back to the document", func(t *testing.T) {
		d := *doc(allow([]string{"alice"}, "s3:GetObject"), deny([]string{"bob", "*"}, "s3:ListBucket"))
		var back policy.Document
		require.NoError(t, json.Unmarshal(policy.Canonical(d), &back))
		require.Equal(t, d, back)
	})

	t.Run("nil and empty lists canonicalize the same", func(t *testing.T) {
		withNil := policy.Document{Statements: nil}
		withEmpty := policy.Document{Statements: []policy.Statement{}}
		require.Equal(t, `{"statements":[]}`, string(policy.Canonical(withNil)))
		require.Equal(t, policy.Canonical(withNil), policy.Canonical(withEmpty))

		stNil := *doc(policy.Statement{Effect: policy.Allow})
		stEmpty := *doc(policy.Statement{Effect: policy.Allow, Principals: []string{}, Actions: []string{}})
		require.Equal(t, `{"statements":[{"effect":"Allow","principals":[],"actions":[]}]}`, string(policy.Canonical(stNil)))
		require.Equal(t, policy.Canonical(stNil), policy.Canonical(stEmpty))
	})

	t.Run("order is significant", func(t *testing.T) {
		a := *doc(allow([]string{"alice", "bob"}, "s3:GetObject"))
		b := *doc(allow([]string{"bob", "alice"}, "s3:GetObject"))
		require.NotEqual(t, policy.Canonical(a), policy.Canonical(b))
	})

	t.Run("does not alias the input", func(t *testing.T) {
		d := *doc(allow([]string{"alice"}, "s3:GetObject"))
		first := string(policy.Canonical(d))
		d.Statements[0].Actions[0] = "s3:PutObject"
		require.NotEqual(t, first, string(policy.Canonical(d)))
	})
}

func TestETag(t *testing.T) {
	d := *doc(allow([]string{"alice"}, "s3:GetObject"))

	t.Run("is a quoted hex sha256 of the canonical form", func(t *testing.T) {
		tag := policy.ETag(d)
		require.Len(t, tag, 66) // two quotes + 64 hex characters
		require.Equal(t, byte('"'), tag[0])
		require.Equal(t, byte('"'), tag[len(tag)-1])
		require.Regexp(t, `^"[0-9a-f]{64}"$`, tag)
	})

	t.Run("is stable and changes with the document", func(t *testing.T) {
		require.Equal(t, policy.ETag(d), policy.ETag(*doc(allow([]string{"alice"}, "s3:GetObject"))))
		require.NotEqual(t, policy.ETag(d), policy.ETag(*doc(allow([]string{"alice"}, "s3:PutObject"))))
		require.NotEqual(t, policy.ETag(d), policy.ETag(*doc(allow([]string{"bob"}, "s3:GetObject"))))
		require.NotEqual(t, policy.ETag(d), policy.ETag(*doc(deny([]string{"alice"}, "s3:GetObject"))))
	})

	t.Run("pins the canonical hashes", func(t *testing.T) {
		// Stored tags are compared against freshly computed ones for If-Match, so
		// these values must never change without a deliberate decision.
		require.Equal(t, `"00ff6f8f85177c9eea82cc033ba1aea2ec68a8f4e6a4f42fb60aa98ab5fe40de"`, policy.ETag(policy.Document{}))
		require.Equal(t, `"9b8911d45979c1b6b5d2aa0c27fbea73221f0791e839850539e8cc1821b8c8fa"`, policy.ETag(d))
		require.Equal(t, policy.ETag(policy.Document{}), policy.ETag(policy.Document{Statements: []policy.Statement{}}))
	})
}

func TestEffective(t *testing.T) {
	tests := []struct {
		name      string
		doc       *policy.Document
		principal string
		want      []string
	}{
		{"nil document is nil", nil, "alice", nil},
		{"no statements is nil", doc(), "alice", nil},
		{"allow naming the principal", doc(allow([]string{"alice"}, "s3:GetObject", "s3:ListBucket")), "alice", []string{"s3:GetObject", "s3:ListBucket"}},
		{"allow naming another principal is nil", doc(allow([]string{"alice"}, "s3:GetObject")), "bob", nil},
		{"wildcard allow reaches everyone", doc(allow([]string{"*"}, "s3:GetObject")), "carol", []string{"s3:GetObject"}},
		{"union of allows, sorted and deduplicated", doc(
			allow([]string{"alice"}, "s3:PutObject", "s3:GetObject"),
			allow([]string{"*"}, "s3:GetObject", "s3:ListBucket"),
		), "alice", []string{"s3:GetObject", "s3:ListBucket", "s3:PutObject"}},
		{"deny wins over allow", doc(
			allow([]string{"alice"}, "s3:GetObject", "s3:PutObject"),
			deny([]string{"alice"}, "s3:PutObject"),
		), "alice", []string{"s3:GetObject"}},
		{"wildcard deny wins over a named allow", doc(
			allow([]string{"alice"}, "s3:GetObject", "s3:DeleteObject"),
			deny([]string{"*"}, "s3:DeleteObject"),
		), "alice", []string{"s3:GetObject"}},
		{"named deny wins over a wildcard allow", doc(
			allow([]string{"*"}, "s3:GetObject", "s3:PutObject"),
			deny([]string{"bob"}, "s3:PutObject"),
		), "bob", []string{"s3:GetObject"}},
		{"deny of another principal does not apply", doc(
			allow([]string{"*"}, "s3:GetObject", "s3:PutObject"),
			deny([]string{"bob"}, "s3:PutObject"),
		), "alice", []string{"s3:GetObject", "s3:PutObject"}},
		{"deny everything is nil", doc(
			allow([]string{"alice"}, "s3:GetObject"),
			deny([]string{"*"}, "s3:GetObject"),
		), "alice", nil},
		{"deny alone grants nothing", doc(deny([]string{"alice"}, "s3:GetObject")), "alice", nil},
		{"statement order does not matter", doc(
			deny([]string{"alice"}, "s3:PutObject"),
			allow([]string{"alice"}, "s3:PutObject", "s3:GetObject"),
		), "alice", []string{"s3:GetObject"}},
		{"wildcard is not a principal name", doc(allow([]string{"alice"}, "s3:GetObject")), "*", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, policy.Effective(tt.doc, tt.principal))
		})
	}
}

func TestNamed(t *testing.T) {
	tests := []struct {
		name         string
		doc          policy.Document
		want         []string
		wantWildcard bool
	}{
		{"empty", policy.Document{}, nil, false},
		{"one principal", *doc(allow([]string{"alice"}, "s3:GetObject")), []string{"alice"}, false},
		{"sorted and deduplicated across statements", *doc(
			allow([]string{"carol", "alice"}, "s3:GetObject"),
			deny([]string{"bob", "alice"}, "s3:PutObject"),
		), []string{"alice", "bob", "carol"}, false},
		{"wildcard alone", *doc(allow([]string{"*"}, "s3:GetObject")), nil, true},
		{"wildcard alongside names", *doc(
			allow([]string{"alice", "*"}, "s3:GetObject"),
			deny([]string{"bob"}, "s3:PutObject"),
		), []string{"alice", "bob"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, wildcard := policy.Named(tt.doc)
			require.Equal(t, tt.want, got)
			require.Equal(t, tt.wantWildcard, wildcard)
		})
	}
}

func TestChanged(t *testing.T) {
	tenant := []string{"alice", "bob", "carol"}
	tests := []struct {
		name       string
		old, new   *policy.Document
		principals []string
		want       []string
	}{
		{"nil to nil", nil, nil, tenant, nil},
		{"creating a policy names its principals", nil, doc(allow([]string{"alice", "bob"}, "s3:GetObject")), tenant, []string{"alice", "bob"}},
		{"deleting a policy names its principals", doc(allow([]string{"alice"}, "s3:GetObject")), nil, tenant, []string{"alice"}},
		{"identical documents change nothing", doc(allow([]string{"alice"}, "s3:GetObject")), doc(allow([]string{"alice"}, "s3:GetObject")), tenant, nil},
		{"reordering changes nothing", doc(
			allow([]string{"alice"}, "s3:GetObject", "s3:PutObject"),
		), doc(
			allow([]string{"alice"}, "s3:PutObject", "s3:GetObject"),
		), tenant, nil},
		{"only the principal whose set changed", doc(
			allow([]string{"alice", "bob"}, "s3:GetObject"),
		), doc(
			allow([]string{"alice"}, "s3:GetObject"),
			allow([]string{"bob"}, "s3:GetObject", "s3:PutObject"),
		), tenant, []string{"bob"}},
		{"removing a principal from a statement", doc(
			allow([]string{"alice", "bob"}, "s3:GetObject"),
		), doc(
			allow([]string{"alice"}, "s3:GetObject"),
		), tenant, []string{"bob"}},
		{"wildcard grant fans out to every tenant principal", nil, doc(allow([]string{"*"}, "s3:GetObject")), tenant, tenant},
		{"wildcard removal fans out to every tenant principal", doc(allow([]string{"*"}, "s3:GetObject")), nil, tenant, tenant},
		{"replacing a wildcard with one name changes the others", doc(
			allow([]string{"*"}, "s3:GetObject"),
		), doc(
			allow([]string{"alice"}, "s3:GetObject"),
		), tenant, []string{"bob", "carol"}},
		{"a wildcard deny that changes nothing effective is not a change", doc(
			allow([]string{"alice"}, "s3:GetObject"),
		), doc(
			allow([]string{"alice"}, "s3:GetObject"),
			deny([]string{"*"}, "s3:PutObject"),
		), tenant, nil},
		{"a deny that narrows one principal", doc(
			allow([]string{"*"}, "s3:GetObject", "s3:PutObject"),
		), doc(
			allow([]string{"*"}, "s3:GetObject", "s3:PutObject"),
			deny([]string{"carol"}, "s3:PutObject"),
		), tenant, []string{"carol"}},
		{"a principal named only in a deny with nothing to deny is not a change", nil, doc(deny([]string{"alice"}, "s3:GetObject")), tenant, nil},
		{"a principal outside the tenant list is still evaluated when named", doc(
			allow([]string{"zed"}, "s3:GetObject"),
		), nil, tenant, []string{"zed"}},
		{"no tenant principals limits wildcard fan-out to named ones", nil, doc(allow([]string{"*", "alice"}, "s3:GetObject")), nil, []string{"alice"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, policy.Changed(tt.old, tt.new, tt.principals))
		})
	}
}
