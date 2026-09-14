package bucketpolicy_test

import (
	"encoding/json"
	"testing"

	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/stretchr/testify/require"
)

func allow(principals []string, actions ...string) bucketpolicy.Statement {
	return bucketpolicy.Statement{Effect: bucketpolicy.Allow, Principals: principals, Actions: actions}
}

func deny(principals []string, actions ...string) bucketpolicy.Statement {
	return bucketpolicy.Statement{Effect: bucketpolicy.Deny, Principals: principals, Actions: actions}
}

func doc(statements ...bucketpolicy.Statement) *bucketpolicy.Policy {
	return &bucketpolicy.Policy{Statements: statements}
}

func TestValidate(t *testing.T) {
	known := func(p string) bool { return p == "alice" || p == "bob" }

	valid := []struct {
		name string
		doc  bucketpolicy.Policy
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
			require.NoError(t, bucketpolicy.Validate(tt.doc, known))
		})
	}

	invalid := []struct {
		name string
		doc  bucketpolicy.Policy
		want string
	}{
		{"empty statements", bucketpolicy.Policy{}, "statements must not be empty"},
		{"nil statements slice", bucketpolicy.Policy{Statements: nil}, "statements must not be empty"},
		{"unknown effect", *doc(bucketpolicy.Statement{Effect: "Permit", Principals: []string{"alice"}, Actions: []string{"s3:GetObject"}}), `effect "Permit"`},
		{"lowercase effect", *doc(bucketpolicy.Statement{Effect: "allow", Principals: []string{"alice"}, Actions: []string{"s3:GetObject"}}), `effect "allow"`},
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
			err := bucketpolicy.Validate(tt.doc, known)
			require.ErrorIs(t, err, bucketpolicy.ErrInvalidPolicy)
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
			string(bucketpolicy.Canonical(d)))
	})

	t.Run("is valid JSON that decodes back to the document", func(t *testing.T) {
		d := *doc(allow([]string{"alice"}, "s3:GetObject"), deny([]string{"bob", "*"}, "s3:ListBucket"))
		var back bucketpolicy.Policy
		require.NoError(t, json.Unmarshal(bucketpolicy.Canonical(d), &back))
		require.Equal(t, d, back)
	})

	t.Run("nil and empty lists canonicalize the same", func(t *testing.T) {
		withNil := bucketpolicy.Policy{Statements: nil}
		withEmpty := bucketpolicy.Policy{Statements: []bucketpolicy.Statement{}}
		require.Equal(t, `{"statements":[]}`, string(bucketpolicy.Canonical(withNil)))
		require.Equal(t, bucketpolicy.Canonical(withNil), bucketpolicy.Canonical(withEmpty))

		stNil := *doc(bucketpolicy.Statement{Effect: bucketpolicy.Allow})
		stEmpty := *doc(bucketpolicy.Statement{Effect: bucketpolicy.Allow, Principals: []string{}, Actions: []string{}})
		require.Equal(t, `{"statements":[{"effect":"Allow","principals":[],"actions":[]}]}`, string(bucketpolicy.Canonical(stNil)))
		require.Equal(t, bucketpolicy.Canonical(stNil), bucketpolicy.Canonical(stEmpty))
	})

	t.Run("order is significant", func(t *testing.T) {
		a := *doc(allow([]string{"alice", "bob"}, "s3:GetObject"))
		b := *doc(allow([]string{"bob", "alice"}, "s3:GetObject"))
		require.NotEqual(t, bucketpolicy.Canonical(a), bucketpolicy.Canonical(b))
	})

	t.Run("does not alias the input", func(t *testing.T) {
		d := *doc(allow([]string{"alice"}, "s3:GetObject"))
		first := string(bucketpolicy.Canonical(d))
		d.Statements[0].Actions[0] = "s3:PutObject"
		require.NotEqual(t, first, string(bucketpolicy.Canonical(d)))
	})
}

func TestETag(t *testing.T) {
	d := *doc(allow([]string{"alice"}, "s3:GetObject"))

	t.Run("is a quoted hex sha256 of the canonical form", func(t *testing.T) {
		tag := bucketpolicy.ETag(d)
		require.Len(t, tag, 66) // two quotes + 64 hex characters
		require.Equal(t, byte('"'), tag[0])
		require.Equal(t, byte('"'), tag[len(tag)-1])
		require.Regexp(t, `^"[0-9a-f]{64}"$`, tag)
	})

	t.Run("is stable and changes with the document", func(t *testing.T) {
		require.Equal(t, bucketpolicy.ETag(d), bucketpolicy.ETag(*doc(allow([]string{"alice"}, "s3:GetObject"))))
		require.NotEqual(t, bucketpolicy.ETag(d), bucketpolicy.ETag(*doc(allow([]string{"alice"}, "s3:PutObject"))))
		require.NotEqual(t, bucketpolicy.ETag(d), bucketpolicy.ETag(*doc(allow([]string{"bob"}, "s3:GetObject"))))
		require.NotEqual(t, bucketpolicy.ETag(d), bucketpolicy.ETag(*doc(deny([]string{"alice"}, "s3:GetObject"))))
	})

	t.Run("pins the canonical hashes", func(t *testing.T) {
		// Stored tags are compared against freshly computed ones for If-Match, so
		// these values must never change without a deliberate decision.
		require.Equal(t, `"00ff6f8f85177c9eea82cc033ba1aea2ec68a8f4e6a4f42fb60aa98ab5fe40de"`, bucketpolicy.ETag(bucketpolicy.Policy{}))
		require.Equal(t, `"9b8911d45979c1b6b5d2aa0c27fbea73221f0791e839850539e8cc1821b8c8fa"`, bucketpolicy.ETag(d))
		require.Equal(t, bucketpolicy.ETag(bucketpolicy.Policy{}), bucketpolicy.ETag(bucketpolicy.Policy{Statements: []bucketpolicy.Statement{}}))
	})
}

func TestEffective(t *testing.T) {
	tests := []struct {
		name      string
		doc       *bucketpolicy.Policy
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
		{"a wildcard statement does not grant the wildcard itself", doc(allow([]string{"*"}, "s3:GetObject")), "*", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, bucketpolicy.Effective(tt.doc, tt.principal))
		})
	}
}

func TestNamed(t *testing.T) {
	tests := []struct {
		name         string
		doc          bucketpolicy.Policy
		want         []string
		wantWildcard bool
	}{
		{"empty", bucketpolicy.Policy{}, nil, false},
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
			got, wildcard := bucketpolicy.Named(tt.doc)
			require.Equal(t, tt.want, got)
			require.Equal(t, tt.wantWildcard, wildcard)
		})
	}
}

func TestChanged(t *testing.T) {
	tenant := []string{"alice", "bob", "carol"}
	tests := []struct {
		name       string
		old, new   *bucketpolicy.Policy
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
			require.Equal(t, tt.want, bucketpolicy.Changed(tt.old, tt.new, tt.principals))
		})
	}
}
