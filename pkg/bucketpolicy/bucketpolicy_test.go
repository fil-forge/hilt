package bucketpolicy_test

import (
	"encoding/json"
	"testing"

	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/stretchr/testify/require"
)

var everyone = bucketpolicy.Everyone()

func only(ids ...string) bucketpolicy.Principal { return bucketpolicy.Only(ids...) }

func allow(p bucketpolicy.Principal, actions ...string) bucketpolicy.Statement {
	return bucketpolicy.Statement{Effect: bucketpolicy.Allow, Principal: p, Actions: actions}
}

func deny(p bucketpolicy.Principal, actions ...string) bucketpolicy.Statement {
	return bucketpolicy.Statement{Effect: bucketpolicy.Deny, Principal: p, Actions: actions}
}

func doc(statements ...bucketpolicy.Statement) *bucketpolicy.Policy {
	return &bucketpolicy.Policy{Statements: statements}
}

func TestDecode(t *testing.T) {
	t.Run("decodes the documented shape", func(t *testing.T) {
		d, err := bucketpolicy.Decode([]byte(`{
			"statement": [
				{"sid": "owners", "effect": "allow", "principal": ["alice", "bob"], "action": ["s3:GetObject", "s3:ListBucket"]},
				{"effect": "deny", "principal": "*", "action": ["s3:PutObjectRetention"]}
			]
		}`))
		require.NoError(t, err)
		require.Equal(t, bucketpolicy.Policy{Statements: []bucketpolicy.Statement{
			{Sid: "owners", Effect: bucketpolicy.Allow, Principal: only("alice", "bob"), Actions: []string{"s3:GetObject", "s3:ListBucket"}},
			{Effect: bucketpolicy.Deny, Principal: everyone, Actions: []string{"s3:PutObjectRetention"}},
		}}, d)
	})

	t.Run("round-trips the canonical form", func(t *testing.T) {
		d := *doc(allow(only("alice"), "s3:GetObject"), deny(everyone, "s3:ListBucket"))
		back, err := bucketpolicy.Decode(bucketpolicy.Canonical(d))
		require.NoError(t, err)
		require.Equal(t, d, back)
	})

	rejects := []struct {
		name string
		body string
		want string
	}{
		{"unknown top-level field", `{"statement": [], "version": "2012-10-17"}`, `unknown field "version"`},
		{"resource field", `{"statement": [{"effect": "allow", "principal": "*", "action": ["s3:GetObject"], "resource": "photos"}]}`, `unknown field "resource"`},
		{"old field names", `{"statements": [{"effect": "allow", "principals": ["alice"], "actions": ["s3:GetObject"]}]}`, `unknown field "statements"`},
		{"a string principal other than the wildcard", `{"statement": [{"effect": "allow", "principal": "alice", "action": ["s3:GetObject"]}]}`, `a string principal must be "*"`},
		{"an object principal", `{"statement": [{"effect": "allow", "principal": {"filone": ["alice"]}, "action": ["s3:GetObject"]}]}`, `must be "*" or a list of principal ids`},
		{"trailing data", `{"statement": []} {}`, `trailing data`},
		{"not JSON", `not json`, `decoding policy`},
		{"a capitalized top-level field", `{"Statement": []}`, `unknown field "Statement"`},
		{"a capitalized statement field", `{"statement": [{"Effect": "allow", "principal": "*", "action": ["s3:GetObject"]}]}`, `unknown field "Effect"`},
		{"an upper-case statement field", `{"statement": [{"effect": "allow", "principal": "*", "ACTION": ["s3:GetObject"]}]}`, `unknown field "ACTION"`},
	}
	for _, tt := range rejects {
		t.Run("rejects "+tt.name, func(t *testing.T) {
			_, err := bucketpolicy.Decode([]byte(tt.body))
			require.ErrorIs(t, err, bucketpolicy.ErrInvalidPolicy)
			require.ErrorContains(t, err, tt.want)
		})
	}
}

func TestValidate(t *testing.T) {
	known := func(p string) bool { return p == "alice" || p == "bob" }

	valid := []struct {
		name string
		doc  bucketpolicy.Policy
	}{
		{"one allow", *doc(allow(only("alice"), "s3:GetObject"))},
		{"wildcard is not looked up", *doc(allow(everyone, "s3:GetObject"))},
		{"deny naming wildcard", *doc(deny(everyone, "s3:DeleteObject"))},
		{"several statements", *doc(
			allow(only("alice", "bob"), "s3:GetObject", "s3:ListBucket"),
			deny(only("bob"), "s3:ListBucket"),
		)},
		{"a sid", *doc(bucketpolicy.Statement{Sid: "owners", Effect: bucketpolicy.Allow, Principal: only("alice"), Actions: []string{"s3:GetObject"}})},
		{"the action wildcard", *doc(allow(only("alice"), s3perm.PolicyWildcard))},
		{"the action wildcard beside named actions", *doc(deny(everyone, "s3:PutObjectRetention"), allow(only("alice"), "s3:GetObject", s3perm.PolicyWildcard))},
		{"versioned object reads", *doc(allow(only("alice"), "s3:GetObjectVersion", "s3:ListBucketVersions"))},
		{"multipart actions", *doc(allow(only("alice"), "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts", "s3:ListBucketMultipartUploads"))},
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
		{"empty statements", bucketpolicy.Policy{}, "statement must not be empty"},
		{"nil statements slice", bucketpolicy.Policy{Statements: nil}, "statement must not be empty"},
		{"unknown effect", *doc(bucketpolicy.Statement{Effect: "Permit", Principal: only("alice"), Actions: []string{"s3:GetObject"}}), `effect "Permit"`},
		{"capitalized effect", *doc(bucketpolicy.Statement{Effect: "Allow", Principal: only("alice"), Actions: []string{"s3:GetObject"}}), `effect "Allow"`},
		{"empty principal", *doc(allow(only(), "s3:GetObject")), "principal must not be empty"},
		{"wildcard inside the principal list", *doc(allow(only("alice", "*"), "s3:GetObject")), `principal "*" must be the bare string`},
		{"empty actions", *doc(allow(only("alice"))), "action must not be empty"},
		{"unknown principal", *doc(allow(only("alice", "mallory"), "s3:GetObject")), `unknown principal "mallory"`},
		{"empty principal id", *doc(allow(only(""), "s3:GetObject")), `unknown principal ""`},
		{"create bucket", *doc(allow(only("alice"), "s3:CreateBucket")), `action "s3:CreateBucket"`},
		{"delete bucket", *doc(allow(only("alice"), "s3:DeleteBucket")), `action "s3:DeleteBucket"`},
		{"list all my buckets", *doc(allow(only("alice"), "s3:ListAllMyBuckets")), `action "s3:ListAllMyBuckets"`},
		{"unknown action", *doc(allow(only("alice"), "s3:Frobnicate")), `action "s3:Frobnicate"`},
		{"a bare star action", *doc(allow(only("alice"), "*")), `action "*"`},
		{"invalid action in a later statement", *doc(
			allow(only("alice"), "s3:GetObject"),
			deny(everyone, "s3:ListAllMyBuckets"),
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
			bucketpolicy.Statement{Sid: "rw", Effect: bucketpolicy.Allow, Principal: only("bob", "alice"), Actions: []string{"s3:PutObject", "s3:GetObject"}},
			deny(everyone, "s3:DeleteObject"),
		)
		require.Equal(t,
			`{"statement":[{"sid":"rw","effect":"allow","principal":["bob","alice"],"action":["s3:PutObject","s3:GetObject"]},{"effect":"deny","principal":"*","action":["s3:DeleteObject"]}]}`,
			string(bucketpolicy.Canonical(d)))
	})

	t.Run("is valid JSON that decodes back to the document", func(t *testing.T) {
		d := *doc(allow(only("alice"), "s3:GetObject"), deny(only("bob"), "s3:ListBucket"))
		var back bucketpolicy.Policy
		require.NoError(t, json.Unmarshal(bucketpolicy.Canonical(d), &back))
		require.Equal(t, d, back)
	})

	t.Run("nil and empty lists canonicalize the same", func(t *testing.T) {
		withNil := bucketpolicy.Policy{Statements: nil}
		withEmpty := bucketpolicy.Policy{Statements: []bucketpolicy.Statement{}}
		require.Equal(t, `{"statement":[]}`, string(bucketpolicy.Canonical(withNil)))
		require.Equal(t, bucketpolicy.Canonical(withNil), bucketpolicy.Canonical(withEmpty))

		stNil := *doc(bucketpolicy.Statement{Effect: bucketpolicy.Allow})
		stEmpty := *doc(bucketpolicy.Statement{Effect: bucketpolicy.Allow, Principal: only(), Actions: []string{}})
		require.Equal(t, `{"statement":[{"effect":"allow","principal":[],"action":[]}]}`, string(bucketpolicy.Canonical(stNil)))
		require.Equal(t, bucketpolicy.Canonical(stNil), bucketpolicy.Canonical(stEmpty))
	})

	t.Run("a wildcard principal ignores stray ids", func(t *testing.T) {
		d := *doc(allow(bucketpolicy.Principal{All: true, IDs: []string{"alice"}}, "s3:GetObject"))
		require.Equal(t, `{"statement":[{"effect":"allow","principal":"*","action":["s3:GetObject"]}]}`, string(bucketpolicy.Canonical(d)))
	})

	t.Run("order is significant", func(t *testing.T) {
		a := *doc(allow(only("alice", "bob"), "s3:GetObject"))
		b := *doc(allow(only("bob", "alice"), "s3:GetObject"))
		require.NotEqual(t, bucketpolicy.Canonical(a), bucketpolicy.Canonical(b))
	})

	t.Run("does not alias the input", func(t *testing.T) {
		d := *doc(allow(only("alice"), "s3:GetObject"))
		first := string(bucketpolicy.Canonical(d))
		d.Statements[0].Actions[0] = "s3:PutObject"
		require.NotEqual(t, first, string(bucketpolicy.Canonical(d)))
	})
}

func TestETag(t *testing.T) {
	d := *doc(allow(only("alice"), "s3:GetObject"))

	t.Run("is a quoted hex sha256 of the canonical form", func(t *testing.T) {
		tag := bucketpolicy.ETag(d)
		require.Len(t, tag, 66) // two quotes + 64 hex characters
		require.Regexp(t, `^"[0-9a-f]{64}"$`, tag)
	})

	t.Run("is stable and changes with the document", func(t *testing.T) {
		require.Equal(t, bucketpolicy.ETag(d), bucketpolicy.ETag(*doc(allow(only("alice"), "s3:GetObject"))))
		require.NotEqual(t, bucketpolicy.ETag(d), bucketpolicy.ETag(*doc(allow(only("alice"), "s3:PutObject"))))
		require.NotEqual(t, bucketpolicy.ETag(d), bucketpolicy.ETag(*doc(allow(only("bob"), "s3:GetObject"))))
		require.NotEqual(t, bucketpolicy.ETag(d), bucketpolicy.ETag(*doc(deny(only("alice"), "s3:GetObject"))))
		withSid := *doc(bucketpolicy.Statement{Sid: "read", Effect: bucketpolicy.Allow, Principal: only("alice"), Actions: []string{"s3:GetObject"}})
		require.NotEqual(t, bucketpolicy.ETag(d), bucketpolicy.ETag(withSid))
	})

	t.Run("pins the canonical hashes", func(t *testing.T) {
		// Stored tags are compared against freshly computed ones for If-Match, so
		// these values must never change without a deliberate decision.
		require.Equal(t, `"6aad9d356389c27aa54b4ed7e706c3ba31b53c9f25d1e656a0b01bf7a5f1f35a"`, bucketpolicy.ETag(bucketpolicy.Policy{}))
		require.Equal(t, `"8c99a1df6101e5df5153b0250526e23ab18d3ae6f0a85e728476930a5dab7d3e"`, bucketpolicy.ETag(d))
		require.Equal(t, bucketpolicy.ETag(bucketpolicy.Policy{}), bucketpolicy.ETag(bucketpolicy.Policy{Statements: []bucketpolicy.Statement{}}))
	})
}

func TestEffective(t *testing.T) {
	all := s3perm.PolicyActions()
	require.NotContains(t, all, "s3:CreateBucket")
	require.NotContains(t, all, "s3:DeleteBucket")
	require.NotContains(t, all, "s3:ListAllMyBuckets")
	var allButRetention []string
	for _, a := range all {
		if a != "s3:PutObjectRetention" && a != "s3:PutObjectLegalHold" {
			allButRetention = append(allButRetention, a)
		}
	}
	tests := []struct {
		name      string
		doc       *bucketpolicy.Policy
		principal string
		want      []string
	}{
		{"nil document is nil", nil, "alice", nil},
		{"no statements is nil", doc(), "alice", nil},
		{"allow naming the principal", doc(allow(only("alice"), "s3:GetObject", "s3:ListBucket")), "alice", []string{"s3:GetObject", "s3:ListBucket"}},
		{"allow naming another principal is nil", doc(allow(only("alice"), "s3:GetObject")), "bob", nil},
		{"wildcard allow reaches everyone", doc(allow(everyone, "s3:GetObject")), "carol", []string{"s3:GetObject"}},
		{"union of allows, sorted and deduplicated", doc(
			allow(only("alice"), "s3:PutObject", "s3:GetObject"),
			allow(everyone, "s3:GetObject", "s3:ListBucket"),
		), "alice", []string{"s3:GetObject", "s3:ListBucket", "s3:PutObject"}},
		{"deny wins over allow", doc(
			allow(only("alice"), "s3:GetObject", "s3:PutObject"),
			deny(only("alice"), "s3:PutObject"),
		), "alice", []string{"s3:GetObject"}},
		{"wildcard deny wins over a named allow", doc(
			allow(only("alice"), "s3:GetObject", "s3:DeleteObject"),
			deny(everyone, "s3:DeleteObject"),
		), "alice", []string{"s3:GetObject"}},
		{"named deny wins over a wildcard allow", doc(
			allow(everyone, "s3:GetObject", "s3:PutObject"),
			deny(only("bob"), "s3:PutObject"),
		), "bob", []string{"s3:GetObject"}},
		{"deny of another principal does not apply", doc(
			allow(everyone, "s3:GetObject", "s3:PutObject"),
			deny(only("bob"), "s3:PutObject"),
		), "alice", []string{"s3:GetObject", "s3:PutObject"}},
		{"deny everything is nil", doc(
			allow(only("alice"), "s3:GetObject"),
			deny(everyone, "s3:GetObject"),
		), "alice", nil},
		{"deny alone grants nothing", doc(deny(only("alice"), "s3:GetObject")), "alice", nil},
		{"statement order does not matter", doc(
			deny(only("alice"), "s3:PutObject"),
			allow(only("alice"), "s3:PutObject", "s3:GetObject"),
		), "alice", []string{"s3:GetObject"}},
		{"the action wildcard grants every policy action", doc(allow(only("alice"), s3perm.PolicyWildcard)), "alice", all},
		{"a named deny narrows the action wildcard", doc(
			allow(only("alice"), s3perm.PolicyWildcard),
			deny(everyone, "s3:PutObjectRetention", "s3:PutObjectLegalHold"),
		), "alice", allButRetention},
		{"a wildcard deny denies everything", doc(
			allow(only("alice"), "s3:GetObject", "s3:PutObject"),
			deny(only("alice"), s3perm.PolicyWildcard),
		), "alice", nil},
		{"wildcard is not a principal name", doc(allow(only("alice"), "s3:GetObject")), "*", nil},
		{"a wildcard statement does not grant the wildcard itself", doc(allow(everyone, "s3:GetObject")), "*", nil},
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
		{"one principal", *doc(allow(only("alice"), "s3:GetObject")), []string{"alice"}, false},
		{"sorted and deduplicated across statements", *doc(
			allow(only("carol", "alice"), "s3:GetObject"),
			deny(only("bob", "alice"), "s3:PutObject"),
		), []string{"alice", "bob", "carol"}, false},
		{"wildcard alone", *doc(allow(everyone, "s3:GetObject")), nil, true},
		{"wildcard alongside names", *doc(
			allow(everyone, "s3:GetObject"),
			deny(only("bob"), "s3:PutObject"),
		), []string{"bob"}, true},
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
		{"creating a policy names its principals", nil, doc(allow(only("alice", "bob"), "s3:GetObject")), tenant, []string{"alice", "bob"}},
		{"deleting a policy names its principals", doc(allow(only("alice"), "s3:GetObject")), nil, tenant, []string{"alice"}},
		{"identical documents change nothing", doc(allow(only("alice"), "s3:GetObject")), doc(allow(only("alice"), "s3:GetObject")), tenant, nil},
		{"a sid changes nothing", doc(allow(only("alice"), "s3:GetObject")), doc(bucketpolicy.Statement{Sid: "read", Effect: bucketpolicy.Allow, Principal: only("alice"), Actions: []string{"s3:GetObject"}}), tenant, nil},
		{"reordering changes nothing", doc(
			allow(only("alice"), "s3:GetObject", "s3:PutObject"),
		), doc(
			allow(only("alice"), "s3:PutObject", "s3:GetObject"),
		), tenant, nil},
		{"spelling out the wildcard changes nothing", doc(allow(only("alice"), s3perm.PolicyWildcard)), doc(allow(only("alice"), s3perm.PolicyActions()...)), tenant, nil},
		{"only the principal whose set changed", doc(
			allow(only("alice", "bob"), "s3:GetObject"),
		), doc(
			allow(only("alice"), "s3:GetObject"),
			allow(only("bob"), "s3:GetObject", "s3:PutObject"),
		), tenant, []string{"bob"}},
		{"removing a principal from a statement", doc(
			allow(only("alice", "bob"), "s3:GetObject"),
		), doc(
			allow(only("alice"), "s3:GetObject"),
		), tenant, []string{"bob"}},
		{"wildcard grant fans out to every tenant principal", nil, doc(allow(everyone, "s3:GetObject")), tenant, tenant},
		{"wildcard removal fans out to every tenant principal", doc(allow(everyone, "s3:GetObject")), nil, tenant, tenant},
		{"replacing a wildcard with one name changes the others", doc(
			allow(everyone, "s3:GetObject"),
		), doc(
			allow(only("alice"), "s3:GetObject"),
		), tenant, []string{"bob", "carol"}},
		{"a wildcard deny that changes nothing effective is not a change", doc(
			allow(only("alice"), "s3:GetObject"),
		), doc(
			allow(only("alice"), "s3:GetObject"),
			deny(everyone, "s3:PutObject"),
		), tenant, nil},
		{"a deny that narrows one principal", doc(
			allow(everyone, "s3:GetObject", "s3:PutObject"),
		), doc(
			allow(everyone, "s3:GetObject", "s3:PutObject"),
			deny(only("carol"), "s3:PutObject"),
		), tenant, []string{"carol"}},
		{"a principal named only in a deny with nothing to deny is not a change", nil, doc(deny(only("alice"), "s3:GetObject")), tenant, nil},
		{"a principal outside the tenant list is still evaluated when named", doc(
			allow(only("zed"), "s3:GetObject"),
		), nil, tenant, []string{"zed"}},
		{"no tenant principals limits wildcard fan-out to named ones", nil, doc(allow(everyone, "s3:GetObject"), allow(only("alice"), "s3:PutObject")), nil, []string{"alice"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, bucketpolicy.Changed(tt.old, tt.new, tt.principals))
		})
	}
}
