package bucketpolicy_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
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
	t.Run("decodes the documented shape in canonical form", func(t *testing.T) {
		d, err := bucketpolicy.Decode([]byte(`{
			"Statement": [
				{"Sid": "owners", "Effect": "Allow", "Principal": ["bob", "alice"], "Action": ["s3:ListBucket", "s3:GetObject"]},
				{"Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectRetention"]}
			]
		}`))
		require.NoError(t, err)
		// Lists are sets: sorted and deduplicated, statements ordered by their
		// CID (see TestETag for the encoding).
		require.Equal(t, bucketpolicy.Policy{Statements: []bucketpolicy.Statement{
			{Effect: bucketpolicy.Deny, Principal: everyone, Actions: []string{"s3:PutObjectRetention"}},
			{Sid: "owners", Effect: bucketpolicy.Allow, Principal: only("alice", "bob"), Actions: []string{"s3:GetObject", "s3:ListBucket"}},
		}}, d)
	})

	t.Run("keeps each principal and action once, sorted", func(t *testing.T) {
		d, err := bucketpolicy.Decode([]byte(`{"Statement": [{"Effect": "Allow", "Principal": ["bob", "alice", "bob", "alice"], "Action": ["s3:PutObject", "s3:GetObject", "s3:PutObject"]}]}`))
		require.NoError(t, err)
		require.Equal(t, *doc(allow(only("alice", "bob"), "s3:GetObject", "s3:PutObject")), d)
	})

	t.Run("drops a duplicate statement", func(t *testing.T) {
		d, err := bucketpolicy.Decode([]byte(`{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"]}, {"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"]}]}`))
		require.NoError(t, err)
		require.Equal(t, *doc(allow(everyone, "s3:GetObject")), d)
	})

	t.Run("round-trips the canonical form", func(t *testing.T) {
		d := *doc(allow(only("alice"), "s3:GetObject"), deny(everyone, "s3:ListBucket"))
		back, err := bucketpolicy.Decode(bucketpolicy.Canonical(d))
		require.NoError(t, err)
		require.Equal(t, bucketpolicy.Canonical(d), bucketpolicy.Canonical(back))
		require.Equal(t, bucketpolicy.ETag(d), bucketpolicy.ETag(back))
		require.ElementsMatch(t, d.Statements, back.Statements)
	})

	rejects := []struct {
		name string
		body string
		want string
	}{
		{"unknown top-level field", `{"Statement": [], "Version": "2012-10-17"}`, `unknown field "Version"`},
		{"an AWS document with a Version", `{"Version": "2012-10-17", "Statement": [{"Sid": "read", "Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"]}]}`, `unknown field "Version"`},
		{"resource field", `{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"], "Resource": "photos"}]}`, `unknown field "Resource"`},
		{"old field names", `{"statements": [{"effect": "allow", "principals": ["alice"], "actions": ["s3:GetObject"]}]}`, `unknown field "statements"`},
		{"a string principal other than the wildcard", `{"Statement": [{"Effect": "Allow", "Principal": "alice", "Action": ["s3:GetObject"]}]}`, `a string principal must be "*"`},
		{"an object principal", `{"Statement": [{"Effect": "Allow", "Principal": {"filone": ["alice"]}, "Action": ["s3:GetObject"]}]}`, `must be "*" or a list of principal ids`},
		{"trailing data", `{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"]}]} {}`, `trailing data`},
		{"not JSON", `not json`, `decoding policy`},
		{"a lowercase top-level field", `{"statement": []}`, `unknown field "statement"`},
		{"a lowercase statement field", `{"Statement": [{"effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"]}]}`, `unknown field "effect"`},
		{"an upper-case statement field", `{"Statement": [{"Effect": "Allow", "Principal": "*", "ACTION": ["s3:GetObject"]}]}`, `unknown field "ACTION"`},
		{"a null sid", `{"Statement": [{"Sid": null, "Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"]}]}`, `Sid must be a string`},
		// The structure is checked while parsing, so an invalid policy never
		// comes into existence.
		{"empty statements", `{"Statement": []}`, `Statement must not be empty`},
		{"an unknown effect", `{"Statement": [{"Effect": "Permit", "Principal": "*", "Action": ["s3:GetObject"]}]}`, `Effect "Permit"`},
		{"a lowercase effect", `{"Statement": [{"Effect": "allow", "Principal": "*", "Action": ["s3:GetObject"]}]}`, `Effect "allow"`},
		{"an empty principal list", `{"Statement": [{"Effect": "Allow", "Principal": [], "Action": ["s3:GetObject"]}]}`, `Principal must not be empty`},
		{"a missing principal", `{"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"]}]}`, `Principal must not be empty`},
		{"the wildcard inside the principal list", `{"Statement": [{"Effect": "Allow", "Principal": ["alice", "*"], "Action": ["s3:GetObject"]}]}`, `Principal "*" must be the bare string`},
		{"empty actions", `{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": []}]}`, `Action must not be empty`},
		{"a bucket-level action", `{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": ["s3:CreateBucket"]}]}`, `Action "s3:CreateBucket"`},
		{"an unknown action", `{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": ["s3:Frobnicate"]}]}`, `Action "s3:Frobnicate"`},
		{"a bare star action", `{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": ["*"]}]}`, `Action "*"`},
		{"an invalid action in a later statement", `{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"]}, {"Effect": "Deny", "Principal": ["alice"], "Action": ["s3:ListAllMyBuckets"]}]}`, `statement 1: Action "s3:ListAllMyBuckets"`},
	}
	for _, tt := range rejects {
		t.Run("rejects "+tt.name, func(t *testing.T) {
			_, err := bucketpolicy.Decode([]byte(tt.body))
			require.ErrorIs(t, err, bucketpolicy.ErrInvalidPolicy)
			require.ErrorContains(t, err, tt.want)
		})
	}

	t.Run("json.Unmarshal applies the same checks", func(t *testing.T) {
		// The stores read documents back with encoding/json.
		var d bucketpolicy.Policy
		err := json.Unmarshal([]byte(`{"Statement": [{"Effect": "Allow", "Principal": [], "Action": ["s3:GetObject"]}]}`), &d)
		require.ErrorIs(t, err, bucketpolicy.ErrInvalidPolicy)
		require.ErrorContains(t, err, `Principal must not be empty`)

		err = json.Unmarshal([]byte(`{"statement": []}`), &d)
		require.ErrorIs(t, err, bucketpolicy.ErrInvalidPolicy)
		require.ErrorContains(t, err, `unknown field "statement"`)

		require.NoError(t, json.Unmarshal([]byte(`{"Statement": [{"Effect": "Allow", "Principal": ["bob", "alice"], "Action": ["s3:GetObject"]}]}`), &d))
		require.Equal(t, *doc(allow(only("alice", "bob"), "s3:GetObject")), d, "and normalizes")
	})
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
		{"empty statements", bucketpolicy.Policy{}, "Statement must not be empty"},
		{"nil statements slice", bucketpolicy.Policy{Statements: nil}, "Statement must not be empty"},
		{"unknown effect", *doc(bucketpolicy.Statement{Effect: "Permit", Principal: only("alice"), Actions: []string{"s3:GetObject"}}), `Effect "Permit"`},
		{"lowercase effect", *doc(bucketpolicy.Statement{Effect: "allow", Principal: only("alice"), Actions: []string{"s3:GetObject"}}), `Effect "allow"`},
		{"empty principal", *doc(allow(only(), "s3:GetObject")), "Principal must not be empty"},
		{"wildcard inside the principal list", *doc(allow(only("alice", "*"), "s3:GetObject")), `Principal "*" must be the bare string`},
		{"empty actions", *doc(allow(only("alice"))), "Action must not be empty"},
		{"unknown principal", *doc(allow(only("alice", "mallory"), "s3:GetObject")), `unknown principal "mallory"`},
		{"empty principal id", *doc(allow(only(""), "s3:GetObject")), `unknown principal ""`},
		{"create bucket", *doc(allow(only("alice"), "s3:CreateBucket")), `Action "s3:CreateBucket"`},
		{"delete bucket", *doc(allow(only("alice"), "s3:DeleteBucket")), `Action "s3:DeleteBucket"`},
		{"list all my buckets", *doc(allow(only("alice"), "s3:ListAllMyBuckets")), `Action "s3:ListAllMyBuckets"`},
		{"unknown action", *doc(allow(only("alice"), "s3:Frobnicate")), `Action "s3:Frobnicate"`},
		{"a bare star action", *doc(allow(only("alice"), "*")), `Action "*"`},
		{"invalid action in a later statement", *doc(
			allow(only("alice"), "s3:GetObject"),
			deny(everyone, "s3:ListAllMyBuckets"),
		), `statement 1: Action "s3:ListAllMyBuckets"`},
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
	t.Run("compact JSON with fixed field order and every list sorted", func(t *testing.T) {
		d := *doc(
			bucketpolicy.Statement{Sid: "rw", Effect: bucketpolicy.Allow, Principal: only("bob", "alice"), Actions: []string{"s3:PutObject", "s3:GetObject"}},
			deny(everyone, "s3:DeleteObject"),
		)
		// Statements are ordered by their CID: the rw statement's
		// (baguqeerajqbl...) sorts before the deny's (baguqeerawxoz...).
		require.Equal(t,
			`{"Statement":[{"Sid":"rw","Effect":"Allow","Principal":["alice","bob"],"Action":["s3:GetObject","s3:PutObject"]},{"Effect":"Deny","Principal":"*","Action":["s3:DeleteObject"]}]}`,
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
		require.Equal(t, `{"Statement":[]}`, string(bucketpolicy.Canonical(withNil)))
		require.Equal(t, bucketpolicy.Canonical(withNil), bucketpolicy.Canonical(withEmpty))

		stNil := *doc(bucketpolicy.Statement{Effect: bucketpolicy.Allow})
		stEmpty := *doc(bucketpolicy.Statement{Effect: bucketpolicy.Allow, Principal: only(), Actions: []string{}})
		require.Equal(t, `{"Statement":[{"Effect":"Allow","Principal":[],"Action":[]}]}`, string(bucketpolicy.Canonical(stNil)))
		require.Equal(t, bucketpolicy.Canonical(stNil), bucketpolicy.Canonical(stEmpty))
	})

	t.Run("a wildcard principal ignores stray ids", func(t *testing.T) {
		d := *doc(allow(bucketpolicy.Principal{All: true, IDs: []string{"alice"}}, "s3:GetObject"))
		require.Equal(t, `{"Statement":[{"Effect":"Allow","Principal":"*","Action":["s3:GetObject"]}]}`, string(bucketpolicy.Canonical(d)))
	})

	t.Run("order and duplicates are not significant", func(t *testing.T) {
		a := *doc(allow(only("alice", "bob"), "s3:GetObject", "s3:PutObject"), deny(everyone, "s3:DeleteObject"))
		b := *doc(deny(everyone, "s3:DeleteObject"), allow(only("bob", "alice", "bob"), "s3:PutObject", "s3:GetObject", "s3:PutObject"))
		require.Equal(t, bucketpolicy.Canonical(a), bucketpolicy.Canonical(b))
		require.Equal(t, bucketpolicy.ETag(a), bucketpolicy.ETag(b))
	})

	t.Run("does not alias the input", func(t *testing.T) {
		d := *doc(allow(only("alice"), "s3:GetObject"))
		first := string(bucketpolicy.Canonical(d))
		d.Statements[0].Actions[0] = "s3:PutObject"
		require.NotEqual(t, first, string(bucketpolicy.Canonical(d)))
	})
}

// dagJSONCID is the CID the ETag is built from: CIDv1, dag-json, sha2-256
// over raw, which the tests assemble by hand so that the pins do not depend
// on the generated encoder.
func dagJSONCID(t *testing.T, raw string) cid.Cid {
	t.Helper()
	sum, err := mh.Sum([]byte(raw), mh.SHA2_256, -1)
	require.NoError(t, err)
	return cid.NewCidV1(cid.DagJSON, sum)
}

// dagJSONSet is the DAG-JSON encoding of a set: an object whose keys are the
// members, sorted, each mapped to {}.
func dagJSONSet(members ...string) string {
	members = slices.Clone(members)
	slices.Sort(members)
	for i, m := range members {
		members[i] = `"` + m + `":{}`
	}
	return "{" + strings.Join(members, ",") + "}"
}

// dagJSONStatement is the DAG-JSON encoding of a statement: keys in sorted
// order, Sid omitted when empty, principals and actions as sets, the wildcard
// principal as the set {"*"}.
func dagJSONStatement(sid string, effect bucketpolicy.Effect, principals []string, actions []string) string {
	raw := `{"Action":` + dagJSONSet(actions...) + `,"Effect":"` + string(effect) + `","Principal":` + dagJSONSet(principals...)
	if sid != "" {
		raw += `,"Sid":"` + sid + `"`
	}
	return raw + "}"
}

// dagJSONPolicy is the DAG-JSON encoding of a policy: the set of its
// statements' CIDs.
func dagJSONPolicy(t *testing.T, statements ...string) string {
	t.Helper()
	keys := make([]string, len(statements))
	for i, st := range statements {
		keys[i] = dagJSONCID(t, st).String()
	}
	return `{"Statement":` + dagJSONSet(keys...) + `}`
}

func TestETag(t *testing.T) {
	d := *doc(allow(only("alice"), "s3:GetObject"))

	t.Run("is the quoted dag-json CID of the set-encoded document", func(t *testing.T) {
		tag := bucketpolicy.ETag(d)
		require.Regexp(t, `^"bagu[a-z2-7]+"$`, tag)
		c, err := cid.Decode(tag[1 : len(tag)-1])
		require.NoError(t, err)
		require.EqualValues(t, cid.DagJSON, c.Type())
		statement := `{"Action":{"s3:GetObject":{}},"Effect":"Allow","Principal":{"alice":{}}}`
		require.Equal(t, dagJSONCID(t, dagJSONPolicy(t, statement)), c)
	})

	t.Run("encodes a sid, a wildcard principal and several statements", func(t *testing.T) {
		d := *doc(
			bucketpolicy.Statement{Sid: "owners", Effect: bucketpolicy.Allow, Principal: only("bob", "alice"), Actions: []string{"s3:ListBucket", "s3:GetObject"}},
			deny(everyone, "s3:PutObjectRetention"),
		)
		want := dagJSONPolicy(t,
			dagJSONStatement("owners", bucketpolicy.Allow, []string{"alice", "bob"}, []string{"s3:GetObject", "s3:ListBucket"}),
			dagJSONStatement("", bucketpolicy.Deny, []string{"*"}, []string{"s3:PutObjectRetention"}),
		)
		require.Equal(t, `"`+dagJSONCID(t, want).String()+`"`, bucketpolicy.ETag(d))
	})

	t.Run("order and duplicates are not significant", func(t *testing.T) {
		a := *doc(allow(only("alice", "bob"), "s3:GetObject", "s3:PutObject"), deny(everyone, "s3:DeleteObject"))
		b := *doc(
			deny(everyone, "s3:DeleteObject"),
			allow(only("bob", "alice", "bob"), "s3:PutObject", "s3:GetObject", "s3:PutObject"),
			deny(everyone, "s3:DeleteObject"),
		)
		require.Equal(t, bucketpolicy.ETag(a), bucketpolicy.ETag(b))
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
		// these values must never change without a deliberate decision. Both
		// were computed from hand-assembled DAG-JSON bytes:
		// {"Statement":{}} and {"Statement":{"<CID of the statement above>":{}}}.
		require.Equal(t, `"baguqeerav5vnkqj6kdp6fajzf4hl6nrb2yf576axft6oda5i7mcv2hopel2q"`, bucketpolicy.ETag(bucketpolicy.Policy{}))
		require.Equal(t, `"baguqeeraacmqmu4j6omaaq3rchrfho2vytgdruhm35kfdtlihmpkzqcpbixa"`, bucketpolicy.ETag(d))
		require.Equal(t, bucketpolicy.ETag(bucketpolicy.Policy{}), bucketpolicy.ETag(bucketpolicy.Policy{Statements: []bucketpolicy.Statement{}}))
		require.Equal(t, `"`+dagJSONCID(t, `{"Statement":{}}`).String()+`"`, bucketpolicy.ETag(bucketpolicy.Policy{}))
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
