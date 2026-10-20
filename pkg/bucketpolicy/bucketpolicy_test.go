package bucketpolicy_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/stretchr/testify/require"
)

var everyone = s3bkt.Everyone()

func only(ids ...string) s3bkt.Principal { return s3bkt.Only(ids...) }

const (
	bucketARN  = "arn:aws:s3:::photos"
	objectsARN = "arn:aws:s3:::photos/*"
)

// both is the resource list every helper statement carries, which covers
// every policy action.
func both() s3bkt.StringSet { return s3bkt.NewStringSet(bucketARN, objectsARN) }

func allow(p s3bkt.Principal, actions ...string) s3bkt.Statement {
	return s3bkt.Statement{Effect: s3bkt.Allow, Principal: p, Actions: s3bkt.NewStringSet(actions...), Resources: both()}
}

func deny(p s3bkt.Principal, actions ...string) s3bkt.Statement {
	return s3bkt.Statement{Effect: s3bkt.Deny, Principal: p, Actions: s3bkt.NewStringSet(actions...), Resources: both()}
}

func doc(statements ...s3bkt.Statement) *s3bkt.PolicyDocument {
	return &s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: statements}
}

// policyJSON wraps statements, given as JSON, in a 2012-10-17 document.
func policyJSON(statements ...string) string {
	return `{"Version": "2012-10-17", "Statement": [` + strings.Join(statements, ",") + `]}`
}

// res is the Resource member covering every policy action on photos.
const res = `"Resource": ["arn:aws:s3:::photos", "arn:aws:s3:::photos/*"]`

func TestDecode(t *testing.T) {
	t.Run("decodes the documented shape in canonical form", func(t *testing.T) {
		d, err := bucketpolicy.Decode([]byte(policyJSON(
			`{"Sid": "owners", "Effect": "Allow", "Principal": {"AWS": ["arn:aws:iam:::user/bob", "arn:aws:iam:::user/alice"]}, "Action": ["s3:ListBucket", "s3:GetObject"], `+res+`}`,
			`{"Effect": "Deny", "Principal": "*", "Action": ["s3:PutObjectRetention"], "Resource": ["arn:aws:s3:::photos/*"]}`,
		)))
		require.NoError(t, err)
		// The lists are sets; the statements keep the document's order in
		// memory and come out in CID order (see TestCanonical).
		require.Equal(t, s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: []s3bkt.Statement{
			{Sid: "owners", Effect: s3bkt.Allow, Principal: only("alice", "bob"), Actions: s3bkt.NewStringSet("s3:GetObject", "s3:ListBucket"), Resources: both()},
			{Effect: s3bkt.Deny, Principal: everyone, Actions: s3bkt.NewStringSet("s3:PutObjectRetention"), Resources: s3bkt.NewStringSet(objectsARN)},
		}}, d)
	})

	principals := []struct {
		name string
		json string
		want s3bkt.Principal
	}{
		{"the bare wildcard", `"*"`, everyone},
		{"the AWS wildcard", `{"AWS": "*"}`, everyone},
		{"one user ARN", `{"AWS": "arn:aws:iam:::user/alice"}`, only("alice")},
		{"a list of user ARNs", `{"AWS": ["arn:aws:iam:::user/bob", "arn:aws:iam:::user/alice"]}`, only("alice", "bob")},
	}
	for _, tt := range principals {
		t.Run("accepts "+tt.name+" as the principal", func(t *testing.T) {
			d, err := bucketpolicy.Decode([]byte(policyJSON(`{"Effect": "Allow", "Principal": ` + tt.json + `, "Action": "s3:GetObject", "Resource": "arn:aws:s3:::photos/*"}`)))
			require.NoError(t, err)
			require.Equal(t, tt.want, d.Statements[0].Principal)
		})
	}

	t.Run("accepts Action and Resource as a string or a list", func(t *testing.T) {
		asStrings, err := bucketpolicy.Decode([]byte(policyJSON(`{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::photos/*"}`)))
		require.NoError(t, err)
		asLists, err := bucketpolicy.Decode([]byte(policyJSON(`{"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::photos/*"]}`)))
		require.NoError(t, err)
		require.Equal(t, asLists, asStrings)
		require.Equal(t, s3bkt.NewStringSet("s3:GetObject"), asStrings.Statements[0].Actions)
		require.Equal(t, s3bkt.NewStringSet(objectsARN), asStrings.Statements[0].Resources)
	})

	t.Run("accepts the 2008-10-17 version and keeps it", func(t *testing.T) {
		d, err := bucketpolicy.Decode([]byte(`{"Version": "2008-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::photos/*"}]}`))
		require.NoError(t, err)
		require.Equal(t, s3bkt.Version2008, d.Version)
	})

	t.Run("keeps each principal, action and resource once, sorted", func(t *testing.T) {
		d, err := bucketpolicy.Decode([]byte(policyJSON(`{"Effect": "Allow", "Principal": {"AWS": ["arn:aws:iam:::user/bob", "arn:aws:iam:::user/alice", "arn:aws:iam:::user/bob"]}, "Action": ["s3:PutObject", "s3:GetObject", "s3:PutObject"], "Resource": ["arn:aws:s3:::photos/*", "arn:aws:s3:::photos", "arn:aws:s3:::photos/*"]}`)))
		require.NoError(t, err)
		require.Equal(t, *doc(allow(only("alice", "bob"), "s3:GetObject", "s3:PutObject")), d)
	})

	t.Run("a duplicate statement is dropped on the way out", func(t *testing.T) {
		st := `{"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"], ` + res + `}`
		d, err := bucketpolicy.Decode([]byte(policyJSON(st, st)))
		require.NoError(t, err)
		require.Len(t, d.Statements, 2)
		require.Equal(t, bucketpolicy.Canonical(*doc(allow(everyone, "s3:GetObject"))), bucketpolicy.Canonical(d))
		require.Equal(t, s3bkt.ETag(*doc(allow(everyone, "s3:GetObject"))), s3bkt.ETag(d))
	})

	t.Run("round-trips the canonical form", func(t *testing.T) {
		d := *doc(allow(only("alice"), "s3:GetObject"), deny(everyone, "s3:ListBucket"))
		back, err := bucketpolicy.Decode(bucketpolicy.Canonical(d))
		require.NoError(t, err)
		require.Equal(t, bucketpolicy.Canonical(d), bucketpolicy.Canonical(back))
		require.Equal(t, s3bkt.ETag(d), s3bkt.ETag(back))
		require.ElementsMatch(t, d.Statements, back.Statements)
	})

	rejects := []struct {
		name string
		body string
		want string
	}{
		{"a missing version", `{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"], ` + res + `}]}`, `Version "" must be`},
		{"an unknown version", `{"Version": "2024-01-01", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"], ` + res + `}]}`, `Version "2024-01-01" must be`},
		{"unknown top-level field", `{"Version": "2012-10-17", "Statement": [], "Id": "x"}`, `unknown field "Id"`},
		{"a condition", policyJSON(`{"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"], ` + res + `, "Condition": {}}`), `unknown field "Condition"`},
		{"a not-principal", policyJSON(`{"Effect": "Deny", "NotPrincipal": "*", "Action": ["s3:GetObject"], ` + res + `}`), `unknown field "NotPrincipal"`},
		{"old field names", `{"statements": [{"effect": "allow", "principals": ["alice"], "actions": ["s3:GetObject"]}]}`, `unknown field "statements"`},
		{"a string principal other than the wildcard", policyJSON(`{"Effect": "Allow", "Principal": "alice", "Action": ["s3:GetObject"], ` + res + `}`), `a string principal must be "*"`},
		{"a bare id list principal", policyJSON(`{"Effect": "Allow", "Principal": ["alice"], "Action": ["s3:GetObject"], ` + res + `}`), `must be "*" or {"AWS": user ARNs}`},
		{"an ARN with an account", policyJSON(`{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:user/alice"}, "Action": ["s3:GetObject"], ` + res + `}`), `must be a user ARN`},
		{"a bare id inside AWS", policyJSON(`{"Effect": "Allow", "Principal": {"AWS": ["alice"]}, "Action": ["s3:GetObject"], ` + res + `}`), `must be a user ARN`},
		{"a user ARN without an id", policyJSON(`{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam:::user/"}, "Action": ["s3:GetObject"], ` + res + `}`), `must be a user ARN`},
		{"a role ARN", policyJSON(`{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam:::role/alice"}, "Action": ["s3:GetObject"], ` + res + `}`), `must be a user ARN`},
		{"a principal key other than AWS", policyJSON(`{"Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"}, "Action": ["s3:GetObject"], ` + res + `}`), `unknown key "Service"`},
		{"a lowercase AWS key", policyJSON(`{"Effect": "Allow", "Principal": {"aws": "*"}, "Action": ["s3:GetObject"], ` + res + `}`), `unknown key "aws"`},
		{"AWS beside another key", policyJSON(`{"Effect": "Allow", "Principal": {"AWS": "*", "Federated": "x"}, "Action": ["s3:GetObject"], ` + res + `}`), `unknown key "Federated"`},
		{"an empty principal object", policyJSON(`{"Effect": "Allow", "Principal": {}, "Action": ["s3:GetObject"], ` + res + `}`), `must be "*" or {"AWS": user ARNs}`},
		{"the wildcard inside the AWS list", policyJSON(`{"Effect": "Allow", "Principal": {"AWS": ["arn:aws:iam:::user/alice", "*"]}, "Action": ["s3:GetObject"], ` + res + `}`), `not a list entry`},
		{"trailing data", policyJSON(`{"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"], `+res+`}`) + ` {}`, `trailing data`},
		{"not JSON", `not json`, `decoding policy`},
		{"a lowercase top-level field", `{"Version": "2012-10-17", "statement": []}`, `unknown field "statement"`},
		{"a lowercase version field", `{"version": "2012-10-17", "Statement": []}`, `unknown field "version"`},
		{"a lowercase statement field", policyJSON(`{"effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"], ` + res + `}`), `unknown field "effect"`},
		{"an upper-case statement field", policyJSON(`{"Effect": "Allow", "Principal": "*", "ACTION": ["s3:GetObject"], ` + res + `}`), `unknown field "ACTION"`},
		{"a lowercase resource field", policyJSON(`{"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"], "resource": "arn:aws:s3:::photos/*"}`), `unknown field "resource"`},
		{"a null sid", policyJSON(`{"Sid": null, "Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"], ` + res + `}`), `Sid must be a string`},
		{"an action that is neither string nor list", policyJSON(`{"Effect": "Allow", "Principal": "*", "Action": 7, ` + res + `}`), `must be a string or a list of strings`},
		// The structure is checked while parsing, so an invalid policy never
		// comes into existence.
		{"empty statements", `{"Version": "2012-10-17", "Statement": []}`, `Statement must not be empty`},
		{"an unknown effect", policyJSON(`{"Effect": "Permit", "Principal": "*", "Action": ["s3:GetObject"], ` + res + `}`), `Effect "Permit"`},
		{"a lowercase effect", policyJSON(`{"Effect": "allow", "Principal": "*", "Action": ["s3:GetObject"], ` + res + `}`), `Effect "allow"`},
		{"an empty principal list", policyJSON(`{"Effect": "Allow", "Principal": {"AWS": []}, "Action": ["s3:GetObject"], ` + res + `}`), `Principal must not be empty`},
		{"a missing principal", policyJSON(`{"Effect": "Allow", "Action": ["s3:GetObject"], ` + res + `}`), `Principal must not be empty`},
		{"empty actions", policyJSON(`{"Effect": "Allow", "Principal": "*", "Action": [], ` + res + `}`), `Action must not be empty`},
		{"a bucket-level action", policyJSON(`{"Effect": "Allow", "Principal": "*", "Action": ["s3:CreateBucket"], ` + res + `}`), `Action "s3:CreateBucket"`},
		{"an unknown action", policyJSON(`{"Effect": "Allow", "Principal": "*", "Action": ["s3:Frobnicate"], ` + res + `}`), `Action "s3:Frobnicate"`},
		{"a bare star action", policyJSON(`{"Effect": "Allow", "Principal": "*", "Action": ["*"], ` + res + `}`), `Action "*"`},
		{"an invalid action in a later statement", policyJSON(
			`{"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"], `+res+`}`,
			`{"Effect": "Deny", "Principal": {"AWS": "arn:aws:iam:::user/alice"}, "Action": ["s3:ListAllMyBuckets"], `+res+`}`,
		), `statement 1: Action "s3:ListAllMyBuckets"`},
		{"a missing resource", policyJSON(`{"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"]}`), `Resource must not be empty`},
		{"an empty resource list", policyJSON(`{"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"], "Resource": []}`), `Resource must not be empty`},
		{"a resource that is not an S3 ARN", policyJSON(`{"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"], "Resource": "photos"}`), `Resource "photos" must be`},
		{"a key-prefix resource", policyJSON(`{"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::photos/2024/*"}`), `Resource "arn:aws:s3:::photos/2024/*" must be`},
		{"a single-object resource", policyJSON(`{"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::photos/cat.jpg"}`), `must be`},
		{"a wildcard bucket", policyJSON(`{"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::*/*"}`), `must be`},
		{"an empty bucket", policyJSON(`{"Effect": "Allow", "Principal": "*", "Action": ["s3:ListBucket"], "Resource": "arn:aws:s3:::"}`), `must be`},
		{"resources naming two buckets", policyJSON(`{"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::photos/*", "arn:aws:s3:::videos/*"]}`), `names bucket "videos", the policy names "photos"`},
		{"statements naming two buckets", policyJSON(
			`{"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::photos/*"}`,
			`{"Effect": "Allow", "Principal": "*", "Action": ["s3:ListBucket"], "Resource": "arn:aws:s3:::videos"}`,
		), `statement 1: Resource "arn:aws:s3:::videos" names bucket "videos"`},
		{"an object action on the bucket ARN", policyJSON(`{"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::photos"}`), `Action "s3:GetObject" needs Resource "arn:aws:s3:::photos/*"`},
		{"a bucket action on the objects ARN", policyJSON(`{"Effect": "Allow", "Principal": "*", "Action": ["s3:ListBucket"], "Resource": "arn:aws:s3:::photos/*"}`), `Action "s3:ListBucket" needs Resource "arn:aws:s3:::photos"`},
		{"the action wildcard on the objects ARN alone", policyJSON(`{"Effect": "Allow", "Principal": "*", "Action": "s3:*", "Resource": "arn:aws:s3:::photos/*"}`), `Action "s3:*" needs Resource "arn:aws:s3:::photos"`},
		{"the action wildcard on the bucket ARN alone", policyJSON(`{"Effect": "Allow", "Principal": "*", "Action": "s3:*", "Resource": "arn:aws:s3:::photos"}`), `Action "s3:*" needs Resource "arn:aws:s3:::photos/*"`},
	}
	for _, tt := range rejects {
		t.Run("rejects "+tt.name, func(t *testing.T) {
			_, err := bucketpolicy.Decode([]byte(tt.body))
			require.ErrorIs(t, err, s3bkt.ErrInvalidPolicy)
			require.ErrorContains(t, err, tt.want)
		})
	}

	t.Run("json.Unmarshal applies the same checks", func(t *testing.T) {
		// The stores read documents back with encoding/json.
		var d s3bkt.PolicyDocument
		err := json.Unmarshal([]byte(policyJSON(`{"Effect": "Allow", "Principal": {"AWS": []}, "Action": ["s3:GetObject"], `+res+`}`)), &d)
		require.ErrorIs(t, err, s3bkt.ErrInvalidPolicy)
		require.ErrorContains(t, err, `Principal must not be empty`)

		err = json.Unmarshal([]byte(`{"statement": []}`), &d)
		require.ErrorIs(t, err, s3bkt.ErrInvalidPolicy)
		require.ErrorContains(t, err, `unknown field "statement"`)
	})
}

// TestActionResources pins which ARN each policy action needs: the bucket ARN
// for the bucket actions, the objects ARN for the rest, as versitygw splits
// them. A new policy action fails here until it is classified.
func TestActionResources(t *testing.T) {
	bucketActions := []string{
		"s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:ListBucketVersions",
		"s3:GetBucketAcl", "s3:GetBucketCORS", "s3:GetBucketLocation",
		"s3:GetBucketObjectLockConfiguration", "s3:GetBucketTagging", "s3:GetBucketVersioning",
	}
	objectActions := []string{
		"s3:AbortMultipartUpload", "s3:DeleteObject", "s3:DeleteObjectVersion",
		"s3:GetObject", "s3:GetObjectLegalHold", "s3:GetObjectRetention", "s3:GetObjectVersion",
		"s3:ListMultipartUploadParts", "s3:PutObject", "s3:PutObjectLegalHold", "s3:PutObjectRetention",
		"s3:GetObjectTagging", "s3:PutObjectTagging", "s3:DeleteObjectTagging", "s3:GetObjectAttributes",
	}
	require.ElementsMatch(t, s3bkt.PolicyActions(), append(slices.Clone(bucketActions), objectActions...))

	on := func(a string, resources ...string) s3bkt.PolicyDocument {
		return *doc(s3bkt.Statement{Effect: s3bkt.Allow, Principal: everyone, Actions: s3bkt.NewStringSet(a), Resources: s3bkt.NewStringSet(resources...)})
	}
	all := func(string) bool { return true }
	for _, a := range bucketActions {
		require.NoError(t, bucketpolicy.Validate(on(a, bucketARN), "photos", all), a)
		require.ErrorIs(t, bucketpolicy.Validate(on(a, objectsARN), "photos", all), s3bkt.ErrInvalidPolicy, a)
	}
	for _, a := range objectActions {
		require.NoError(t, bucketpolicy.Validate(on(a, objectsARN), "photos", all), a)
		require.ErrorIs(t, bucketpolicy.Validate(on(a, bucketARN), "photos", all), s3bkt.ErrInvalidPolicy, a)
	}
	require.NoError(t, bucketpolicy.Validate(on(s3bkt.PolicyWildcard, bucketARN, objectsARN), "photos", all))
}

func TestValidate(t *testing.T) {
	known := func(p string) bool { return p == "alice" || p == "bob" }

	valid := []struct {
		name string
		doc  s3bkt.PolicyDocument
	}{
		{"one allow", *doc(allow(only("alice"), "s3:GetObject"))},
		{"wildcard is not looked up", *doc(allow(everyone, "s3:GetObject"))},
		{"deny naming wildcard", *doc(deny(everyone, "s3:DeleteObject"))},
		{"several statements", *doc(
			allow(only("alice", "bob"), "s3:GetObject", "s3:ListBucket"),
			deny(only("bob"), "s3:ListBucket"),
		)},
		{"a sid", *doc(s3bkt.Statement{Sid: "owners", Effect: s3bkt.Allow, Principal: only("alice"), Actions: s3bkt.NewStringSet("s3:GetObject"), Resources: s3bkt.NewStringSet(objectsARN)})},
		{"the 2008 version", s3bkt.PolicyDocument{Version: s3bkt.Version2008, Statements: []s3bkt.Statement{allow(only("alice"), "s3:GetObject")}}},
		{"the action wildcard", *doc(allow(only("alice"), s3bkt.PolicyWildcard))},
		{"the action wildcard beside named actions", *doc(deny(everyone, "s3:PutObjectRetention"), allow(only("alice"), "s3:GetObject", s3bkt.PolicyWildcard))},
		{"versioned object reads", *doc(allow(only("alice"), "s3:GetObjectVersion", "s3:ListBucketVersions"))},
		{"multipart actions", *doc(allow(only("alice"), "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts", "s3:ListBucketMultipartUploads"))},
	}
	for _, tt := range valid {
		t.Run("accepts "+tt.name, func(t *testing.T) {
			require.NoError(t, bucketpolicy.Validate(tt.doc, "photos", known))
		})
	}

	invalid := []struct {
		name string
		doc  s3bkt.PolicyDocument
		want string
	}{
		{"a missing version", s3bkt.PolicyDocument{Statements: []s3bkt.Statement{allow(only("alice"), "s3:GetObject")}}, `Version "" must be`},
		{"empty statements", *doc(), "Statement must not be empty"},
		{"unknown effect", *doc(s3bkt.Statement{Effect: "Permit", Principal: only("alice"), Actions: s3bkt.NewStringSet("s3:GetObject"), Resources: both()}), `Effect "Permit"`},
		{"lowercase effect", *doc(s3bkt.Statement{Effect: "allow", Principal: only("alice"), Actions: s3bkt.NewStringSet("s3:GetObject"), Resources: both()}), `Effect "allow"`},
		{"empty principal", *doc(allow(only(), "s3:GetObject")), "Principal must not be empty"},
		{"wildcard inside the principal list", *doc(allow(only("alice", "*"), "s3:GetObject")), `Principal "*" must be the bare string`},
		{"empty actions", *doc(allow(only("alice"))), "Action must not be empty"},
		{"missing resources", *doc(s3bkt.Statement{Effect: s3bkt.Allow, Principal: only("alice"), Actions: s3bkt.NewStringSet("s3:GetObject")}), "Resource must not be empty"},
		{"another bucket", *doc(s3bkt.Statement{Effect: s3bkt.Allow, Principal: only("alice"), Actions: s3bkt.NewStringSet("s3:GetObject"), Resources: s3bkt.NewStringSet("arn:aws:s3:::videos/*")}), `Resource "arn:aws:s3:::videos/*" must name bucket "photos"`},
		{"an object action on the bucket ARN", *doc(s3bkt.Statement{Effect: s3bkt.Allow, Principal: only("alice"), Actions: s3bkt.NewStringSet("s3:PutObject"), Resources: s3bkt.NewStringSet(bucketARN)}), `Action "s3:PutObject" needs Resource "arn:aws:s3:::photos/*"`},
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
			err := bucketpolicy.Validate(tt.doc, "photos", known)
			require.ErrorIs(t, err, s3bkt.ErrInvalidPolicy)
			require.ErrorContains(t, err, tt.want)
		})
	}
}

func TestCanonical(t *testing.T) {
	t.Run("compact JSON with fixed field order and every list sorted", func(t *testing.T) {
		d := *doc(
			s3bkt.Statement{Sid: "rw", Effect: s3bkt.Allow, Principal: only("bob", "alice"), Actions: s3bkt.NewStringSet("s3:PutObject", "s3:GetObject"), Resources: s3bkt.NewStringSet(objectsARN)},
			deny(everyone, "s3:DeleteObject"),
		)
		// Statements are ordered by their CID: the rw statement's sorts before
		// the deny's.
		require.Equal(t,
			`{"Version":"2012-10-17","Statement":[`+
				`{"Sid":"rw","Effect":"Allow","Principal":{"AWS":["arn:aws:iam:::user/alice","arn:aws:iam:::user/bob"]},"Action":["s3:GetObject","s3:PutObject"],"Resource":["arn:aws:s3:::photos/*"]},`+
				`{"Effect":"Deny","Principal":"*","Action":["s3:DeleteObject"],"Resource":["arn:aws:s3:::photos","arn:aws:s3:::photos/*"]}]}`,
			string(bucketpolicy.Canonical(d)))
	})

	t.Run("is valid JSON that decodes back to the document", func(t *testing.T) {
		d := *doc(allow(only("alice"), "s3:GetObject"), deny(only("bob"), "s3:ListBucket"))
		var back s3bkt.PolicyDocument
		require.NoError(t, json.Unmarshal(bucketpolicy.Canonical(d), &back))
		require.ElementsMatch(t, d.Statements, back.Statements)
		require.Equal(t, d.Version, back.Version)
	})

	t.Run("nil and empty lists canonicalize the same", func(t *testing.T) {
		withNil := s3bkt.PolicyDocument{Statements: nil}
		withEmpty := s3bkt.PolicyDocument{Statements: []s3bkt.Statement{}}
		require.Equal(t, `{"Version":"","Statement":[]}`, string(bucketpolicy.Canonical(withNil)))
		require.Equal(t, bucketpolicy.Canonical(withNil), bucketpolicy.Canonical(withEmpty))

		stNil := *doc(s3bkt.Statement{Effect: s3bkt.Allow})
		stEmpty := *doc(s3bkt.Statement{Effect: s3bkt.Allow, Principal: only(), Actions: s3bkt.NewStringSet(), Resources: s3bkt.NewStringSet()})
		require.Equal(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":[]},"Action":[],"Resource":[]}]}`, string(bucketpolicy.Canonical(stNil)))
		require.Equal(t, bucketpolicy.Canonical(stNil), bucketpolicy.Canonical(stEmpty))
	})

	t.Run("a wildcard principal ignores stray ids", func(t *testing.T) {
		d := *doc(s3bkt.Statement{Effect: s3bkt.Allow, Principal: s3bkt.Principal{"*": {}, "alice": {}}, Actions: s3bkt.NewStringSet("s3:GetObject"), Resources: s3bkt.NewStringSet(objectsARN)})
		require.Equal(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::photos/*"]}]}`, string(bucketpolicy.Canonical(d)))
	})

	t.Run("order and duplicates are not significant", func(t *testing.T) {
		a := *doc(allow(only("alice", "bob"), "s3:GetObject", "s3:PutObject"), deny(everyone, "s3:DeleteObject"))
		reversed := deny(everyone, "s3:DeleteObject")
		reversed.Resources = s3bkt.NewStringSet(objectsARN, bucketARN, objectsARN)
		b := *doc(reversed, allow(only("bob", "alice", "bob"), "s3:PutObject", "s3:GetObject", "s3:PutObject"))
		require.Equal(t, bucketpolicy.Canonical(a), bucketpolicy.Canonical(b))
		require.Equal(t, s3bkt.ETag(a), s3bkt.ETag(b))
	})

	t.Run("does not alias the input", func(t *testing.T) {
		d := *doc(allow(only("alice"), "s3:GetObject"))
		first := string(bucketpolicy.Canonical(d))
		d.Statements[0].Actions["s3:PutObject"] = struct{}{}
		require.NotEqual(t, first, string(bucketpolicy.Canonical(d)))
	})
}

func TestEffective(t *testing.T) {
	all := s3bkt.PolicyActions()
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
		doc       *s3bkt.PolicyDocument
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
		{"the action wildcard grants every policy action", doc(allow(only("alice"), s3bkt.PolicyWildcard)), "alice", all},
		{"a named deny narrows the action wildcard", doc(
			allow(only("alice"), s3bkt.PolicyWildcard),
			deny(everyone, "s3:PutObjectRetention", "s3:PutObjectLegalHold"),
		), "alice", allButRetention},
		{"a wildcard deny denies everything", doc(
			allow(only("alice"), "s3:GetObject", "s3:PutObject"),
			deny(only("alice"), s3bkt.PolicyWildcard),
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
		doc          s3bkt.PolicyDocument
		want         []string
		wantWildcard bool
	}{
		{"empty", s3bkt.PolicyDocument{}, nil, false},
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
		old, new   *s3bkt.PolicyDocument
		principals []string
		want       []string
	}{
		{"nil to nil", nil, nil, tenant, nil},
		{"creating a policy names its principals", nil, doc(allow(only("alice", "bob"), "s3:GetObject")), tenant, []string{"alice", "bob"}},
		{"deleting a policy names its principals", doc(allow(only("alice"), "s3:GetObject")), nil, tenant, []string{"alice"}},
		{"identical documents change nothing", doc(allow(only("alice"), "s3:GetObject")), doc(allow(only("alice"), "s3:GetObject")), tenant, nil},
		{"a sid changes nothing", doc(allow(only("alice"), "s3:GetObject")), doc(s3bkt.Statement{Sid: "read", Effect: s3bkt.Allow, Principal: only("alice"), Actions: s3bkt.NewStringSet("s3:GetObject")}), tenant, nil},
		{"reordering changes nothing", doc(
			allow(only("alice"), "s3:GetObject", "s3:PutObject"),
		), doc(
			allow(only("alice"), "s3:PutObject", "s3:GetObject"),
		), tenant, nil},
		{"spelling out the wildcard changes nothing", doc(allow(only("alice"), s3bkt.PolicyWildcard)), doc(allow(only("alice"), s3bkt.PolicyActions()...)), tenant, nil},
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
