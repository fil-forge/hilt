package bucketpolicy_test

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/store"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	bucketpolicypostgres "github.com/fil-forge/hilt/pkg/store/bucketpolicy/postgres"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/libforge/testutil"
	"github.com/fil-forge/ucantone/did"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// fixtures creates the rows the policy tables reference: the bucket
// (bucket_policy.bucket_id), its tenant, and the principals a document names
// (bucket_policy_principal's foreign key).
type fixtures struct {
	pool    *pgxpool.Pool
	buckets atomic.Int64
}

func (f *fixtures) tenant(t *testing.T) did.DID {
	tenantID := testutil.RandomDID(t)
	require.NoError(t, tenantpostgres.New(f.pool).Add(t.Context(), tenantID, "ext-"+tenantID.String(), tenant.Active))
	return tenantID
}

func (f *fixtures) bucket(t *testing.T, tenantID did.DID) did.DID {
	id := testutil.RandomDID(t)
	name := fmt.Sprintf("policy-test-%d", f.buckets.Add(1))
	// A bucket is served by a provider, so one must exist for the foreign key.
	providerID := testutil.RandomDID(t)
	require.NoError(t, providerpostgres.New(f.pool).Add(t.Context(), providerID, "region-"+providerID.String(), nil))
	require.NoError(t, bucketpostgres.New(f.pool).Add(t.Context(), id, tenantID, providerID, name))
	return id
}

func (f *fixtures) principal(t *testing.T, tenantID did.DID, id string) {
	require.NoError(t, principalpostgres.New(f.pool).Add(t.Context(), tenantID, id))
}

var everyone = s3bkt.Everyone()

func only(ids ...string) s3bkt.Principal { return s3bkt.Only(ids...) }

func allow(p s3bkt.Principal, actions ...string) s3bkt.Statement {
	return s3bkt.Statement{Effect: s3bkt.Allow, Principal: p, Actions: s3bkt.NewStringSet(actions...), Resources: s3bkt.NewStringSet(s3bkt.BucketARN("photos"), s3bkt.ObjectsARN("photos"))}
}

func deny(p s3bkt.Principal, actions ...string) s3bkt.Statement {
	return s3bkt.Statement{Effect: s3bkt.Deny, Principal: p, Actions: s3bkt.NewStringSet(actions...), Resources: s3bkt.NewStringSet(s3bkt.BucketARN("photos"), s3bkt.ObjectsARN("photos"))}
}

func doc(statements ...s3bkt.Statement) s3bkt.PolicyDocument {
	return s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: statements}
}

func ptr(s string) *string { return &s }

// commit runs first and then rest in one transaction, as a task's commit
// does, and reports whether first affected a row; when it affected none,
// nothing is committed, as a failed WriteConditional fails the commit.
func commit(t *testing.T, pool *pgxpool.Pool, first store.Statement, rest ...store.Statement) bool {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx) // no-op once committed
	tag, err := tx.Exec(ctx, first.SQL, first.Args...)
	require.NoError(t, err)
	if tag.RowsAffected() == 0 {
		return false
	}
	for _, st := range rest {
		if _, err := tx.Exec(ctx, st.SQL, st.Args...); err != nil {
			t.Logf("statement failed: %v", err)
			return false
		}
	}
	require.NoError(t, tx.Commit(ctx))
	return true
}

// TestPolicyStore covers the store's reads and the writes a policy task's
// commit runs.
func TestPolicyStore(t *testing.T) {
	pool := htestutil.PostgresOrSkip(t)
	s := bucketpolicypostgres.New(pool)
	f := &fixtures{pool: pool}
	ctx := t.Context()

	put := func(t *testing.T, tenantID, bucket did.DID, d s3bkt.PolicyDocument) bool {
		t.Helper()
		first, index := s.PutStatements(tenantID, bucket, d)
		return commit(t, pool, first, index...)
	}
	remove := func(t *testing.T, bucket did.DID) bool {
		t.Helper()
		del, index := s.DeleteStatements(bucket)
		return commit(t, pool, del, index)
	}
	get := func(t *testing.T, bucket did.DID) *bucketpolicystore.Record {
		t.Helper()
		rec, err := s.Get(ctx, bucket)
		if errors.Is(err, store.ErrRecordNotFound) {
			return nil
		}
		require.NoError(t, err)
		return &rec
	}
	listed := func(t *testing.T, tenantID did.DID, principal string) []did.DID {
		t.Helper()
		recs, err := s.ListByPrincipal(ctx, tenantID, principal)
		require.NoError(t, err)
		var out []did.DID
		for _, rec := range recs {
			out = append(out, rec.Bucket)
		}
		return out
	}
	// indexRows returns the (principal) index rows for a bucket, with the
	// wildcard row as a nil principal.
	indexRows := func(t *testing.T, bucket did.DID) (tenant string, principals []*string) {
		t.Helper()
		rows, err := pool.Query(ctx,
			`SELECT tenant_id, principal_id FROM bucket_policy_principal WHERE bucket_id = $1 ORDER BY principal_id NULLS FIRST`, bucket.String())
		require.NoError(t, err)
		defer rows.Close()
		for rows.Next() {
			var p *string
			require.NoError(t, rows.Scan(&tenant, &p))
			principals = append(principals, p)
		}
		require.NoError(t, rows.Err())
		return tenant, principals
	}
	setup := func(t *testing.T) (tenantID, bucket did.DID) {
		tenantID = f.tenant(t)
		f.principal(t, tenantID, "alice")
		f.principal(t, tenantID, "bob")
		return tenantID, f.bucket(t, tenantID)
	}
	first, second := doc(allow(only("alice"), "s3:GetObject")), doc(allow(only("bob"), "s3:GetObject"), deny(everyone, "s3:PutObject"))

	t.Run("creates a policy that Get returns with its ETag", func(t *testing.T) {
		tenantID, bucket := setup(t)
		require.Nil(t, get(t, bucket), "a bucket without a policy has none")
		require.True(t, put(t, tenantID, bucket, first))

		rec := get(t, bucket)
		require.NotNil(t, rec)
		require.Equal(t, bucket, rec.Bucket)
		require.Equal(t, first, rec.Policy)
		require.Equal(t, s3bkt.ETag(first), rec.ETag)
		require.False(t, rec.UpdatedAt.IsZero())
	})

	t.Run("replaces whatever is stored and rewrites the index", func(t *testing.T) {
		tenantID, bucket := setup(t)
		require.True(t, put(t, tenantID, bucket, first))
		require.True(t, put(t, tenantID, bucket, second))

		rec := get(t, bucket)
		require.Equal(t, second, rec.Policy)
		require.Equal(t, s3bkt.ETag(second), rec.ETag)
		require.Equal(t, []did.DID{bucket}, listed(t, tenantID, "alice"), "through the wildcard")
		require.Equal(t, []did.DID{bucket}, listed(t, tenantID, "bob"))

		require.True(t, put(t, tenantID, bucket, first))
		require.Empty(t, listed(t, tenantID, "bob"), "the wildcard row and bob's are gone")
		require.True(t, put(t, tenantID, bucket, first), "writing the same document again affects the row")
	})

	t.Run("stores the normalized document", func(t *testing.T) {
		// A document built directly, without Decode, may repeat and misorder
		// its sets; the ETag is computed from the normalized form either way.
		tenantID, bucket := setup(t)
		d := doc(allow(only("bob", "alice", "bob"), "s3:PutObject", "s3:GetObject", "s3:PutObject"))
		require.True(t, put(t, tenantID, bucket, d))

		want, err := bucketpolicy.Decode(bucketpolicy.Canonical(d))
		require.NoError(t, err)
		require.Equal(t, want, get(t, bucket).Policy)
	})

	t.Run("a write affects no row for a bucket that is gone or another tenant's", func(t *testing.T) {
		tenantID, bucket := setup(t)
		other := f.tenant(t)
		require.False(t, put(t, other, bucket, doc(allow(everyone, "s3:GetObject"))))
		require.False(t, put(t, tenantID, testutil.RandomDID(t), first))
		require.Nil(t, get(t, bucket), "nothing was written")
	})

	t.Run("index rows: one per named principal and a NULL row for the wildcard", func(t *testing.T) {
		tenantID, bucket := setup(t)
		require.True(t, put(t, tenantID, bucket, doc(allow(only("alice", "bob"), "s3:GetObject"), deny(only("alice"), "s3:PutObject"), deny(everyone, "s3:PutObject"))))

		tenant, principals := indexRows(t, bucket)
		require.Equal(t, tenantID.String(), tenant)
		require.Equal(t, []*string{nil, ptr("alice"), ptr("bob")}, principals, "alice is indexed once across two statements")
	})

	t.Run("a principal the tenant does not have fails the index write", func(t *testing.T) {
		tenantID, bucket := setup(t)
		require.False(t, put(t, tenantID, bucket, doc(allow(only("alice", "mallory"), "s3:GetObject"))))
		require.Nil(t, get(t, bucket), "nothing was written")
	})

	t.Run("removes the policy and its index rows, and no other", func(t *testing.T) {
		tenantID, bucket := setup(t)
		kept := f.bucket(t, tenantID)
		require.True(t, put(t, tenantID, bucket, first))
		require.True(t, put(t, tenantID, kept, first))

		require.True(t, remove(t, bucket))
		require.Nil(t, get(t, bucket))
		_, principals := indexRows(t, bucket)
		require.Empty(t, principals)
		require.NotNil(t, get(t, kept))
		require.Equal(t, []did.DID{kept}, listed(t, tenantID, "alice"))

		require.False(t, remove(t, bucket), "a removal affects no row when there is no policy")
	})

	t.Run("deleting the bucket cascades to the policy and its index rows", func(t *testing.T) {
		tenantID, bucket := setup(t)
		require.True(t, put(t, tenantID, bucket, doc(allow(only("alice"), "s3:GetObject"), allow(everyone, "s3:GetObject"))))

		require.NoError(t, bucketpostgres.New(pool).Delete(ctx, bucket))
		require.Nil(t, get(t, bucket))
		_, principals := indexRows(t, bucket)
		require.Empty(t, principals)
	})

	t.Run("tombstoning a principal leaves the policy and its index rows in place", func(t *testing.T) {
		// The tombstone keeps the principal's row, so the index foreign key
		// does not cascade; principal removal strips the statements naming it
		// instead.
		tenantID, bucket := setup(t)
		require.True(t, put(t, tenantID, bucket, doc(allow(only("alice"), "s3:GetObject"), allow(everyone, "s3:GetObject"))))

		st := principalpostgres.New(pool).TombstoneStatement(tenantID, "alice")
		_, err := pool.Exec(ctx, st.SQL, st.Args...)
		require.NoError(t, err)
		_, principals := indexRows(t, bucket)
		require.Len(t, principals, 2, "the named row and the wildcard row both remain")
		require.NotNil(t, get(t, bucket))
	})

	t.Run("ListByPrincipal returns the policies naming the principal or the wildcard, by bucket", func(t *testing.T) {
		tenantID := f.tenant(t)
		f.principal(t, tenantID, "alice")
		f.principal(t, tenantID, "bob")
		named := f.bucket(t, tenantID)    // names alice
		wildcard := f.bucket(t, tenantID) // names *
		both := f.bucket(t, tenantID)     // names alice and *
		denied := f.bucket(t, tenantID)   // names alice in a Deny only
		other := f.bucket(t, tenantID)    // names bob only
		f.bucket(t, tenantID)             // no policy

		require.True(t, put(t, tenantID, named, doc(allow(only("alice"), "s3:GetObject"))))
		require.True(t, put(t, tenantID, wildcard, doc(allow(everyone, "s3:GetObject"))))
		require.True(t, put(t, tenantID, both, doc(allow(everyone, "s3:GetObject"), deny(only("alice"), "s3:GetObject"))))
		require.True(t, put(t, tenantID, denied, doc(allow(only("bob"), "s3:GetObject"), deny(only("alice"), "s3:PutObject"))))
		require.True(t, put(t, tenantID, other, doc(allow(only("bob"), "s3:GetObject"))))

		recs, err := s.ListByPrincipal(ctx, tenantID, "alice")
		require.NoError(t, err)
		var ids []string
		for _, r := range recs {
			ids = append(ids, r.Bucket.String())
			require.NotEmpty(t, r.ETag)
			require.NotEmpty(t, r.Policy.Statements)
		}
		require.IsIncreasing(t, ids)
		// A policy naming the principal in a Deny is listed: the index records
		// which documents name it, whatever the effect. A policy naming both the
		// principal and the wildcard is listed once.
		require.ElementsMatch(t, []did.DID{named, wildcard, both, denied}, listed(t, tenantID, "alice"))
		require.ElementsMatch(t, []did.DID{wildcard, both, denied, other}, listed(t, tenantID, "bob"))
		// A principal named nowhere sees only the wildcard policies.
		f.principal(t, tenantID, "carol")
		require.ElementsMatch(t, []did.DID{wildcard, both}, listed(t, tenantID, "carol"))
	})

	t.Run("ListByPrincipal isolates by tenant", func(t *testing.T) {
		tenantID, bucket := setup(t)
		otherTenant, otherBucket := setup(t)
		require.True(t, put(t, tenantID, bucket, doc(allow(everyone, "s3:GetObject"))))
		require.True(t, put(t, otherTenant, otherBucket, doc(allow(only("alice"), "s3:GetObject"))))

		require.Equal(t, []did.DID{bucket}, listed(t, tenantID, "alice"))
		require.Empty(t, listed(t, testutil.RandomDID(t), "alice"))
	})
}

func TestCheckPrecondition(t *testing.T) {
	rec := &bucketpolicystore.Record{ETag: "current"}
	require.NoError(t, bucketpolicystore.CheckPrecondition(nil, nil), "If-None-Match: * with no policy")
	require.ErrorIs(t, bucketpolicystore.CheckPrecondition(rec, nil), store.ErrPreconditionFailed, "If-None-Match: * over a policy")
	require.NoError(t, bucketpolicystore.CheckPrecondition(rec, ptr("current")))
	require.ErrorIs(t, bucketpolicystore.CheckPrecondition(rec, ptr("stale")), store.ErrPreconditionFailed)
	require.ErrorIs(t, bucketpolicystore.CheckPrecondition(nil, ptr("current")), store.ErrPreconditionFailed, "If-Match with no policy")
}
