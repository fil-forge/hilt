package policy_test

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/policy"
	"github.com/fil-forge/hilt/pkg/store"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	policystore "github.com/fil-forge/hilt/pkg/store/policy"
	policymemory "github.com/fil-forge/hilt/pkg/store/policy/memory"
	policypostgres "github.com/fil-forge/hilt/pkg/store/policy/postgres"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/libforge/testutil"
	"github.com/fil-forge/ucantone/did"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

type StoreKind string

const (
	Memory   StoreKind = "memory"
	Postgres StoreKind = "postgres"
)

var storeKinds = []StoreKind{Memory, Postgres}

// fixtures creates the rows the policy tables reference: the bucket
// (bucket_policy.bucket_id), its tenant, and the principals a document names
// (bucket_policy_principal's foreign key). The memory store enforces no
// referential integrity, so its fixtures only hand out identifiers.
type fixtures interface {
	tenant(t *testing.T) did.DID
	bucket(t *testing.T, tenant did.DID) did.DID
	principal(t *testing.T, tenant did.DID, id string)
}

type memoryFixtures struct{}

func (memoryFixtures) tenant(t *testing.T) did.DID            { return testutil.RandomDID(t) }
func (memoryFixtures) bucket(t *testing.T, _ did.DID) did.DID { return testutil.RandomDID(t) }
func (memoryFixtures) principal(*testing.T, did.DID, string)  {}

type postgresFixtures struct {
	pool    *pgxpool.Pool
	buckets atomic.Int64
}

func (f *postgresFixtures) tenant(t *testing.T) did.DID {
	tenantID := testutil.RandomDID(t)
	providerID := testutil.RandomDID(t)
	require.NoError(t, providerpostgres.New(f.pool).Add(t.Context(), providerID, tenantID.String(), nil))
	require.NoError(t, tenantpostgres.New(f.pool).Add(t.Context(), tenantID, "ext-"+tenantID.String(), providerID, tenant.Active))
	return tenantID
}

func (f *postgresFixtures) bucket(t *testing.T, tenantID did.DID) did.DID {
	id := testutil.RandomDID(t)
	name := fmt.Sprintf("policy-test-%d", f.buckets.Add(1))
	require.NoError(t, bucketpostgres.New(f.pool).Add(t.Context(), id, tenantID, name))
	return id
}

func (f *postgresFixtures) principal(t *testing.T, tenantID did.DID, id string) {
	require.NoError(t, principalpostgres.New(f.pool).Add(t.Context(), tenantID, id))
}

func makeStore(t *testing.T, k StoreKind) (policystore.Store, fixtures) {
	switch k {
	case Memory:
		return policymemory.New(), memoryFixtures{}
	case Postgres:
		pool := createPostgresPool(t)
		return policypostgres.New(pool), &postgresFixtures{pool: pool}
	}
	panic("unknown store kind")
}

func createPostgresPool(t *testing.T) *pgxpool.Pool {
	if htestutil.IsRunningInCI(t) && runtime.GOOS == "linux" {
		if !htestutil.IsDockerAvailable(t) {
			t.Fatalf("docker is expected in CI linux testing environments, but wasn't found")
		}
	}
	if !htestutil.IsDockerAvailable(t) {
		t.SkipNow()
	}
	return htestutil.CreatePostgres(t)
}

func allow(principals []string, actions ...string) policy.Statement {
	return policy.Statement{Effect: policy.Allow, Principals: principals, Actions: actions}
}

func deny(principals []string, actions ...string) policy.Statement {
	return policy.Statement{Effect: policy.Deny, Principals: principals, Actions: actions}
}

func doc(statements ...policy.Statement) policy.Document {
	return policy.Document{Statements: statements}
}

func ptr(s string) *string { return &s }

func noCallback(context.Context, *policystore.Record) error { return nil }

func TestPolicyStore(t *testing.T) {
	for _, k := range storeKinds {
		t.Run(string(k), func(t *testing.T) {
			s, fx := makeStore(t, k)

			// newBucket seeds a tenant with the named principals and one bucket.
			newBucket := func(t *testing.T, principals ...string) (tenantID, bucketID did.DID) {
				tenantID = fx.tenant(t)
				for _, p := range principals {
					fx.principal(t, tenantID, p)
				}
				return tenantID, fx.bucket(t, tenantID)
			}

			t.Run("Put creates a policy and Get returns it with its ETag", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice")
				d := doc(allow([]string{"alice"}, "s3:GetObject", "s3:ListBucket"))

				etag, err := s.Put(t.Context(), policystore.Input{Bucket: bucketID, Tenant: tenantID, Document: d}, noCallback)
				require.NoError(t, err)
				require.Equal(t, policy.ETag(d), etag)

				rec, err := s.Get(t.Context(), bucketID)
				require.NoError(t, err)
				require.Equal(t, bucketID, rec.Bucket)
				require.Equal(t, d, rec.Document)
				require.Equal(t, etag, rec.ETag)
				require.False(t, rec.UpdatedAt.IsZero())
			})

			t.Run("Get honours the share lock option", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice")
				d := doc(allow([]string{"alice"}, "s3:GetObject"))
				_, err := s.Put(t.Context(), policystore.Input{Bucket: bucketID, Tenant: tenantID, Document: d}, nil)
				require.NoError(t, err)

				rec, err := s.Get(t.Context(), bucketID, store.WithLock(store.LockShare))
				require.NoError(t, err)
				require.Equal(t, d, rec.Document)
			})

			t.Run("Get returns ErrRecordNotFound for a bucket without a policy", func(t *testing.T) {
				_, bucketID := newBucket(t)
				_, err := s.Get(t.Context(), bucketID)
				require.ErrorIs(t, err, store.ErrRecordNotFound)
				_, err = s.Get(t.Context(), bucketID, store.WithLock(store.LockShare))
				require.ErrorIs(t, err, store.ErrRecordNotFound)
			})

			t.Run("Put creating passes a nil old record to the callback", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice")
				var calls int
				var seen *policystore.Record
				_, err := s.Put(t.Context(), policystore.Input{
					Bucket: bucketID, Tenant: tenantID, Document: doc(allow([]string{"alice"}, "s3:GetObject")),
				}, func(_ context.Context, old *policystore.Record) error {
					calls++
					seen = old
					return nil
				})
				require.NoError(t, err)
				require.Equal(t, 1, calls)
				require.Nil(t, seen)
			})

			t.Run("Put with nil IfMatch fails when a policy exists and writes nothing", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice", "bob")
				first := doc(allow([]string{"alice"}, "s3:GetObject"))
				etag, err := s.Put(t.Context(), policystore.Input{Bucket: bucketID, Tenant: tenantID, Document: first}, nil)
				require.NoError(t, err)

				called := false
				_, err = s.Put(t.Context(), policystore.Input{
					Bucket: bucketID, Tenant: tenantID, Document: doc(allow([]string{"bob"}, "s3:GetObject")),
				}, func(context.Context, *policystore.Record) error {
					called = true
					return nil
				})
				require.ErrorIs(t, err, store.ErrPreconditionFailed)
				require.False(t, called, "the callback must not run when the precondition fails")

				rec, err := s.Get(t.Context(), bucketID)
				require.NoError(t, err)
				require.Equal(t, first, rec.Document)
				require.Equal(t, etag, rec.ETag)
				recs, err := s.ListByPrincipal(t.Context(), tenantID, "bob")
				require.NoError(t, err)
				require.Empty(t, recs, "the index must not be rewritten")
			})

			t.Run("Put with a matching IfMatch replaces the policy and hands the callback the old record", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice", "bob")
				first := doc(allow([]string{"alice"}, "s3:GetObject"))
				etag1, err := s.Put(t.Context(), policystore.Input{Bucket: bucketID, Tenant: tenantID, Document: first}, nil)
				require.NoError(t, err)

				second := doc(allow([]string{"bob"}, "s3:PutObject"))
				var seen *policystore.Record
				etag2, err := s.Put(t.Context(), policystore.Input{
					Bucket: bucketID, Tenant: tenantID, Document: second, IfMatch: ptr(etag1),
				}, func(_ context.Context, old *policystore.Record) error {
					seen = old
					return nil
				})
				require.NoError(t, err)
				require.Equal(t, policy.ETag(second), etag2)
				require.NotEqual(t, etag1, etag2)
				require.NotNil(t, seen)
				require.Equal(t, first, seen.Document)
				require.Equal(t, etag1, seen.ETag)

				rec, err := s.Get(t.Context(), bucketID)
				require.NoError(t, err)
				require.Equal(t, second, rec.Document)
				require.Equal(t, etag2, rec.ETag)
			})

			t.Run("Put with a stale IfMatch fails and writes nothing", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice", "bob")
				first := doc(allow([]string{"alice"}, "s3:GetObject"))
				etag1, err := s.Put(t.Context(), policystore.Input{Bucket: bucketID, Tenant: tenantID, Document: first}, nil)
				require.NoError(t, err)
				second := doc(allow([]string{"alice"}, "s3:GetObject", "s3:PutObject"))
				etag2, err := s.Put(t.Context(), policystore.Input{Bucket: bucketID, Tenant: tenantID, Document: second, IfMatch: ptr(etag1)}, nil)
				require.NoError(t, err)

				// A writer that read etag1 lost the race.
				called := false
				_, err = s.Put(t.Context(), policystore.Input{
					Bucket: bucketID, Tenant: tenantID, Document: doc(allow([]string{"bob"}, "s3:GetObject")), IfMatch: ptr(etag1),
				}, func(context.Context, *policystore.Record) error {
					called = true
					return nil
				})
				require.ErrorIs(t, err, store.ErrPreconditionFailed)
				require.False(t, called)

				rec, err := s.Get(t.Context(), bucketID)
				require.NoError(t, err)
				require.Equal(t, second, rec.Document)
				require.Equal(t, etag2, rec.ETag)
			})

			t.Run("Put with IfMatch on a bucket without a policy fails", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice")
				_, err := s.Put(t.Context(), policystore.Input{
					Bucket: bucketID, Tenant: tenantID, Document: doc(allow([]string{"alice"}, "s3:GetObject")), IfMatch: ptr(`"nope"`),
				}, nil)
				require.ErrorIs(t, err, store.ErrPreconditionFailed)
				_, err = s.Get(t.Context(), bucketID)
				require.ErrorIs(t, err, store.ErrRecordNotFound)
			})

			t.Run("Put returns the callback error and writes nothing when creating", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice")
				publishFailed := errors.New("publish failed")
				_, err := s.Put(t.Context(), policystore.Input{
					Bucket: bucketID, Tenant: tenantID, Document: doc(allow([]string{"alice"}, "s3:GetObject")),
				}, func(context.Context, *policystore.Record) error { return publishFailed })
				require.ErrorIs(t, err, publishFailed)

				_, err = s.Get(t.Context(), bucketID)
				require.ErrorIs(t, err, store.ErrRecordNotFound)
				recs, err := s.ListByPrincipal(t.Context(), tenantID, "alice")
				require.NoError(t, err)
				require.Empty(t, recs)
			})

			t.Run("Put returns the callback error and keeps the old policy and index when replacing", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice", "bob")
				first := doc(allow([]string{"alice"}, "s3:GetObject"))
				etag1, err := s.Put(t.Context(), policystore.Input{Bucket: bucketID, Tenant: tenantID, Document: first}, nil)
				require.NoError(t, err)

				publishFailed := errors.New("publish failed")
				_, err = s.Put(t.Context(), policystore.Input{
					Bucket: bucketID, Tenant: tenantID, Document: doc(allow([]string{"bob"}, "s3:GetObject")), IfMatch: ptr(etag1),
				}, func(context.Context, *policystore.Record) error { return publishFailed })
				require.ErrorIs(t, err, publishFailed)

				rec, err := s.Get(t.Context(), bucketID)
				require.NoError(t, err)
				require.Equal(t, first, rec.Document)
				require.Equal(t, etag1, rec.ETag)
				recs, err := s.ListByPrincipal(t.Context(), tenantID, "alice")
				require.NoError(t, err)
				require.Len(t, recs, 1)
				recs, err = s.ListByPrincipal(t.Context(), tenantID, "bob")
				require.NoError(t, err)
				require.Empty(t, recs)

				// The failed write did not consume the tag: a retry with it succeeds.
				_, err = s.Put(t.Context(), policystore.Input{
					Bucket: bucketID, Tenant: tenantID, Document: doc(allow([]string{"bob"}, "s3:GetObject")), IfMatch: ptr(etag1),
				}, nil)
				require.NoError(t, err)
			})

			t.Run("Put returns ErrInvalidArgument for an undef bucket or tenant", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice")
				d := doc(allow([]string{"alice"}, "s3:GetObject"))
				_, err := s.Put(t.Context(), policystore.Input{Bucket: did.Undef, Tenant: tenantID, Document: d}, nil)
				require.ErrorIs(t, err, store.ErrInvalidArgument)
				_, err = s.Put(t.Context(), policystore.Input{Bucket: bucketID, Tenant: did.Undef, Document: d}, nil)
				require.ErrorIs(t, err, store.ErrInvalidArgument)
			})

			t.Run("Put does not alias the caller's document", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice")
				d := doc(allow([]string{"alice"}, "s3:GetObject"))
				_, err := s.Put(t.Context(), policystore.Input{Bucket: bucketID, Tenant: tenantID, Document: d}, nil)
				require.NoError(t, err)
				d.Statements[0].Actions[0] = "s3:PutObject"

				rec, err := s.Get(t.Context(), bucketID)
				require.NoError(t, err)
				require.Equal(t, "s3:GetObject", rec.Document.Statements[0].Actions[0])
				rec.Document.Statements[0].Actions[0] = "s3:DeleteObject"
				again, err := s.Get(t.Context(), bucketID)
				require.NoError(t, err)
				require.Equal(t, "s3:GetObject", again.Document.Statements[0].Actions[0])
			})

			t.Run("Delete with the current ETag removes the policy and hands the callback the old record", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice")
				d := doc(allow([]string{"alice"}, "s3:GetObject"))
				etag, err := s.Put(t.Context(), policystore.Input{Bucket: bucketID, Tenant: tenantID, Document: d}, nil)
				require.NoError(t, err)

				var seen policystore.Record
				require.NoError(t, s.Delete(t.Context(), bucketID, etag, func(_ context.Context, old policystore.Record) error {
					seen = old
					return nil
				}))
				require.Equal(t, d, seen.Document)
				require.Equal(t, etag, seen.ETag)

				_, err = s.Get(t.Context(), bucketID)
				require.ErrorIs(t, err, store.ErrRecordNotFound)
				recs, err := s.ListByPrincipal(t.Context(), tenantID, "alice")
				require.NoError(t, err)
				require.Empty(t, recs, "the index rows go with the policy")
			})

			t.Run("Delete with a stale ETag fails and keeps the policy", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice")
				d := doc(allow([]string{"alice"}, "s3:GetObject"))
				etag, err := s.Put(t.Context(), policystore.Input{Bucket: bucketID, Tenant: tenantID, Document: d}, nil)
				require.NoError(t, err)

				called := false
				err = s.Delete(t.Context(), bucketID, `"stale"`, func(context.Context, policystore.Record) error {
					called = true
					return nil
				})
				require.ErrorIs(t, err, store.ErrPreconditionFailed)
				require.False(t, called)
				rec, err := s.Get(t.Context(), bucketID)
				require.NoError(t, err)
				require.Equal(t, etag, rec.ETag)
			})

			t.Run("Delete returns ErrRecordNotFound for a bucket without a policy", func(t *testing.T) {
				_, bucketID := newBucket(t)
				called := false
				err := s.Delete(t.Context(), bucketID, `"any"`, func(context.Context, policystore.Record) error {
					called = true
					return nil
				})
				require.ErrorIs(t, err, store.ErrRecordNotFound)
				require.False(t, called)
			})

			t.Run("Delete returns the callback error and keeps the policy", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice")
				d := doc(allow([]string{"alice"}, "s3:GetObject"))
				etag, err := s.Put(t.Context(), policystore.Input{Bucket: bucketID, Tenant: tenantID, Document: d}, nil)
				require.NoError(t, err)

				publishFailed := errors.New("publish failed")
				err = s.Delete(t.Context(), bucketID, etag, func(context.Context, policystore.Record) error { return publishFailed })
				require.ErrorIs(t, err, publishFailed)

				rec, err := s.Get(t.Context(), bucketID)
				require.NoError(t, err)
				require.Equal(t, d, rec.Document)
				recs, err := s.ListByPrincipal(t.Context(), tenantID, "alice")
				require.NoError(t, err)
				require.Len(t, recs, 1)

				// A retry completes the removal.
				require.NoError(t, s.Delete(t.Context(), bucketID, etag, nil))
			})

			t.Run("DeleteByBucket removes the policy and its index rows and is idempotent", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice")
				_, err := s.Put(t.Context(), policystore.Input{
					Bucket: bucketID, Tenant: tenantID, Document: doc(allow([]string{"alice", "*"}, "s3:GetObject")),
				}, nil)
				require.NoError(t, err)

				require.NoError(t, s.DeleteByBucket(t.Context(), bucketID))
				_, err = s.Get(t.Context(), bucketID)
				require.ErrorIs(t, err, store.ErrRecordNotFound)
				recs, err := s.ListByPrincipal(t.Context(), tenantID, "alice")
				require.NoError(t, err)
				require.Empty(t, recs)

				require.NoError(t, s.DeleteByBucket(t.Context(), bucketID))
				require.NoError(t, s.DeleteByBucket(t.Context(), testutil.RandomDID(t)))
			})

			t.Run("ListByPrincipal returns the policies naming the principal or the wildcard, by bucket", func(t *testing.T) {
				tenantID := fx.tenant(t)
				fx.principal(t, tenantID, "alice")
				fx.principal(t, tenantID, "bob")
				named := fx.bucket(t, tenantID)     // names alice
				wildcard := fx.bucket(t, tenantID)  // names *
				both := fx.bucket(t, tenantID)      // names alice and *
				denied := fx.bucket(t, tenantID)    // names alice in a Deny only
				other := fx.bucket(t, tenantID)     // names bob only
				unpoliced := fx.bucket(t, tenantID) // no policy
				_ = unpoliced

				put := func(bucket did.DID, d policy.Document) {
					_, err := s.Put(t.Context(), policystore.Input{Bucket: bucket, Tenant: tenantID, Document: d}, nil)
					require.NoError(t, err)
				}
				put(named, doc(allow([]string{"alice"}, "s3:GetObject")))
				put(wildcard, doc(allow([]string{"*"}, "s3:GetObject")))
				put(both, doc(allow([]string{"*"}, "s3:GetObject"), deny([]string{"alice"}, "s3:GetObject")))
				put(denied, doc(allow([]string{"bob"}, "s3:GetObject"), deny([]string{"alice"}, "s3:PutObject")))
				put(other, doc(allow([]string{"bob"}, "s3:GetObject")))

				recs, err := s.ListByPrincipal(t.Context(), tenantID, "alice")
				require.NoError(t, err)
				var got []did.DID
				for _, r := range recs {
					got = append(got, r.Bucket)
				}
				// A policy naming the principal in a Deny is listed: the index records
				// which documents name it, whatever the effect. A policy naming both the
				// principal and the wildcard is listed once.
				require.ElementsMatch(t, []did.DID{named, wildcard, both, denied}, got)
				require.IsIncreasing(t, func() []string {
					var ids []string
					for _, r := range recs {
						ids = append(ids, r.Bucket.String())
					}
					return ids
				}())
				for _, r := range recs {
					require.NotEmpty(t, r.ETag)
					require.NotEmpty(t, r.Document.Statements)
				}

				recs, err = s.ListByPrincipal(t.Context(), tenantID, "bob")
				require.NoError(t, err)
				got = got[:0]
				for _, r := range recs {
					got = append(got, r.Bucket)
				}
				require.ElementsMatch(t, []did.DID{wildcard, both, denied, other}, got)

				// A principal named nowhere sees only the wildcard policies.
				fx.principal(t, tenantID, "carol")
				recs, err = s.ListByPrincipal(t.Context(), tenantID, "carol")
				require.NoError(t, err)
				got = got[:0]
				for _, r := range recs {
					got = append(got, r.Bucket)
				}
				require.ElementsMatch(t, []did.DID{wildcard, both}, got)

				recs, err = s.ListByPrincipal(t.Context(), tenantID, "alice", store.WithLock(store.LockShare))
				require.NoError(t, err)
				require.Len(t, recs, 4)
			})

			t.Run("ListByPrincipal isolates by tenant", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice")
				otherTenant, otherBucket := newBucket(t, "alice")
				_, err := s.Put(t.Context(), policystore.Input{Bucket: bucketID, Tenant: tenantID, Document: doc(allow([]string{"*"}, "s3:GetObject"))}, nil)
				require.NoError(t, err)
				_, err = s.Put(t.Context(), policystore.Input{Bucket: otherBucket, Tenant: otherTenant, Document: doc(allow([]string{"alice"}, "s3:GetObject"))}, nil)
				require.NoError(t, err)

				recs, err := s.ListByPrincipal(t.Context(), tenantID, "alice")
				require.NoError(t, err)
				require.Len(t, recs, 1)
				require.Equal(t, bucketID, recs[0].Bucket)

				recs, err = s.ListByPrincipal(t.Context(), testutil.RandomDID(t), "alice")
				require.NoError(t, err)
				require.Empty(t, recs)
			})

			t.Run("Put rewrites the index so a principal dropped from the document is no longer listed", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice", "bob")
				etag, err := s.Put(t.Context(), policystore.Input{
					Bucket: bucketID, Tenant: tenantID, Document: doc(allow([]string{"alice", "*"}, "s3:GetObject")),
				}, nil)
				require.NoError(t, err)

				_, err = s.Put(t.Context(), policystore.Input{
					Bucket: bucketID, Tenant: tenantID, Document: doc(allow([]string{"bob"}, "s3:GetObject")), IfMatch: ptr(etag),
				}, nil)
				require.NoError(t, err)

				recs, err := s.ListByPrincipal(t.Context(), tenantID, "alice")
				require.NoError(t, err)
				require.Empty(t, recs, "neither the named row nor the wildcard row survives")
				recs, err = s.ListByPrincipal(t.Context(), tenantID, "bob")
				require.NoError(t, err)
				require.Len(t, recs, 1)
			})
		})
	}
}

// TestPolicyStorePostgres covers what only the Postgres backend can show: the
// index rows themselves, referential integrity, and the locking contract the
// authorizer relies on.
func TestPolicyStorePostgres(t *testing.T) {
	pool := createPostgresPool(t)
	s := policypostgres.New(pool)
	fx := &postgresFixtures{pool: pool}

	// indexRows returns the (principal) index rows for a bucket, with the
	// wildcard row as a nil principal.
	indexRows := func(t *testing.T, bucket did.DID) (tenant string, principals []*string) {
		rows, err := pool.Query(t.Context(),
			`SELECT tenant_id, principal FROM bucket_policy_principal WHERE bucket_id = $1 ORDER BY principal NULLS FIRST`, bucket.String())
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

	t.Run("index rows: one per named principal and a NULL row for the wildcard", func(t *testing.T) {
		tenantID := fx.tenant(t)
		fx.principal(t, tenantID, "alice")
		fx.principal(t, tenantID, "bob")
		bucketID := fx.bucket(t, tenantID)

		_, err := s.Put(t.Context(), policystore.Input{
			Bucket: bucketID, Tenant: tenantID,
			Document: doc(allow([]string{"alice", "bob"}, "s3:GetObject"), deny([]string{"alice", "*"}, "s3:PutObject")),
		}, nil)
		require.NoError(t, err)

		tenant, principals := indexRows(t, bucketID)
		require.Equal(t, tenantID.String(), tenant)
		require.Equal(t, []*string{nil, ptr("alice"), ptr("bob")}, principals, "alice is indexed once across two statements")
	})

	t.Run("index rows are rewritten on replace and removed on delete", func(t *testing.T) {
		tenantID := fx.tenant(t)
		fx.principal(t, tenantID, "alice")
		fx.principal(t, tenantID, "bob")
		bucketID := fx.bucket(t, tenantID)

		etag, err := s.Put(t.Context(), policystore.Input{
			Bucket: bucketID, Tenant: tenantID, Document: doc(allow([]string{"alice", "*"}, "s3:GetObject")),
		}, nil)
		require.NoError(t, err)
		_, principals := indexRows(t, bucketID)
		require.Equal(t, []*string{nil, ptr("alice")}, principals)

		etag, err = s.Put(t.Context(), policystore.Input{
			Bucket: bucketID, Tenant: tenantID, Document: doc(allow([]string{"bob"}, "s3:GetObject")), IfMatch: ptr(etag),
		}, nil)
		require.NoError(t, err)
		_, principals = indexRows(t, bucketID)
		require.Equal(t, []*string{ptr("bob")}, principals)

		require.NoError(t, s.Delete(t.Context(), bucketID, etag, nil))
		_, principals = indexRows(t, bucketID)
		require.Empty(t, principals)
	})

	t.Run("Put rejects a principal the tenant does not have", func(t *testing.T) {
		tenantID := fx.tenant(t)
		fx.principal(t, tenantID, "alice")
		bucketID := fx.bucket(t, tenantID)

		_, err := s.Put(t.Context(), policystore.Input{
			Bucket: bucketID, Tenant: tenantID, Document: doc(allow([]string{"alice", "mallory"}, "s3:GetObject")),
		}, nil)
		require.ErrorIs(t, err, store.ErrInvalidArgument)
		_, err = s.Get(t.Context(), bucketID)
		require.ErrorIs(t, err, store.ErrRecordNotFound, "the failed write leaves no policy row")
		_, principals := indexRows(t, bucketID)
		require.Empty(t, principals)
	})

	t.Run("Put rejects a bucket that does not exist", func(t *testing.T) {
		tenantID := fx.tenant(t)
		_, err := s.Put(t.Context(), policystore.Input{
			Bucket: testutil.RandomDID(t), Tenant: tenantID, Document: doc(allow([]string{"*"}, "s3:GetObject")),
		}, nil)
		require.ErrorIs(t, err, store.ErrInvalidArgument)
	})

	t.Run("deleting the bucket cascades to the policy and its index rows", func(t *testing.T) {
		tenantID := fx.tenant(t)
		fx.principal(t, tenantID, "alice")
		bucketID := fx.bucket(t, tenantID)
		_, err := s.Put(t.Context(), policystore.Input{
			Bucket: bucketID, Tenant: tenantID, Document: doc(allow([]string{"alice", "*"}, "s3:GetObject")),
		}, nil)
		require.NoError(t, err)

		require.NoError(t, bucketpostgres.New(pool).Delete(t.Context(), bucketID))
		_, err = s.Get(t.Context(), bucketID)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		_, principals := indexRows(t, bucketID)
		require.Empty(t, principals)
	})

	t.Run("deleting a principal cascades to its index rows but keeps the policy", func(t *testing.T) {
		tenantID := fx.tenant(t)
		fx.principal(t, tenantID, "alice")
		bucketID := fx.bucket(t, tenantID)
		_, err := s.Put(t.Context(), policystore.Input{
			Bucket: bucketID, Tenant: tenantID, Document: doc(allow([]string{"alice", "*"}, "s3:GetObject")),
		}, nil)
		require.NoError(t, err)

		require.NoError(t, principalpostgres.New(pool).Delete(t.Context(), tenantID, "alice", nil))
		_, principals := indexRows(t, bucketID)
		require.Equal(t, []*string{nil}, principals, "only the wildcard row remains")
		_, err = s.Get(t.Context(), bucketID)
		require.NoError(t, err)
	})

	const grace = 300 * time.Millisecond

	t.Run("a FOR UPDATE holder blocks a share-locked Get until commit", func(t *testing.T) {
		tenantID := fx.tenant(t)
		fx.principal(t, tenantID, "alice")
		bucketID := fx.bucket(t, tenantID)
		_, err := s.Put(t.Context(), policystore.Input{
			Bucket: bucketID, Tenant: tenantID, Document: doc(allow([]string{"alice"}, "s3:GetObject")),
		}, nil)
		require.NoError(t, err)

		tx, err := pool.Begin(t.Context())
		require.NoError(t, err)
		defer tx.Rollback(t.Context())
		var found bool
		require.NoError(t, tx.QueryRow(t.Context(), `SELECT TRUE FROM bucket_policy WHERE bucket_id = $1 FOR UPDATE`, bucketID.String()).Scan(&found))

		// An unlocked read is answered from the snapshot and never waits.
		_, err = s.Get(t.Context(), bucketID)
		require.NoError(t, err)

		done := make(chan error, 1)
		go func() {
			_, err := s.Get(context.Background(), bucketID, store.WithLock(store.LockShare))
			done <- err
		}()
		select {
		case <-done:
			t.Fatal("share-locked Get returned while the row was held FOR UPDATE")
		case <-time.After(grace):
		}

		require.NoError(t, tx.Commit(t.Context()))
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Fatal("share-locked Get did not return after the holder committed")
		}
	})

	t.Run("a share-locked Get during Put waits and sees the new policy once it commits", func(t *testing.T) {
		tenantID := fx.tenant(t)
		fx.principal(t, tenantID, "alice")
		bucketID := fx.bucket(t, tenantID)
		first := doc(allow([]string{"alice"}, "s3:GetObject"))
		etag1, err := s.Put(t.Context(), policystore.Input{Bucket: bucketID, Tenant: tenantID, Document: first}, nil)
		require.NoError(t, err)
		second := doc(allow([]string{"alice"}, "s3:GetObject", "s3:PutObject"))

		inCallback := make(chan struct{})
		release := make(chan struct{})
		written := make(chan error, 1)
		go func() {
			_, err := s.Put(context.Background(), policystore.Input{
				Bucket: bucketID, Tenant: tenantID, Document: second, IfMatch: ptr(etag1),
			}, func(context.Context, *policystore.Record) error {
				close(inCallback)
				<-release
				return nil
			})
			written <- err
		}()
		<-inCallback

		type result struct {
			rec policystore.Record
			err error
		}
		got := make(chan result, 1)
		go func() {
			rec, err := s.Get(context.Background(), bucketID, store.WithLock(store.LockShare))
			got <- result{rec, err}
		}()
		select {
		case <-got:
			t.Fatal("share-locked Get returned while Put held the row")
		case <-time.After(grace):
		}

		close(release)
		require.NoError(t, <-written)
		select {
		case res := <-got:
			require.NoError(t, res.err)
			require.Equal(t, second, res.rec.Document, "the waiting read is answered from the committed state")
			require.Equal(t, policy.ETag(second), res.rec.ETag)
		case <-time.After(10 * time.Second):
			t.Fatal("share-locked Get did not return after the write committed")
		}
	})

	t.Run("a share-locked Get during a first Put waits and sees the created policy", func(t *testing.T) {
		tenantID := fx.tenant(t)
		fx.principal(t, tenantID, "alice")
		bucketID := fx.bucket(t, tenantID)
		created := doc(allow([]string{"alice"}, "s3:GetObject"))

		inCallback := make(chan struct{})
		release := make(chan struct{})
		written := make(chan error, 1)
		go func() {
			_, err := s.Put(context.Background(), policystore.Input{
				Bucket: bucketID, Tenant: tenantID, Document: created,
			}, func(_ context.Context, old *policystore.Record) error {
				close(inCallback)
				<-release
				return nil
			})
			written <- err
		}()
		<-inCallback

		// An unlocked read sees no row yet; it does not wait.
		_, err := s.Get(t.Context(), bucketID)
		require.ErrorIs(t, err, store.ErrRecordNotFound)

		type result struct {
			rec policystore.Record
			err error
		}
		got := make(chan result, 1)
		go func() {
			rec, err := s.Get(context.Background(), bucketID, store.WithLock(store.LockShare))
			got <- result{rec, err}
		}()
		select {
		case res := <-got:
			t.Fatalf("share-locked Get returned (%v) while the create was in flight; a reader must not cache \"no policy\"", res.err)
		case <-time.After(grace):
		}

		close(release)
		require.NoError(t, <-written)
		select {
		case res := <-got:
			require.NoError(t, res.err)
			require.Equal(t, created, res.rec.Document, "the waiting read is answered from the committed create")
		case <-time.After(10 * time.Second):
			t.Fatal("share-locked Get did not return after the create committed")
		}
	})

	t.Run("a share-locked Get during a failed Put sees the old policy once it rolls back", func(t *testing.T) {
		tenantID := fx.tenant(t)
		fx.principal(t, tenantID, "alice")
		bucketID := fx.bucket(t, tenantID)
		first := doc(allow([]string{"alice"}, "s3:GetObject"))
		etag1, err := s.Put(t.Context(), policystore.Input{Bucket: bucketID, Tenant: tenantID, Document: first}, nil)
		require.NoError(t, err)

		inCallback := make(chan struct{})
		release := make(chan struct{})
		written := make(chan error, 1)
		go func() {
			_, err := s.Put(context.Background(), policystore.Input{
				Bucket: bucketID, Tenant: tenantID, Document: doc(allow([]string{"alice"}, "s3:PutObject")), IfMatch: ptr(etag1),
			}, func(context.Context, *policystore.Record) error {
				close(inCallback)
				<-release
				return errors.New("publish failed")
			})
			written <- err
		}()
		<-inCallback

		type result struct {
			rec policystore.Record
			err error
		}
		got := make(chan result, 1)
		go func() {
			rec, err := s.Get(context.Background(), bucketID, store.WithLock(store.LockShare))
			got <- result{rec, err}
		}()
		select {
		case <-got:
			t.Fatal("share-locked Get returned while Put held the row")
		case <-time.After(grace):
		}

		close(release)
		require.Error(t, <-written)
		select {
		case res := <-got:
			require.NoError(t, res.err)
			require.Equal(t, first, res.rec.Document)
			require.Equal(t, etag1, res.rec.ETag)
		case <-time.After(10 * time.Second):
			t.Fatal("share-locked Get did not return after the write rolled back")
		}
	})
}
