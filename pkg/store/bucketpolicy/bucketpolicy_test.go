package bucketpolicy_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/store"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	bucketpolicymemory "github.com/fil-forge/hilt/pkg/store/bucketpolicy/memory"
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

type StoreKind string

const (
	Memory   StoreKind = "memory"
	Postgres StoreKind = "postgres"
)

var storeKinds = []StoreKind{Memory, Postgres}

// fixtures creates the rows the policy tables reference: the bucket
// (bucket_policy.bucket_id), its tenant, and the principals a document names
// (bucket_policy_principal's foreign key). The memory store checks only the
// bucket, through the probe its fixtures hand it, and its fixtures otherwise
// only hand out identifiers.
type fixtures interface {
	tenant(t *testing.T) did.DID
	bucket(t *testing.T, tenant did.DID) did.DID
	principal(t *testing.T, tenant did.DID, id string)
}

type memoryFixtures struct {
	mu      sync.Mutex
	buckets map[did.DID]bool
}

func (f *memoryFixtures) tenant(t *testing.T) did.DID { return testutil.RandomDID(t) }
func (f *memoryFixtures) bucket(t *testing.T, _ did.DID) did.DID {
	id := testutil.RandomDID(t)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.buckets[id] = true
	return id
}
func (f *memoryFixtures) principal(*testing.T, did.DID, string) {}
func (f *memoryFixtures) has(id did.DID) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.buckets[id]
}

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

func makeStore(t *testing.T, k StoreKind) (bucketpolicystore.Store, fixtures) {
	switch k {
	case Memory:
		fx := &memoryFixtures{buckets: map[did.DID]bool{}}
		return bucketpolicymemory.New(bucketpolicymemory.WithBuckets(fx.has)), fx
	case Postgres:
		pool := htestutil.PostgresOrSkip(t)
		return bucketpolicypostgres.New(pool), &postgresFixtures{pool: pool}
	}
	panic("unknown store kind")
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

func noCallback(context.Context, *bucketpolicystore.Record) error { return nil }

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

			t.Run("Put rejects a bucket that does not exist before running the callback", func(t *testing.T) {
				tenantID := fx.tenant(t)
				called := false
				err := s.Put(t.Context(), bucketpolicystore.Input{
					Bucket: testutil.RandomDID(t), Tenant: tenantID, Policy: doc(allow(everyone, "s3:GetObject")),
				}, func(context.Context, *bucketpolicystore.Record) error { called = true; return nil })
				require.ErrorIs(t, err, store.ErrRecordNotFound)
				require.False(t, called, "the callback must not run for a missing bucket")
			})

			t.Run("DeleteByBucket returns its callback's error and keeps the policy", func(t *testing.T) {
				tenantID, bucketID := newBucket(t)
				err := s.Put(t.Context(), bucketpolicystore.Input{Bucket: bucketID, Tenant: tenantID, Policy: doc(allow(everyone, "s3:GetObject"))}, nil)
				require.NoError(t, err)
				boom := errors.New("boom")
				err = s.DeleteByBucket(t.Context(), bucketID, func(context.Context) error { return boom })
				require.ErrorIs(t, err, boom)
				_, err = s.Get(t.Context(), bucketID)
				require.NoError(t, err)
			})

			t.Run("Put creates a policy and Get returns it", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice")
				d := doc(allow(only("alice"), "s3:GetObject", "s3:ListBucket"))

				require.NoError(t, s.Put(t.Context(), bucketpolicystore.Input{Bucket: bucketID, Tenant: tenantID, Policy: d}, noCallback))

				rec, err := s.Get(t.Context(), bucketID)
				require.NoError(t, err)
				require.False(t, rec.UpdatedAt.IsZero())
				require.Equal(t, bucketpolicystore.Record{Bucket: bucketID, Policy: d, UpdatedAt: rec.UpdatedAt}, rec)
			})

			t.Run("Get returns ErrRecordNotFound for a bucket without a policy", func(t *testing.T) {
				_, bucketID := newBucket(t)
				_, err := s.Get(t.Context(), bucketID)
				require.ErrorIs(t, err, store.ErrRecordNotFound)
			})

			t.Run("Put creating passes a nil old record to the callback", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice")
				var calls int
				var seen *bucketpolicystore.Record
				err := s.Put(t.Context(), bucketpolicystore.Input{
					Bucket: bucketID, Tenant: tenantID, Policy: doc(allow(only("alice"), "s3:GetObject")),
				}, func(_ context.Context, old *bucketpolicystore.Record) error {
					calls++
					seen = old
					return nil
				})
				require.NoError(t, err)
				require.Equal(t, 1, calls)
				require.Nil(t, seen)
			})

			t.Run("Put replaces an existing policy and hands the callback the old record", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice", "bob")
				first := doc(allow(only("alice"), "s3:GetObject"))
				require.NoError(t, s.Put(t.Context(), bucketpolicystore.Input{Bucket: bucketID, Tenant: tenantID, Policy: first}, nil))

				second := doc(allow(only("bob"), "s3:PutObject"))
				var seen *bucketpolicystore.Record
				require.NoError(t, s.Put(t.Context(), bucketpolicystore.Input{Bucket: bucketID, Tenant: tenantID, Policy: second}, func(_ context.Context, old *bucketpolicystore.Record) error {
					seen = old
					return nil
				}))

				require.NotNil(t, seen)
				require.Equal(t, bucketpolicystore.Record{Bucket: bucketID, Policy: first, UpdatedAt: seen.UpdatedAt}, *seen)
				rec, err := s.Get(t.Context(), bucketID)
				require.NoError(t, err)
				require.Equal(t, bucketpolicystore.Record{Bucket: bucketID, Policy: second, UpdatedAt: rec.UpdatedAt}, rec)
			})

			t.Run("the second of two Puts to one bucket succeeds and is stored", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice", "bob")
				first := doc(allow(only("alice"), "s3:GetObject"))
				second := doc(allow(only("bob"), "s3:PutObject"))

				require.NoError(t, s.Put(t.Context(), bucketpolicystore.Input{Bucket: bucketID, Tenant: tenantID, Policy: first}, nil))
				require.NoError(t, s.Put(t.Context(), bucketpolicystore.Input{Bucket: bucketID, Tenant: tenantID, Policy: second}, nil))

				rec, err := s.Get(t.Context(), bucketID)
				require.NoError(t, err)
				require.Equal(t, second, rec.Policy)
			})

			t.Run("of two overlapping Puts to one bucket both succeed and the one that commits last is stored", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice", "bob")
				require.NoError(t, s.Put(t.Context(), bucketpolicystore.Input{Bucket: bucketID, Tenant: tenantID, Policy: doc(allow(everyone, "s3:GetObject"))}, nil))
				early := doc(allow(only("alice"), "s3:GetObject"))
				late := doc(allow(only("bob"), "s3:PutObject"))

				// late reads the stored policy first and commits after early has.
				entered, release := make(chan struct{}), make(chan struct{})
				lateDone := make(chan error, 1)
				go func() {
					lateDone <- s.Put(context.Background(), bucketpolicystore.Input{Bucket: bucketID, Tenant: tenantID, Policy: late}, func(context.Context, *bucketpolicystore.Record) error {
						close(entered)
						<-release
						return nil
					})
				}()
				<-entered
				earlyErr := s.Put(t.Context(), bucketpolicystore.Input{Bucket: bucketID, Tenant: tenantID, Policy: early}, nil)
				close(release)

				require.NoError(t, earlyErr)
				require.NoError(t, <-lateDone)
				rec, err := s.Get(t.Context(), bucketID)
				require.NoError(t, err)
				require.Equal(t, late, rec.Policy)
				recs, err := s.ListByPrincipal(t.Context(), tenantID, "alice")
				require.NoError(t, err)
				require.Empty(t, recs, "the index matches the stored document")
			})

			t.Run("Delete removes the policy whatever was written last", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice", "bob")
				require.NoError(t, s.Put(t.Context(), bucketpolicystore.Input{Bucket: bucketID, Tenant: tenantID, Policy: doc(allow(only("alice"), "s3:GetObject"))}, nil))
				require.NoError(t, s.Put(t.Context(), bucketpolicystore.Input{Bucket: bucketID, Tenant: tenantID, Policy: doc(allow(only("bob"), "s3:GetObject"))}, nil))

				require.NoError(t, s.Delete(t.Context(), bucketID, nil))

				_, err := s.Get(t.Context(), bucketID)
				require.ErrorIs(t, err, store.ErrRecordNotFound)
				require.ErrorIs(t, s.Delete(t.Context(), bucketID, nil), store.ErrRecordNotFound)
			})

			t.Run("Put returns the callback error and writes nothing when creating", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice")
				publishFailed := errors.New("publish failed")
				err := s.Put(t.Context(), bucketpolicystore.Input{
					Bucket: bucketID, Tenant: tenantID, Policy: doc(allow(only("alice"), "s3:GetObject")),
				}, func(context.Context, *bucketpolicystore.Record) error { return publishFailed })
				require.ErrorIs(t, err, publishFailed)

				_, err = s.Get(t.Context(), bucketID)
				require.ErrorIs(t, err, store.ErrRecordNotFound)
				recs, err := s.ListByPrincipal(t.Context(), tenantID, "alice")
				require.NoError(t, err)
				require.Empty(t, recs)
			})

			t.Run("Put returns the callback error and keeps the old policy and index when replacing", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice", "bob")
				first := doc(allow(only("alice"), "s3:GetObject"))
				err := s.Put(t.Context(), bucketpolicystore.Input{Bucket: bucketID, Tenant: tenantID, Policy: first}, nil)
				require.NoError(t, err)

				publishFailed := errors.New("publish failed")
				err = s.Put(t.Context(), bucketpolicystore.Input{
					Bucket: bucketID, Tenant: tenantID, Policy: doc(allow(only("bob"), "s3:GetObject")),
				}, func(context.Context, *bucketpolicystore.Record) error { return publishFailed })
				require.ErrorIs(t, err, publishFailed)

				rec, err := s.Get(t.Context(), bucketID)
				require.NoError(t, err)
				require.Equal(t, first, rec.Policy)
				recs, err := s.ListByPrincipal(t.Context(), tenantID, "alice")
				require.NoError(t, err)
				require.Len(t, recs, 1)
				recs, err = s.ListByPrincipal(t.Context(), tenantID, "bob")
				require.NoError(t, err)
				require.Empty(t, recs)
			})

			t.Run("Put returns ErrInvalidArgument for an undef bucket or tenant", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice")
				d := doc(allow(only("alice"), "s3:GetObject"))
				err := s.Put(t.Context(), bucketpolicystore.Input{Bucket: did.Undef, Tenant: tenantID, Policy: d}, nil)
				require.ErrorIs(t, err, store.ErrInvalidArgument)
				err = s.Put(t.Context(), bucketpolicystore.Input{Bucket: bucketID, Tenant: did.Undef, Policy: d}, nil)
				require.ErrorIs(t, err, store.ErrInvalidArgument)
			})

			t.Run("Put does not alias the caller's document", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice")
				d := doc(allow(only("alice"), "s3:GetObject"))
				err := s.Put(t.Context(), bucketpolicystore.Input{Bucket: bucketID, Tenant: tenantID, Policy: d}, nil)
				require.NoError(t, err)
				d.Statements[0].Actions["s3:PutObject"] = struct{}{}

				rec, err := s.Get(t.Context(), bucketID)
				require.NoError(t, err)
				require.Equal(t, s3bkt.NewStringSet("s3:GetObject"), rec.Policy.Statements[0].Actions)
				rec.Policy.Statements[0].Actions["s3:DeleteObject"] = struct{}{}
				again, err := s.Get(t.Context(), bucketID)
				require.NoError(t, err)
				require.Equal(t, s3bkt.NewStringSet("s3:GetObject"), again.Policy.Statements[0].Actions)
			})

			t.Run("Put stores the normalized document whatever the backend", func(t *testing.T) {
				// A document built directly, without Decode, may repeat and misorder
				// its sets; the store keeps the normalized form either way.
				tenantID, bucketID := newBucket(t, "alice", "bob")
				d := doc(allow(only("bob", "alice", "bob"), "s3:PutObject", "s3:GetObject", "s3:PutObject"))
				err := s.Put(t.Context(), bucketpolicystore.Input{Bucket: bucketID, Tenant: tenantID, Policy: d}, nil)
				require.NoError(t, err)

				want, err := bucketpolicy.Decode(bucketpolicy.Canonical(d))
				require.NoError(t, err)
				rec, err := s.Get(t.Context(), bucketID)
				require.NoError(t, err)
				require.Equal(t, want, rec.Policy)
			})

			t.Run("Delete removes the policy and hands the callback the old record", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice")
				d := doc(allow(only("alice"), "s3:GetObject"))
				err := s.Put(t.Context(), bucketpolicystore.Input{Bucket: bucketID, Tenant: tenantID, Policy: d}, nil)
				require.NoError(t, err)

				var seen bucketpolicystore.Record
				require.NoError(t, s.Delete(t.Context(), bucketID, func(_ context.Context, old bucketpolicystore.Record) error {
					seen = old
					return nil
				}))
				require.Equal(t, bucketpolicystore.Record{Bucket: bucketID, Policy: d, UpdatedAt: seen.UpdatedAt}, seen)

				_, err = s.Get(t.Context(), bucketID)
				require.ErrorIs(t, err, store.ErrRecordNotFound)
				recs, err := s.ListByPrincipal(t.Context(), tenantID, "alice")
				require.NoError(t, err)
				require.Empty(t, recs, "the index rows go with the policy")
			})

			t.Run("Delete returns ErrRecordNotFound for a bucket without a policy", func(t *testing.T) {
				_, bucketID := newBucket(t)
				called := false
				err := s.Delete(t.Context(), bucketID, func(context.Context, bucketpolicystore.Record) error {
					called = true
					return nil
				})
				require.ErrorIs(t, err, store.ErrRecordNotFound)
				require.False(t, called)
			})

			t.Run("Delete returns the callback error and keeps the policy", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice")
				d := doc(allow(only("alice"), "s3:GetObject"))
				err := s.Put(t.Context(), bucketpolicystore.Input{Bucket: bucketID, Tenant: tenantID, Policy: d}, nil)
				require.NoError(t, err)

				publishFailed := errors.New("publish failed")
				err = s.Delete(t.Context(), bucketID, func(context.Context, bucketpolicystore.Record) error { return publishFailed })
				require.ErrorIs(t, err, publishFailed)

				rec, err := s.Get(t.Context(), bucketID)
				require.NoError(t, err)
				require.Equal(t, d, rec.Policy)
				recs, err := s.ListByPrincipal(t.Context(), tenantID, "alice")
				require.NoError(t, err)
				require.Len(t, recs, 1)

				// A retry completes the removal.
				require.NoError(t, s.Delete(t.Context(), bucketID, nil))
			})

			t.Run("DeleteByBucket removes the policy and its index rows and is idempotent", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice")
				err := s.Put(t.Context(), bucketpolicystore.Input{
					Bucket: bucketID, Tenant: tenantID, Policy: doc(allow(only("alice"), "s3:GetObject"), allow(everyone, "s3:GetObject")),
				}, nil)
				require.NoError(t, err)

				require.NoError(t, s.DeleteByBucket(t.Context(), bucketID, nil))
				_, err = s.Get(t.Context(), bucketID)
				require.ErrorIs(t, err, store.ErrRecordNotFound)
				recs, err := s.ListByPrincipal(t.Context(), tenantID, "alice")
				require.NoError(t, err)
				require.Empty(t, recs)

				require.NoError(t, s.DeleteByBucket(t.Context(), bucketID, nil))
				require.NoError(t, s.DeleteByBucket(t.Context(), testutil.RandomDID(t), nil))
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

				put := func(bucket did.DID, d s3bkt.PolicyDocument) {
					err := s.Put(t.Context(), bucketpolicystore.Input{Bucket: bucket, Tenant: tenantID, Policy: d}, nil)
					require.NoError(t, err)
				}
				put(named, doc(allow(only("alice"), "s3:GetObject")))
				put(wildcard, doc(allow(everyone, "s3:GetObject")))
				put(both, doc(allow(everyone, "s3:GetObject"), deny(only("alice"), "s3:GetObject")))
				put(denied, doc(allow(only("bob"), "s3:GetObject"), deny(only("alice"), "s3:PutObject")))
				put(other, doc(allow(only("bob"), "s3:GetObject")))

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
					require.NotEmpty(t, r.Policy.Statements)
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

			})

			t.Run("ListByPrincipal isolates by tenant", func(t *testing.T) {
				tenantID, bucketID := newBucket(t, "alice")
				otherTenant, otherBucket := newBucket(t, "alice")
				err := s.Put(t.Context(), bucketpolicystore.Input{Bucket: bucketID, Tenant: tenantID, Policy: doc(allow(everyone, "s3:GetObject"))}, nil)
				require.NoError(t, err)
				err = s.Put(t.Context(), bucketpolicystore.Input{Bucket: otherBucket, Tenant: otherTenant, Policy: doc(allow(only("alice"), "s3:GetObject"))}, nil)
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
				err := s.Put(t.Context(), bucketpolicystore.Input{
					Bucket: bucketID, Tenant: tenantID, Policy: doc(allow(only("alice"), "s3:GetObject"), allow(everyone, "s3:GetObject")),
				}, nil)
				require.NoError(t, err)

				err = s.Put(t.Context(), bucketpolicystore.Input{
					Bucket: bucketID, Tenant: tenantID, Policy: doc(allow(only("bob"), "s3:GetObject")),
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
// index rows themselves, referential integrity, and how a write that takes no
// lock interleaves with a bucket deletion and a principal removal.
func TestPolicyStorePostgres(t *testing.T) {
	pool := htestutil.PostgresOrSkip(t)
	s := bucketpolicypostgres.New(pool)
	fx := &postgresFixtures{pool: pool}

	// indexRows returns the (principal) index rows for a bucket, with the
	// wildcard row as a nil principal.
	indexRows := func(t *testing.T, bucket did.DID) (tenant string, principals []*string) {
		rows, err := pool.Query(t.Context(),
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

	t.Run("index rows: one per named principal and a NULL row for the wildcard", func(t *testing.T) {
		tenantID := fx.tenant(t)
		fx.principal(t, tenantID, "alice")
		fx.principal(t, tenantID, "bob")
		bucketID := fx.bucket(t, tenantID)

		err := s.Put(t.Context(), bucketpolicystore.Input{
			Bucket: bucketID, Tenant: tenantID,
			Policy: doc(allow(only("alice", "bob"), "s3:GetObject"), deny(only("alice"), "s3:PutObject"), deny(everyone, "s3:PutObject")),
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

		err := s.Put(t.Context(), bucketpolicystore.Input{
			Bucket: bucketID, Tenant: tenantID, Policy: doc(allow(only("alice"), "s3:GetObject"), allow(everyone, "s3:GetObject")),
		}, nil)
		require.NoError(t, err)
		_, principals := indexRows(t, bucketID)
		require.Equal(t, []*string{nil, ptr("alice")}, principals)

		err = s.Put(t.Context(), bucketpolicystore.Input{
			Bucket: bucketID, Tenant: tenantID, Policy: doc(allow(only("bob"), "s3:GetObject")),
		}, nil)
		require.NoError(t, err)
		_, principals = indexRows(t, bucketID)
		require.Equal(t, []*string{ptr("bob")}, principals)

		require.NoError(t, s.Delete(t.Context(), bucketID, nil))
		_, principals = indexRows(t, bucketID)
		require.Empty(t, principals)
	})

	t.Run("Put rejects a principal the tenant does not have", func(t *testing.T) {
		tenantID := fx.tenant(t)
		fx.principal(t, tenantID, "alice")
		bucketID := fx.bucket(t, tenantID)

		err := s.Put(t.Context(), bucketpolicystore.Input{
			Bucket: bucketID, Tenant: tenantID, Policy: doc(allow(only("alice", "mallory"), "s3:GetObject")),
		}, nil)
		require.ErrorIs(t, err, store.ErrInvalidArgument)
		_, err = s.Get(t.Context(), bucketID)
		require.ErrorIs(t, err, store.ErrRecordNotFound, "the failed write leaves no policy row")
		_, principals := indexRows(t, bucketID)
		require.Empty(t, principals)
	})

	t.Run("Put rejects a bucket of another tenant", func(t *testing.T) {
		owner := fx.tenant(t)
		bucketID := fx.bucket(t, owner)
		other := fx.tenant(t)
		fx.principal(t, other, "alice")

		err := s.Put(t.Context(), bucketpolicystore.Input{
			Bucket: bucketID, Tenant: other, Policy: doc(allow(only("alice"), "s3:GetObject")),
		}, nil)
		require.ErrorIs(t, err, store.ErrInvalidArgument)
		require.ErrorContains(t, err, "is not a bucket of tenant")

		err = s.Put(t.Context(), bucketpolicystore.Input{
			Bucket: bucketID, Tenant: other, Policy: doc(allow(everyone, "s3:GetObject")),
		}, nil)
		require.ErrorIs(t, err, store.ErrInvalidArgument, "the wildcard row carries the tenant too")

		_, err = s.Get(t.Context(), bucketID)
		require.ErrorIs(t, err, store.ErrRecordNotFound, "nothing was written")
	})

	t.Run("deleting the bucket cascades to the policy and its index rows", func(t *testing.T) {
		tenantID := fx.tenant(t)
		fx.principal(t, tenantID, "alice")
		bucketID := fx.bucket(t, tenantID)
		err := s.Put(t.Context(), bucketpolicystore.Input{
			Bucket: bucketID, Tenant: tenantID, Policy: doc(allow(only("alice"), "s3:GetObject"), allow(everyone, "s3:GetObject")),
		}, nil)
		require.NoError(t, err)

		require.NoError(t, bucketpostgres.New(pool).Delete(t.Context(), bucketID))
		_, err = s.Get(t.Context(), bucketID)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		_, principals := indexRows(t, bucketID)
		require.Empty(t, principals)
	})

	t.Run("removing a principal leaves the policy and its index rows in place", func(t *testing.T) {
		// Removal tombstones the principal row, so the index foreign key does not
		// cascade; the principal service strips the statements naming it instead.
		tenantID := fx.tenant(t)
		fx.principal(t, tenantID, "alice")
		bucketID := fx.bucket(t, tenantID)
		err := s.Put(t.Context(), bucketpolicystore.Input{
			Bucket: bucketID, Tenant: tenantID, Policy: doc(allow(only("alice"), "s3:GetObject"), allow(everyone, "s3:GetObject")),
		}, nil)
		require.NoError(t, err)

		require.NoError(t, principalpostgres.New(pool).Tombstone(t.Context(), tenantID, "alice", nil))
		_, principals := indexRows(t, bucketID)
		require.Len(t, principals, 2, "the named row and the wildcard row both remain")
		_, err = s.Get(t.Context(), bucketID)
		require.NoError(t, err)
	})

	t.Run("a write naming a removed principal is refused inside the transaction", func(t *testing.T) {
		// The service validates against live rows before it writes; the store is
		// what stops a statement for a principal removed in between, since the
		// index row's foreign key is satisfied by the tombstone.
		tenantID := fx.tenant(t)
		fx.principal(t, tenantID, "alice")
		bucketID := fx.bucket(t, tenantID)
		require.NoError(t, principalpostgres.New(pool).Tombstone(t.Context(), tenantID, "alice", nil))

		err := s.Put(t.Context(), bucketpolicystore.Input{
			Bucket: bucketID, Tenant: tenantID, Policy: doc(allow(only("alice"), "s3:GetObject")),
		}, nil)
		require.ErrorIs(t, err, store.ErrInvalidArgument)
		require.ErrorContains(t, err, `principal "alice"`)
		_, err = s.Get(t.Context(), bucketID)
		require.ErrorIs(t, err, store.ErrRecordNotFound, "nothing was written")
	})

	t.Run("a Put whose bucket is deleted before it writes fails and leaves no policy", func(t *testing.T) {
		tenantID := fx.tenant(t)
		bucketID := fx.bucket(t, tenantID)
		require.NoError(t, s.Put(t.Context(), bucketpolicystore.Input{Bucket: bucketID, Tenant: tenantID, Policy: doc(allow(everyone, "s3:GetObject"))}, nil))

		written := parkedPut(t, s, bucketpolicystore.Input{Bucket: bucketID, Tenant: tenantID, Policy: doc(allow(everyone, "s3:PutObject"))}, func() {
			require.NoError(t, bucketpostgres.New(pool).Delete(t.Context(), bucketID), "the deletion does not wait for the Put")
		})

		require.ErrorIs(t, written, store.ErrInvalidArgument)
		_, err := s.Get(t.Context(), bucketID)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		_, principals := indexRows(t, bucketID)
		require.Empty(t, principals)
	})

	t.Run("concurrent Puts and Deletes of one bucket never deadlock", func(t *testing.T) {
		tenantID := fx.tenant(t)
		fx.principal(t, tenantID, "any-user")
		bucketID := fx.bucket(t, tenantID)
		in := bucketpolicystore.Input{Bucket: bucketID, Tenant: tenantID, Policy: doc(allow(only("any-user"), "s3:GetObject"), allow(everyone, "s3:ListBucket"))}
		for i := range 100 {
			require.NoError(t, s.Put(t.Context(), in, nil))
			var wg sync.WaitGroup
			var putErr, deleteErr error
			wg.Add(2)
			go func() { defer wg.Done(); putErr = s.Put(t.Context(), in, nil) }()
			go func() { defer wg.Done(); deleteErr = s.Delete(t.Context(), bucketID, nil) }()
			wg.Wait()
			require.NoError(t, putErr, "round %d", i)
			// A Delete that runs after the Put's commit deletes it; one that read
			// no row because the Put had not committed finds nothing to delete.
			if deleteErr != nil {
				require.ErrorIs(t, deleteErr, store.ErrRecordNotFound, "round %d", i)
			}
		}
	})

	t.Run("a Put naming a principal removed while it runs succeeds and is stored", func(t *testing.T) {
		// The removal strips alice from the policy it lists; the Put read the
		// principals before the removal committed and writes after it, so its
		// document, naming alice, is the one stored. Evaluation skips a removed
		// principal.
		tenantID := fx.tenant(t)
		fx.principal(t, tenantID, "alice")
		bucketID := fx.bucket(t, tenantID)
		require.NoError(t, s.Put(t.Context(), bucketpolicystore.Input{Bucket: bucketID, Tenant: tenantID, Policy: doc(allow(only("alice"), "s3:GetObject"), allow(everyone, "s3:GetObject"))}, nil))
		late := doc(allow(only("alice"), "s3:PutObject"), allow(everyone, "s3:GetObject"))

		written := parkedPut(t, s, bucketpolicystore.Input{Bucket: bucketID, Tenant: tenantID, Policy: late}, func() {
			require.NoError(t, principalpostgres.New(pool).Tombstone(t.Context(), tenantID, "alice", func(ctx context.Context) error {
				recs, err := s.ListByPrincipal(ctx, tenantID, "alice")
				if err != nil {
					return err
				}
				for _, rec := range recs {
					if err := s.Put(ctx, bucketpolicystore.Input{Bucket: rec.Bucket, Tenant: tenantID, Policy: doc(allow(everyone, "s3:GetObject"))}, nil); err != nil {
						return err
					}
				}
				return nil
			}), "the removal does not wait for the Put")
		})

		require.NoError(t, written)
		rec, err := s.Get(t.Context(), bucketID)
		require.NoError(t, err)
		require.Equal(t, late, rec.Policy)
	})
}

// parkedPut runs a Put that stops inside its callback, runs meanwhile while it
// is stopped, and then lets the Put finish and returns its error. The Put is
// bounded so a write that waits on it fails the test instead of hanging it.
func parkedPut(t *testing.T, s bucketpolicystore.Store, in bucketpolicystore.Input, meanwhile func()) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), htestutil.WaitTimeout)
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- s.Put(ctx, in, func(context.Context, *bucketpolicystore.Record) error {
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("the Put returned before its callback ran: %v", err)
	}
	meanwhile()
	close(release)
	return <-done
}
