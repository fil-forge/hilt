package bucketpolicy_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	"github.com/fil-forge/hilt/internal/testutil"
	accesskeysvc "github.com/fil-forge/hilt/pkg/api/service/accesskey"
	bucketpolicysvc "github.com/fil-forge/hilt/pkg/api/service/bucketpolicy"
	principalsvc "github.com/fil-forge/hilt/pkg/api/service/principal"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	bucketpolicypostgres "github.com/fil-forge/hilt/pkg/store/bucketpolicy/postgres"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	principalstore "github.com/fil-forge/hilt/pkg/store/principal"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// blockingSwarf never answers a publish: it blocks until the context is done
// and reports why, standing in for a revocation service that hangs.
type blockingSwarf struct{}

func (blockingSwarf) PublishBatch(ctx context.Context, _ ucan.Issuer, _ []ucan.Delegation) error {
	<-ctx.Done()
	return ctx.Err()
}

// rejectingPolicies fails every Put with err, standing in for the store
// refusing the document.
type rejectingPolicies struct {
	bucketpolicystore.Store
	err error
}

func (r *rejectingPolicies) Put(context.Context, bucketpolicystore.Input, func(context.Context, *bucketpolicystore.Record) error) (string, error) {
	return "", r.err
}

// parkedPolicies holds Put until resume is closed, closing reached when it
// gets there. It parks before the wrapped store takes its lock, so the write
// has validated its document and holds nothing.
type parkedPolicies struct {
	bucketpolicystore.Store
	reached chan struct{}
	resume  chan struct{}
}

func (p *parkedPolicies) Put(ctx context.Context, in bucketpolicystore.Input, fn func(context.Context, *bucketpolicystore.Record) error) (string, error) {
	close(p.reached)
	<-p.resume
	return p.Store.Put(ctx, in, fn)
}

// growingPrincipals records a new principal for the tenant right after the
// first ListIDsByTenant answers, so the list a write takes before the bucket lock
// and the one its store callback takes differ: it stands in for a principal
// created in that gap. added, when set, runs once the principal exists.
type growingPrincipals struct {
	principalstore.Store
	late   string
	added  func()
	listed bool
}

func (g *growingPrincipals) ListIDsByTenant(ctx context.Context, tenant did.DID) ([]string, error) {
	ids, err := g.Store.ListIDsByTenant(ctx, tenant)
	if err != nil || g.listed {
		return ids, err
	}
	g.listed = true
	if err := g.Store.Add(ctx, tenant, g.late); err != nil {
		return nil, err
	}
	if g.added != nil {
		g.added()
	}
	return ids, nil
}

// gatedPrincipals holds the nth ListIDsByTenant until resume is closed, closing
// reached when it gets there; with after set it holds once that call has
// returned. A policy write makes that call from inside the policy store's
// write, so the gate parks the write holding one store and about to read the
// other, or having read it.
type gatedPrincipals struct {
	principalstore.Store
	mu      sync.Mutex
	calls   int
	nth     int
	after   bool
	reached chan struct{}
	resume  chan struct{}
}

func (g *gatedPrincipals) ListIDsByTenant(ctx context.Context, tenant did.DID) ([]string, error) {
	g.mu.Lock()
	hold := false
	g.calls++
	if g.calls == g.nth {
		hold = true
	}
	g.mu.Unlock()
	if hold && !g.after {
		close(g.reached)
		<-g.resume
	}
	ids, err := g.Store.ListIDsByTenant(ctx, tenant)
	if hold && g.after {
		close(g.reached)
		<-g.resume
	}
	return ids, err
}

type deps struct {
	svc     *bucketpolicysvc.Service
	pool    *pgxpool.Pool
	tenants *tenantpostgres.Store
	// providerID is the provider the tenant's buckets are placed with.
	providerID  did.DID
	buckets     *bucketpostgres.Store
	policies    *bucketpolicypostgres.Store
	principals  *principalpostgres.Store
	accessKeys  *accesskeypostgres.Store
	delegations *delegationpostgres.Store
	secrets     *vaultmemory.Store
	swarf       *testutil.FakeSwarf
	tenantID    did.DID
	tenant      ucan.Issuer
	otherTenant did.DID
	// photos is the tenant's bucket; archive is a bucket every key holds a
	// delegation over, so a removal always has something to revoke.
	photos, archive did.DID
	// keys maps each principal-bound key to its principal.
	keys map[did.DID]string
}

// setup wires the service over a fresh database with two tenants and one
// bucket, "photos", owned by "tenant-1", whose key is in the vault so the grant
// rotator can sign as it. wrapPrincipals, when given, wraps the principal
// store the service is built over.
func setup(t *testing.T, wrapPrincipals ...func(principalstore.Store) principalstore.Store) deps {
	t.Helper()
	ctx := t.Context()
	pool := testutil.PostgresOrSkip(t)
	tenants := tenantpostgres.New(pool)
	providerID := testutil.RandomDID(t)
	require.NoError(t, providerpostgres.New(pool).Add(ctx, providerID, "us-east-1", nil))
	tenantID, otherTenant := testutil.RandomDID(t), testutil.RandomDID(t)
	require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", tenant.Active))
	require.NoError(t, tenants.Add(ctx, otherTenant, "tenant-2", tenant.Active))

	d := deps{
		pool:        pool,
		tenants:     tenants,
		providerID:  providerID,
		buckets:     bucketpostgres.New(pool),
		policies:    bucketpolicypostgres.New(pool),
		principals:  principalpostgres.New(pool),
		accessKeys:  accesskeypostgres.New(pool),
		delegations: delegationpostgres.New(pool),
		secrets:     vaultmemory.New(),
		swarf:       &testutil.FakeSwarf{},
		tenantID:    tenantID,
		otherTenant: otherTenant,
		photos:      testutil.RandomDID(t),
		archive:     testutil.RandomDID(t),
		keys:        map[did.DID]string{},
	}
	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	require.NoError(t, d.secrets.Write(ctx, vault.TenantKeyPath(tenantID), signer.Bytes()))
	d.tenant = multikey.NewIssuer(tenantID, signer)
	require.NoError(t, d.buckets.Add(ctx, d.photos, tenantID, providerID, "photos"))
	var principals principalstore.Store = d.principals
	for _, wrap := range wrapPrincipals {
		principals = wrap(principals)
	}
	d.svc = bucketpolicysvc.New(zap.NewNop(), tenants, d.buckets, principals, d.policies, d.rotator(d.swarf))
	return d
}

// hookedKeys runs before once, when the first key creation's task builds the
// write of its key: the task has read everything it reads and has written
// nothing.
type hookedKeys struct {
	accesskeystore.Store
	before func()
	once   sync.Once
}

func (h *hookedKeys) AddStatement(in accesskeystore.Input) (store.Statement, error) {
	h.once.Do(h.before)
	return h.Store.AddStatement(in)
}

// keyService returns the access-key service over d's database and the task
// runner its creations and deletions run on. before, when not nil, runs once,
// as hookedKeys runs it.
func (d deps) keyService(t *testing.T, before func()) (*accesskeysvc.Service, *taskrunner.Runner) {
	t.Helper()
	runner := testutil.StartServiceTasks(t, d.pool, d.secrets, d.swarf, func(deps *tenantqueue.Deps) {
		if before != nil {
			deps.AccessKeys = &hookedKeys{Store: deps.AccessKeys, before: before}
		}
	})
	return accesskeysvc.New(zap.NewNop(), d.tenants, d.accessKeys, d.principals, d.buckets, d.secrets, runner), runner
}

// rotator builds a grant rotator over the stores publishing to swarf.
func (d deps) rotator(swarf grant.RevocationPublisher) *grant.Rotator {
	return grant.NewRotator(zap.NewNop(), d.delegations, d.accessKeys, d.secrets, swarf)
}

// principal records the principals, each with one key, so a rotation of the
// principal is observable.
func (d deps) principal(t *testing.T, ids ...string) {
	t.Helper()
	for _, id := range ids {
		require.NoError(t, d.principals.Add(t.Context(), d.tenantID, id))
		d.key(t, id)
	}
}

// key stores a key bound to the principal, holding one delegation over
// archive and nothing over photos.
func (d deps) key(t *testing.T, principal string) did.DID {
	t.Helper()
	ctx := t.Context()
	signer, err := ed25519.Generate()
	require.NoError(t, err)
	id := signer.KeyDID()
	require.NoError(t, d.accessKeys.Add(ctx, accesskeystore.Input{
		ID: id, Tenant: d.tenantID, Name: fmt.Sprintf("key-%d", len(d.keys)), Principal: &principal,
	}))
	dels, err := grant.Issue(d.tenant, id, []did.DID{d.archive}, []string{"s3:GetObject"}, nil)
	require.NoError(t, err)
	require.NoError(t, d.delegations.PutBatch(ctx, dels))
	d.keys[id] = principal
	return id
}

// over returns the commands the key holds over the bucket, sorted.
func (d deps) over(t *testing.T, key, bucket did.DID) []string {
	t.Helper()
	var out []string
	for _, dlg := range d.held(t, key) {
		if dlg.Subject() == bucket {
			out = append(out, dlg.Command().String())
		}
	}
	slices.Sort(out)
	return out
}

// granted returns the principals whose keys hold something over photos, sorted.
func (d deps) granted(t *testing.T) []string {
	t.Helper()
	var out []string
	for key, principal := range d.keys {
		if len(d.over(t, key, d.photos)) > 0 {
			out = append(out, principal)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// commandsFor returns the Forge commands the actions map to, sorted.
func commandsFor(actions ...string) []string {
	var out []string
	for _, c := range s3perm.CommandsFor(actions...) {
		out = append(out, c.String())
	}
	slices.Sort(out)
	return out
}

// rotated returns the principals whose keys' delegations were revoked, sorted.
func (d deps) rotated() []string {
	var out []string
	for _, r := range d.swarf.Revocations() {
		out = append(out, d.keys[r.Delegation.Audience()])
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// held returns the delegations the key holds.
func (d deps) held(t *testing.T, key did.DID) []ucan.Delegation {
	t.Helper()
	page, err := d.delegations.ListByAudience(t.Context(), key)
	require.NoError(t, err)
	return page.Results
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

// createOnly is the condition of a first write: the bucket has no policy.
var createOnly = bucketpolicysvc.WithCondition(bucketpolicysvc.IfNoneMatch("*"))

func ptr(s string) *string { return &s }

func TestWriteCondition(t *testing.T) {
	ctx := t.Context()
	d := setup(t)
	d.principal(t, "user-1")
	document := doc(allow(only("user-1"), "s3:GetObject"))

	t.Run("a second condition is refused", func(t *testing.T) {
		_, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", document, createOnly, bucketpolicysvc.WithCondition(bucketpolicysvc.IfMatch(`"x"`)))
		require.ErrorIs(t, err, bucketpolicysvc.ErrInvalidPrecondition)
		_, err = d.policies.Get(ctx, d.photos)
		require.ErrorIs(t, err, store.ErrRecordNotFound, "nothing is written")
	})

	t.Run("If-None-Match takes only *", func(t *testing.T) {
		_, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", document, bucketpolicysvc.WithCondition(bucketpolicysvc.IfNoneMatch(`"x"`)))
		require.ErrorIs(t, err, bucketpolicysvc.ErrInvalidPrecondition)
	})
}

func TestPutAndGet(t *testing.T) {
	ctx := t.Context()

	t.Run("creates the first policy and reads it back with its ETag", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		document := doc(allow(only("user-1"), "s3:GetObject"))

		etag, created, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", document, createOnly)
		require.NoError(t, err)
		require.True(t, created)
		require.Equal(t, s3bkt.ETag(document), etag)

		rec, err := d.policies.Get(ctx, d.photos)
		require.NoError(t, err)
		require.Equal(t, etag, rec.ETag)
		require.Equal(t, document, rec.Policy)
	})

	t.Run("a write without a precondition creates or replaces", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		first := doc(allow(only("user-1"), "s3:GetObject"))
		etag, created, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", first)
		require.NoError(t, err)
		require.True(t, created)
		require.Equal(t, s3bkt.ETag(first), etag)

		second := doc(allow(only("user-1"), "s3:PutObject"))
		etag, created, err = d.svc.Write(ctx, d.tenantID, d.photos, "photos", second)
		require.NoError(t, err)
		require.False(t, created)
		require.Equal(t, s3bkt.ETag(second), etag)
		rec, err := d.policies.Get(ctx, d.photos)
		require.NoError(t, err)
		require.Equal(t, second, rec.Policy)
	})

	t.Run("a create over an existing policy fails and writes nothing", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		first := doc(allow(only("user-1"), "s3:GetObject"))
		etag, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", first, createOnly)
		require.NoError(t, err)

		_, _, err = d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:PutObject")), createOnly)
		require.ErrorIs(t, err, bucketpolicysvc.ErrPreconditionFailed)

		rec, err := d.policies.Get(ctx, d.photos)
		require.NoError(t, err)
		require.Equal(t, etag, rec.ETag)
	})

	t.Run("a replace with a stale ETag logs the stored ETag and the one sent", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		etag, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:GetObject")), createOnly)
		require.NoError(t, err)

		tenants := d.tenants
		core, logs := observer.New(zapcore.WarnLevel)
		svc := bucketpolicysvc.New(zap.New(core), tenants, d.buckets, d.principals, d.policies, d.rotator(d.swarf))

		stale := `"any-stale-etag"`
		_, _, err = svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:PutObject")), bucketpolicysvc.WithCondition(bucketpolicysvc.IfMatch(stale)))
		require.ErrorIs(t, err, bucketpolicysvc.ErrPreconditionFailed)

		entries := logs.FilterMessage("bucket policy precondition failed").All()
		require.Len(t, entries, 1)
		require.Equal(t, map[string]any{
			"bucket": "photos",
			"error":  fmt.Sprintf("policy ETag is %s, not %s: %s", etag, stale, store.ErrPreconditionFailed),
		}, entries[0].ContextMap())
	})

	t.Run("a replace with a stale ETag fails and writes nothing", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		etag, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:GetObject")), createOnly)
		require.NoError(t, err)

		stale := `"deadbeef"`
		_, _, err = d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:PutObject")), bucketpolicysvc.WithCondition(bucketpolicysvc.IfMatch(stale)))
		require.ErrorIs(t, err, bucketpolicysvc.ErrPreconditionFailed)

		rec, err := d.policies.Get(ctx, d.photos)
		require.NoError(t, err)
		require.Equal(t, etag, rec.ETag)
	})

	t.Run("a replace with the current ETag replaces the document", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		etag, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:GetObject")), createOnly)
		require.NoError(t, err)

		next := doc(allow(only("user-1"), "s3:GetObject", "s3:PutObject"))
		newETag, created, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", next, bucketpolicysvc.WithCondition(bucketpolicysvc.IfMatch(etag)))
		require.NoError(t, err)
		require.False(t, created)
		require.NotEqual(t, etag, newETag)

		rec, err := d.policies.Get(ctx, d.photos)
		require.NoError(t, err)
		require.Equal(t, next, rec.Policy)
	})

	t.Run("rejects a document the caller may not store", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")

		_, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("ghost"), "s3:GetObject")), createOnly)
		require.ErrorIs(t, err, s3bkt.ErrInvalidPolicy)

		_, _, err = d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:CreateBucket")), createOnly)
		require.ErrorIs(t, err, s3bkt.ErrInvalidPolicy)

		_, _, err = d.svc.Write(ctx, d.tenantID, d.photos, "photos", s3bkt.PolicyDocument{}, createOnly)
		require.ErrorIs(t, err, s3bkt.ErrInvalidPolicy)

		_, err = d.policies.Get(ctx, d.photos)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})
}

func TestRotations(t *testing.T) {
	ctx := t.Context()

	t.Run("a create issues the granted principals' keys their delegations and publishes nothing", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2", "user-3")

		_, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos",
			doc(allow(only("user-1", "user-2"), "s3:GetObject")), createOnly)
		require.NoError(t, err)
		require.Empty(t, d.swarf.Revocations(), "a first grant over the bucket revokes nothing")
		require.Equal(t, []string{"user-1", "user-2"}, d.granted(t))

		for key, principal := range d.keys {
			if principal == "user-3" {
				require.Empty(t, d.over(t, key, d.photos))
				continue
			}
			require.Equal(t, commandsFor("s3:GetObject"), d.over(t, key, d.photos))
			require.Equal(t, commandsFor("s3:GetObject"), d.over(t, key, d.archive), "other buckets are untouched")
		}
	})

	t.Run("a principal with several keys has each rotated", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2")
		second := d.key(t, "user-1")

		etag, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:GetObject")), createOnly)
		require.NoError(t, err)
		require.Equal(t, commandsFor("s3:GetObject"), d.over(t, second, d.photos))

		_, _, err = d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:PutObject")), bucketpolicysvc.WithCondition(bucketpolicysvc.IfMatch(etag)))
		require.NoError(t, err)
		require.Len(t, d.swarf.Revocations(), 2, "one revocation per key over the bucket")
		require.Equal(t, 1, d.swarf.Calls(), "every revocation of one write goes in one request")
		require.Equal(t, []string{"user-1"}, d.rotated())
		require.Equal(t, commandsFor("s3:PutObject"), d.over(t, second, d.photos))
	})

	t.Run("a replace rotates only the principals whose actions changed", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2", "user-3")
		etag, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos",
			doc(allow(only("user-1", "user-2"), "s3:GetObject")), createOnly)
		require.NoError(t, err)
		d.swarf.Reset()

		// user-1 keeps GetObject, user-2 gains PutObject, user-3 gains nothing.
		_, _, err = d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(
			allow(only("user-1"), "s3:GetObject"),
			allow(only("user-2"), "s3:GetObject", "s3:PutObject"),
		), bucketpolicysvc.WithCondition(bucketpolicysvc.IfMatch(etag)))
		require.NoError(t, err)
		require.Equal(t, []string{"user-2"}, d.rotated())
		for key, principal := range d.keys {
			switch principal {
			case "user-1":
				require.Equal(t, commandsFor("s3:GetObject"), d.over(t, key, d.photos))
			case "user-2":
				require.Equal(t, commandsFor("s3:GetObject", "s3:PutObject"), d.over(t, key, d.photos))
			default:
				require.Empty(t, d.over(t, key, d.photos))
			}
		}
	})

	t.Run("the wildcard fans out to every principal of the tenant", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2", "user-3")

		_, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos",
			doc(allow(everyone, "s3:ListBucket")), createOnly)
		require.NoError(t, err)
		require.Equal(t, []string{"user-1", "user-2", "user-3"}, d.granted(t))
	})

	t.Run("the wildcard reaches a principal created while the write was under way", func(t *testing.T) {
		// "user-2" appears after the pre-lock list and before the write commits.
		// Its first authorize waits on the bucket lock this write holds, so the
		// rotation from inside the lock still reaches it in time.
		// user-2's key is created with the principal, for the rotation to find.
		var d deps
		d = setup(t, func(s principalstore.Store) principalstore.Store {
			return &growingPrincipals{Store: s, late: "user-2", added: func() { d.key(t, "user-2") }}
		})
		d.principal(t, "user-1")

		_, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos",
			doc(allow(everyone, "s3:ListBucket")), createOnly)
		require.NoError(t, err)
		require.Equal(t, []string{"user-1", "user-2"}, d.granted(t))
	})

	t.Run("a Deny narrowing the wildcard rotates only the denied principal", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2", "user-3")
		etag, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos",
			doc(allow(everyone, "s3:ListBucket")), createOnly)
		require.NoError(t, err)
		d.swarf.Reset()

		_, _, err = d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(
			allow(everyone, "s3:ListBucket"),
			deny(only("user-2"), "s3:ListBucket"),
		), bucketpolicysvc.WithCondition(bucketpolicysvc.IfMatch(etag)))
		require.NoError(t, err)
		require.Equal(t, []string{"user-2"}, d.rotated())
		require.Equal(t, []string{"user-1", "user-3"}, d.granted(t))
	})

	t.Run("a delete rotates every principal the policy reached", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2")
		etag, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos",
			doc(allow(only("user-1", "user-2"), "s3:GetObject")), createOnly)
		require.NoError(t, err)
		d.swarf.Reset()

		require.NoError(t, d.svc.Remove(ctx, d.tenantID, d.photos, "photos", &etag))
		require.Equal(t, []string{"user-1", "user-2"}, d.rotated())
		require.Equal(t, 1, d.swarf.Calls())
		require.Empty(t, d.granted(t))

		_, err = d.policies.Get(ctx, d.photos)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})

	t.Run("a delete with a stale ETag fails, publishes nothing and keeps the policy", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		etag, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:GetObject")), createOnly)
		require.NoError(t, err)
		d.swarf.Reset()

		require.ErrorIs(t, d.svc.Remove(ctx, d.tenantID, d.photos, "photos", ptr(`"stale"`)), bucketpolicysvc.ErrPreconditionFailed)
		require.Empty(t, d.rotated())

		rec, err := d.policies.Get(ctx, d.photos)
		require.NoError(t, err)
		require.Equal(t, etag, rec.ETag)
	})

	t.Run("a publish failure leaves the old document and the delegations in place", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2")
		etag, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:GetObject")), createOnly)
		require.NoError(t, err)
		before := map[did.DID][]string{}
		for key := range d.keys {
			before[key] = links(d.held(t, key))
		}
		d.swarf.Err = errors.New("swarf unreachable")

		_, _, err = d.svc.Write(ctx, d.tenantID, d.photos, "photos",
			doc(allow(only("user-1", "user-2"), "s3:GetObject", "s3:PutObject")), bucketpolicysvc.WithCondition(bucketpolicysvc.IfMatch(etag)))
		require.ErrorContains(t, err, "swarf unreachable")

		rec, err := d.policies.Get(ctx, d.photos)
		require.NoError(t, err)
		require.Equal(t, etag, rec.ETag, "the old document must survive")
		require.Equal(t, doc(allow(only("user-1"), "s3:GetObject")), rec.Policy)
		for key, want := range before {
			require.Equal(t, want, links(d.held(t, key)), "the delegations must survive")
		}

		require.ErrorContains(t, d.svc.Remove(ctx, d.tenantID, d.photos, "photos", &etag), "swarf unreachable")
		_, err = d.policies.Get(ctx, d.photos)
		require.NoError(t, err, "a failed delete must leave the policy")
	})

	t.Run("a batch of publishes that never answer fails the write at the batch deadline", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2", "user-3")
		old := doc(allow(only("user-1"), "s3:GetObject"))
		etag, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", old, createOnly)
		require.NoError(t, err)

		tenants := d.tenants
		svc := bucketpolicysvc.New(zap.NewNop(), tenants, d.buckets, d.principals, d.policies, d.rotator(blockingSwarf{}))

		start := time.Now()
		// user-1's actions change, so the write has revocations to publish.
		_, _, err = svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(everyone, "s3:PutObject")), bucketpolicysvc.WithCondition(bucketpolicysvc.IfMatch(etag)))
		elapsed := time.Since(start)
		// The batch deadline is reported as the retryable conflict the lock
		// timeout it runs under would be.
		require.ErrorIs(t, err, bucketpolicysvc.ErrConcurrentChange)
		require.Less(t, elapsed, grant.BatchTimeout+2*time.Second,
			"the write must give up at the batch deadline")
		require.Less(t, elapsed, store.LockTimeout, "the write must release the bucket before a reader gives up")

		rec, err := d.policies.Get(ctx, d.photos)
		require.NoError(t, err)
		require.Equal(t, old, rec.Policy, "the old document must survive")
		require.Equal(t, etag, rec.ETag)
	})

	t.Run("a principal removed between validation and the write is an invalid policy", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		tenants := d.tenants
		// The store's index foreign key refuses a document naming a principal
		// that is gone; rejectingPolicies stands in for that refusal.
		policies := &rejectingPolicies{Store: d.policies, err: store.ErrInvalidArgument}
		svc := bucketpolicysvc.New(zap.NewNop(), tenants, d.buckets, d.principals, policies, d.rotator(d.swarf))

		_, _, err := svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:GetObject")), createOnly)
		require.ErrorIs(t, err, s3bkt.ErrInvalidPolicy)
	})

	t.Run("a replace whose publish fails writes nothing", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		old := doc(allow(only("user-1"), "s3:GetObject"))
		etag, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", old, createOnly)
		require.NoError(t, err)
		d.swarf.Err = errors.New("swarf unreachable")

		_, _, err = d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:PutObject")), bucketpolicysvc.WithCondition(bucketpolicysvc.IfMatch(etag)))
		require.ErrorContains(t, err, "swarf unreachable")

		rec, err := d.policies.Get(ctx, d.photos)
		require.NoError(t, err)
		require.Equal(t, old, rec.Policy)
		for key := range d.keys {
			require.Equal(t, commandsFor("s3:GetObject"), d.over(t, key, d.photos))
		}
	})
}

// TestConcurrentPolicyWriteAndPrincipalRemoval runs a policy write against the
// removal of a principal it names: the write holds the bucket while it reads
// and locks the principals, and the removal rewrites that bucket's policy. The
// removal strips its policies before it locks the principal, so neither waits
// on what the other holds and both return: the write commits, and the removal
// finishes or reports a conflict its caller repeats.
func TestConcurrentPolicyWriteAndPrincipalRemoval(t *testing.T) {
	reached, resume := make(chan struct{}), make(chan struct{})
	d := setup(t, func(s principalstore.Store) principalstore.Store {
		// The second list is the one the policy store's callback makes; the
		// first runs before the write takes the bucket.
		return &gatedPrincipals{Store: s, nth: 2, reached: reached, resume: resume}
	})
	d.principal(t, "user-1")

	tenants := d.tenants
	started := make(chan struct{})
	// A principal removal revokes its keys' delegations first, so the first
	// publish says the removal has started and is about to strip its policies.
	d.swarf.OnPublish = sync.OnceFunc(func() { close(started) })
	principals := principalsvc.New(zap.NewNop(), tenants, d.principals, d.policies,
		d.accessKeys, d.delegations, d.secrets, d.swarf, d.rotator(d.swarf))

	put := make(chan error, 1)
	go func() {
		_, _, err := d.svc.Write(context.Background(), d.tenantID, d.photos, "photos",
			doc(allow(only("user-1"), "s3:GetObject")), createOnly)
		put <- err
	}()
	<-reached // the write holds the policy store and is about to read the principals

	del := make(chan error, 1)
	go func() { del <- principals.Delete(context.Background(), "tenant-1", "user-1") }()
	<-started // the removal has revoked and is about to read the policies

	close(resume)

	deadline := time.After(30 * time.Second)
	conflicted := false
	for range 2 {
		select {
		case err := <-put:
			require.NoError(t, err)
		case err := <-del:
			if err != nil {
				require.ErrorIs(t, err, principalsvc.ErrConcurrentChange)
				conflicted = true
			}
		case <-deadline:
			t.Fatal("the policy write and the principal removal deadlocked")
		}
	}
	if conflicted {
		require.NoError(t, principals.Delete(t.Context(), "tenant-1", "user-1"), "a repeat finishes the removal")
	}

	// The removal ran last and took the policy with it: its only statement
	// named the principal that is gone.
	_, err := d.policies.Get(t.Context(), d.photos)
	require.ErrorIs(t, err, store.ErrRecordNotFound)
}

// TestPolicyWriteAfterPrincipalRemoval removes a principal after a policy
// write naming it has validated its document and before the write reaches the
// store. The write must fail, so a principal revived under the same id starts
// named in no statement.
func TestPolicyWriteAfterPrincipalRemoval(t *testing.T) {
	ctx := t.Context()
	d := setup(t)
	d.principal(t, "user-1")
	tenants := d.tenants
	policies := &parkedPolicies{Store: d.policies, reached: make(chan struct{}), resume: make(chan struct{})}
	svc := bucketpolicysvc.New(zap.NewNop(), tenants, d.buckets, d.principals, policies, d.rotator(d.swarf))
	principals := principalsvc.New(zap.NewNop(), tenants, d.principals, d.policies,
		d.accessKeys, d.delegations, d.secrets, d.swarf, d.rotator(d.swarf))

	put := make(chan error, 1)
	go func() {
		_, _, err := svc.Write(context.Background(), d.tenantID, d.photos, "photos",
			doc(allow(only("user-1"), "s3:GetObject")), createOnly)
		put <- err
	}()
	<-policies.reached
	require.NoError(t, principals.Delete(ctx, "tenant-1", "user-1"))
	close(policies.resume)
	require.ErrorIs(t, <-put, s3bkt.ErrInvalidPolicy)

	_, created, err := principals.Create(ctx, "tenant-1", "user-1")
	require.NoError(t, err)
	require.True(t, created)
	access, err := svc.Access(ctx, "tenant-1", "user-1")
	require.NoError(t, err)
	require.Empty(t, access, "a revived principal is named in no statement")
}

// TestPrincipalAddedDuringPolicyWritePostgres adds a principal while a policy
// write granting the wildcard is parked after its callback listed the
// tenant's principals, so the write cannot rotate the new principal's keys.
// The add waits for the write to commit, and the key created for the
// principal afterwards reads the committed policy and holds its grants.
func TestPrincipalAddedDuringPolicyWritePostgres(t *testing.T) {
	ctx := t.Context()
	d := setup(t)
	tenants, principals, policies := d.tenants, d.principals, d.policies

	// The second list is the one the policy store's callback makes.
	reached, resume := make(chan struct{}), make(chan struct{})
	gated := &gatedPrincipals{Store: principals, nth: 2, after: true, reached: reached, resume: resume}
	svc := bucketpolicysvc.New(zap.NewNop(), tenants, d.buckets, gated, policies, d.rotator(d.swarf))
	keys, _ := d.keyService(t, nil)

	written, added := testutil.RequireWaitsForWriter(t,
		func(entered chan<- struct{}, release <-chan struct{}) error {
			go func() { <-reached; close(entered) }()
			go func() { <-release; close(resume) }()
			_, _, err := svc.Write(context.Background(), d.tenantID, d.photos, "photos", doc(allow(everyone, "s3:GetObject")), createOnly)
			return err
		},
		func() error {
			return principals.Add(context.Background(), d.tenantID, "user-2")
		})
	require.NoError(t, written)
	require.NoError(t, added)

	rec, _, err := keys.Create(ctx, "tenant-1", "key", nil, nil, new("user-2"), nil)
	require.NoError(t, err)
	require.Equal(t, commandsFor("s3:GetObject"), d.over(t, rec.ID, d.photos), "the key is created from the committed policy")
}

// afterLock calls after once, when the first WithLock returns: under a policy
// write that is after the rotation and before the document is written, with
// the write's transaction still open.
type afterLock struct {
	principalstore.Store
	after func()
}

func (a *afterLock) WithLock(ctx context.Context, tenant did.DID, ids []string, fn func(context.Context) error) error {
	err := a.Store.WithLock(ctx, tenant, ids, fn)
	if a.after != nil {
		after := a.after
		a.after = nil
		after()
	}
	return err
}

// TestPolicyWriteCancelledAfterRotationPostgres cancels a policy write once
// its rotation has run and its principal lock call has returned, before the
// document is written. The rotation's delegation writes joined the policy
// transaction, so the old policy stays with its own grants: a principal is
// never left with the grants of a policy that was not stored.
func TestPolicyWriteCancelledAfterRotationPostgres(t *testing.T) {
	ctx := t.Context()
	d := setup(t)
	require.NoError(t, d.principals.Add(ctx, d.tenantID, "user-1"))
	key := testutil.RandomDID(t)
	user := "user-1"
	require.NoError(t, d.accessKeys.Add(ctx, accesskeystore.Input{ID: key, Tenant: d.tenantID, Name: "laptop", Principal: &user}))

	rotator := grant.NewRotator(zap.NewNop(), d.delegations, d.accessKeys, d.secrets, d.swarf)
	svc := bucketpolicysvc.New(zap.NewNop(), d.tenants, d.buckets, d.principals, d.policies, rotator)
	etagA, _, err := svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:GetObject", "s3:ListBucket")), createOnly)
	require.NoError(t, err)
	require.Equal(t, commandsFor("s3:GetObject", "s3:ListBucket"), d.over(t, key, d.photos))

	writeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	principals := &afterLock{Store: d.principals, after: cancel}
	cancelling := bucketpolicysvc.New(zap.NewNop(), d.tenants, d.buckets, principals, d.policies, rotator)
	_, _, err = cancelling.Write(writeCtx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:ListBucket")), bucketpolicysvc.WithCondition(bucketpolicysvc.IfMatch(etagA)))
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, principals.after, "the rotation ran")

	rec, err := d.policies.Get(ctx, d.photos)
	require.NoError(t, err)
	require.Equal(t, etagA, rec.ETag, "the document was not replaced")
	require.Equal(t, commandsFor("s3:GetObject", "s3:ListBucket"), d.over(t, key, d.photos), "and the key keeps the stored policy's grants")
}

// TestKeyCreatedDuringPolicyWritePostgres creates a key for an existing
// principal while a policy write that changes what the principal may do is
// in flight, parked once its principal lock call has returned: it has listed
// the principal's keys, without the new one, and has not committed. The write
// holds the principal's row until it commits, so the creation's commit waits
// for it, finds the policies changed, and the task runs again from the
// committed policy. The key holds that policy's grants.
func TestKeyCreatedDuringPolicyWritePostgres(t *testing.T) {
	for name, tc := range map[string]struct {
		// before is the bucket's policy when the creation starts, nil for
		// none.
		before []string
		// after is the policy the write in flight stores.
		after []string
	}{
		"the first policy naming the principal": {nil, []string{"s3:GetObject"}},
		"a policy that takes an action away":    {[]string{"s3:GetObject", "s3:PutObject"}, []string{"s3:GetObject"}},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			d := setup(t)
			require.NoError(t, d.principals.Add(ctx, d.tenantID, "user-1"))
			// The principal holds a key already, so the write has a rotation to run.
			user := "user-1"
			require.NoError(t, d.accessKeys.Add(ctx, accesskeystore.Input{ID: testutil.RandomDID(t), Tenant: d.tenantID, Name: "phone", Principal: &user}))
			var opts []bucketpolicysvc.WriteOption
			if tc.before != nil {
				_, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), tc.before...)), createOnly)
				require.NoError(t, err)
			} else {
				opts = append(opts, createOnly)
			}

			keys, _ := d.keyService(t, nil)
			var created accesskeystore.Record
			written, added := testutil.RequireWaitsForWriter(t,
				func(entered chan<- struct{}, release <-chan struct{}) error {
					principals := &afterLock{Store: d.principals, after: func() { close(entered); <-release }}
					svc := bucketpolicysvc.New(zap.NewNop(), d.tenants, d.buckets, principals, d.policies,
						grant.NewRotator(zap.NewNop(), d.delegations, d.accessKeys, d.secrets, d.swarf))
					_, _, err := svc.Write(context.Background(), d.tenantID, d.photos, "photos", doc(allow(only("user-1"), tc.after...)), opts...)
					return err
				},
				func() error {
					var err error
					created, _, err = keys.Create(context.Background(), "tenant-1", "laptop", nil, nil, new("user-1"), nil)
					return err
				})
			require.NoError(t, written)
			require.NoError(t, added)
			require.Equal(t, commandsFor(tc.after...), d.over(t, created.ID, d.photos), "the key is created from the committed policy")
		})
	}
}

// TestKeyCreatedAcrossPolicyWritePostgres commits a policy write that takes
// an action away from a principal after a key creation's task has read the
// principal's policies and before the task commits. The write's rotation
// lists the principal's keys before the new one exists, so nothing rewrites
// the new key's grants: the creation's commit finds the policies changed,
// and the task runs again and issues the grants of the policy as written.
func TestKeyCreatedAcrossPolicyWritePostgres(t *testing.T) {
	ctx := t.Context()
	d := setup(t)
	require.NoError(t, d.principals.Add(ctx, d.tenantID, "user-1"))
	_, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:GetObject", "s3:PutObject")), createOnly)
	require.NoError(t, err)
	require.NotEqual(t, commandsFor("s3:GetObject"), commandsFor("s3:GetObject", "s3:PutObject"), "the two policies grant different commands")

	var wrote bool
	keys, _ := d.keyService(t, func() {
		_, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:GetObject")))
		require.NoError(t, err)
		wrote = true
	})
	created, _, err := keys.Create(ctx, "tenant-1", "laptop", nil, nil, new("user-1"), nil)
	require.NoError(t, err)
	require.True(t, wrote, "the policy was written while the creation was in flight")
	require.Equal(t, commandsFor("s3:GetObject"), d.over(t, created.ID, d.photos), "the key holds what the policy grants now, and no more")
}

// rotatingKeys parks the rotation it serves inside the keys' delegation
// locks: the read of the keys that remain, which a rotation makes under
// those locks before it stores their fresh grants, closes reached and waits
// for resume once it has its answer.
type rotatingKeys struct {
	accesskeystore.Store
	reached chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (r *rotatingKeys) ListByTenant(ctx context.Context, tenantID did.DID, opts ...accesskeystore.ListOption) ([]accesskeystore.Record, error) {
	recs, err := r.Store.ListByTenant(ctx, tenantID, opts...)
	if accesskeystore.NewListConfig(opts...).IDs != nil {
		r.once.Do(func() {
			close(r.reached)
			<-r.resume
		})
	}
	return recs, err
}

// TestKeyDeletedDuringRotationPostgres deletes a principal-bound key while a
// policy write is rewriting its grants, parked under the key's delegation
// lock: it has found the key still there and is about to store its fresh
// grants. The deletion's commit waits for the lock, so the grants the write
// stores are withdrawn with the rest and none outlives the key.
func TestKeyDeletedDuringRotationPostgres(t *testing.T) {
	ctx := t.Context()
	d := setup(t)
	require.NoError(t, d.principals.Add(ctx, d.tenantID, "user-1"))
	_, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:GetObject")), createOnly)
	require.NoError(t, err)
	keys, runner := d.keyService(t, nil)
	created, _, err := keys.Create(ctx, "tenant-1", "laptop", nil, nil, new("user-1"), nil)
	require.NoError(t, err)
	original := d.held(t, created.ID)
	require.NotEmpty(t, original)

	written, deleted := testutil.RequireWaitsForWriter(t,
		func(entered chan<- struct{}, release <-chan struct{}) error {
			rotating := &rotatingKeys{Store: d.accessKeys, reached: make(chan struct{}), resume: make(chan struct{})}
			go func() { <-rotating.reached; close(entered) }()
			go func() { <-release; close(rotating.resume) }()
			svc := bucketpolicysvc.New(zap.NewNop(), d.tenants, d.buckets, d.principals, d.policies,
				grant.NewRotator(zap.NewNop(), d.delegations, rotating, d.secrets, d.swarf))
			_, _, err := svc.Write(context.Background(), d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:GetObject", "s3:PutObject")))
			return err
		},
		func() error { return keys.Delete(context.Background(), "tenant-1", created.ID.Identifier()) })
	require.NoError(t, written)
	require.NoError(t, deleted)

	_, err = d.accessKeys.Get(ctx, created.ID)
	require.ErrorIs(t, err, store.ErrRecordNotFound)
	require.Empty(t, d.held(t, created.ID), "no grant outlives the key")
	// The write revoked the grants it replaced, and the deletion's publish
	// revokes the ones the write stored.
	testutil.AwaitPublished(t, runner, d.tenantID)
	fresh := len(commandsFor("s3:GetObject", "s3:PutObject"))
	require.Len(t, d.swarf.Revoked(), len(original)+fresh)
	for _, r := range d.swarf.Revocations() {
		require.Equal(t, created.ID, r.Delegation.Audience())
	}
}

// TestPolicyWriteToMissingBucketPostgres writes a policy for a bucket the
// caller resolved but the store has no row for, standing in for a bucket
// deleted between the lookup and the write. It is reported as a missing
// bucket.
func TestPolicyWriteToMissingBucketPostgres(t *testing.T) {
	d := setup(t)
	_, _, err := d.svc.Write(t.Context(), d.tenantID, testutil.RandomDID(t), "photos", doc(allow(everyone, "s3:ListBucket")), createOnly)
	require.ErrorIs(t, err, bucketpolicysvc.ErrBucketNotFound)
}

func TestPrincipalReads(t *testing.T) {
	ctx := t.Context()

	// twoBuckets adds a second bucket, "backups", and a policy on each: photos
	// names user-1 explicitly, backups names the wildcard and denies user-2.
	twoBuckets := func(t *testing.T) deps {
		d := setup(t)
		d.principal(t, "user-1", "user-2")
		backups := testutil.RandomDID(t)
		require.NoError(t, d.buckets.Add(ctx, backups, d.tenantID, d.providerID, "backups"))
		_, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:GetObject")), createOnly)
		require.NoError(t, err)
		onBackups := func(st s3bkt.Statement) s3bkt.Statement {
			st.Resources = s3bkt.NewStringSet(s3bkt.BucketARN("backups"))
			return st
		}
		_, _, err = d.svc.Write(ctx, d.tenantID, backups, "backups", doc(
			onBackups(allow(everyone, "s3:ListBucket")),
			onBackups(deny(only("user-2"), "s3:ListBucket")),
		), createOnly)
		require.NoError(t, err)
		return d
	}

	t.Run("lists the policies naming the principal or the wildcard, by bucket", func(t *testing.T) {
		d := twoBuckets(t)

		recs, err := d.svc.ListByPrincipal(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		require.Len(t, recs, 2)
		require.Equal(t, "backups", recs[0].BucketName)
		require.Equal(t, "photos", recs[1].BucketName)

		// user-2 is named by the wildcard on backups only.
		recs, err = d.svc.ListByPrincipal(ctx, "tenant-1", "user-2")
		require.NoError(t, err)
		require.Len(t, recs, 1)
		require.Equal(t, "backups", recs[0].BucketName)
	})

	t.Run("reports the effective actions per bucket and omits the empty ones", func(t *testing.T) {
		d := twoBuckets(t)

		access, err := d.svc.Access(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		require.Equal(t, []bucketpolicysvc.Access{
			{Name: "backups", Actions: []string{"s3:ListBucket"}},
			{Name: "photos", Actions: []string{"s3:GetObject"}},
		}, access)

		// The Deny empties user-2's set on backups, its only policy.
		access, err = d.svc.Access(ctx, "tenant-1", "user-2")
		require.NoError(t, err)
		require.Empty(t, access)
	})

	t.Run("an unknown tenant or principal is not found", func(t *testing.T) {
		d := twoBuckets(t)
		_, err := d.svc.ListByPrincipal(ctx, "missing", "user-1")
		require.ErrorIs(t, err, bucketpolicysvc.ErrTenantNotFound)
		_, err = d.svc.ListByPrincipal(ctx, "tenant-1", "ghost")
		require.ErrorIs(t, err, bucketpolicysvc.ErrPrincipalNotFound)
		_, err = d.svc.Access(ctx, "tenant-1", "ghost")
		require.ErrorIs(t, err, bucketpolicysvc.ErrPrincipalNotFound)
	})
}

// links returns the CIDs of the delegations, sorted.
func links(dels []ucan.Delegation) []string {
	var out []string
	for _, d := range dels {
		out = append(out, d.Link().String())
	}
	slices.Sort(out)
	return out
}
