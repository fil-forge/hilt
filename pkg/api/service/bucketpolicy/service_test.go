package bucketpolicy_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	"github.com/fil-forge/hilt/internal/testutil"
	accesskeysvc "github.com/fil-forge/hilt/pkg/api/service/accesskey"
	bucketpolicysvc "github.com/fil-forge/hilt/pkg/api/service/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	bucketpolicypostgres "github.com/fil-forge/hilt/pkg/store/bucketpolicy/postgres"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/revocation"
	revocationpostgres "github.com/fil-forge/hilt/pkg/store/revocation/postgres"
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

// heldSwarf is a revocation service that refuses every publish while holding
// is set, so a test can look at the revocations owed before they are
// published, and can stand in for a service that is down.
type heldSwarf struct {
	testutil.FakeSwarf
	holding atomic.Bool
}

func (h *heldSwarf) PublishBatch(ctx context.Context, revoker ucan.Issuer, revoked []ucan.Delegation) error {
	if h.holding.Load() {
		return errors.New("revocation service unavailable")
	}
	return h.FakeSwarf.PublishBatch(ctx, revoker, revoked)
}

// park closes entered and waits for release. It gives up when the test ends,
// so a test that fails while a writer is parked leaves nothing blocked.
func park(t *testing.T, entered chan<- struct{}, release <-chan struct{}) {
	close(entered)
	select {
	case <-release:
	case <-t.Context().Done():
	}
}

// commitHook lets a test act between a policy task's reads and its commit
// (see [testutil.BeforePolicyCommit]).
type commitHook struct {
	mu sync.Mutex
	// next runs on the handler's next pass, and then no more.
	next func()
	// passes counts the passes of policy handlers since the last arm.
	passes int
}

// arm makes fn run on the next pass of a policy handler, once it has read
// everything it reads and before it records a write.
func (h *commitHook) arm(fn func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.next, h.passes = fn, 0
}

func (h *commitHook) run() {
	h.mu.Lock()
	fn := h.next
	h.next = nil
	h.passes++
	h.mu.Unlock()
	if fn != nil {
		fn()
	}
}

// ran is the number of passes policy handlers have made since the last arm.
func (h *commitHook) ran() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.passes
}

type deps struct {
	svc     *bucketpolicysvc.Service
	runner  *taskrunner.Runner
	hook    *commitHook
	pool    *pgxpool.Pool
	tenants *tenantpostgres.Store
	// providerID is the provider the tenant's buckets are placed with.
	providerID  did.DID
	buckets     *bucketpostgres.Store
	policies    *bucketpolicypostgres.Store
	principals  *principalpostgres.Store
	accessKeys  *accesskeypostgres.Store
	delegations *delegationpostgres.Store
	owed        *revocationpostgres.Store
	secrets     *vaultmemory.Store
	swarf       *heldSwarf
	tenantID    did.DID
	tenant      ucan.Issuer
	otherTenant did.DID
	// photos is the tenant's bucket; archive is a bucket every key holds a
	// delegation over, so a write to photos has another bucket's grants to
	// leave alone and a removal always has something to revoke.
	photos, archive did.DID
	// keys maps each principal-bound key to its principal.
	keys map[did.DID]string
}

// setup wires the service over a fresh database with two tenants and one
// bucket, "photos", owned by "tenant-1", whose key is in the vault so the
// policy tasks can sign as it, and a running task runner with the service's
// handlers. Each wrap replaces what queue-tenant's handlers work through.
func setup(t *testing.T, wrap ...func(*tenantqueue.Deps)) deps {
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
		hook:        &commitHook{},
		pool:        pool,
		tenants:     tenants,
		providerID:  providerID,
		buckets:     bucketpostgres.New(pool),
		policies:    bucketpolicypostgres.New(pool),
		principals:  principalpostgres.New(pool),
		accessKeys:  accesskeypostgres.New(pool),
		delegations: delegationpostgres.New(pool),
		owed:        revocationpostgres.New(pool),
		secrets:     vaultmemory.New(),
		swarf:       &heldSwarf{},
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
	d.runner = testutil.StartServiceTasks(t, pool, d.secrets, d.swarf, append(wrap, testutil.BeforePolicyCommit(d.hook.run))...)
	d.svc = bucketpolicysvc.New(zap.NewNop(), tenants, d.buckets, d.principals, d.policies, d.runner)
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

// keyService returns the access-key service over d's database and runner.
func (d deps) keyService() *accesskeysvc.Service {
	return accesskeysvc.New(zap.NewNop(), d.tenants, d.accessKeys, d.principals, d.buckets, d.secrets, d.runner)
}

// principal records the principals, each with one key, so a change to what
// the principal may do is observable.
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

// keysOf returns the keys bound to the principal.
func (d deps) keysOf(principal string) []did.DID {
	var out []did.DID
	for key, p := range d.keys {
		if p == principal {
			out = append(out, key)
		}
	}
	return out
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

// heldOver returns the CIDs of the delegations the key holds over the
// bucket, sorted.
func (d deps) heldOver(t *testing.T, key, bucket did.DID) []string {
	t.Helper()
	var over []ucan.Delegation
	for _, dlg := range d.held(t, key) {
		if dlg.Subject() == bucket {
			over = append(over, dlg)
		}
	}
	return links(over)
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

// requireGrants requires that every key of the principals holds exactly the
// commands the actions map to over photos, and still holds what it held
// over archive.
func (d deps) requireGrants(t *testing.T, actions []string, principals ...string) {
	t.Helper()
	for _, p := range principals {
		keys := d.keysOf(p)
		require.NotEmpty(t, keys, p)
		for _, key := range keys {
			require.Equal(t, commandsFor(actions...), d.over(t, key, d.photos), "%s over photos", p)
			require.Equal(t, commandsFor("s3:GetObject"), d.over(t, key, d.archive), "%s over another bucket", p)
		}
	}
}

// commandsFor returns the Forge commands the actions map to, sorted, and nil
// for no actions.
func commandsFor(actions ...string) []string {
	var out []string
	for _, c := range s3perm.CommandsFor(actions...) {
		out = append(out, c.String())
	}
	slices.Sort(out)
	return out
}

// owedLinks returns the CIDs of the revocations the tenant owes, sorted.
func (d deps) owedLinks(t *testing.T) []string {
	t.Helper()
	dels, _, err := d.owed.Oldest(t.Context(), d.tenantID, revocation.Cursor{}, 10_000)
	require.NoError(t, err)
	return links(dels)
}

// published waits for the revocations the tenant owes to be published and
// returns the CIDs of every delegation revoked so far, sorted.
func (d deps) published(t *testing.T) []string {
	t.Helper()
	testutil.AwaitPublished(t, d.runner, d.tenantID)
	require.Empty(t, d.owedLinks(t), "nothing is left owed")
	var out []string
	for _, c := range d.swarf.Revoked() {
		out = append(out, c.String())
	}
	slices.Sort(out)
	return out
}

// rotated waits for the tenant's revocations to be published and returns the
// principals whose keys' delegations were revoked, sorted.
func (d deps) rotated(t *testing.T) []string {
	t.Helper()
	d.published(t)
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

// policy returns the bucket's stored policy, nil when it has none.
func (d deps) policy(t *testing.T, bucket did.DID) *bucketpolicystore.Record {
	t.Helper()
	rec, err := d.policies.Get(t.Context(), bucket)
	if errors.Is(err, store.ErrRecordNotFound) {
		return nil
	}
	require.NoError(t, err)
	return &rec
}

var everyone = s3bkt.Everyone()

func only(ids ...string) s3bkt.Principal { return s3bkt.Only(ids...) }

func allow(p s3bkt.Principal, actions ...string) s3bkt.Statement {
	return s3bkt.Statement{Effect: s3bkt.Allow, Principal: p, Actions: s3bkt.NewStringSet(actions...), Resources: s3bkt.NewStringSet(s3bkt.BucketARN("photos"), s3bkt.ObjectsARN("photos"))}
}

func deny(p s3bkt.Principal, actions ...string) s3bkt.Statement {
	return s3bkt.Statement{Effect: s3bkt.Deny, Principal: p, Actions: s3bkt.NewStringSet(actions...), Resources: s3bkt.NewStringSet(s3bkt.BucketARN("photos"), s3bkt.ObjectsARN("photos"))}
}

// on returns the statement with its resources naming the bucket.
func on(bucket string, st s3bkt.Statement) s3bkt.Statement {
	st.Resources = s3bkt.NewStringSet(s3bkt.BucketARN(bucket), s3bkt.ObjectsARN(bucket))
	return st
}

func doc(statements ...s3bkt.Statement) s3bkt.PolicyDocument {
	return s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: statements}
}

// createOnly is the condition of a first write: the bucket has no policy.
var createOnly = bucketpolicysvc.WithCondition(bucketpolicysvc.IfNoneMatch("*"))

func ifMatch(etag string) bucketpolicysvc.WriteOption {
	return bucketpolicysvc.WithCondition(bucketpolicysvc.IfMatch(etag))
}

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

		core, logs := observer.New(zapcore.WarnLevel)
		svc := bucketpolicysvc.New(zap.New(core), d.tenants, d.buckets, d.principals, d.policies, d.runner)

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

func TestGrants(t *testing.T) {
	ctx := t.Context()

	t.Run("a first policy issues the granted principals' keys their grants and revokes nothing", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2", "user-3")
		second := d.key(t, "user-1")

		_, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos",
			doc(allow(only("user-1", "user-2"), "s3:GetObject")), createOnly)
		require.NoError(t, err)
		d.requireGrants(t, []string{"s3:GetObject"}, "user-1", "user-2")
		d.requireGrants(t, nil, "user-3")
		require.Equal(t, commandsFor("s3:GetObject"), d.over(t, second, d.photos), "each key of a principal is granted")
		require.Empty(t, d.published(t), "a first grant over the bucket revokes nothing")
	})

	t.Run("a write that narrows leaves each key the new document's grants and revokes the old ones", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2")
		d.key(t, "user-1")
		etag, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos",
			doc(allow(only("user-1", "user-2"), "s3:GetObject", "s3:PutObject")), createOnly)
		require.NoError(t, err)
		d.requireGrants(t, []string{"s3:GetObject", "s3:PutObject"}, "user-1", "user-2")
		var old []string
		for key := range d.keys {
			old = append(old, d.heldOver(t, key, d.photos)...)
		}
		slices.Sort(old)

		d.swarf.holding.Store(true)
		_, _, err = d.svc.Write(ctx, d.tenantID, d.photos, "photos",
			doc(allow(only("user-1", "user-2"), "s3:GetObject")), ifMatch(etag))
		require.NoError(t, err)
		d.requireGrants(t, []string{"s3:GetObject"}, "user-1", "user-2")
		require.Equal(t, old, d.owedLinks(t), "what the keys held over the bucket is owed a revocation")
		require.Empty(t, d.swarf.Revoked(), "and is published after the write")

		d.swarf.holding.Store(false)
		require.Equal(t, old, d.published(t))
		for _, r := range d.swarf.Revocations() {
			require.Equal(t, d.tenantID, r.Revoker)
		}
		d.requireGrants(t, []string{"s3:GetObject"}, "user-1", "user-2")
	})

	t.Run("a write that removes a principal's access leaves its keys nothing over the bucket", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2")
		etag, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos",
			doc(allow(only("user-1", "user-2"), "s3:GetObject")), createOnly)
		require.NoError(t, err)
		var old []string
		for _, key := range d.keysOf("user-2") {
			old = append(old, d.heldOver(t, key, d.photos)...)
		}

		_, _, err = d.svc.Write(ctx, d.tenantID, d.photos, "photos",
			doc(allow(only("user-1"), "s3:GetObject")), ifMatch(etag))
		require.NoError(t, err)
		d.requireGrants(t, []string{"s3:GetObject"}, "user-1")
		d.requireGrants(t, nil, "user-2")
		require.Equal(t, old, d.published(t), "only the principal that lost its access is revoked")
	})

	t.Run("a replace changes only the principals whose actions changed", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2", "user-3")
		etag, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos",
			doc(allow(only("user-1", "user-2"), "s3:GetObject")), createOnly)
		require.NoError(t, err)
		kept := d.heldOver(t, d.keysOf("user-1")[0], d.photos)

		// user-1 keeps GetObject, user-2 gains PutObject, user-3 gains nothing.
		_, _, err = d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(
			allow(only("user-1"), "s3:GetObject"),
			allow(only("user-2"), "s3:GetObject", "s3:PutObject"),
		), ifMatch(etag))
		require.NoError(t, err)
		require.Equal(t, []string{"user-2"}, d.rotated(t))
		require.Equal(t, kept, d.heldOver(t, d.keysOf("user-1")[0], d.photos), "an unaffected key keeps the delegations it held")
		d.requireGrants(t, []string{"s3:GetObject"}, "user-1")
		d.requireGrants(t, []string{"s3:GetObject", "s3:PutObject"}, "user-2")
		d.requireGrants(t, nil, "user-3")
	})

	t.Run("the wildcard reaches every key of the tenant", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2", "user-3")
		d.key(t, "user-2")

		etag, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos",
			doc(allow(everyone, "s3:ListBucket")), createOnly)
		require.NoError(t, err)
		d.requireGrants(t, []string{"s3:ListBucket"}, "user-1", "user-2", "user-3")

		_, _, err = d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(
			allow(everyone, "s3:ListBucket"),
			deny(only("user-2"), "s3:ListBucket"),
		), ifMatch(etag))
		require.NoError(t, err)
		require.Equal(t, []string{"user-2"}, d.rotated(t), "a Deny narrowing the wildcard changes only the denied principal")
		require.Equal(t, []string{"user-1", "user-3"}, d.granted(t))
	})

	t.Run("a write that changes no principal's actions revokes and issues nothing", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2")
		first := doc(allow(only("user-1", "user-2"), "s3:GetObject"))
		etag, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", first, createOnly)
		require.NoError(t, err)
		before := map[did.DID][]string{}
		for key := range d.keys {
			before[key] = links(d.held(t, key))
		}

		// The same document, and one that says the same in two statements.
		same, created, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", first, ifMatch(etag))
		require.NoError(t, err)
		require.False(t, created)
		require.Equal(t, etag, same)
		split := doc(allow(only("user-1"), "s3:GetObject"), allow(only("user-2"), "s3:GetObject"))
		next, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", split, ifMatch(etag))
		require.NoError(t, err)
		require.NotEqual(t, etag, next)
		require.Equal(t, s3bkt.ETag(split), d.policy(t, d.photos).ETag)

		for key, want := range before {
			require.Equal(t, want, links(d.held(t, key)), "every key keeps the delegations it held")
		}
		require.Empty(t, d.owedLinks(t))
		require.Empty(t, d.published(t))
		require.Zero(t, d.swarf.Calls())
	})

	t.Run("a removal leaves every principal the policy reached nothing over the bucket", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2")
		etag, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos",
			doc(allow(only("user-1", "user-2"), "s3:GetObject")), createOnly)
		require.NoError(t, err)
		var old []string
		for key := range d.keys {
			old = append(old, d.heldOver(t, key, d.photos)...)
		}
		slices.Sort(old)

		require.NoError(t, d.svc.Remove(ctx, d.tenantID, d.photos, "photos", &etag))
		require.Nil(t, d.policy(t, d.photos))
		d.requireGrants(t, nil, "user-1", "user-2")
		require.Equal(t, old, d.published(t))
		recs, err := d.policies.ListByPrincipal(ctx, d.tenantID, "user-1")
		require.NoError(t, err)
		require.Empty(t, recs, "the index rows went with the policy")
	})

	t.Run("a removal without a condition removes whatever is stored", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		_, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(everyone, "s3:GetObject")), createOnly)
		require.NoError(t, err)

		require.NoError(t, d.svc.Remove(ctx, d.tenantID, d.photos, "photos", nil))
		require.Nil(t, d.policy(t, d.photos))
		d.requireGrants(t, nil, "user-1")
	})

	t.Run("a removal with a stale ETag fails, revokes nothing and keeps the policy", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		etag, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:GetObject")), createOnly)
		require.NoError(t, err)

		require.ErrorIs(t, d.svc.Remove(ctx, d.tenantID, d.photos, "photos", ptr(`"stale"`)), bucketpolicysvc.ErrPreconditionFailed)
		require.Equal(t, etag, d.policy(t, d.photos).ETag)
		d.requireGrants(t, []string{"s3:GetObject"}, "user-1")
		require.Empty(t, d.published(t))
	})

	t.Run("a removal of a policy the bucket does not have is reported", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		require.ErrorIs(t, d.svc.Remove(ctx, d.tenantID, d.photos, "photos", nil), bucketpolicysvc.ErrPolicyNotFound)
		require.ErrorIs(t, d.svc.Remove(ctx, d.tenantID, d.photos, "photos", ptr(`"any"`)), bucketpolicysvc.ErrPolicyNotFound)
		require.Empty(t, d.published(t))
	})

	t.Run("a write succeeds while the revocation service is down, and its revocations are published once it is back", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		etag, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:GetObject")), createOnly)
		require.NoError(t, err)
		old := d.heldOver(t, d.keysOf("user-1")[0], d.photos)

		d.swarf.holding.Store(true)
		next := doc(allow(only("user-1"), "s3:PutObject"))
		_, _, err = d.svc.Write(ctx, d.tenantID, d.photos, "photos", next, ifMatch(etag))
		require.NoError(t, err)
		require.Equal(t, next, d.policy(t, d.photos).Policy)
		d.requireGrants(t, []string{"s3:PutObject"}, "user-1")
		require.Equal(t, old, d.owedLinks(t))

		d.swarf.holding.Store(false)
		require.Equal(t, old, d.published(t))
	})

	t.Run("a key that has expired is issued nothing", func(t *testing.T) {
		d := setup(t)
		require.NoError(t, d.principals.Add(ctx, d.tenantID, "user-1"))
		expired, user := time.Now().Add(-time.Hour), "user-1"
		key := testutil.RandomDID(t)
		require.NoError(t, d.accessKeys.Add(ctx, accesskeystore.Input{ID: key, Tenant: d.tenantID, Name: "old", Principal: &user, ExpiresAt: &expired}))

		_, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:GetObject")), createOnly)
		require.NoError(t, err)
		require.Empty(t, d.held(t, key))
	})

	t.Run("a disabled tenant's keys are issued nothing, and hold the policy's grants once it is active again", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		_, err := d.runner.Run(ctx, tenantqueue.SetStatusSpec(d.tenantID, tenant.Disabled))
		require.NoError(t, err)
		key := d.keysOf("user-1")[0]
		require.Empty(t, d.held(t, key), "disabling withdrew what the key held")

		written := doc(allow(only("user-1"), "s3:GetObject"))
		_, _, err = d.svc.Write(ctx, d.tenantID, d.photos, "photos", written, createOnly)
		require.NoError(t, err)
		require.Equal(t, written, d.policy(t, d.photos).Policy)
		require.Empty(t, d.held(t, key))

		_, err = d.runner.Run(ctx, tenantqueue.SetStatusSpec(d.tenantID, tenant.Active))
		require.NoError(t, err)
		require.Equal(t, commandsFor("s3:GetObject"), d.over(t, key, d.photos))
	})

	t.Run("fails when grants are to be issued and the tenant's signing key is not in the vault", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		require.NoError(t, d.secrets.Delete(ctx, vault.TenantKeyPath(d.tenantID)))

		_, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:GetObject")), createOnly)
		require.ErrorIs(t, err, vault.ErrNotFound)
		require.Nil(t, d.policy(t, d.photos))
	})
}

// TestConcurrentWrites issues changes to one tenant at once. They are tasks
// on the tenant, so each runs in its turn and none reports a conflict.
func TestConcurrentWrites(t *testing.T) {
	ctx := t.Context()

	t.Run("two writes to one bucket both succeed, and the keys hold the grants of the one that ran last", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2")
		actions := [][]string{{"s3:GetObject"}, {"s3:PutObject", "s3:ListBucket"}}
		errs := make(chan error, len(actions))
		for _, a := range actions {
			go func() {
				_, _, err := d.svc.Write(context.Background(), d.tenantID, d.photos, "photos", doc(allow(only("user-1", "user-2"), a...)))
				errs <- err
			}()
		}
		for range actions {
			require.NoError(t, <-errs)
		}

		stored := d.policy(t, d.photos)
		last := actions[0]
		if stored.ETag != s3bkt.ETag(doc(allow(only("user-1", "user-2"), last...))) {
			last = actions[1]
		}
		require.Equal(t, doc(allow(only("user-1", "user-2"), last...)), stored.Policy)
		d.requireGrants(t, last, "user-1", "user-2")
		// The write that ran first issued grants the second took away.
		require.NotEmpty(t, d.published(t))
		d.requireGrants(t, last, "user-1", "user-2")
	})

	t.Run("the second of two writes to one bucket waits for the first", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		first, second := doc(allow(only("user-1"), "s3:GetObject")), doc(allow(only("user-1"), "s3:PutObject"))

		var created bool
		wrote, waited := testutil.RequireWaitsForWriter(t,
			func(entered chan<- struct{}, release <-chan struct{}) error {
				d.hook.arm(func() { park(t, entered, release) })
				_, _, err := d.svc.Write(context.Background(), d.tenantID, d.photos, "photos", first, createOnly)
				return err
			},
			func() (err error) {
				_, created, err = d.svc.Write(context.Background(), d.tenantID, d.photos, "photos", second)
				return err
			})
		require.NoError(t, wrote)
		require.NoError(t, waited)
		require.False(t, created, "the second write replaced the first's policy")
		require.Equal(t, second, d.policy(t, d.photos).Policy)
		d.requireGrants(t, []string{"s3:PutObject"}, "user-1")
	})

	t.Run("writes to two buckets of one tenant both succeed", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		backups := testutil.RandomDID(t)
		require.NoError(t, d.buckets.Add(ctx, backups, d.tenantID, d.providerID, "backups"))
		key := d.keysOf("user-1")[0]

		errs := make(chan error, 2)
		go func() {
			_, _, err := d.svc.Write(context.Background(), d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:GetObject")), createOnly)
			errs <- err
		}()
		go func() {
			_, _, err := d.svc.Write(context.Background(), d.tenantID, backups, "backups", doc(on("backups", allow(only("user-1"), "s3:PutObject"))), createOnly)
			errs <- err
		}()
		require.NoError(t, <-errs)
		require.NoError(t, <-errs)

		require.Equal(t, commandsFor("s3:GetObject"), d.over(t, key, d.photos))
		require.Equal(t, commandsFor("s3:PutObject"), d.over(t, key, backups))
		require.Equal(t, commandsFor("s3:GetObject"), d.over(t, key, d.archive))

		// A second write to one bucket leaves the other bucket's grants alone.
		kept := d.heldOver(t, key, backups)
		_, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:ListBucket")))
		require.NoError(t, err)
		require.Equal(t, commandsFor("s3:ListBucket"), d.over(t, key, d.photos))
		require.Equal(t, kept, d.heldOver(t, key, backups))
	})

	t.Run("a write still waiting for its turn at the caller's deadline writes nothing", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		first := doc(allow(only("user-1"), "s3:GetObject"))
		entered, release := make(chan struct{}), make(chan struct{})
		d.hook.arm(func() { park(t, entered, release) })
		wrote := make(chan error, 1)
		go func() {
			_, _, err := d.svc.Write(context.Background(), d.tenantID, d.photos, "photos", first, createOnly)
			wrote <- err
		}()
		select {
		case <-entered:
		case err := <-wrote:
			t.Fatalf("the first write returned before its task ran: %v", err)
		case <-time.After(testutil.WaitTimeout):
			t.Fatal("the first write's task did not start")
		}

		short, cancel := context.WithTimeout(ctx, testutil.MinBlock)
		defer cancel()
		_, _, err := d.svc.Write(short, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:PutObject")))
		// The task expires at the caller's deadline, and the wait ends on
		// whichever of the two it sees first.
		if !errors.Is(err, context.DeadlineExceeded) {
			require.ErrorIs(t, err, bucketpolicysvc.ErrConcurrentChange)
		}

		close(release)
		require.NoError(t, <-wrote)
		// A third write runs after the abandoned one's turn has passed, and
		// finds the first write's policy still there.
		_, _, err = d.svc.Write(ctx, d.tenantID, d.photos, "photos", first, ifMatch(s3bkt.ETag(first)))
		require.NoError(t, err, "the abandoned write did not run later")
		require.Equal(t, first, d.policy(t, d.photos).Policy)
		d.requireGrants(t, []string{"s3:GetObject"}, "user-1")
	})
}

// TestPolicyWriteAndKeyCreation issues a policy write and the creation of a
// key for a principal the write affects together. Both are tasks on the
// tenant, so one waits for the other, and either way the new key holds the
// grants of the policy the write stored.
func TestPolicyWriteAndKeyCreation(t *testing.T) {
	ctx := t.Context()
	before, after := doc(allow(only("user-1"), "s3:GetObject", "s3:PutObject")), doc(allow(only("user-1"), "s3:ListBucket"))

	t.Run("issued at once", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		_, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", before, createOnly)
		require.NoError(t, err)
		keys := d.keyService()

		wrote, made := make(chan error, 1), make(chan error, 1)
		var created accesskeystore.Record
		go func() {
			_, _, err := d.svc.Write(context.Background(), d.tenantID, d.photos, "photos", after)
			wrote <- err
		}()
		go func() {
			var err error
			created, _, err = keys.Create(context.Background(), "tenant-1", "laptop", nil, nil, new("user-1"), nil)
			made <- err
		}()
		require.NoError(t, <-wrote)
		require.NoError(t, <-made)
		require.Equal(t, commandsFor("s3:ListBucket"), d.over(t, created.ID, d.photos))
		d.requireGrants(t, []string{"s3:ListBucket"}, "user-1")
	})

	t.Run("the creation waits for a write that has read the principal's keys", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		_, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", before, createOnly)
		require.NoError(t, err)
		keys := d.keyService()

		var created accesskeystore.Record
		wrote, made := testutil.RequireWaitsForWriter(t,
			func(entered chan<- struct{}, release <-chan struct{}) error {
				d.hook.arm(func() { park(t, entered, release) })
				_, _, err := d.svc.Write(context.Background(), d.tenantID, d.photos, "photos", after)
				return err
			},
			func() (err error) {
				created, _, err = keys.Create(context.Background(), "tenant-1", "laptop", nil, nil, new("user-1"), nil)
				return err
			})
		require.NoError(t, wrote)
		require.NoError(t, made)
		require.Equal(t, commandsFor("s3:ListBucket"), d.over(t, created.ID, d.photos), "the key is created from the policy the write stored")
	})

	t.Run("the write waits for a creation that has read the principal's policies", func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		d := setup(t, func(deps *tenantqueue.Deps) {
			deps.AccessKeys = &hookedKeys{Store: deps.AccessKeys, before: func() { park(t, entered, release) }}
		})
		d.principal(t, "user-1")
		_, _, err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", before, createOnly)
		require.NoError(t, err)
		keys := d.keyService()

		var created accesskeystore.Record
		made, wrote := testutil.RequireWaitsForWriter(t,
			func(in chan<- struct{}, out <-chan struct{}) (err error) {
				go func() { <-entered; close(in) }()
				go func() { <-out; close(release) }()
				created, _, err = keys.Create(context.Background(), "tenant-1", "laptop", nil, nil, new("user-1"), nil)
				return err
			},
			func() error {
				_, _, err := d.svc.Write(context.Background(), d.tenantID, d.photos, "photos", after)
				return err
			})
		require.NoError(t, made)
		require.NoError(t, wrote)
		require.Equal(t, commandsFor("s3:ListBucket"), d.over(t, created.ID, d.photos), "the write rewrote the new key's grants")
		d.requireGrants(t, []string{"s3:ListBucket"}, "user-1")
	})
}

// TestPolicyWriteToMissingBucket writes a policy for a bucket the caller
// resolved but the tenant does not have, as for a bucket deleted between the
// lookup and the write, and for another tenant's bucket. Each is reported as
// a missing bucket to a write, and as a missing policy to a removal.
func TestPolicyWriteToMissingBucket(t *testing.T) {
	ctx := t.Context()
	d := setup(t)
	theirs := testutil.RandomDID(t)
	require.NoError(t, d.buckets.Add(ctx, theirs, d.otherTenant, d.providerID, "theirs"))
	for name, bucket := range map[string]did.DID{"no such bucket": testutil.RandomDID(t), "another tenant's bucket": theirs} {
		_, _, err := d.svc.Write(ctx, d.tenantID, bucket, "photos", doc(allow(everyone, "s3:ListBucket")), createOnly)
		require.ErrorIs(t, err, bucketpolicysvc.ErrBucketNotFound, name)
		require.ErrorIs(t, d.svc.Remove(ctx, d.tenantID, bucket, "photos", nil), bucketpolicysvc.ErrPolicyNotFound, name)
		require.Nil(t, d.policy(t, bucket), name)
	}
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
