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
	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	bucketpolicymemory "github.com/fil-forge/hilt/pkg/store/bucketpolicy/memory"
	bucketpolicypostgres "github.com/fil-forge/hilt/pkg/store/bucketpolicy/postgres"
	delegationstore "github.com/fil-forge/hilt/pkg/store/delegation"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	principalstore "github.com/fil-forge/hilt/pkg/store/principal"
	principalmemory "github.com/fil-forge/hilt/pkg/store/principal/memory"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
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

func (r *rejectingPolicies) Put(context.Context, bucketpolicystore.Input, func(context.Context, *bucketpolicystore.Record) error) error {
	return r.err
}

// parkedPolicies holds Put until resume is closed, closing reached when it
// gets there. It parks before the wrapped store runs, so the write has
// validated its document and written nothing.
type parkedPolicies struct {
	bucketpolicystore.Store
	reached chan struct{}
	resume  chan struct{}
}

func (p *parkedPolicies) Put(ctx context.Context, in bucketpolicystore.Input, fn func(context.Context, *bucketpolicystore.Record) error) error {
	close(p.reached)
	<-p.resume
	return p.Store.Put(ctx, in, fn)
}

// growingPrincipals records a new principal for the tenant right after the
// first ListIDsByTenant answers, so the list a write validates against and
// the one its store callback takes differ: it stands in for a principal
// created in that gap.
type growingPrincipals struct {
	principalstore.Store
	late   string
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
	return ids, nil
}

// gatedPrincipals holds once the nth ListIDsByTenant has returned, closing
// reached, until resume is closed. A policy write makes that call from inside
// the policy store's write, so the gate parks the write having read the
// principals and before it commits.
type gatedPrincipals struct {
	principalstore.Store
	mu      sync.Mutex
	calls   int
	nth     int
	reached chan struct{}
	resume  chan struct{}
}

func (g *gatedPrincipals) ListIDsByTenant(ctx context.Context, tenant did.DID) ([]string, error) {
	g.mu.Lock()
	g.calls++
	hold := g.calls == g.nth
	g.mu.Unlock()
	ids, err := g.Store.ListIDsByTenant(ctx, tenant)
	if hold {
		close(g.reached)
		<-g.resume
	}
	return ids, err
}

type deps struct {
	svc         *bucketpolicysvc.Service
	buckets     *bucketmemory.Store
	policies    *bucketpolicymemory.Store
	principals  *principalmemory.Store
	accessKeys  *accesskeymemory.Store
	delegations *delegationmemory.Store
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

// setup wires the service over memory stores with two tenants and one bucket,
// "photos", owned by "tenant-1", whose key is in the vault so the grant
// rotator can sign as it. wrapPrincipals, when given, wraps the memory
// principal store the service is built over.
func setup(t *testing.T, wrapPrincipals ...func(principalstore.Store) principalstore.Store) deps {
	t.Helper()
	ctx := t.Context()
	tenants := tenantmemory.New()
	tenantID, otherTenant := testutil.RandomDID(t), testutil.RandomDID(t)
	require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", testutil.RandomDID(t), tenant.Active))
	require.NoError(t, tenants.Add(ctx, otherTenant, "tenant-2", testutil.RandomDID(t), tenant.Active))

	d := deps{
		buckets:     bucketmemory.New(),
		policies:    bucketpolicymemory.New(),
		principals:  principalmemory.New(),
		accessKeys:  accesskeymemory.New(),
		delegations: delegationmemory.New(),
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
	require.NoError(t, d.buckets.Add(ctx, d.photos, tenantID, "photos"))
	var principals principalstore.Store = d.principals
	for _, wrap := range wrapPrincipals {
		principals = wrap(principals)
	}
	d.svc = bucketpolicysvc.New(zap.NewNop(), tenants, d.buckets, principals, d.policies, d.rotator(d.swarf))
	return d
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

// holdings returns the links of the delegations each key holds, sorted, so a
// test can compare every key's delegations before and after a write.
func (d deps) holdings(t *testing.T) map[did.DID][]string {
	t.Helper()
	out := make(map[did.DID][]string, len(d.keys))
	for key := range d.keys {
		var links []string
		for _, dlg := range d.held(t, key) {
			links = append(links, dlg.Link().String())
		}
		slices.Sort(links)
		out[key] = links
	}
	return out
}

// overPhotos returns the links of the delegations every key holds over photos,
// sorted.
func (d deps) overPhotos(t *testing.T) []string {
	t.Helper()
	var out []string
	for key := range d.keys {
		for _, dlg := range d.held(t, key) {
			if dlg.Subject() == d.photos {
				out = append(out, dlg.Link().String())
			}
		}
	}
	slices.Sort(out)
	return out
}

// grantedCommands returns, per principal holding something over photos, the
// commands its keys hold over photos.
func (d deps) grantedCommands(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for key, principal := range d.keys {
		if cmds := d.over(t, key, d.photos); len(cmds) > 0 {
			out[principal] = cmds
		}
	}
	return out
}

// revokedBatches returns the links each successful publish revoked, sorted
// within each request, in request order.
func (d deps) revokedBatches() [][]string {
	var out [][]string
	for _, b := range d.swarf.Batches() {
		var links []string
		for _, r := range b {
			links = append(links, r.Revoked.String())
		}
		slices.Sort(links)
		out = append(out, links)
	}
	return out
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

func TestPutAndGet(t *testing.T) {
	ctx := t.Context()

	t.Run("creates the first policy and reads it back", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		document := doc(allow(only("user-1"), "s3:GetObject"))

		require.NoError(t, d.svc.Write(ctx, d.tenantID, d.photos, "photos", document))

		rec, err := d.policies.Get(ctx, d.photos)
		require.NoError(t, err)
		require.Equal(t, bucketpolicystore.Record{Bucket: d.photos, Policy: document, UpdatedAt: rec.UpdatedAt}, rec)
	})

	t.Run("a write replaces the stored policy unconditionally", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		require.NoError(t, d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:GetObject"))))

		second := doc(allow(only("user-1"), "s3:PutObject"))
		require.NoError(t, d.svc.Write(ctx, d.tenantID, d.photos, "photos", second))

		rec, err := d.policies.Get(ctx, d.photos)
		require.NoError(t, err)
		require.Equal(t, second, rec.Policy)
	})

	t.Run("rejects a document the caller may not store", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")

		err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("ghost"), "s3:GetObject")))
		require.ErrorIs(t, err, s3bkt.ErrInvalidPolicy)

		err = d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:CreateBucket")))
		require.ErrorIs(t, err, s3bkt.ErrInvalidPolicy)

		err = d.svc.Write(ctx, d.tenantID, d.photos, "photos", s3bkt.PolicyDocument{})
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

		err := d.svc.Write(ctx, d.tenantID, d.photos, "photos",
			doc(allow(only("user-1", "user-2"), "s3:GetObject")))
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

		err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:GetObject")))
		require.NoError(t, err)
		require.Equal(t, commandsFor("s3:GetObject"), d.over(t, second, d.photos))

		err = d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:PutObject")))
		require.NoError(t, err)
		require.Len(t, d.swarf.Revocations(), 2, "one revocation per key over the bucket")
		require.Equal(t, 1, d.swarf.Calls(), "every revocation of one write goes in one request")
		require.Equal(t, []string{"user-1"}, d.rotated())
		require.Equal(t, commandsFor("s3:PutObject"), d.over(t, second, d.photos))
	})

	t.Run("a replace rotates only the principals whose actions changed", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2", "user-3")
		err := d.svc.Write(ctx, d.tenantID, d.photos, "photos",
			doc(allow(only("user-1", "user-2"), "s3:GetObject")))
		require.NoError(t, err)
		d.swarf.Reset()

		// user-1 keeps GetObject, user-2 gains PutObject, user-3 gains nothing.
		err = d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(
			allow(only("user-1"), "s3:GetObject"),
			allow(only("user-2"), "s3:GetObject", "s3:PutObject"),
		))
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

		err := d.svc.Write(ctx, d.tenantID, d.photos, "photos",
			doc(allow(everyone, "s3:ListBucket")))
		require.NoError(t, err)
		require.Equal(t, []string{"user-1", "user-2", "user-3"}, d.granted(t))
	})

	t.Run("the wildcard reaches a principal created while the write was under way", func(t *testing.T) {
		// "user-2" appears after the validation's list and before the write's
		// callback lists the principals again, so the rotation reaches it.
		d := setup(t, func(s principalstore.Store) principalstore.Store {
			return &growingPrincipals{Store: s, late: "user-2"}
		})
		d.principal(t, "user-1")
		// user-2's key is there for the rotation to find once the principal is.
		d.key(t, "user-2")

		err := d.svc.Write(ctx, d.tenantID, d.photos, "photos",
			doc(allow(everyone, "s3:ListBucket")))
		require.NoError(t, err)
		require.Equal(t, []string{"user-1", "user-2"}, d.granted(t))
	})

	t.Run("a Deny narrowing the wildcard rotates only the denied principal", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2", "user-3")
		err := d.svc.Write(ctx, d.tenantID, d.photos, "photos",
			doc(allow(everyone, "s3:ListBucket")))
		require.NoError(t, err)
		d.swarf.Reset()

		err = d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(
			allow(everyone, "s3:ListBucket"),
			deny(only("user-2"), "s3:ListBucket"),
		))
		require.NoError(t, err)
		require.Equal(t, []string{"user-2"}, d.rotated())
		require.Equal(t, []string{"user-1", "user-3"}, d.granted(t))
	})

	t.Run("a delete rotates every principal the policy reached", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2")
		err := d.svc.Write(ctx, d.tenantID, d.photos, "photos",
			doc(allow(only("user-1", "user-2"), "s3:GetObject")))
		require.NoError(t, err)
		d.swarf.Reset()

		require.NoError(t, d.svc.Remove(ctx, d.tenantID, d.photos, "photos"))
		require.Equal(t, []string{"user-1", "user-2"}, d.rotated())
		require.Equal(t, 1, d.swarf.Calls())
		require.Empty(t, d.granted(t))

		_, err = d.policies.Get(ctx, d.photos)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})

	t.Run("returns the publish error and leaves the old document and every key's delegations in place when a write's publish fails", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2")
		old := doc(allow(only("user-1"), "s3:GetObject"))
		require.NoError(t, d.svc.Write(ctx, d.tenantID, d.photos, "photos", old))
		before := d.holdings(t)
		down := errors.New("swarf unreachable")
		d.swarf.Err = down

		next := doc(allow(only("user-1", "user-2"), "s3:GetObject", "s3:PutObject"))
		require.ErrorIs(t, d.svc.Write(ctx, d.tenantID, d.photos, "photos", next), down)

		rec, err := d.policies.Get(ctx, d.photos)
		require.NoError(t, err)
		require.Equal(t, old, rec.Policy)
		require.Equal(t, before, d.holdings(t))
	})

	t.Run("stores the new document and publishes its revocations once when a write is retried after its publish failed", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2")
		require.NoError(t, d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:GetObject"))))
		replaced := d.overPhotos(t)
		d.swarf.Err = errors.New("swarf unreachable")
		next := doc(allow(only("user-1", "user-2"), "s3:GetObject", "s3:PutObject"))
		require.Error(t, d.svc.Write(ctx, d.tenantID, d.photos, "photos", next))
		d.swarf.Err = nil

		require.NoError(t, d.svc.Write(ctx, d.tenantID, d.photos, "photos", next))

		rec, err := d.policies.Get(ctx, d.photos)
		require.NoError(t, err)
		require.Equal(t, next, rec.Policy)
		require.Equal(t, map[string][]string{
			"user-1": commandsFor("s3:GetObject", "s3:PutObject"),
			"user-2": commandsFor("s3:GetObject", "s3:PutObject"),
		}, d.grantedCommands(t))
		require.Equal(t, [][]string{replaced}, d.revokedBatches(), "the retry revokes user-1's old delegations in one request")
	})

	t.Run("returns the publish error and leaves the policy and every key's delegations in place when a remove's publish fails", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		old := doc(allow(only("user-1"), "s3:GetObject"))
		require.NoError(t, d.svc.Write(ctx, d.tenantID, d.photos, "photos", old))
		before := d.holdings(t)
		down := errors.New("swarf unreachable")
		d.swarf.Err = down

		require.ErrorIs(t, d.svc.Remove(ctx, d.tenantID, d.photos, "photos"), down)

		rec, err := d.policies.Get(ctx, d.photos)
		require.NoError(t, err)
		require.Equal(t, old, rec.Policy)
		require.Equal(t, before, d.holdings(t))
	})

	t.Run("removes the policy and publishes its revocations once when a remove is retried after its publish failed", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		require.NoError(t, d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:GetObject"))))
		replaced := d.overPhotos(t)
		d.swarf.Err = errors.New("swarf unreachable")
		require.Error(t, d.svc.Remove(ctx, d.tenantID, d.photos, "photos"))
		d.swarf.Err = nil

		require.NoError(t, d.svc.Remove(ctx, d.tenantID, d.photos, "photos"))

		_, err := d.policies.Get(ctx, d.photos)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		require.Empty(t, d.granted(t))
		require.Equal(t, [][]string{replaced}, d.revokedBatches())
	})

	t.Run("returns at the batch deadline with the old document and every key's delegations in place when a write's publish never answers", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2", "user-3")
		old := doc(allow(only("user-1"), "s3:GetObject"))
		require.NoError(t, d.svc.Write(ctx, d.tenantID, d.photos, "photos", old))
		before := d.holdings(t)

		tenants := tenantmemory.New()
		require.NoError(t, tenants.Add(ctx, d.tenantID, "tenant-1", testutil.RandomDID(t), tenant.Active))
		svc := bucketpolicysvc.New(zap.NewNop(), tenants, d.buckets, d.principals, d.policies, d.rotator(blockingSwarf{}))

		start := time.Now()
		// user-1's actions change, so the write has revocations to publish.
		err := svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(everyone, "s3:PutObject")))
		elapsed := time.Since(start)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.Less(t, elapsed, grant.BatchTimeout+2*time.Second,
			"the write must give up at the batch deadline")

		rec, err := d.policies.Get(ctx, d.photos)
		require.NoError(t, err)
		require.Equal(t, old, rec.Policy)
		require.Equal(t, before, d.holdings(t))
	})

	t.Run("a principal removed between validation and the write is an invalid policy", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		tenants := tenantmemory.New()
		require.NoError(t, tenants.Add(ctx, d.tenantID, "tenant-1", testutil.RandomDID(t), tenant.Active))
		// The store's index foreign key refuses a document naming a principal
		// that is gone; the memory store does not check it, so stand in for it.
		policies := &rejectingPolicies{Store: d.policies, err: store.ErrInvalidArgument}
		svc := bucketpolicysvc.New(zap.NewNop(), tenants, d.buckets, d.principals, policies, d.rotator(d.swarf))

		err := svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:GetObject")))
		require.ErrorIs(t, err, s3bkt.ErrInvalidPolicy)
	})

}

// TestPolicyWriteAfterPrincipalRemoval removes a principal after a policy
// write naming it has validated its document and before the write reaches the
// store. The write must fail, so a principal revived under the same id starts
// named in no statement.
func TestPolicyWriteAfterPrincipalRemoval(t *testing.T) {
	ctx := t.Context()
	d := setup(t)
	d.principal(t, "user-1")
	tenants := tenantmemory.New()
	require.NoError(t, tenants.Add(ctx, d.tenantID, "tenant-1", testutil.RandomDID(t), tenant.Active))
	policies := &parkedPolicies{Store: d.policies, reached: make(chan struct{}), resume: make(chan struct{})}
	svc := bucketpolicysvc.New(zap.NewNop(), tenants, d.buckets, d.principals, policies, d.rotator(d.swarf))
	principals := principalsvc.New(zap.NewNop(), tenants, d.principals, d.policies,
		d.accessKeys, d.delegations, d.secrets, d.rotator(d.swarf))

	put := make(chan error, 1)
	go func() {
		err := svc.Write(context.Background(), d.tenantID, d.photos, "photos",
			doc(allow(only("user-1"), "s3:GetObject")))
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
// The add does not wait for the write, and the key created for the principal
// after the write commits reads the committed policy and holds its grants.
func TestPrincipalAddedDuringPolicyWritePostgres(t *testing.T) {
	pool := testutil.PostgresOrSkip(t)
	ctx := t.Context()
	d := setup(t)
	// The rows the policy tables reference, under the memory setup's DIDs.
	providerID := testutil.RandomDID(t)
	require.NoError(t, providerpostgres.New(pool).Add(ctx, providerID, "us-east-1", nil))
	require.NoError(t, tenantpostgres.New(pool).Add(ctx, d.tenantID, "tenant-1", providerID, tenant.Active))
	require.NoError(t, bucketpostgres.New(pool).Add(ctx, d.photos, d.tenantID, "photos"))
	tenants := tenantmemory.New()
	require.NoError(t, tenants.Add(ctx, d.tenantID, "tenant-1", providerID, tenant.Active))
	principals := principalpostgres.New(pool)
	policies := bucketpolicypostgres.New(pool)

	// The second list is the one the policy store's callback makes.
	reached, resume := make(chan struct{}), make(chan struct{})
	gated := &gatedPrincipals{Store: principals, nth: 2, reached: reached, resume: resume}
	svc := bucketpolicysvc.New(zap.NewNop(), tenants, d.buckets, gated, policies, d.rotator(d.swarf))
	keys := accesskeysvc.New(zap.NewNop(), tenants, d.accessKeys, principals, d.buckets, policies, d.delegations, d.secrets, d.swarf)

	written := make(chan error, 1)
	go func() {
		written <- svc.Write(context.Background(), d.tenantID, d.photos, "photos", doc(allow(everyone, "s3:GetObject")))
	}()
	<-reached
	require.NoError(t, principals.Add(ctx, d.tenantID, "user-2"), "the add does not wait for the write")
	close(resume)
	require.NoError(t, <-written)

	rec, _, err := keys.Create(ctx, "tenant-1", "key", nil, nil, new("user-2"), nil)
	require.NoError(t, err)
	require.Equal(t, commandsFor("s3:GetObject"), d.over(t, rec.ID, d.photos), "the key is created from the committed policy")
}

// postgresDeps is the memory setup's world on Postgres: the rows the policy
// tables reference under the setup's DIDs, and the stores a write's callback
// joins the transaction of.
type postgresDeps struct {
	tenants     *tenantmemory.Store
	principals  *principalpostgres.Store
	policies    *bucketpolicypostgres.Store
	accessKeys  *accesskeypostgres.Store
	delegations *delegationpostgres.Store
}

func (d deps) postgres(t *testing.T, pool *pgxpool.Pool) postgresDeps {
	t.Helper()
	ctx := t.Context()
	providerID := testutil.RandomDID(t)
	require.NoError(t, providerpostgres.New(pool).Add(ctx, providerID, "us-east-1", nil))
	require.NoError(t, tenantpostgres.New(pool).Add(ctx, d.tenantID, "tenant-1", providerID, tenant.Active))
	require.NoError(t, bucketpostgres.New(pool).Add(ctx, d.photos, d.tenantID, "photos"))
	tenants := tenantmemory.New()
	require.NoError(t, tenants.Add(ctx, d.tenantID, "tenant-1", providerID, tenant.Active))
	return postgresDeps{
		tenants:     tenants,
		principals:  principalpostgres.New(pool),
		policies:    bucketpolicypostgres.New(pool),
		accessKeys:  accesskeypostgres.New(pool),
		delegations: delegationpostgres.New(pool),
	}
}

// over returns the commands the key holds over the bucket in the Postgres
// delegation store, sorted.
func (p postgresDeps) over(t *testing.T, key, bucket did.DID) []string {
	t.Helper()
	page, err := p.delegations.ListByAudience(t.Context(), key)
	require.NoError(t, err)
	var out []string
	for _, dlg := range page.Results {
		if dlg.Subject() == bucket {
			out = append(out, dlg.Command().String())
		}
	}
	slices.Sort(out)
	return out
}

// cancelAfterCallback cancels the write's ctx once the store's callback (the
// rotation) has returned, before the store writes the document.
type cancelAfterCallback struct {
	bucketpolicystore.Store
	cancel context.CancelFunc
	ran    bool
}

func (c *cancelAfterCallback) Put(ctx context.Context, in bucketpolicystore.Input, fn func(context.Context, *bucketpolicystore.Record) error) error {
	return c.Store.Put(ctx, in, func(ctx context.Context, old *bucketpolicystore.Record) error {
		err := fn(ctx, old)
		c.ran = true
		c.cancel()
		return err
	})
}

// TestPolicyWriteCancelledAfterRotationPostgres cancels a policy write once
// its rotation has run, before the
// document is written. The rotation's delegation writes joined the policy
// transaction, so the old policy stays with its own grants: a principal is
// never left with the grants of a policy that was not stored.
func TestPolicyWriteCancelledAfterRotationPostgres(t *testing.T) {
	pool := testutil.PostgresOrSkip(t)
	ctx := t.Context()
	d := setup(t)
	pg := d.postgres(t, pool)
	require.NoError(t, pg.principals.Add(ctx, d.tenantID, "user-1"))
	key := testutil.RandomDID(t)
	user := "user-1"
	require.NoError(t, pg.accessKeys.Add(ctx, accesskeystore.Input{ID: key, Tenant: d.tenantID, Name: "laptop", Principal: &user}))

	rotator := grant.NewRotator(zap.NewNop(), pg.delegations, pg.accessKeys, d.secrets, d.swarf)
	svc := bucketpolicysvc.New(zap.NewNop(), pg.tenants, d.buckets, pg.principals, pg.policies, rotator)
	err := svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:GetObject", "s3:ListBucket")))
	require.NoError(t, err)
	require.Equal(t, commandsFor("s3:GetObject", "s3:ListBucket"), pg.over(t, key, d.photos))

	writeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	policies := &cancelAfterCallback{Store: pg.policies, cancel: cancel}
	cancelling := bucketpolicysvc.New(zap.NewNop(), pg.tenants, d.buckets, pg.principals, policies, rotator)
	err = cancelling.Write(writeCtx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:ListBucket")))
	require.ErrorIs(t, err, context.Canceled)
	require.True(t, policies.ran, "the rotation ran")

	rec, err := pg.policies.Get(ctx, d.photos)
	require.NoError(t, err)
	require.Equal(t, doc(allow(only("user-1"), "s3:GetObject", "s3:ListBucket")), rec.Policy, "the document was not replaced")
	require.Equal(t, commandsFor("s3:GetObject", "s3:ListBucket"), pg.over(t, key, d.photos), "and the key keeps the stored policy's grants")
}

// TestPolicyWriteToMissingBucketPostgres writes a policy for a bucket the
// service resolves but Postgres has no row for, standing in for a bucket
// deleted between the lookup and the write. It is reported as a missing
// bucket.
func TestPolicyWriteToMissingBucketPostgres(t *testing.T) {
	pool := testutil.PostgresOrSkip(t)
	d := setup(t)
	tenants := tenantmemory.New()
	require.NoError(t, tenants.Add(t.Context(), d.tenantID, "tenant-1", testutil.RandomDID(t), tenant.Active))
	svc := bucketpolicysvc.New(zap.NewNop(), tenants, d.buckets, d.principals,
		bucketpolicypostgres.New(pool), d.rotator(d.swarf))

	err := svc.Write(t.Context(), d.tenantID, d.photos, "photos", doc(allow(everyone, "s3:ListBucket")))
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
		require.NoError(t, d.buckets.Add(ctx, backups, d.tenantID, "backups"))
		err := d.svc.Write(ctx, d.tenantID, d.photos, "photos", doc(allow(only("user-1"), "s3:GetObject")))
		require.NoError(t, err)
		onBackups := func(st s3bkt.Statement) s3bkt.Statement {
			st.Resources = s3bkt.NewStringSet(s3bkt.BucketARN("backups"))
			return st
		}
		err = d.svc.Write(ctx, d.tenantID, backups, "backups", doc(
			onBackups(allow(everyone, "s3:ListBucket")),
			onBackups(deny(only("user-2"), "s3:ListBucket")),
		))
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

// policyStores are the stores a policy write runs over, on one backend.
type policyStores struct {
	tenants     tenant.Store
	principals  principalstore.Store
	policies    bucketpolicystore.Store
	accessKeys  accesskeystore.Store
	delegations delegationstore.Store
	// addBucket records a bucket of the tenant where the policy store
	// requires one.
	addBucket func(t *testing.T, id did.DID, name string)
}

// backends builds the setup's world on each backend; postgres skips without
// Docker.
var backends = []struct {
	name   string
	stores func(t *testing.T, d deps) policyStores
}{
	{"memory", func(t *testing.T, d deps) policyStores {
		tenants := tenantmemory.New()
		require.NoError(t, tenants.Add(t.Context(), d.tenantID, "tenant-1", testutil.RandomDID(t), tenant.Active))
		return policyStores{
			tenants: tenants, principals: d.principals, policies: d.policies,
			accessKeys: d.accessKeys, delegations: d.delegations,
			addBucket: func(t *testing.T, id did.DID, name string) {
				require.NoError(t, d.buckets.Add(t.Context(), id, d.tenantID, name))
			},
		}
	}},
	{"postgres", func(t *testing.T, d deps) policyStores {
		// Fewer connections than the concurrent tests run writes, so a write
		// that takes a second connection while it holds its first waits
		// forever and the test fails.
		cfg := testutil.PostgresOrSkip(t).Config()
		cfg.MaxConns = 2
		pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
		require.NoError(t, err)
		t.Cleanup(pool.Close)
		pg := d.postgres(t, pool)
		buckets := bucketpostgres.New(pool)
		return policyStores{
			tenants: pg.tenants, principals: pg.principals, policies: pg.policies,
			accessKeys: pg.accessKeys, delegations: pg.delegations,
			addBucket: func(t *testing.T, id did.DID, name string) {
				require.NoError(t, buckets.Add(t.Context(), id, d.tenantID, name))
			},
		}
	}},
}

// allowOn is a statement allowing the principal the actions on the named bucket.
func allowOn(bucket, principal string, actions ...string) s3bkt.Statement {
	return s3bkt.Statement{Effect: s3bkt.Allow, Principal: only(principal), Actions: s3bkt.NewStringSet(actions...), Resources: s3bkt.NewStringSet(s3bkt.BucketARN(bucket), s3bkt.ObjectsARN(bucket))}
}

// grantPairs returns the (subject, command) pair of every delegation the key
// holds.
func grantPairs(t *testing.T, delegations delegationstore.Store, key did.DID) [][2]string {
	t.Helper()
	dels, err := store.Collect(t.Context(), func(ctx context.Context, opts store.PaginationConfig) (store.Page[ucan.Delegation], error) {
		var o []store.PaginationOption
		if opts.Cursor != nil {
			o = append(o, store.WithCursor(*opts.Cursor))
		}
		return delegations.ListByAudience(ctx, key, o...)
	})
	require.NoError(t, err)
	out := make([][2]string, 0, len(dels))
	for _, dlg := range dels {
		out = append(out, [2]string{dlg.Subject().String(), dlg.Command().String()})
	}
	return out
}

// runConcurrently starts every write at once and returns each one's error, in
// order.
func runConcurrently(writes ...func() error) []error {
	errs := make([]error, len(writes))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, write := range writes {
		wg.Go(func() {
			<-start
			errs[i] = write()
		})
	}
	close(start)
	wg.Wait()
	return errs
}

func TestConcurrentPolicyWrites(t *testing.T) {
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			t.Run("concurrent writes to different buckets naming one principal all succeed and leave each key with the delegations the stored policies grant", func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
				defer cancel()
				d := setup(t)
				s := b.stores(t, d)
				const principal = "any-principal"
				require.NoError(t, s.principals.Add(ctx, d.tenantID, principal))
				var keys []did.DID
				for i := range 2 {
					key := testutil.RandomDID(t)
					require.NoError(t, s.accessKeys.Add(ctx, accesskeystore.Input{ID: key, Tenant: d.tenantID, Name: fmt.Sprintf("key-%d", i), Principal: new(principal)}))
					keys = append(keys, key)
				}
				actionSets := [][]string{
					{"s3:GetObject"},
					{"s3:PutObject"},
					{"s3:ListBucket"},
					{"s3:DeleteObject"},
					{"s3:GetObject", "s3:PutObject"},
					{"s3:GetObject", "s3:ListBucket"},
					{"s3:PutObject", "s3:DeleteObject"},
					{"s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:DeleteObject"},
				}
				buckets := make([]did.DID, len(actionSets))
				for i := range buckets {
					buckets[i] = testutil.RandomDID(t)
					s.addBucket(t, buckets[i], fmt.Sprintf("bucket-%d", i))
				}
				svc := bucketpolicysvc.New(zap.NewNop(), s.tenants, d.buckets, s.principals, s.policies,
					grant.NewRotator(zap.NewNop(), s.delegations, s.accessKeys, d.secrets, d.swarf))

				writes := make([]func() error, len(buckets))
				for i, bucket := range buckets {
					name := fmt.Sprintf("bucket-%d", i)
					writes[i] = func() error {
						return svc.Write(ctx, d.tenantID, bucket, name, doc(allowOn(name, principal, actionSets[i]...)))
					}
				}
				require.Equal(t, make([]error, len(buckets)), runConcurrently(writes...))

				var want [][2]string
				for _, bucket := range buckets {
					rec, err := s.policies.Get(ctx, bucket)
					require.NoError(t, err)
					for _, cmd := range s3perm.CommandsFor(bucketpolicy.Effective(&rec.Policy, principal)...) {
						want = append(want, [2]string{bucket.String(), cmd.String()})
					}
				}
				for _, key := range keys {
					require.ElementsMatch(t, want, grantPairs(t, s.delegations, key), key)
				}
			})

			t.Run("two concurrent writes to one bucket both succeed and the stored policy is one of the two documents", func(t *testing.T) {
				ctx := t.Context()
				d := setup(t)
				s := b.stores(t, d)
				require.NoError(t, s.principals.Add(ctx, d.tenantID, "any-principal"))
				key := testutil.RandomDID(t)
				require.NoError(t, s.accessKeys.Add(ctx, accesskeystore.Input{ID: key, Tenant: d.tenantID, Name: "any-key", Principal: new("any-principal")}))
				svc := bucketpolicysvc.New(zap.NewNop(), s.tenants, d.buckets, s.principals, s.policies,
					grant.NewRotator(zap.NewNop(), s.delegations, s.accessKeys, d.secrets, d.swarf))

				docs := []s3bkt.PolicyDocument{
					doc(allow(only("any-principal"), "s3:GetObject")),
					doc(allow(only("any-principal"), "s3:PutObject")),
				}
				errs := runConcurrently(
					func() error { return svc.Write(ctx, d.tenantID, d.photos, "photos", docs[0]) },
					func() error { return svc.Write(ctx, d.tenantID, d.photos, "photos", docs[1]) },
				)
				require.Equal(t, []error{nil, nil}, errs)

				rec, err := s.policies.Get(ctx, d.photos)
				require.NoError(t, err)
				require.Contains(t, docs, rec.Policy)
			})
		})
	}
}
