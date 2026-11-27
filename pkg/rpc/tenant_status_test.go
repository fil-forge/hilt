package rpc_test

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	accesskeysvc "github.com/fil-forge/hilt/pkg/api/service/accesskey"
	tenantsvc "github.com/fil-forge/hilt/pkg/api/service/tenant"
	"github.com/fil-forge/hilt/pkg/rpc"
	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	bucketpolicypostgres "github.com/fil-forge/hilt/pkg/store/bucketpolicy/postgres"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	"github.com/fil-forge/hilt/pkg/store/pglock"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	revocationpostgres "github.com/fil-forge/hilt/pkg/store/revocation/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	wrapkeypostgres "github.com/fil-forge/hilt/pkg/store/wrapkey/postgres"
	"github.com/fil-forge/hilt/pkg/tasks/revocationqueue"
	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	s3req "github.com/fil-forge/libforge/commands/s3/request"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/libforge/testutil"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// pausedTenants is the tenant store queue-tenant.set-status reads through. It
// holds each read while a gate is set, which keeps the task running for as
// long as a test needs it pending.
type pausedTenants struct {
	tenant.Store
	mu sync.Mutex
	// entered is closed when a read reaches the gate, and release lets it go.
	entered, release chan struct{}
}

// pause makes the next read wait, and returns the channels that report it
// waiting and let it go.
func (p *pausedTenants) pause() (entered <-chan struct{}, release chan<- struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.entered, p.release = make(chan struct{}), make(chan struct{})
	return p.entered, p.release
}

func (p *pausedTenants) Get(ctx context.Context, id did.DID) (tenant.Record, error) {
	p.mu.Lock()
	entered, release := p.entered, p.release
	p.entered, p.release = nil, nil
	p.mu.Unlock()
	if entered != nil {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return tenant.Record{}, ctx.Err()
		}
	}
	return p.Store.Get(ctx, id)
}

// pausedKeys is the access-key store queue-tenant.delete-key reads through.
// It holds a read while a gate is set, as pausedTenants does, which keeps a
// key deletion's task running for as long as a test needs it pending.
type pausedKeys struct {
	accesskey.Store
	mu sync.Mutex
	// entered is closed when a read reaches the gate, and release lets it go.
	entered, release chan struct{}
}

// pause makes the next read wait, and returns the channels that report it
// waiting and let it go.
func (p *pausedKeys) pause() (entered <-chan struct{}, release chan<- struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.entered, p.release = make(chan struct{}), make(chan struct{})
	return p.entered, p.release
}

func (p *pausedKeys) Get(ctx context.Context, id did.DID) (accesskey.Record, error) {
	p.mu.Lock()
	entered, release := p.entered, p.release
	p.entered, p.release = nil, nil
	p.mu.Unlock()
	if entered != nil {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return accesskey.Record{}, ctx.Err()
		}
	}
	return p.Store.Get(ctx, id)
}

// afterStatusRead is the tenant store the authorizer reads through. It runs
// then, once, right after the authorizer has read the tenant's status, which
// lands a change between that read and the reads that follow it.
type afterStatusRead struct {
	tenant.Store
	once sync.Once
	then func()
}

func (a *afterStatusRead) Get(ctx context.Context, id did.DID) (tenant.Record, error) {
	rec, err := a.Store.Get(ctx, id)
	if a.then != nil {
		a.once.Do(a.then)
	}
	return rec, err
}

// statusEnv is an active tenant with one bucket and a service key that may
// read and delete its objects, served by the real tenant service, task
// runner and authorizer.
type statusEnv struct {
	svc         *tenantsvc.Service
	authorizer  *auth.Authorizer
	delegations *delegationpostgres.Store
	swarf       *htestutil.FakeSwarf
	// keys is the access-key service, on the same runner.
	keys *accesskeysvc.Service
	// queueTenants is the store the status task reads through.
	queueTenants *pausedTenants
	// queueKeys is the store the key deletion task reads through.
	queueKeys *pausedKeys
	// authTenants is the store the authorizer reads through.
	authTenants *afterStatusRead
	provider    did.DID
	tenant      did.DID
	bucket      did.DID
	key         ed25519.Signer
}

const (
	statusRegion = "us-west-2"
	statusBucket = "status-bucket"
)

func setupStatus(t *testing.T) *statusEnv {
	t.Helper()
	ctx := t.Context()
	pool := htestutil.PostgresOrSkip(t)
	tenants, accessKeys, buckets := tenantpostgres.New(pool), accesskeypostgres.New(pool), bucketpostgres.New(pool)
	providers, principals, policies := providerpostgres.New(pool), principalpostgres.New(pool), bucketpolicypostgres.New(pool)
	delegations, owed := delegationpostgres.New(pool), revocationpostgres.New(pool)
	secrets, swarf := vaultmemory.New(), &htestutil.FakeSwarf{}
	env := &statusEnv{
		delegations:  delegations,
		swarf:        swarf,
		queueTenants: &pausedTenants{Store: tenants},
		queueKeys:    &pausedKeys{Store: accessKeys},
		authTenants:  &afterStatusRead{Store: tenants},
		provider:     testutil.RandomDID(t),
	}

	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	env.tenant = signer.KeyDID()
	require.NoError(t, providers.Add(ctx, env.provider, statusRegion, nil))
	require.NoError(t, tenants.Add(ctx, env.tenant, "tenant-1", tenant.Active))
	require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(env.tenant), signer.Bytes()))

	bucketSigner, err := ed25519.Generate()
	require.NoError(t, err)
	env.bucket = bucketSigner.KeyDID()
	require.NoError(t, buckets.Add(ctx, env.bucket, env.tenant, env.provider, statusBucket))
	root, err := delegation.Delegate(multikey.NewIssuer(env.bucket, bucketSigner), env.tenant, env.bucket, command.Top(), delegation.WithNoExpiration())
	require.NoError(t, err)
	require.NoError(t, delegations.PutBatch(ctx, []ucan.Delegation{root}))

	runner := htestutil.StartTaskRunner(t, pool, func(r *taskrunner.Runner) {
		_, err := tenantqueue.New(r, tenantqueue.Deps{
			Tenants: env.queueTenants, AccessKeys: env.queueKeys, Principals: principals, Buckets: buckets,
			Policies: policies, Delegations: delegations, Secrets: secrets,
		})
		require.NoError(t, err)
		_, err = revocationqueue.New(r, revocationqueue.Deps{Owed: owed, Secrets: secrets, Publisher: swarf})
		require.NoError(t, err)
	})
	env.keys = accesskeysvc.New(zap.NewNop(), tenants, accessKeys, principals, buckets, secrets, runner)
	rec, _, err := env.keys.Create(ctx, "tenant-1", "service", []string{"s3:GetObject", "s3:DeleteObject"}, []string{statusBucket}, nil, nil)
	require.NoError(t, err)
	keyBytes, err := secrets.Read(ctx, vault.AccessKeyPath(env.tenant, rec.ID))
	require.NoError(t, err)
	env.key, err = ed25519.Decode(keyBytes)
	require.NoError(t, err)

	env.svc = tenantsvc.New(zap.NewNop(), tenants, secrets, wrapkeypostgres.New(pool), nil, nil, runner)
	env.authorizer = auth.NewAuthorizer(zap.NewNop(), accessKeys, env.authTenants, providers, buckets, principals, policies, secrets,
		auth.WithTenantChanges(runner), auth.WithSnapshots(pglock.NewSnapshots(pool)))
	return env
}

// get is a signed GetObject of the bucket, and del a signed DeleteObject.
func (e *statusEnv) get(t *testing.T) *s3req.AuthorizeArguments {
	return signedGetArgs(t, e.key, statusBucket, statusRegion, time.Now(), time.Hour)
}

func (e *statusEnv) del(t *testing.T) *s3req.AuthorizeArguments {
	return signedArgs(t, e.key, "DELETE", "https://s3.fil.one/"+statusBucket+"/object-key", statusRegion)
}

func (e *statusEnv) authorize(t *testing.T, args *s3req.AuthorizeArguments) (*s3req.AuthorizeOK, []ucan.Delegation, error) {
	t.Helper()
	return rpc.AuthorizeRequest(t.Context(), zap.NewNop(), e.authorizer, e.delegations, e.provider, args)
}

// grants returns the delegations the key holds in the store.
func (e *statusEnv) grants(t *testing.T) []ucan.Delegation {
	t.Helper()
	page, err := e.delegations.ListByAudience(t.Context(), e.key.KeyDID())
	require.NoError(t, err)
	return page.Results
}

// chained reports whether the store holds a chain from the key to the bucket
// for the command: what a delegation the key issues needs to carry any
// authority.
func (e *statusEnv) chained(t *testing.T, cmd ucan.Command) bool {
	t.Helper()
	chain, _, err := e.delegations.ProofChain(t.Context(), e.key.KeyDID(), cmd, e.bucket)
	require.NoError(t, err)
	return len(chain) > 0
}

func cids(dels []ucan.Delegation) []cid.Cid {
	out := make([]cid.Cid, len(dels))
	for i, d := range dels {
		out[i] = d.Link()
	}
	return out
}

func TestSetStatusThroughTheService(t *testing.T) {
	env := setupStatus(t)
	ctx := t.Context()

	// Active: the request is authorized and what the key delegates is backed
	// by its stored grants.
	_, issued, err := env.authorize(t, env.get(t))
	require.NoError(t, err)
	fromKey := issuedBy(issued, env.key.KeyDID())
	require.NotEmpty(t, fromKey)
	for _, d := range fromKey {
		require.True(t, env.chained(t, d.Command()))
	}
	original := env.grants(t)
	require.NotEmpty(t, original)

	// Disable, with the change held running. An authorization that arrives
	// meanwhile waits for it, and is then refused.
	entered, release := env.queueTenants.pause()
	changed := make(chan error, 1)
	go func() { changed <- env.svc.SetStatus(ctx, "tenant-1", "disabled") }()
	select {
	case <-entered:
	case err := <-changed:
		t.Fatalf("the status change returned without running its task: %v", err)
	case <-time.After(htestutil.WaitTimeout):
		t.Fatal("the status change did not start")
	}
	answered := make(chan error, 1)
	go func() {
		_, _, err := env.authorize(t, env.get(t))
		answered <- err
	}()
	select {
	case err := <-answered:
		t.Fatalf("authorization answered while the change was pending: %v", err)
	case err := <-changed:
		t.Fatalf("the status change returned while its task was held: %v", err)
	case <-time.After(htestutil.MinBlock):
	}
	close(release)
	select {
	case err := <-changed:
		require.NoError(t, err)
	case <-time.After(htestutil.WaitTimeout):
		t.Fatal("the status change did not finish")
	}
	select {
	case err := <-answered:
		require.ErrorIs(t, err, auth.ErrTenantDisabled)
	case <-time.After(htestutil.WaitTimeout):
		t.Fatal("authorization did not answer once the change finished")
	}

	rec, err := env.svc.Get(ctx, "tenant-1")
	require.NoError(t, err)
	require.Equal(t, tenant.Disabled, rec.Status)
	require.Empty(t, env.grants(t))
	require.Eventually(t, func() bool { return len(env.swarf.Revoked()) == len(original) }, htestutil.WaitTimeout, 10*time.Millisecond)
	require.ElementsMatch(t, cids(original), env.swarf.Revoked())

	// Reactivate: the key is issued fresh grants, and requests are
	// authorized on them.
	require.NoError(t, env.svc.SetStatus(ctx, "tenant-1", "active"))
	rec, err = env.svc.Get(ctx, "tenant-1")
	require.NoError(t, err)
	require.Equal(t, tenant.Active, rec.Status)
	fresh := env.grants(t)
	require.Len(t, fresh, len(original))
	for _, d := range fresh {
		require.NotContains(t, cids(original), d.Link(), "a revoked grant is not issued again")
	}
	_, issued, err = env.authorize(t, env.get(t))
	require.NoError(t, err)
	for _, d := range issuedBy(issued, env.key.KeyDID()) {
		require.True(t, env.chained(t, d.Command()))
	}
}

// A status change that commits between the authorizer's read of the status
// and the reads that follow it never widens the answer.
func TestAuthorizeAcrossAStatusChange(t *testing.T) {
	t.Run("read as active, then disabled: the reply carries grants the change revokes", func(t *testing.T) {
		for name, request := range map[string]func(*statusEnv, *testing.T) *s3req.AuthorizeArguments{
			"GetObject":    (*statusEnv).get,
			"DeleteObject": (*statusEnv).del,
		} {
			t.Run(name, func(t *testing.T) {
				env := setupStatus(t)
				before := cids(env.grants(t))
				require.NotEmpty(t, before)
				env.authTenants.then = func() {
					require.NoError(t, env.svc.SetStatus(t.Context(), "tenant-1", "disabled"))
				}

				ok, issued, err := env.authorize(t, request(env, t))

				// The answer is built on the state before the change, so it
				// is not a refusal, and it carries the grants the key held
				// then. The change revokes every one of them, which is how
				// the gateway knows not to keep the answer.
				require.NoError(t, err)
				require.Equal(t, env.tenant, ok.Tenant)
				require.Empty(t, env.grants(t), "the change committed before the answer")
				var carried []cid.Cid
				for _, d := range issuedBy(issued, env.tenant) {
					if d.Audience() == env.key.KeyDID() {
						carried = append(carried, d.Link())
					}
				}
				require.ElementsMatch(t, before, carried)
				require.Eventually(t, func() bool {
					revoked := env.swarf.Revoked()
					for _, c := range carried {
						if !slices.Contains(revoked, c) {
							return false
						}
					}
					return true
				}, htestutil.WaitTimeout, 10*time.Millisecond, "every grant the answer carries is revoked")

				// The next request reads the new status.
				_, _, err = env.authorize(t, request(env, t))
				require.ErrorIs(t, err, auth.ErrTenantDisabled)
			})
		}
	})

	t.Run("read as disabled, then reactivated: refused", func(t *testing.T) {
		env := setupStatus(t)
		require.NoError(t, env.svc.SetStatus(t.Context(), "tenant-1", "disabled"))
		env.authTenants.then = func() {
			require.NoError(t, env.svc.SetStatus(t.Context(), "tenant-1", "active"))
		}

		_, issued, err := env.authorize(t, env.get(t))

		require.ErrorIs(t, err, auth.ErrTenantDisabled)
		require.Empty(t, issued)
		require.NotEmpty(t, env.grants(t), "the change committed before the request was refused")

		_, _, err = env.authorize(t, env.get(t))
		require.NoError(t, err)
	})
}

// An authorization reads the access key before it waits for the tenant's
// pending changes, since the key names the tenant. When the change it waited
// for deleted the key, the request is refused as one with an unknown key.
func TestAuthorizeAfterWaitingForItsKeysDeletion(t *testing.T) {
	env := setupStatus(t)
	ctx := t.Context()
	_, _, err := env.authorize(t, env.get(t))
	require.NoError(t, err)

	// Delete the key, with the deletion's task held running.
	entered, release := env.queueKeys.pause()
	deleted := make(chan error, 1)
	go func() { deleted <- env.keys.Delete(ctx, "tenant-1", env.key.KeyDID().Identifier()) }()
	select {
	case <-entered:
	case err := <-deleted:
		t.Fatalf("the deletion returned without running its task: %v", err)
	case <-time.After(htestutil.WaitTimeout):
		t.Fatal("the deletion did not start")
	}
	answered := make(chan error, 1)
	go func() {
		_, _, err := env.authorize(t, env.get(t))
		answered <- err
	}()
	select {
	case err := <-answered:
		t.Fatalf("authorization answered while the deletion was pending: %v", err)
	case err := <-deleted:
		t.Fatalf("the deletion returned while its task was held: %v", err)
	case <-time.After(htestutil.MinBlock):
	}
	close(release)
	select {
	case err := <-deleted:
		require.NoError(t, err)
	case <-time.After(htestutil.WaitTimeout):
		t.Fatal("the deletion did not finish")
	}
	select {
	case err := <-answered:
		require.ErrorIs(t, err, auth.ErrUnknownAccessKey)
	case <-time.After(htestutil.WaitTimeout):
		t.Fatal("authorization did not answer once the deletion finished")
	}
	require.Empty(t, env.grants(t))
}
