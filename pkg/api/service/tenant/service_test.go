package tenant_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	"github.com/fil-forge/hilt/internal/testutil"
	tenantsvc "github.com/fil-forge/hilt/pkg/api/service/tenant"
	"github.com/fil-forge/hilt/pkg/client/upload"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	bucketpolicymemory "github.com/fil-forge/hilt/pkg/store/bucketpolicy/memory"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	principalmemory "github.com/fil-forge/hilt/pkg/store/principal/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	wrapkeysmemory "github.com/fil-forge/hilt/pkg/store/wrapkey/memory"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	customercmds "github.com/fil-forge/libforge/commands/customer"
	ucanlib "github.com/fil-forge/libforge/ucan"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/plc"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type provisionEnv struct {
	svc         *tenantsvc.Service
	sprueFailed *bool
}

// provisionSetup builds a tenant service with a PLC directory that returns
// plcStatus to POSTs and an in-process Sprue stub whose /customer/add fails when
// *sprueFailed is set.
func provisionSetup(t *testing.T, plcStatus int) provisionEnv {
	t.Helper()

	plcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status := http.StatusOK
		if plcStatus != 0 {
			status = plcStatus
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(plcServer.Close)
	endpoint, err := url.Parse(plcServer.URL)
	require.NoError(t, err)
	plcClient, err := plc.NewDirectoryClient(*endpoint)
	require.NoError(t, err)

	sprue := testutil.RandomIssuer(t)
	hilt := testutil.RandomIssuer(t)
	dlg, err := customercmds.Add.Delegate(sprue, hilt.DID(), sprue.DID())
	require.NoError(t, err)
	proofs := ucanlib.NewContainerProofStore(container.New(container.WithDelegations(dlg)))

	sprueFailed := new(bool)
	srv := server.NewHTTP(sprue)
	srv.Handle(customercmds.Add.Command, customercmds.Add.Handler(
		func(req *binding.Request[*customercmds.AddArguments], res *binding.Response[*customercmds.AddOK]) error {
			if *sprueFailed {
				return res.SetFailure(errors.New("sprue rejected"))
			}
			return res.SetSuccess(&customercmds.AddOK{})
		}))
	sprueURL, err := url.Parse("http://sprue.test")
	require.NoError(t, err)
	upload, err := upload.NewClient(sprue.DID(), *sprueURL, hilt,
		upload.WithBaseProofs(proofs),
		upload.WithProduct(testutil.RandomDID(t)),
		upload.WithHTTPClient(&http.Client{Transport: srv}))
	require.NoError(t, err)

	svc := tenantsvc.New(zap.NewNop(), tenantmemory.New(), bucketmemory.New(),
		accesskeymemory.New(), principalmemory.New(), bucketpolicymemory.New(), delegationmemory.New(), vaultmemory.New(), wrapkeysmemory.New(), plcClient, upload, &testutil.FakeSwarf{})
	return provisionEnv{svc: svc, sprueFailed: sprueFailed}
}

func TestProvision(t *testing.T) {
	ctx := t.Context()

	t.Run("provisions a new tenant", func(t *testing.T) {
		env := provisionSetup(t, 0)
		rec, created, err := env.svc.Provision(ctx, "tenant-1")
		require.NoError(t, err)
		require.True(t, created)
		require.Equal(t, "tenant-1", rec.ExternalID)
		require.Equal(t, tenant.Active, rec.Status)
	})

	t.Run("is idempotent on the external id", func(t *testing.T) {
		env := provisionSetup(t, 0)
		first, created, err := env.svc.Provision(ctx, "tenant-2")
		require.NoError(t, err)
		require.True(t, created)
		again, created, err := env.svc.Provision(ctx, "tenant-2")
		require.NoError(t, err)
		require.False(t, created)
		require.Equal(t, first.ID, again.ID)
	})

	t.Run("maps a PLC failure to ErrDIDRegistration", func(t *testing.T) {
		env := provisionSetup(t, http.StatusInternalServerError)
		_, _, err := env.svc.Provision(ctx, "tenant-4")
		require.ErrorIs(t, err, tenantsvc.ErrDIDRegistration)
	})

	t.Run("maps an upload failure to ErrUploadRegistration", func(t *testing.T) {
		env := provisionSetup(t, 0)
		*env.sprueFailed = true
		_, _, err := env.svc.Provision(ctx, "tenant-5")
		require.ErrorIs(t, err, tenantsvc.ErrUploadRegistration)
	})
}

// simpleService builds a service with the given tenant store and no PLC/upload
// clients — enough for Get and SetStatus, which never touch them.
func simpleService(tenants tenant.Store) *tenantsvc.Service {
	return tenantsvc.New(zap.NewNop(), tenants, bucketmemory.New(),
		accesskeymemory.New(), principalmemory.New(), bucketpolicymemory.New(), delegationmemory.New(), vaultmemory.New(), wrapkeysmemory.New(), nil, nil, &testutil.FakeSwarf{})
}

func TestGetAndSetStatus(t *testing.T) {
	ctx := t.Context()

	newWithTenant := func(t *testing.T) (*tenantsvc.Service, tenant.Store) {
		tenants := tenantmemory.New()
		require.NoError(t, tenants.Add(ctx, testutil.RandomDID(t), "tenant-1", tenant.Active))
		return simpleService(tenants), tenants
	}

	t.Run("get returns the tenant", func(t *testing.T) {
		svc, _ := newWithTenant(t)
		rec, err := svc.Get(ctx, "tenant-1")
		require.NoError(t, err)
		require.Equal(t, "tenant-1", rec.ExternalID)
	})

	t.Run("get rejects an unknown tenant", func(t *testing.T) {
		svc, _ := newWithTenant(t)
		_, err := svc.Get(ctx, "missing")
		require.ErrorIs(t, err, tenantsvc.ErrTenantNotFound)
	})

	t.Run("set status updates the tenant", func(t *testing.T) {
		svc, tenants := newWithTenant(t)
		require.NoError(t, svc.SetStatus(ctx, "tenant-1", "write-locked"))
		rec, err := tenants.GetByExternalID(ctx, "tenant-1")
		require.NoError(t, err)
		require.Equal(t, tenant.WriteLocked, rec.Status)
	})

	t.Run("set status rejects an invalid status", func(t *testing.T) {
		svc, _ := newWithTenant(t)
		require.ErrorIs(t, svc.SetStatus(ctx, "tenant-1", "bogus"), tenantsvc.ErrInvalidStatus)
	})

	t.Run("set status rejects an unknown tenant", func(t *testing.T) {
		svc, _ := newWithTenant(t)
		require.ErrorIs(t, svc.SetStatus(ctx, "missing", "disabled"), tenantsvc.ErrTenantNotFound)
	})
}

// plcDirectory is an httptest-backed did:plc directory for the delete tests: it
// serves the tenant's last operation at GET .../log/last and accepts the tombstone
// POST, so the service can fetch the genesis op and publish a tombstone.
type plcDirectory struct {
	logLast       []byte
	logLastStatus int
	deactivations int
}

func (d *plcDirectory) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if d.logLastStatus != 0 {
			w.WriteHeader(d.logLastStatus)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(d.logLast)
	case http.MethodPost:
		d.deactivations++
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

type deleteEnv struct {
	svc        *tenantsvc.Service
	tenants    *tenantmemory.Store
	buckets    *bucketmemory.Store
	policies   *bucketpolicymemory.Store
	principals *principalmemory.Store
	swarf      *testutil.FakeSwarf
	// publisher is swarf as the service sees it, recording each publish's deadline.
	publisher *deadlinePublisher
	bucketID  did.DID
	tenantID  did.DID
	// grants are the delegations the tenant's one access key holds.
	grants    []cid.Cid
	directory *plcDirectory
	// tombstone is the DID's signed tombstone, for a directory that already
	// served a deactivation.
	tombstone []byte
}

func deleteSetup(t *testing.T, status tenant.Status) deleteEnv {
	t.Helper()
	ctx := t.Context()

	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	key := signer.KeyDID()
	tenantID, genesis, err := plc.New(signer,
		plc.WithRotationKeys(key),
		plc.WithVerificationMethods(map[string]did.DID{"hilt": key}),
	)
	require.NoError(t, err)

	var genesisJSON bytes.Buffer
	require.NoError(t, genesis.MarshalDagJSON(&genesisJSON))
	tomb, err := plc.NewTombstoneFromPrevious(genesis)
	require.NoError(t, err)
	signedTomb, err := plc.SignTombstone(signer, tomb)
	require.NoError(t, err)
	var tombstoneJSON bytes.Buffer
	require.NoError(t, signedTomb.MarshalDagJSON(&tombstoneJSON))
	directory := &plcDirectory{logLast: genesisJSON.Bytes()}
	dirServer := httptest.NewServer(directory)
	t.Cleanup(dirServer.Close)
	endpoint, err := url.Parse(dirServer.URL)
	require.NoError(t, err)
	plcClient, err := plc.NewDirectoryClient(*endpoint)
	require.NoError(t, err)

	tenants := tenantmemory.New()
	secrets := vaultmemory.New()
	principals := principalmemory.New()
	require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", status))
	require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), signer.Bytes()))
	require.NoError(t, principals.Add(ctx, tenantID, "user-1"))

	// One bucket with a policy, so the cascade over buckets and their policies
	// is exercised.
	buckets, policies := bucketmemory.New(), bucketpolicymemory.New()
	bucketID := testutil.RandomDID(t)
	require.NoError(t, buckets.Add(ctx, bucketID, tenantID, testutil.RandomDID(t), "tenant-1-bucket"))
	_, err = policies.Put(ctx, bucketpolicystore.Input{
		Bucket: bucketID, Tenant: tenantID,
		Policy: s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: []s3bkt.Statement{{Effect: s3bkt.Allow, Principal: s3bkt.Everyone(), Actions: s3bkt.NewStringSet("s3:GetObject"), Resources: s3bkt.NewStringSet(s3bkt.BucketARN("photos"), s3bkt.ObjectsARN("photos"))}}},

		Conditional: true,
	}, nil)
	require.NoError(t, err)

	// One access key holding a grant over the bucket, so the revocations the
	// removal publishes are observable.
	accessKeys, delegations := accesskeymemory.New(), delegationmemory.New()
	keyID := testutil.RandomDID(t)
	require.NoError(t, accessKeys.Add(ctx, accesskeystore.Input{ID: keyID, Tenant: tenantID, Name: "k1", Permissions: []string{"s3:GetObject"}}))
	held, err := grant.Issue(multikey.NewIssuer(tenantID, signer), keyID, []did.DID{bucketID}, []string{"s3:GetObject"}, nil)
	require.NoError(t, err)
	require.NoError(t, delegations.PutBatch(ctx, held))
	var grants []cid.Cid
	for _, d := range held {
		grants = append(grants, d.Link())
	}

	swarf := &testutil.FakeSwarf{}
	publisher := &deadlinePublisher{FakeSwarf: swarf}
	svc := tenantsvc.New(zap.NewNop(), tenants, buckets,
		accessKeys, principals, policies, delegations, secrets, wrapkeysmemory.New(), plcClient, nil, publisher)
	return deleteEnv{svc: svc, tenants: tenants, buckets: buckets, policies: policies,
		principals: principals, swarf: swarf, publisher: publisher, bucketID: bucketID, tenantID: tenantID, grants: grants, directory: directory,
		tombstone: tombstoneJSON.Bytes()}
}

// deadlinePublisher records how long each publish had left on its deadline,
// zero when it had none.
type deadlinePublisher struct {
	*testutil.FakeSwarf
	remaining []time.Duration
}

func (p *deadlinePublisher) PublishBatch(ctx context.Context, revoker ucan.Issuer, revoked []ucan.Delegation) error {
	var left time.Duration
	if deadline, ok := ctx.Deadline(); ok {
		left = time.Until(deadline)
	}
	p.remaining = append(p.remaining, left)
	return p.FakeSwarf.PublishBatch(ctx, revoker, revoked)
}

func TestDelete(t *testing.T) {
	ctx := t.Context()

	t.Run("deletes a disabled tenant", func(t *testing.T) {
		env := deleteSetup(t, tenant.Disabled)
		require.NoError(t, env.svc.Delete(ctx, "tenant-1"))
		_, err := env.tenants.GetByExternalID(ctx, "tenant-1")
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		ps, err := env.principals.ListByTenant(ctx, env.tenantID)
		require.NoError(t, err)
		require.Empty(t, ps)
		require.Equal(t, 1, env.directory.deactivations)
	})

	t.Run("revokes every key's delegations in one request before deactivating the DID", func(t *testing.T) {
		env := deleteSetup(t, tenant.Disabled)
		require.NoError(t, env.svc.Delete(ctx, "tenant-1"))
		require.Equal(t, 1, env.swarf.Calls())
		require.ElementsMatch(t, env.grants, env.swarf.Revoked())
		require.Equal(t, 1, env.directory.deactivations)
	})

	t.Run("bounds the revocation publish at the batch deadline", func(t *testing.T) {
		env := deleteSetup(t, tenant.Disabled)
		require.NoError(t, env.svc.Delete(context.Background(), "tenant-1"))
		require.Len(t, env.publisher.remaining, 1)
		require.Greater(t, env.publisher.remaining[0], time.Duration(0), "a stalled publish must not hold the keys' delegation locks past the batch deadline")
		require.LessOrEqual(t, env.publisher.remaining[0], grant.BatchTimeout)
	})

	t.Run("a publish failure leaves the tenant and its DID in place", func(t *testing.T) {
		env := deleteSetup(t, tenant.Disabled)
		env.swarf.Err = errors.New("swarf unreachable")
		require.ErrorContains(t, env.svc.Delete(ctx, "tenant-1"), "swarf unreachable")
		_, err := env.tenants.GetByExternalID(ctx, "tenant-1")
		require.NoError(t, err)
		require.Zero(t, env.directory.deactivations)
	})

	t.Run("an already deactivated DID publishes nothing and finishes the cascade", func(t *testing.T) {
		env := deleteSetup(t, tenant.Disabled)
		env.directory.logLast = env.tombstone
		require.NoError(t, env.svc.Delete(ctx, "tenant-1"))
		require.Zero(t, env.swarf.Calls())
		require.Zero(t, env.directory.deactivations)
		_, err := env.tenants.GetByExternalID(ctx, "tenant-1")
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})

	t.Run("deletes the tenant's buckets and their policies", func(t *testing.T) {
		env := deleteSetup(t, tenant.Disabled)
		require.NoError(t, env.svc.Delete(ctx, "tenant-1"))
		_, err := env.buckets.GetByName(ctx, "tenant-1-bucket")
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		_, err = env.policies.Get(ctx, env.bucketID)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})

	t.Run("is idempotent for an unknown tenant", func(t *testing.T) {
		env := deleteSetup(t, tenant.Disabled)
		require.NoError(t, env.svc.Delete(ctx, "missing"))
		require.Equal(t, 0, env.directory.deactivations)
	})

	t.Run("rejects a non-disabled tenant", func(t *testing.T) {
		env := deleteSetup(t, tenant.Active)
		require.ErrorIs(t, env.svc.Delete(ctx, "tenant-1"), tenantsvc.ErrTenantNotDisabled)
	})

	t.Run("maps a directory failure to ErrDIDDeactivation", func(t *testing.T) {
		env := deleteSetup(t, tenant.Disabled)
		env.directory.logLastStatus = http.StatusInternalServerError
		require.ErrorIs(t, env.svc.Delete(ctx, "tenant-1"), tenantsvc.ErrDIDDeactivation)
	})
}

// writeLockEnv is a tenant holding one access key with a read grant and a write
// grant over one bucket, which is the smallest shape that shows a write lock
// separating the two.
type writeLockEnv struct {
	svc         *tenantsvc.Service
	delegations *delegationmemory.Store
	swarf       *testutil.FakeSwarf
	keyID       did.DID
	// readGrants and writeGrants partition what the key holds by whether the
	// grant's command mutates. The split is per command, not per permission: a
	// permission maps to several Forge commands, and s3:PutObject's set
	// includes the retrieve command s3:GetObject maps to.
	readGrants  []cid.Cid
	writeGrants []cid.Cid
}

func writeLockSetup(t *testing.T, status tenant.Status) writeLockEnv {
	t.Helper()
	ctx := t.Context()

	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	tenantID := signer.KeyDID()

	tenants := tenantmemory.New()
	require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", status))

	secrets := vaultmemory.New()
	require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), signer.Bytes()))

	buckets := bucketmemory.New()
	bucketID := testutil.RandomDID(t)
	require.NoError(t, buckets.Add(ctx, bucketID, tenantID, testutil.RandomDID(t), "photos"))

	accessKeys, delegations := accesskeymemory.New(), delegationmemory.New()
	keyID := testutil.RandomDID(t)
	require.NoError(t, accessKeys.Add(ctx, accesskeystore.Input{
		ID: keyID, Tenant: tenantID, Name: "any-key",
		Permissions: []string{"s3:GetObject", "s3:PutObject"},
	}))

	issuer := multikey.NewIssuer(tenantID, signer)
	held, err := grant.Issue(issuer, keyID, []did.DID{bucketID}, []string{"s3:GetObject", "s3:PutObject"}, nil)
	require.NoError(t, err)
	require.NoError(t, delegations.PutBatch(ctx, held))

	var read, write []cid.Cid
	for _, d := range held {
		if s3perm.RevokedByWriteLock(d.Command()) {
			write = append(write, d.Link())
		} else {
			read = append(read, d.Link())
		}
	}
	require.NotEmpty(t, read, "the fixture must hold a grant the lock leaves alone")
	require.NotEmpty(t, write, "the fixture must hold a grant the lock revokes")

	swarf := &testutil.FakeSwarf{}
	svc := tenantsvc.New(zap.NewNop(), tenants, buckets,
		accessKeys, principalmemory.New(), bucketpolicymemory.New(), delegations, secrets,
		wrapkeysmemory.New(), nil, nil, swarf)

	return writeLockEnv{
		svc: svc, delegations: delegations, swarf: swarf, keyID: keyID,
		readGrants: read, writeGrants: write,
	}
}

// held is every delegation the key currently holds, by CID.
func (e writeLockEnv) held(t *testing.T) []cid.Cid {
	t.Helper()
	page, err := e.delegations.ListByAudience(t.Context(), e.keyID)
	require.NoError(t, err)
	out := make([]cid.Cid, 0, len(page.Results))
	for _, d := range page.Results {
		out = append(out, d.Link())
	}
	return out
}

func TestSetStatusWriteLock(t *testing.T) {
	ctx := t.Context()

	t.Run("revokes the write grant and leaves the read grant alone", func(t *testing.T) {
		env := writeLockSetup(t, tenant.Active)

		require.NoError(t, env.svc.SetStatus(ctx, "tenant-1", string(tenant.WriteLocked)))

		require.ElementsMatch(t, env.writeGrants, env.swarf.Revoked())
		// Both are still stored: the unlock rebuilds the write grants from the
		// ones it revoked, having nothing else that names their subject and command.
		require.ElementsMatch(t, append(append([]cid.Cid{}, env.readGrants...), env.writeGrants...), env.held(t))
	})

	t.Run("replaces the write grant with a fresh one on unlock", func(t *testing.T) {
		env := writeLockSetup(t, tenant.Active)
		require.NoError(t, env.svc.SetStatus(ctx, "tenant-1", string(tenant.WriteLocked)))
		env.swarf.Reset()

		require.NoError(t, env.svc.SetStatus(ctx, "tenant-1", string(tenant.Active)))

		held := env.held(t)
		require.Len(t, held, len(env.readGrants)+len(env.writeGrants))
		require.Subset(t, held, env.readGrants, "the read grants are never touched")
		for _, revoked := range env.writeGrants {
			require.NotContains(t, held, revoked, "a revoked write grant is replaced, not kept")
		}
		// The replacements carry new CIDs, so the revocation of the grants they
		// replace does not reach them.
		require.ElementsMatch(t, env.writeGrants, env.swarf.Revoked())
	})

	t.Run("leaves an abort usable after the lock", func(t *testing.T) {
		// A lock must not strand a multipart upload left in flight: the tenant
		// goes on paying for its parts and has no way to drop them. Aborting is
		// the one mutation the lock keeps, so every command an abort needs has to
		// come through still live — stored is not enough, since the sweep keeps
		// the grants it revoked so the unlock can rebuild them.
		env := writeLockSetup(t, tenant.Active)

		require.NoError(t, env.svc.SetStatus(ctx, "tenant-1", string(tenant.WriteLocked)))

		revoked := env.swarf.Revoked()
		page, err := env.delegations.ListByAudience(ctx, env.keyID)
		require.NoError(t, err)
		live := map[string]bool{}
		for _, d := range page.Results {
			if !slices.Contains(revoked, d.Link()) {
				live[d.Command().String()] = true
			}
		}
		for _, cmd := range s3perm.CommandsFor("s3:AbortMultipartUpload") {
			require.True(t, live[cmd.String()],
				"a write-locked tenant must keep %s, which an abort needs", cmd)
		}
		// The write path is not reopened with it: a put still loses a command.
		var putLost bool
		for _, cmd := range s3perm.CommandsFor("s3:PutObject") {
			putLost = putLost || !live[cmd.String()]
		}
		require.True(t, putLost, "a write-locked tenant must still lose a command s3:PutObject needs")
	})

	t.Run("revokes nothing when the status does not change the lock", func(t *testing.T) {
		env := writeLockSetup(t, tenant.Active)

		require.NoError(t, env.svc.SetStatus(ctx, "tenant-1", string(tenant.Disabled)))

		require.Empty(t, env.swarf.Revoked())
		require.ElementsMatch(t, append(append([]cid.Cid{}, env.readGrants...), env.writeGrants...), env.held(t))
	})
}
