package tenant_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/fil-forge/hilt/internal/testutil"
	tenantsvc "github.com/fil-forge/hilt/pkg/api/service/tenant"
	"github.com/fil-forge/hilt/pkg/client/upload"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	providermemory "github.com/fil-forge/hilt/pkg/store/provider/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	wrapkeysmemory "github.com/fil-forge/hilt/pkg/store/wrapkey/memory"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	blobcmds "github.com/fil-forge/libforge/commands/blob"
	contentcmds "github.com/fil-forge/libforge/commands/content"
	customercmds "github.com/fil-forge/libforge/commands/customer"
	ucanlib "github.com/fil-forge/libforge/ucan"
	swarfclient "github.com/fil-forge/swarf/pkg/client"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/plc"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type recordingRevocations struct {
	err       error
	published []ucan.Delegation
}

func (r *recordingRevocations) Publish(_ context.Context, _ ucan.Issuer, revoked ucan.Delegation, _ ...swarfclient.PublishOption) error {
	if r.err != nil {
		return r.err
	}
	r.published = append(r.published, revoked)
	return nil
}

// failingTenants is a tenant store whose SetStatus can be made to fail.
type failingTenants struct {
	tenant.Store
	failSetStatus bool
}

func (f *failingTenants) SetStatus(ctx context.Context, id did.DID, status tenant.Status) error {
	if f.failSetStatus {
		return errors.New("tenant store unavailable")
	}
	return f.Store.SetStatus(ctx, id, status)
}

func (r *recordingRevocations) links() []cid.Cid {
	links := make([]cid.Cid, 0, len(r.published))
	for _, d := range r.published {
		links = append(links, d.Link())
	}
	return links
}

// grantEnv is a tenant ("tenant-1") in the given status with one access key
// holding a read grant (tenant-wide /content/retrieve) and a write grant
// (/blob/add over a bucket, expiring in an hour).
type grantEnv struct {
	svc         *tenantsvc.Service
	tenants     *failingTenants
	delegations *delegationmemory.Store
	revocations *recordingRevocations
	tenantID    did.DID
	accessKey   did.DID
	bucketID    did.DID
	exp         ucan.UnixTimestamp
	read, write ucan.Delegation
}

func newGrantEnv(t *testing.T, status tenant.Status) grantEnv {
	t.Helper()
	ctx := t.Context()
	tenants := &failingTenants{Store: tenantmemory.New()}
	accessKeys, delegations, secrets := accesskeymemory.New(), delegationmemory.New(), vaultmemory.New()
	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	env := grantEnv{
		tenants:     tenants,
		delegations: delegations,
		revocations: &recordingRevocations{},
		tenantID:    signer.KeyDID(),
		accessKey:   testutil.RandomIssuer(t).DID(),
		bucketID:    testutil.RandomDID(t),
		exp:         ucan.UnixTimestamp(time.Now().Add(time.Hour).Unix()),
	}
	require.NoError(t, tenants.Add(ctx, env.tenantID, "tenant-1", testutil.RandomDID(t), status))
	require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(env.tenantID), signer.Bytes()))
	require.NoError(t, accessKeys.Add(ctx, env.accessKey, env.tenantID, "key", nil, []string{"s3:GetObject", "s3:PutObject"}, nil))

	tenantIssuer := multikey.NewIssuer(env.tenantID, signer)
	env.read, err = delegation.Delegate(tenantIssuer, env.accessKey, did.Undef, contentcmds.Retrieve.Command, delegation.WithNoExpiration())
	require.NoError(t, err)
	env.write, err = delegation.Delegate(tenantIssuer, env.accessKey, env.bucketID, blobcmds.Add.Command, delegation.WithExpiration(env.exp))
	require.NoError(t, err)
	require.NoError(t, delegations.PutBatch(ctx, []ucan.Delegation{env.read, env.write}))

	env.svc = tenantsvc.New(zap.NewNop(), tenants, providermemory.New(), bucketmemory.New(),
		accessKeys, delegations, secrets, wrapkeysmemory.New(), nil, nil, env.revocations)
	return env
}

// requireReissued checks the key now holds the unchanged read grant and one
// write grant of the original's shape, other than the original, and returns
// that write grant.
func (e grantEnv) requireReissued(t *testing.T) ucan.Delegation {
	t.Helper()
	page, err := e.delegations.ListByAudience(t.Context(), e.accessKey)
	require.NoError(t, err)
	require.Len(t, page.Results, 2)
	var reissued ucan.Delegation
	for _, d := range page.Results {
		if d.Link() == e.read.Link() {
			continue
		}
		reissued = d
	}
	require.NotNil(t, reissued, "the read grant must be kept")
	require.NotEqual(t, e.write.Link(), reissued.Link(), "the replaced grant must be gone")
	require.Equal(t, e.tenantID, reissued.Issuer())
	require.Equal(t, e.bucketID, reissued.Subject())
	require.Equal(t, blobcmds.Add.Command.String(), reissued.Command().String())
	require.Equal(t, e.exp, *reissued.Expiration())
	return reissued
}

func (e grantEnv) requireStatus(t *testing.T, want tenant.Status) {
	t.Helper()
	rec, err := e.tenants.Get(t.Context(), e.tenantID)
	require.NoError(t, err)
	require.Equal(t, want, rec.Status)
}

type provisionEnv struct {
	svc         *tenantsvc.Service
	providers   *providermemory.Store
	sprueFailed *bool
}

// provisionSetup builds a tenant service with a PLC directory that returns
// plcStatus to POSTs and an in-process Sprue stub whose /customer/add fails when
// *sprueFailed is set.
func provisionSetup(t *testing.T, plcStatus int) provisionEnv {
	t.Helper()
	providers := providermemory.New()

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

	svc := tenantsvc.New(zap.NewNop(), tenantmemory.New(), providers, bucketmemory.New(),
		accesskeymemory.New(), delegationmemory.New(), vaultmemory.New(), wrapkeysmemory.New(), plcClient, upload, nil)
	return provisionEnv{svc: svc, providers: providers, sprueFailed: sprueFailed}
}

func TestProvision(t *testing.T) {
	ctx := t.Context()

	t.Run("provisions a new tenant", func(t *testing.T) {
		env := provisionSetup(t, 0)
		require.NoError(t, env.providers.Add(ctx, testutil.RandomDID(t), "us-east-1", nil))
		rec, created, err := env.svc.Provision(ctx, "tenant-1", "us-east-1")
		require.NoError(t, err)
		require.True(t, created)
		require.Equal(t, "tenant-1", rec.ExternalID)
		require.Equal(t, tenant.Active, rec.Status)
	})

	t.Run("is idempotent on the external id", func(t *testing.T) {
		env := provisionSetup(t, 0)
		require.NoError(t, env.providers.Add(ctx, testutil.RandomDID(t), "us-east-1", nil))
		first, created, err := env.svc.Provision(ctx, "tenant-2", "us-east-1")
		require.NoError(t, err)
		require.True(t, created)
		again, created, err := env.svc.Provision(ctx, "tenant-2", "us-east-1")
		require.NoError(t, err)
		require.False(t, created)
		require.Equal(t, first.ID, again.ID)
	})

	t.Run("rejects a missing region", func(t *testing.T) {
		env := provisionSetup(t, 0)
		_, _, err := env.svc.Provision(ctx, "tenant-3", "")
		require.ErrorIs(t, err, tenantsvc.ErrRegionRequired)
	})

	t.Run("rejects an unknown region", func(t *testing.T) {
		env := provisionSetup(t, 0)
		_, _, err := env.svc.Provision(ctx, "tenant-3", "nowhere")
		require.ErrorIs(t, err, tenantsvc.ErrUnknownRegion)
	})

	t.Run("maps a PLC failure to ErrDIDRegistration", func(t *testing.T) {
		env := provisionSetup(t, http.StatusInternalServerError)
		require.NoError(t, env.providers.Add(ctx, testutil.RandomDID(t), "us-east-1", nil))
		_, _, err := env.svc.Provision(ctx, "tenant-4", "us-east-1")
		require.ErrorIs(t, err, tenantsvc.ErrDIDRegistration)
	})

	t.Run("maps an upload failure to ErrUploadRegistration", func(t *testing.T) {
		env := provisionSetup(t, 0)
		*env.sprueFailed = true
		require.NoError(t, env.providers.Add(ctx, testutil.RandomDID(t), "us-east-1", nil))
		_, _, err := env.svc.Provision(ctx, "tenant-5", "us-east-1")
		require.ErrorIs(t, err, tenantsvc.ErrUploadRegistration)
	})
}

// simpleService builds a service with the given tenant store and no PLC/upload
// clients — enough for Get and SetStatus, which never touch them.
func simpleService(tenants tenant.Store) *tenantsvc.Service {
	return tenantsvc.New(zap.NewNop(), tenants, providermemory.New(), bucketmemory.New(),
		accesskeymemory.New(), delegationmemory.New(), vaultmemory.New(), wrapkeysmemory.New(), nil, nil, nil)
}

func TestGetAndSetStatus(t *testing.T) {
	ctx := t.Context()

	newWithTenant := func(t *testing.T) (*tenantsvc.Service, tenant.Store) {
		tenants := tenantmemory.New()
		require.NoError(t, tenants.Add(ctx, testutil.RandomDID(t), "tenant-1", testutil.RandomDID(t), tenant.Active))
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

	t.Run("write-lock revokes only write grants, and unlock reissues them", func(t *testing.T) {
		env := newGrantEnv(t, tenant.Active)

		// Locking revokes the write grant and leaves the read grant valid.
		require.NoError(t, env.svc.SetStatus(ctx, "tenant-1", "write-locked"))
		require.Equal(t, []cid.Cid{env.write.Link()}, env.revocations.links())

		// Reapplying the lock sweeps again, so a retried lock finishes a partial
		// sweep; the repeat revocation is harmless.
		require.NoError(t, env.svc.SetStatus(ctx, "tenant-1", "write-locked"))
		require.Equal(t, []cid.Cid{env.write.Link(), env.write.Link()}, env.revocations.links())

		// Unlocking replaces the revoked write grant with one of the same shape,
		// and keeps the read grant as it was. The replaced grant is revoked again
		// on the way out, which is harmless.
		require.NoError(t, env.svc.SetStatus(ctx, "tenant-1", "active"))
		reissued := env.requireReissued(t)
		require.Len(t, env.revocations.published, 3)
		require.NotEqual(t, env.write.Link(), reissued.Link())
		env.requireStatus(t, tenant.Active)
	})

	t.Run("returning to active revokes the grants it replaces", func(t *testing.T) {
		// A tenant that was disabled, not write-locked, still holds live write
		// grants. Unlocking replaces them, so it must revoke them: a later lock
		// sweeps only the grants Hilt still stores, and would leave these live in
		// a gateway's cache.
		env := newGrantEnv(t, tenant.Active)
		require.NoError(t, env.svc.SetStatus(ctx, "tenant-1", "disabled"))
		require.Empty(t, env.revocations.published)

		require.NoError(t, env.svc.SetStatus(ctx, "tenant-1", "active"))
		reissued := env.requireReissued(t)
		require.Equal(t, []cid.Cid{env.write.Link()}, env.revocations.links())

		require.NoError(t, env.svc.SetStatus(ctx, "tenant-1", "write-locked"))
		require.Equal(t, []cid.Cid{env.write.Link(), reissued.Link()}, env.revocations.links())
	})

	t.Run("a lock whose status update fails revokes nothing", func(t *testing.T) {
		// The sweep runs only once the lock is stored, so a failed lock leaves the
		// tenant active with its write grants intact.
		env := newGrantEnv(t, tenant.Active)
		env.tenants.failSetStatus = true
		require.Error(t, env.svc.SetStatus(ctx, "tenant-1", "write-locked"))
		require.Empty(t, env.revocations.published)
		env.requireStatus(t, tenant.Active)
	})

	t.Run("a retried lock finishes a sweep that failed", func(t *testing.T) {
		env := newGrantEnv(t, tenant.Active)
		env.revocations.err = errors.New("swarf unavailable")
		require.Error(t, env.svc.SetStatus(ctx, "tenant-1", "write-locked"))
		// The lock holds even though the sweep failed, so Hilt refuses writes.
		env.requireStatus(t, tenant.WriteLocked)
		require.Empty(t, env.revocations.published)

		env.revocations.err = nil
		require.NoError(t, env.svc.SetStatus(ctx, "tenant-1", "write-locked"))
		require.Equal(t, []cid.Cid{env.write.Link()}, env.revocations.links())
	})

	t.Run("a failed status update revokes the grants it reissued", func(t *testing.T) {
		env := newGrantEnv(t, tenant.WriteLocked)
		env.tenants.failSetStatus = true

		require.Error(t, env.svc.SetStatus(ctx, "tenant-1", "active"))
		env.requireStatus(t, tenant.WriteLocked)
		reissued := env.requireReissued(t)
		// The replaced grant, then the replacement that must not stay live while
		// the tenant is still locked.
		require.Equal(t, []cid.Cid{env.write.Link(), reissued.Link()}, env.revocations.links())

		// A retry reissues again and succeeds.
		env.tenants.failSetStatus = false
		require.NoError(t, env.svc.SetStatus(ctx, "tenant-1", "active"))
		require.NotEqual(t, reissued.Link(), env.requireReissued(t).Link())
		env.requireStatus(t, tenant.Active)
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
	svc       *tenantsvc.Service
	tenants   *tenantmemory.Store
	directory *plcDirectory
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
	directory := &plcDirectory{logLast: genesisJSON.Bytes()}
	dirServer := httptest.NewServer(directory)
	t.Cleanup(dirServer.Close)
	endpoint, err := url.Parse(dirServer.URL)
	require.NoError(t, err)
	plcClient, err := plc.NewDirectoryClient(*endpoint)
	require.NoError(t, err)

	tenants := tenantmemory.New()
	secrets := vaultmemory.New()
	require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", testutil.RandomDID(t), status))
	require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), signer.Bytes()))

	svc := tenantsvc.New(zap.NewNop(), tenants, providermemory.New(), bucketmemory.New(),
		accesskeymemory.New(), delegationmemory.New(), secrets, wrapkeysmemory.New(), plcClient, nil, nil)
	return deleteEnv{svc: svc, tenants: tenants, directory: directory}
}

func TestDelete(t *testing.T) {
	ctx := t.Context()

	t.Run("deletes a disabled tenant", func(t *testing.T) {
		env := deleteSetup(t, tenant.Disabled)
		require.NoError(t, env.svc.Delete(ctx, "tenant-1"))
		_, err := env.tenants.GetByExternalID(ctx, "tenant-1")
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		require.Equal(t, 1, env.directory.deactivations)
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
