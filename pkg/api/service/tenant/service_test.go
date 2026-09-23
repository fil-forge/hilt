package tenant_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	tenantsvc "github.com/fil-forge/hilt/pkg/api/service/tenant"
	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/client/upload"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	bucketpolicymemory "github.com/fil-forge/hilt/pkg/store/bucketpolicy/memory"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	principalmemory "github.com/fil-forge/hilt/pkg/store/principal/memory"
	providermemory "github.com/fil-forge/hilt/pkg/store/provider/memory"
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
		accesskeymemory.New(), principalmemory.New(), bucketpolicymemory.New(), delegationmemory.New(), vaultmemory.New(), wrapkeysmemory.New(), plcClient, upload, &fakeSwarf{})
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
		accesskeymemory.New(), principalmemory.New(), bucketpolicymemory.New(), delegationmemory.New(), vaultmemory.New(), wrapkeysmemory.New(), nil, nil, &fakeSwarf{})
}

// fakeSwarf records the delegations it was asked to revoke, and fails every
// publish once err is set.
type fakeSwarf struct {
	err     error
	calls   int
	revoked []cid.Cid
}

func (f *fakeSwarf) PublishBatch(_ context.Context, _ ucan.Issuer, revoked []ucan.Delegation) error {
	if f.err != nil {
		return f.err
	}
	f.calls++
	for _, d := range revoked {
		f.revoked = append(f.revoked, d.Link())
	}
	return nil
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
	swarf      *fakeSwarf
	bucketID   did.DID
	tenantID   did.DID
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
	require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", testutil.RandomDID(t), status))
	require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), signer.Bytes()))
	require.NoError(t, principals.Add(ctx, tenantID, "user-1"))

	// One bucket with a policy, so the cascade over buckets and their policies
	// is exercised.
	buckets, policies := bucketmemory.New(), bucketpolicymemory.New()
	bucketID := testutil.RandomDID(t)
	require.NoError(t, buckets.Add(ctx, bucketID, tenantID, "tenant-1-bucket"))
	_, err = policies.Put(ctx, bucketpolicystore.Input{
		Bucket: bucketID, Tenant: tenantID,
		Policy: bucketpolicy.Policy{Statements: []bucketpolicy.Statement{{Effect: bucketpolicy.Allow, Principal: bucketpolicy.Everyone(), Actions: []string{"s3:GetObject"}}}},
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

	swarf := &fakeSwarf{}
	svc := tenantsvc.New(zap.NewNop(), tenants, providermemory.New(), buckets,
		accessKeys, principals, policies, delegations, secrets, wrapkeysmemory.New(), plcClient, nil, swarf)
	return deleteEnv{svc: svc, tenants: tenants, buckets: buckets, policies: policies,
		principals: principals, swarf: swarf, bucketID: bucketID, tenantID: tenantID, grants: grants, directory: directory,
		tombstone: tombstoneJSON.Bytes()}
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
		require.Equal(t, 1, env.swarf.calls)
		require.ElementsMatch(t, env.grants, env.swarf.revoked)
		require.Equal(t, 1, env.directory.deactivations)
	})

	t.Run("a publish failure leaves the tenant and its DID in place", func(t *testing.T) {
		env := deleteSetup(t, tenant.Disabled)
		env.swarf.err = errors.New("swarf unreachable")
		require.ErrorContains(t, env.svc.Delete(ctx, "tenant-1"), "swarf unreachable")
		_, err := env.tenants.GetByExternalID(ctx, "tenant-1")
		require.NoError(t, err)
		require.Zero(t, env.directory.deactivations)
	})

	t.Run("an already deactivated DID publishes nothing and finishes the cascade", func(t *testing.T) {
		env := deleteSetup(t, tenant.Disabled)
		env.directory.logLast = env.tombstone
		require.NoError(t, env.svc.Delete(ctx, "tenant-1"))
		require.Zero(t, env.swarf.calls)
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
