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

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	"github.com/fil-forge/hilt/internal/testutil"
	tenantsvc "github.com/fil-forge/hilt/pkg/api/service/tenant"
	"github.com/fil-forge/hilt/pkg/client/upload"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	bucketpolicypostgres "github.com/fil-forge/hilt/pkg/store/bucketpolicy/postgres"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/revocation"
	revocationpostgres "github.com/fil-forge/hilt/pkg/store/revocation/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	wrapkeyspostgres "github.com/fil-forge/hilt/pkg/store/wrapkey/postgres"
	"github.com/fil-forge/hilt/pkg/tasks/revocationqueue"
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
	"github.com/jackc/pgx/v5/pgxpool"
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
	pool := testutil.PostgresOrSkip(t)

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

	svc := tenantsvc.New(zap.NewNop(), tenantpostgres.New(pool), bucketpostgres.New(pool),
		accesskeypostgres.New(pool), principalpostgres.New(pool), bucketpolicypostgres.New(pool), delegationpostgres.New(pool), vaultmemory.New(), wrapkeyspostgres.New(pool), plcClient, upload, &testutil.FakeSwarf{}, revocationpostgres.New(pool), nil)
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

// simpleService builds a service over pool with the given tenant store, a
// running task runner and no PLC/upload clients — enough for Get and
// SetStatus, which never touch them.
func simpleService(t *testing.T, pool *pgxpool.Pool, tenants tenant.Store) *tenantsvc.Service {
	t.Helper()
	secrets, swarf := vaultmemory.New(), &testutil.FakeSwarf{}
	return tenantsvc.New(zap.NewNop(), tenants, bucketpostgres.New(pool),
		accesskeypostgres.New(pool), principalpostgres.New(pool), bucketpolicypostgres.New(pool), delegationpostgres.New(pool), secrets, wrapkeyspostgres.New(pool), nil, nil, swarf,
		revocationpostgres.New(pool), testutil.StartServiceTasks(t, pool, secrets, swarf))
}

func TestGetAndSetStatus(t *testing.T) {
	ctx := t.Context()

	newWithTenant := func(t *testing.T) (*tenantsvc.Service, tenant.Store) {
		pool := testutil.PostgresOrSkip(t)
		tenants := tenantpostgres.New(pool)
		require.NoError(t, tenants.Add(ctx, testutil.RandomDID(t), "tenant-1", tenant.Active))
		return simpleService(t, pool, tenants), tenants
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
	svc  *tenantsvc.Service
	pool *pgxpool.Pool
	// keyID is the tenant's one access key.
	keyID did.DID
	// owed is the store of the revocations the tenant owes.
	owed *revocationpostgres.Store
	// issuer signs as the tenant.
	issuer     ucan.Issuer
	tenants    *tenantpostgres.Store
	buckets    *bucketpostgres.Store
	policies   *bucketpolicypostgres.Store
	principals *principalpostgres.Store
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
	pool := testutil.PostgresOrSkip(t)
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

	tenants := tenantpostgres.New(pool)
	secrets := vaultmemory.New()
	principals := principalpostgres.New(pool)
	require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", tenant.Active))
	require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), signer.Bytes()))
	require.NoError(t, principals.Add(ctx, tenantID, "user-1"))

	// One bucket with a policy, so the cascade over buckets and their policies
	// is exercised.
	buckets, policies := bucketpostgres.New(pool), bucketpolicypostgres.New(pool)
	bucketID, providerID := testutil.RandomDID(t), testutil.RandomDID(t)
	require.NoError(t, providerpostgres.New(pool).Add(ctx, providerID, "region-1", nil))
	require.NoError(t, buckets.Add(ctx, bucketID, tenantID, providerID, "tenant-1-bucket"))
	testutil.PutPolicy(t, pool, tenantID, bucketID, s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: []s3bkt.Statement{{Effect: s3bkt.Allow, Principal: s3bkt.Everyone(), Actions: s3bkt.NewStringSet("s3:GetObject"), Resources: s3bkt.NewStringSet(s3bkt.BucketARN("photos"), s3bkt.ObjectsARN("photos"))}}})

	// One access key holding a grant over the bucket, so the revocations the
	// removal publishes are observable.
	accessKeys, delegations := accesskeypostgres.New(pool), delegationpostgres.New(pool)
	keyID := testutil.RandomDID(t)
	require.NoError(t, accessKeys.Add(ctx, accesskeystore.Input{ID: keyID, Tenant: tenantID, Name: "k1", Permissions: []string{"s3:GetObject"}}))
	held, err := grant.Issue(multikey.NewIssuer(tenantID, signer), keyID, []did.DID{bucketID}, []string{"s3:GetObject"}, nil)
	require.NoError(t, err)
	require.NoError(t, delegations.PutBatch(ctx, held))
	var grants []cid.Cid
	for _, d := range held {
		grants = append(grants, d.Link())
	}

	// The status is set once the key exists: a disabled tenant takes no new key.
	require.NoError(t, tenants.SetStatus(ctx, tenantID, status))

	swarf := &testutil.FakeSwarf{}
	publisher := &deadlinePublisher{FakeSwarf: swarf}
	owed := revocationpostgres.New(pool)
	svc := tenantsvc.New(zap.NewNop(), tenants, buckets,
		accessKeys, principals, policies, delegations, secrets, wrapkeyspostgres.New(pool), plcClient, nil, publisher, owed, nil)
	return deleteEnv{svc: svc, pool: pool, keyID: keyID, owed: owed, issuer: multikey.NewIssuer(tenantID, signer), tenants: tenants, buckets: buckets, policies: policies,
		principals: principals, swarf: swarf, publisher: publisher, bucketID: bucketID, tenantID: tenantID, grants: grants, directory: directory,
		tombstone: tombstoneJSON.Bytes()}
}

// issueOwed records n delegations issued by the tenant as revocations it
// owes, and returns their CIDs.
func issueOwed(t *testing.T, env deleteEnv, n int) []cid.Cid {
	t.Helper()
	var dels []ucan.Delegation
	for len(dels) < n {
		issued, err := grant.Issue(env.issuer, testutil.RandomDID(t), []did.DID{testutil.RandomDID(t)}, []string{"s3:GetObject"}, nil)
		require.NoError(t, err)
		require.NotEmpty(t, issued)
		dels = append(dels, issued...)
	}
	dels = dels[:n]
	require.NoError(t, env.owed.Add(t.Context(), env.tenantID, dels))
	out := make([]cid.Cid, n)
	for i, d := range dels {
		out[i] = d.Link()
	}
	return out
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

	t.Run("publishes the revocations still owed before deactivating the DID", func(t *testing.T) {
		env := deleteSetup(t, tenant.Disabled)
		// More than one batch is owed, as after a disable the revocation
		// service has not taken yet.
		owed := issueOwed(t, env, revocationqueue.BatchSize+1)
		var deactivatedAtPublish []int
		env.swarf.OnPublish = func() { deactivatedAtPublish = append(deactivatedAtPublish, env.directory.deactivations) }

		require.NoError(t, env.svc.Delete(ctx, "tenant-1"))

		batches := env.swarf.Batches()
		require.Len(t, batches, 3, "two requests for what was owed, then one for the key's grants")
		var published []cid.Cid
		for _, b := range batches[:2] {
			for _, r := range b {
				require.Equal(t, env.tenantID, r.Revoker)
				published = append(published, r.Revoked)
			}
		}
		require.ElementsMatch(t, owed, published)
		require.Equal(t, []int{0, 0, 0}, deactivatedAtPublish, "every publish came before the tombstone")
		require.Equal(t, 1, env.directory.deactivations)
		_, err := env.tenants.GetByExternalID(ctx, "tenant-1")
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		stats, err := env.owed.Stats(ctx)
		require.NoError(t, err)
		require.Zero(t, stats.Count)
	})

	t.Run("a failed publish of the revocations owed leaves everything in place", func(t *testing.T) {
		env := deleteSetup(t, tenant.Disabled)
		owed := issueOwed(t, env, 3)
		env.swarf.Err = errors.New("swarf unreachable")

		err := env.svc.Delete(ctx, "tenant-1")
		require.ErrorContains(t, err, "swarf unreachable")
		require.ErrorContains(t, err, "revocations owed")

		_, err = env.tenants.GetByExternalID(ctx, "tenant-1")
		require.NoError(t, err)
		require.Zero(t, env.directory.deactivations)
		still, _, err := env.owed.Oldest(ctx, env.tenantID, revocation.Cursor{}, 10)
		require.NoError(t, err)
		require.Len(t, still, len(owed), "the rows stay owed")
		held, err := delegationpostgres.New(env.pool).ListByAudience(ctx, env.keyID)
		require.NoError(t, err)
		require.Len(t, held.Results, len(env.grants), "the key's grants were not touched")

		// The retry publishes them and deletes the tenant.
		env.swarf.Err = nil
		require.NoError(t, env.svc.Delete(ctx, "tenant-1"))
		require.Subset(t, env.swarf.Revoked(), owed)
		require.Equal(t, 1, env.directory.deactivations)
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
