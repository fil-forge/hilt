package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/api"
	principalsvc "github.com/fil-forge/hilt/pkg/api/service/principal"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	bucketpolicypostgres "github.com/fil-forge/hilt/pkg/store/bucketpolicy/postgres"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	revocationpostgres "github.com/fil-forge/hilt/pkg/store/revocation/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type principalDeps struct {
	pool        *pgxpool.Pool
	principals  *principalpostgres.Store
	policies    *bucketpolicypostgres.Store
	accessKeys  *accesskeypostgres.Store
	vault       *vaultmemory.Store
	delegations *delegationpostgres.Store
	owed        *revocationpostgres.Store
	revocations *outageSwarf
	runner      *taskrunner.Runner
	tenantID    did.DID // "tenant-1"
	tenant      ucan.Issuer
}

// outageSwarf is a revocation service that refuses every publish while down
// is set.
type outageSwarf struct {
	testutil.FakeSwarf
	down atomic.Bool
}

func (o *outageSwarf) PublishBatch(ctx context.Context, revoker ucan.Issuer, revoked []ucan.Delegation) error {
	if o.down.Load() {
		return errors.New("swarf unreachable")
	}
	return o.FakeSwarf.PublishBatch(ctx, revoker, revoked)
}

// setupPrincipals serves every principal route over a test database with two
// tenants.
func setupPrincipals(t *testing.T) (*echo.Echo, *principalDeps) {
	t.Helper()
	pool := testutil.PostgresOrSkip(t)
	tenants := tenantpostgres.New(pool)
	deps := &principalDeps{
		pool:        pool,
		principals:  principalpostgres.New(pool),
		policies:    bucketpolicypostgres.New(pool),
		accessKeys:  accesskeypostgres.New(pool),
		vault:       vaultmemory.New(),
		delegations: delegationpostgres.New(pool),
		owed:        revocationpostgres.New(pool),
		revocations: &outageSwarf{},
		tenantID:    testutil.RandomDID(t),
	}
	require.NoError(t, tenants.Add(t.Context(), deps.tenantID, "tenant-1", tenant.Active))
	require.NoError(t, tenants.Add(t.Context(), testutil.RandomDID(t), "tenant-2", tenant.Active))
	// The tenant's key is in the vault: the tasks sign revocations as the
	// tenant.
	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	require.NoError(t, deps.vault.Write(t.Context(), vault.TenantKeyPath(deps.tenantID), signer.Bytes()))
	deps.tenant = multikey.NewIssuer(deps.tenantID, signer)

	deps.runner = testutil.StartServiceTasks(t, pool, deps.vault, deps.revocations)
	svc := principalsvc.New(zap.NewNop(), tenants, deps.principals, deps.vault, deps.runner)
	e := echo.New()
	for _, r := range []api.Route{
		api.NewCreatePrincipalHandler(zap.NewNop(), svc),
		api.NewListPrincipalsHandler(zap.NewNop(), svc),
		api.NewGetPrincipalHandler(zap.NewNop(), svc),
		api.NewDeletePrincipalHandler(zap.NewNop(), svc),
	} {
		e.Add(r.Method, r.Path, r.Handler)
	}
	return e, deps
}

// createPrincipal records a principal through the API and fails the test if the
// call does not create it.
func createPrincipal(t *testing.T, e *echo.Echo, principalID string) {
	t.Helper()
	rec := doRequest(t, e, http.MethodPut, "/tenants/tenant-1/principals/"+principalID, nil)
	require.Equal(t, http.StatusCreated, rec.Code)
}

// addPrincipalKey stores a principal-bound access key and its vault entry the
// way the access-key create route does, so the principal routes have one to
// list and to remove.
func addPrincipalKey(t *testing.T, deps *principalDeps, principalID, name string) did.DID {
	t.Helper()
	ctx := t.Context()
	signer, err := ed25519.Generate()
	require.NoError(t, err)
	id := signer.KeyDID()
	require.NoError(t, deps.accessKeys.Add(ctx, accesskeystore.Input{
		ID: id, Tenant: deps.tenantID, Name: name, Principal: &principalID,
	}))
	require.NoError(t, deps.vault.Write(ctx, vault.AccessKeyPath(deps.tenantID, id), signer.Bytes()))
	dels, err := grant.Issue(deps.tenant, id, []did.DID{testutil.RandomDID(t)}, []string{"s3:GetObject"}, nil)
	require.NoError(t, err)
	require.NoError(t, deps.delegations.PutBatch(ctx, dels))
	return id
}

func TestCreatePrincipalHandler(t *testing.T) {
	t.Run("creates with 201 and repeats with 200", func(t *testing.T) {
		e, _ := setupPrincipals(t)
		rec := doRequest(t, e, http.MethodPut, "/tenants/tenant-1/principals/user-1", nil)
		require.Equal(t, http.StatusCreated, rec.Code)
		var p api.Principal
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &p))
		require.Equal(t, "user-1", p.PrincipalID)
		require.False(t, p.CreatedAt.IsZero())

		again := doRequest(t, e, http.MethodPut, "/tenants/tenant-1/principals/user-1", nil)
		require.Equal(t, http.StatusOK, again.Code)
		var repeat api.Principal
		require.NoError(t, json.Unmarshal(again.Body.Bytes(), &repeat))
		require.Equal(t, p.CreatedAt, repeat.CreatedAt)
	})

	t.Run("revives a removed principal with 201", func(t *testing.T) {
		e, _ := setupPrincipals(t)
		require.Equal(t, http.StatusCreated, doRequest(t, e, http.MethodPut, "/tenants/tenant-1/principals/user-1", nil).Code)
		require.Equal(t, http.StatusNoContent, doRequest(t, e, http.MethodDelete, "/tenants/tenant-1/principals/user-1", nil).Code)
		require.Equal(t, http.StatusNotFound, doRequest(t, e, http.MethodGet, "/tenants/tenant-1/principals/user-1", nil).Code)
		require.Equal(t, http.StatusCreated, doRequest(t, e, http.MethodPut, "/tenants/tenant-1/principals/user-1", nil).Code)
	})

	t.Run("a principalId holding a slash is refused", func(t *testing.T) {
		e, deps := setupPrincipals(t)
		rec := doRequest(t, e, http.MethodPut, "/tenants/tenant-1/principals/a%2Fb", nil)
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
		require.Equal(t, "InvalidPrincipalID", decodeError(t, rec).Code)
		recs, err := deps.principals.ListByTenant(t.Context(), deps.tenantID)
		require.NoError(t, err)
		require.Empty(t, recs)
	})

	t.Run("a principalId holding a percent is refused", func(t *testing.T) {
		e, deps := setupPrincipals(t)
		rec := doRequest(t, e, http.MethodPut, "/tenants/tenant-1/principals/x%2525y", nil)
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
		require.Equal(t, "InvalidPrincipalID", decodeError(t, rec).Code)
		recs, err := deps.principals.ListByTenant(t.Context(), deps.tenantID)
		require.NoError(t, err)
		require.Empty(t, recs)
	})

	t.Run("refuses a principalId holding a path delimiter or naming a dot segment", func(t *testing.T) {
		e, deps := setupPrincipals(t)
		for _, wire := range []string{"a;b", "a,b", "a%3Fb", "a%25b", ".", "..", "%2E", "%2E%2E"} {
			for _, method := range []string{http.MethodPut, http.MethodGet, http.MethodDelete} {
				rec := doRequest(t, e, method, "/tenants/tenant-1/principals/"+wire, nil)
				require.Equal(t, http.StatusUnprocessableEntity, rec.Code, "%s %s", method, wire)
				require.Equal(t, "InvalidPrincipalID", decodeError(t, rec).Code, "%s %s", method, wire)
			}
		}
		recs, err := deps.principals.ListByTenant(t.Context(), deps.tenantID)
		require.NoError(t, err)
		require.Empty(t, recs)
	})

	t.Run("a principalId holding a space or unicode is recorded decoded", func(t *testing.T) {
		e, deps := setupPrincipals(t)
		for wire, id := range map[string]string{"a%20b": "a b", "%C3%BCnicode": "\u00fcnicode"} {
			require.Equal(t, http.StatusCreated, doRequest(t, e, http.MethodPut, "/tenants/tenant-1/principals/"+wire, nil).Code, wire)
			_, err := deps.principals.Get(t.Context(), deps.tenantID, id)
			require.NoError(t, err, id)
		}
	})

	t.Run("a tenantId holding a slash is refused", func(t *testing.T) {
		e, _ := setupPrincipals(t)
		rec := doRequest(t, e, http.MethodPut, "/tenants/a%2Fb/principals/user-1", nil)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Equal(t, "InvalidTenantID", decodeError(t, rec).Code)
	})

	t.Run("unknown tenant is 404", func(t *testing.T) {
		e, _ := setupPrincipals(t)
		rec := doRequest(t, e, http.MethodPut, "/tenants/missing/principals/user-1", nil)
		require.Equal(t, http.StatusNotFound, rec.Code)
		require.Equal(t, api.Error{Code: "TenantNotFound", Message: "tenant not found"}, decodeError(t, rec))
	})

	t.Run("the policy wildcard is 422", func(t *testing.T) {
		e, deps := setupPrincipals(t)
		rec := doRequest(t, e, http.MethodPut, "/tenants/tenant-1/principals/"+s3bkt.Wildcard, nil)
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
		require.Equal(t, "InvalidPrincipalID", decodeError(t, rec).Code)
		recs, err := deps.principals.ListByTenant(t.Context(), deps.tenantID)
		require.NoError(t, err)
		require.Empty(t, recs)
	})
}

func TestListGetPrincipalHandlers(t *testing.T) {
	e, _ := setupPrincipals(t)
	createPrincipal(t, e, "user-2")
	createPrincipal(t, e, "user-1")

	t.Run("lists the tenant's principals", func(t *testing.T) {
		rec := doRequest(t, e, http.MethodGet, "/tenants/tenant-1/principals", nil)
		require.Equal(t, http.StatusOK, rec.Code)
		var list api.PrincipalList
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
		require.Len(t, list.Items, 2)
		require.Equal(t, "user-1", list.Items[0].PrincipalID)
		require.Equal(t, "user-2", list.Items[1].PrincipalID)
	})

	t.Run("gets one principal", func(t *testing.T) {
		rec := doRequest(t, e, http.MethodGet, "/tenants/tenant-1/principals/user-1", nil)
		require.Equal(t, http.StatusOK, rec.Code)
		var p api.Principal
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &p))
		require.Equal(t, "user-1", p.PrincipalID)
	})

	t.Run("unknown principal is 404", func(t *testing.T) {
		rec := doRequest(t, e, http.MethodGet, "/tenants/tenant-1/principals/user-9", nil)
		require.Equal(t, http.StatusNotFound, rec.Code)
		require.Equal(t, api.Error{Code: "PrincipalNotFound", Message: "principal not found"}, decodeError(t, rec))
	})

	t.Run("another tenant's principal is 404", func(t *testing.T) {
		rec := doRequest(t, e, http.MethodGet, "/tenants/tenant-2/principals/user-1", nil)
		require.Equal(t, http.StatusNotFound, rec.Code)
		require.Equal(t, api.Error{Code: "PrincipalNotFound", Message: "principal not found"}, decodeError(t, rec))
	})
}

func TestDeletePrincipalHandler(t *testing.T) {
	ctx := t.Context()

	t.Run("removes the principal, its keys and its access, and is idempotent", func(t *testing.T) {
		e, deps := setupPrincipals(t)
		createPrincipal(t, e, "user-1")
		keyID := addPrincipalKey(t, deps, "user-1", "laptop")
		bucket := testutil.RandomDID(t)
		require.NoError(t, bucketpostgres.New(deps.pool).Add(ctx, bucket, deps.tenantID, addProvider(t, deps.pool), "photos"))
		testutil.PutPolicy(t, deps.pool, deps.tenantID, bucket, s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: []s3bkt.Statement{
			{Effect: s3bkt.Allow, Principal: s3bkt.Only("user-1"), Actions: s3bkt.NewStringSet("s3:GetObject"), Resources: s3bkt.NewStringSet(s3bkt.BucketARN("photos"), s3bkt.ObjectsARN("photos"))},
		}})

		rec := doRequest(t, e, http.MethodDelete, "/tenants/tenant-1/principals/user-1", nil)
		require.Equal(t, http.StatusNoContent, rec.Code)
		testutil.AwaitPublished(t, deps.runner, deps.tenantID)
		require.Len(t, deps.revocations.Revoked(), 1, "the key's delegation is revoked")

		_, err := deps.accessKeys.Get(ctx, keyID)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		dels, err := deps.delegations.ListByAudience(ctx, keyID)
		require.NoError(t, err)
		require.Empty(t, dels.Results)
		_, err = deps.vault.Read(ctx, vault.AccessKeyPath(deps.tenantID, keyID))
		require.ErrorIs(t, err, vault.ErrNotFound)
		_, err = deps.policies.Get(ctx, bucket)
		require.ErrorIs(t, err, store.ErrRecordNotFound)

		again := doRequest(t, e, http.MethodDelete, "/tenants/tenant-1/principals/user-1", nil)
		require.Equal(t, http.StatusNoContent, again.Code, "a principal already gone is 204")
	})

	t.Run("an unreachable revocation service still removes the principal, and owes the revocations", func(t *testing.T) {
		e, deps := setupPrincipals(t)
		createPrincipal(t, e, "user-1")
		keyID := addPrincipalKey(t, deps, "user-1", "laptop")
		held, err := deps.delegations.ListByAudience(ctx, keyID)
		require.NoError(t, err)
		require.Len(t, held.Results, 1)
		deps.revocations.down.Store(true)

		rec := doRequest(t, e, http.MethodDelete, "/tenants/tenant-1/principals/user-1", nil)
		require.Equal(t, http.StatusNoContent, rec.Code)

		get := doRequest(t, e, http.MethodGet, "/tenants/tenant-1/principals/user-1", nil)
		require.Equal(t, http.StatusNotFound, get.Code)
		_, err = deps.accessKeys.Get(ctx, keyID)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		owed, err := deps.owed.Oldest(ctx, deps.tenantID, 10)
		require.NoError(t, err)
		require.Len(t, owed, 1)
		require.Equal(t, held.Results[0].Link(), owed[0].Link())
		require.Empty(t, deps.revocations.Revoked())
	})

	t.Run("unknown tenant is 404", func(t *testing.T) {
		e, _ := setupPrincipals(t)
		rec := doRequest(t, e, http.MethodDelete, "/tenants/missing/principals/user-1", nil)
		require.Equal(t, http.StatusNotFound, rec.Code)
	})
}
