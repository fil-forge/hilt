package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/api"
	accesskeysvc "github.com/fil-forge/hilt/pkg/api/service/accesskey"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	principalmemory "github.com/fil-forge/hilt/pkg/store/principal/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	swarfclient "github.com/fil-forge/swarf/pkg/client"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/plc"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// noopRevocations stands in for the revocation service: these tests exercise the
// HTTP layer, not revocation (see the accesskey service tests for that).
type noopRevocations struct{}

func (noopRevocations) Publish(context.Context, ucan.Issuer, ucan.Delegation, ...swarfclient.PublishOption) error {
	return nil
}

// errAssertPublishFailed is the canned failure a test publisher returns.
var errAssertPublishFailed = errors.New("swarf unreachable")

// recordingInvalidations stands in for the principal invalidation publisher,
// recording the principals it was asked to invalidate. A policy write
// publishes its batch concurrently, so the record is kept in sorted order
// rather than arrival order.
type recordingInvalidations struct {
	mu         sync.Mutex
	err        error
	principals []string
}

func (r *recordingInvalidations) Invalidate(_ context.Context, _ did.DID, principal string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.principals = append(r.principals, principal)
	slices.Sort(r.principals)
	return nil
}

type accessKeyDeps struct {
	tenants       *tenantmemory.Store
	accessKeys    *accesskeymemory.Store
	principals    *principalmemory.Store
	buckets       *bucketmemory.Store
	delegations   *delegationmemory.Store
	vault         vault.Vault
	invalidations *recordingInvalidations
	tenantID      did.DID // owner of "tenant-1" + "bucket-a", with principal "alice"
	bucketID      did.DID // "bucket-a", owned by tenant-1
	otherBucket   string  // "bucket-b", owned by a different tenant
}

// addTenant creates a tenant with a real did:plc key written to the vault and a
// single bucket owned by it, returning the tenant DID and bucket DID.
func addTenant(t *testing.T, deps *accessKeyDeps, externalID, bucketName string) (did.DID, did.DID) {
	t.Helper()
	ctx := t.Context()
	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	key := signer.KeyDID()
	tenantID, _, err := plc.New(signer,
		plc.WithRotationKeys(key),
		plc.WithVerificationMethods(map[string]did.DID{"hilt": key}),
	)
	require.NoError(t, err)
	require.NoError(t, deps.tenants.Add(ctx, tenantID, externalID, testutil.RandomDID(t), tenant.Active))
	require.NoError(t, deps.vault.Write(ctx, "/tenant/"+tenantID.String(), signer.Bytes()))
	bucketID := testutil.RandomDID(t)
	require.NoError(t, deps.buckets.Add(ctx, bucketID, tenantID, bucketName))
	return tenantID, bucketID
}

func setupAccessKeys(t *testing.T) (*echo.Echo, *accessKeyDeps) {
	t.Helper()
	deps := &accessKeyDeps{
		tenants:       tenantmemory.New(),
		accessKeys:    accesskeymemory.New(),
		principals:    principalmemory.New(),
		buckets:       bucketmemory.New(),
		delegations:   delegationmemory.New(),
		vault:         vaultmemory.New(),
		invalidations: &recordingInvalidations{},
		otherBucket:   "bucket-b",
	}
	deps.tenantID, deps.bucketID = addTenant(t, deps, "tenant-1", "bucket-a")
	addTenant(t, deps, "tenant-2", deps.otherBucket) // a foreign tenant + bucket
	require.NoError(t, deps.principals.Add(t.Context(), deps.tenantID, "alice"))

	svc := accesskeysvc.New(zap.NewNop(), deps.tenants, deps.accessKeys, deps.principals, deps.buckets, deps.delegations, deps.vault, noopRevocations{}, deps.invalidations)
	e := echo.New()
	for _, r := range []api.Route{
		api.NewCreateAccessKeyHandler(zap.NewNop(), svc),
		api.NewListAccessKeysHandler(zap.NewNop(), svc),
		api.NewGetAccessKeyHandler(zap.NewNop(), svc),
		api.NewDeleteAccessKeyHandler(zap.NewNop(), svc),
	} {
		e.Add(r.Method, r.Path, r.Handler)
	}
	return e, deps
}

func createAccessKey(t *testing.T, e *echo.Echo, tenantID string, body api.CreateAccessKeyRequest) *httptest.ResponseRecorder {
	t.Helper()
	enc, err := json.Marshal(body)
	require.NoError(t, err)
	return doRequest(t, e, http.MethodPost, "/tenants/"+tenantID+"/access-keys", enc)
}

func TestCreateAccessKeyHandler(t *testing.T) {
	ctx := t.Context()

	t.Run("creates a bucket-scoped key and issues delegations", func(t *testing.T) {
		e, deps := setupAccessKeys(t)
		rec := createAccessKey(t, e, "tenant-1", api.CreateAccessKeyRequest{
			Name:        "k1",
			Permissions: []string{"s3:GetObject", "s3:PutObject"},
			Buckets:     []string{"bucket-a"},
		})
		require.Equal(t, http.StatusCreated, rec.Code)

		var created api.CreatedAccessKey
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
		require.NotEmpty(t, created.AccessKeyID)
		require.True(t, strings.HasPrefix(created.SecretAccessKey, "u"), "secret is multibase base64url")
		require.Equal(t, []string{"bucket-a"}, created.Buckets)
		require.Nil(t, created.ExpiresAt)

		akID, err := did.Parse(did.KeyPrefix + created.AccessKeyID)
		require.NoError(t, err)

		// Record persisted.
		storedRec, err := deps.accessKeys.Get(ctx, akID)
		require.NoError(t, err)
		require.Equal(t, "k1", storedRec.Name)
		require.Equal(t, []did.DID{deps.bucketID}, storedRec.Buckets)

		// Private key in the vault.
		_, err = deps.vault.Read(ctx, "/tenant/"+deps.tenantID.String()+"/access-key/"+akID.String())
		require.NoError(t, err)

		// 6 delegations: /content/retrieve + /blob/add + /index/add + /upload/add +
		// /blob/abort + /blob/remove, all scoped to the bucket, issued by the
		// tenant to the access key.
		dels, err := deps.delegations.ListByAudience(ctx, akID)
		require.NoError(t, err)
		require.Len(t, dels.Results, 6)
		cmds := map[string]bool{}
		for _, d := range dels.Results {
			cmds[d.Command().String()] = true
			require.Equal(t, deps.bucketID, d.Subject())
			require.Equal(t, akID, d.Audience())
			require.Equal(t, deps.tenantID, d.Issuer())
		}
		require.Equal(t, map[string]bool{
			"/content/retrieve": true,
			"/blob/add":         true,
			"/index/add":        true,
			"/upload/add":       true,
			"/blob/abort":       true,
			"/blob/remove":      true,
		}, cmds)
	})

	t.Run("tenant-wide key issues powerline delegations", func(t *testing.T) {
		e, deps := setupAccessKeys(t)
		rec := createAccessKey(t, e, "tenant-1", api.CreateAccessKeyRequest{
			Name:        "wide",
			Permissions: []string{"s3:GetObject"},
		})
		require.Equal(t, http.StatusCreated, rec.Code)
		var created api.CreatedAccessKey
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
		require.Empty(t, created.Buckets)

		akID, err := did.Parse(did.KeyPrefix + created.AccessKeyID)
		require.NoError(t, err)
		dels, err := deps.delegations.ListByAudience(ctx, akID)
		require.NoError(t, err)
		require.Len(t, dels.Results, 1)
		require.False(t, dels.Results[0].Subject().Defined(), "powerline subject is undefined")
	})

	t.Run("permissions without a Forge command issue no delegations", func(t *testing.T) {
		e, deps := setupAccessKeys(t)
		rec := createAccessKey(t, e, "tenant-1", api.CreateAccessKeyRequest{
			Name:        "buckets-only",
			Permissions: []string{"s3:CreateBucket", "s3:ListAllMyBuckets"},
		})
		require.Equal(t, http.StatusCreated, rec.Code)
		var created api.CreatedAccessKey
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))

		akID, err := did.Parse(did.KeyPrefix + created.AccessKeyID)
		require.NoError(t, err)
		dels, err := deps.delegations.ListByAudience(ctx, akID)
		require.NoError(t, err)
		require.Empty(t, dels.Results)

		// Still retrievable, with the permissions stored.
		got, err := deps.accessKeys.Get(ctx, akID)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"s3:CreateBucket", "s3:ListAllMyBuckets"}, got.Permissions)
	})

	t.Run("expiry is persisted, returned, and set on delegations", func(t *testing.T) {
		e, deps := setupAccessKeys(t)
		exp := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
		rec := createAccessKey(t, e, "tenant-1", api.CreateAccessKeyRequest{
			Name:        "expiring",
			Permissions: []string{"s3:GetObject"},
			Buckets:     []string{"bucket-a"},
			ExpiresAt:   &exp,
		})
		require.Equal(t, http.StatusCreated, rec.Code)
		var created api.CreatedAccessKey
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
		require.NotNil(t, created.ExpiresAt)
		require.True(t, exp.Equal(*created.ExpiresAt))

		akID, err := did.Parse(did.KeyPrefix + created.AccessKeyID)
		require.NoError(t, err)
		got, err := deps.accessKeys.Get(ctx, akID)
		require.NoError(t, err)
		require.NotNil(t, got.ExpiresAt)
		require.True(t, exp.Equal(*got.ExpiresAt))

		dels, err := deps.delegations.ListByAudience(ctx, akID)
		require.NoError(t, err)
		require.Len(t, dels.Results, 1)
		require.NotNil(t, dels.Results[0].Expiration())
		require.Equal(t, ucan.UnixTimestamp(exp.Unix()), *dels.Results[0].Expiration())
	})

	t.Run("duplicate name is rejected", func(t *testing.T) {
		e, _ := setupAccessKeys(t)
		body := api.CreateAccessKeyRequest{Name: "dup", Permissions: []string{"s3:GetObject"}}
		require.Equal(t, http.StatusCreated, createAccessKey(t, e, "tenant-1", body).Code)
		require.Equal(t, http.StatusConflict, createAccessKey(t, e, "tenant-1", body).Code)
	})

	t.Run("unknown tenant is 404", func(t *testing.T) {
		e, _ := setupAccessKeys(t)
		rec := createAccessKey(t, e, "missing", api.CreateAccessKeyRequest{Name: "k", Permissions: []string{"s3:GetObject"}})
		require.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("invalid requests are 422", func(t *testing.T) {
		e, _ := setupAccessKeys(t)
		cases := map[string]api.CreateAccessKeyRequest{
			"empty name":                       {Name: "", Permissions: []string{"s3:GetObject"}},
			"empty permissions":                {Name: "k", Permissions: nil},
			"unknown permission":               {Name: "k", Permissions: []string{"s3:Frobnicate"}},
			"unknown bucket":                   {Name: "k", Permissions: []string{"s3:GetObject"}, Buckets: []string{"ghost"}},
			"foreign bucket":                   {Name: "k", Permissions: []string{"s3:GetObject"}, Buckets: []string{"bucket-b"}},
			"principal with permissions":       {Name: "k", PrincipalID: "alice", Permissions: []string{"s3:GetObject"}},
			"principal with buckets":           {Name: "k", PrincipalID: "alice", Buckets: []string{"bucket-a"}},
			"principal with both":              {Name: "k", PrincipalID: "alice", Permissions: []string{"s3:GetObject"}, Buckets: []string{"bucket-a"}},
			"unknown principal":                {Name: "k", PrincipalID: "ghost"},
			"empty name for a principal's key": {Name: "", PrincipalID: "alice"},
		}
		for name, body := range cases {
			t.Run(name, func(t *testing.T) {
				rec := createAccessKey(t, e, "tenant-1", body)
				require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
			})
		}
	})
}

func TestCreatePrincipalBoundAccessKeyHandler(t *testing.T) {
	ctx := t.Context()

	t.Run("creates a key bound to the principal with no delegations", func(t *testing.T) {
		e, deps := setupAccessKeys(t)
		rec := createAccessKey(t, e, "tenant-1", api.CreateAccessKeyRequest{Name: "laptop", PrincipalID: "alice"})
		require.Equal(t, http.StatusCreated, rec.Code)

		// The body carries the principal in place of permissions and buckets.
		var body map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		require.Contains(t, body, "principal")
		require.NotContains(t, body, "permissions")
		require.NotContains(t, body, "buckets")

		var created api.CreatedAccessKey
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
		require.NotEmpty(t, created.AccessKeyID)
		require.True(t, strings.HasPrefix(created.SecretAccessKey, "u"), "secret is multibase base64url")
		require.Equal(t, "laptop", created.Name)
		require.Equal(t, "alice", created.Principal)
		require.Nil(t, created.ExpiresAt)

		akID, err := did.Parse(did.KeyPrefix + created.AccessKeyID)
		require.NoError(t, err)
		storedRec, err := deps.accessKeys.Get(ctx, akID)
		require.NoError(t, err)
		require.NotNil(t, storedRec.Principal)
		require.Equal(t, "alice", *storedRec.Principal)
		require.Empty(t, storedRec.Permissions)
		require.Empty(t, storedRec.Buckets)

		// The key pair is in the vault under the access-key path, and nothing was
		// delegated to it.
		_, err = deps.vault.Read(ctx, "/tenant/"+deps.tenantID.String()+"/access-key/"+akID.String())
		require.NoError(t, err)
		dels, err := deps.delegations.ListByAudience(ctx, akID)
		require.NoError(t, err)
		require.Empty(t, dels.Results)
	})

	t.Run("a service key's body carries no principal", func(t *testing.T) {
		e, _ := setupAccessKeys(t)
		rec := createAccessKey(t, e, "tenant-1", api.CreateAccessKeyRequest{Name: "ci", Permissions: []string{"s3:GetObject"}})
		require.Equal(t, http.StatusCreated, rec.Code)
		var body map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		require.Contains(t, body, "permissions")
		require.NotContains(t, body, "principal")
	})

	t.Run("duplicate name within the principal is 409, across principals and kinds it is not", func(t *testing.T) {
		e, deps := setupAccessKeys(t)
		require.NoError(t, deps.principals.Add(ctx, deps.tenantID, "bob"))
		require.Equal(t, http.StatusCreated, createAccessKey(t, e, "tenant-1", api.CreateAccessKeyRequest{Name: "laptop", PrincipalID: "alice"}).Code)
		require.Equal(t, http.StatusConflict, createAccessKey(t, e, "tenant-1", api.CreateAccessKeyRequest{Name: "laptop", PrincipalID: "alice"}).Code)
		require.Equal(t, http.StatusCreated, createAccessKey(t, e, "tenant-1", api.CreateAccessKeyRequest{Name: "laptop", PrincipalID: "bob"}).Code)
		require.Equal(t, http.StatusCreated, createAccessKey(t, e, "tenant-1", api.CreateAccessKeyRequest{Name: "laptop", Permissions: []string{"s3:GetObject"}}).Code)
	})

	t.Run("unknown tenant is 404", func(t *testing.T) {
		e, _ := setupAccessKeys(t)
		rec := createAccessKey(t, e, "missing", api.CreateAccessKeyRequest{Name: "laptop", PrincipalID: "alice"})
		require.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestListAccessKeysHandler(t *testing.T) {
	e, _ := setupAccessKeys(t)
	require.Equal(t, http.StatusCreated, createAccessKey(t, e, "tenant-1", api.CreateAccessKeyRequest{Name: "a", Permissions: []string{"s3:GetObject"}, Buckets: []string{"bucket-a"}}).Code)
	require.Equal(t, http.StatusCreated, createAccessKey(t, e, "tenant-1", api.CreateAccessKeyRequest{Name: "b", Permissions: []string{"s3:PutObject"}}).Code)
	require.Equal(t, http.StatusCreated, createAccessKey(t, e, "tenant-1", api.CreateAccessKeyRequest{Name: "laptop", PrincipalID: "alice"}).Code)

	t.Run("lists both kinds without secrets", func(t *testing.T) {
		rec := doRequest(t, e, http.MethodGet, "/tenants/tenant-1/access-keys", nil)
		require.Equal(t, http.StatusOK, rec.Code)
		require.NotContains(t, rec.Body.String(), "secretAccessKey")

		var list api.AccessKeyList
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
		require.Len(t, list.Items, 3)
		byName := map[string]api.AccessKey{}
		for _, k := range list.Items {
			byName[k.Name] = k
		}
		require.Equal(t, []string{"bucket-a"}, byName["a"].Buckets) // bucket DID resolved back to name
		require.Equal(t, []string{"s3:GetObject"}, byName["a"].Permissions)
		require.Empty(t, byName["a"].Principal)
		require.Empty(t, byName["b"].Buckets)
		require.Empty(t, byName["b"].Principal)
		require.Equal(t, "alice", byName["laptop"].Principal)
		require.Empty(t, byName["laptop"].Permissions)
		require.Empty(t, byName["laptop"].Buckets)
	})

	t.Run("unknown tenant is 404", func(t *testing.T) {
		rec := doRequest(t, e, http.MethodGet, "/tenants/missing/access-keys", nil)
		require.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestGetAccessKeyHandler(t *testing.T) {
	e, _ := setupAccessKeys(t)
	created := createAccessKey(t, e, "tenant-1", api.CreateAccessKeyRequest{Name: "g", Permissions: []string{"s3:GetObject"}, Buckets: []string{"bucket-a"}})
	require.Equal(t, http.StatusCreated, created.Code)
	var ck api.CreatedAccessKey
	require.NoError(t, json.Unmarshal(created.Body.Bytes(), &ck))

	t.Run("found", func(t *testing.T) {
		rec := doRequest(t, e, http.MethodGet, "/tenants/tenant-1/access-keys/"+ck.AccessKeyID, nil)
		require.Equal(t, http.StatusOK, rec.Code)
		require.NotContains(t, rec.Body.String(), "secretAccessKey")
		var ak api.AccessKey
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &ak))
		require.Equal(t, ck.AccessKeyID, ak.AccessKeyID)
		require.Equal(t, []string{"bucket-a"}, ak.Buckets)
	})

	t.Run("unknown key is 404", func(t *testing.T) {
		rec := doRequest(t, e, http.MethodGet, "/tenants/tenant-1/access-keys/z6MkUnknownKeyIdentifier", nil)
		require.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("key owned by another tenant is 404", func(t *testing.T) {
		rec := doRequest(t, e, http.MethodGet, "/tenants/tenant-2/access-keys/"+ck.AccessKeyID, nil)
		require.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("a principal-bound key carries its principal", func(t *testing.T) {
		created := createAccessKey(t, e, "tenant-1", api.CreateAccessKeyRequest{Name: "laptop", PrincipalID: "alice"})
		require.Equal(t, http.StatusCreated, created.Code)
		var bound api.CreatedAccessKey
		require.NoError(t, json.Unmarshal(created.Body.Bytes(), &bound))

		rec := doRequest(t, e, http.MethodGet, "/tenants/tenant-1/access-keys/"+bound.AccessKeyID, nil)
		require.Equal(t, http.StatusOK, rec.Code)
		var body map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		require.NotContains(t, body, "permissions")
		require.NotContains(t, body, "buckets")
		var ak api.AccessKey
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &ak))
		require.Equal(t, bound.AccessKeyID, ak.AccessKeyID)
		require.Equal(t, "alice", ak.Principal)
	})
}

func TestDeleteAccessKeyHandler(t *testing.T) {
	ctx := t.Context()

	t.Run("deletes key, vault entry, and delegations; idempotent", func(t *testing.T) {
		e, deps := setupAccessKeys(t)
		created := createAccessKey(t, e, "tenant-1", api.CreateAccessKeyRequest{Name: "d", Permissions: []string{"s3:GetObject"}, Buckets: []string{"bucket-a"}})
		require.Equal(t, http.StatusCreated, created.Code)
		var ck api.CreatedAccessKey
		require.NoError(t, json.Unmarshal(created.Body.Bytes(), &ck))
		akID, err := did.Parse(did.KeyPrefix + ck.AccessKeyID)
		require.NoError(t, err)

		rec := doRequest(t, e, http.MethodDelete, "/tenants/tenant-1/access-keys/"+ck.AccessKeyID, nil)
		require.Equal(t, http.StatusNoContent, rec.Code)

		_, err = deps.accessKeys.Get(ctx, akID)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		_, err = deps.vault.Read(ctx, "/tenant/"+deps.tenantID.String()+"/access-key/"+akID.String())
		require.ErrorIs(t, err, vault.ErrNotFound)
		dels, err := deps.delegations.ListByAudience(ctx, akID)
		require.NoError(t, err)
		require.Empty(t, dels.Results)

		require.Empty(t, deps.invalidations.principals,
			"a service key's delegations are revoked; no principal is invalidated")

		again := doRequest(t, e, http.MethodDelete, "/tenants/tenant-1/access-keys/"+ck.AccessKeyID, nil)
		require.Equal(t, http.StatusNotFound, again.Code)
	})

	t.Run("deletes a principal-bound key and its vault entry; idempotent", func(t *testing.T) {
		e, deps := setupAccessKeys(t)
		created := createAccessKey(t, e, "tenant-1", api.CreateAccessKeyRequest{Name: "laptop", PrincipalID: "alice"})
		require.Equal(t, http.StatusCreated, created.Code)
		var ck api.CreatedAccessKey
		require.NoError(t, json.Unmarshal(created.Body.Bytes(), &ck))
		akID, err := did.Parse(did.KeyPrefix + ck.AccessKeyID)
		require.NoError(t, err)

		rec := doRequest(t, e, http.MethodDelete, "/tenants/tenant-1/access-keys/"+ck.AccessKeyID, nil)
		require.Equal(t, http.StatusNoContent, rec.Code)

		_, err = deps.accessKeys.Get(ctx, akID)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		_, err = deps.vault.Read(ctx, "/tenant/"+deps.tenantID.String()+"/access-key/"+akID.String())
		require.ErrorIs(t, err, vault.ErrNotFound)

		require.Equal(t, []string{"alice"}, deps.invalidations.principals,
			"the key holds no delegation, so its principal is invalidated instead")

		again := doRequest(t, e, http.MethodDelete, "/tenants/tenant-1/access-keys/"+ck.AccessKeyID, nil)
		require.Equal(t, http.StatusNotFound, again.Code)
	})

	t.Run("unknown tenant is 404", func(t *testing.T) {
		e, _ := setupAccessKeys(t)
		rec := doRequest(t, e, http.MethodDelete, "/tenants/missing/access-keys/z6MkWhatever", nil)
		require.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("a lock the store gave up on is 409", func(t *testing.T) {
		e, deps := setupAccessKeys(t)
		created := createAccessKey(t, e, "tenant-1", api.CreateAccessKeyRequest{Name: "d", PrincipalID: "alice"})
		require.Equal(t, http.StatusCreated, created.Code)
		var ck api.CreatedAccessKey
		require.NoError(t, json.Unmarshal(created.Body.Bytes(), &ck))

		locked := &lockedAccessKeys{Store: deps.accessKeys, err: store.ErrLockTimeout}
		svc := accesskeysvc.New(zap.NewNop(), deps.tenants, locked, deps.principals, deps.buckets, deps.delegations, deps.vault, noopRevocations{}, deps.invalidations)
		lockedEcho := echo.New()
		r := api.NewDeleteAccessKeyHandler(zap.NewNop(), svc)
		lockedEcho.Add(r.Method, r.Path, r.Handler)

		rec := doRequest(t, lockedEcho, http.MethodDelete, "/tenants/tenant-1/access-keys/"+ck.AccessKeyID, nil)
		require.Equal(t, http.StatusConflict, rec.Code)
		akID, err := did.Parse(did.KeyPrefix + ck.AccessKeyID)
		require.NoError(t, err)
		_, err = deps.accessKeys.Get(ctx, akID)
		require.NoError(t, err, "the key must survive")
	})
}

// lockedAccessKeys fails Delete with err, standing in for the store giving up
// on a row another write holds.
type lockedAccessKeys struct {
	accesskeystore.Store
	err error
}

func (l *lockedAccessKeys) Delete(context.Context, did.DID, func(context.Context) error) error {
	return l.err
}
