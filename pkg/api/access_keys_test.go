package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/api"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/plc"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type accessKeyDeps struct {
	tenants     *tenantmemory.Store
	accessKeys  *accesskeymemory.Store
	buckets     *bucketmemory.Store
	delegations *delegationmemory.Store
	vault       vault.Vault
	tenantID    did.DID // owner of "tenant-1" + "bucket-a"
	bucketID    did.DID // "bucket-a", owned by tenant-1
	otherBucket string  // "bucket-b", owned by a different tenant
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
		tenants:     tenantmemory.New(),
		accessKeys:  accesskeymemory.New(),
		buckets:     bucketmemory.New(),
		delegations: delegationmemory.New(),
		vault:       vaultmemory.New(),
		otherBucket: "bucket-b",
	}
	deps.tenantID, deps.bucketID = addTenant(t, deps, "tenant-1", "bucket-a")
	addTenant(t, deps, "tenant-2", deps.otherBucket) // a foreign tenant + bucket

	e := echo.New()
	for _, r := range []api.Route{
		api.NewCreateAccessKeyHandler(zap.NewNop(), deps.tenants, deps.accessKeys, deps.buckets, deps.delegations, deps.vault),
		api.NewListAccessKeysHandler(zap.NewNop(), deps.tenants, deps.accessKeys, deps.buckets),
		api.NewGetAccessKeyHandler(zap.NewNop(), deps.tenants, deps.accessKeys, deps.buckets),
		api.NewDeleteAccessKeyHandler(zap.NewNop(), deps.tenants, deps.accessKeys, deps.delegations, deps.vault),
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

		// 4 delegations: /content/retrieve + /blob/add + /index/add + /upload/add,
		// all scoped to the bucket, issued by the tenant to the access key.
		dels, err := deps.delegations.ListByAudience(ctx, akID)
		require.NoError(t, err)
		require.Len(t, dels.Results, 4)
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
			"empty name":         {Name: "", Permissions: []string{"s3:GetObject"}},
			"empty permissions":  {Name: "k", Permissions: nil},
			"unknown permission": {Name: "k", Permissions: []string{"s3:Frobnicate"}},
			"unknown bucket":     {Name: "k", Permissions: []string{"s3:GetObject"}, Buckets: []string{"ghost"}},
			"foreign bucket":     {Name: "k", Permissions: []string{"s3:GetObject"}, Buckets: []string{"bucket-b"}},
		}
		for name, body := range cases {
			t.Run(name, func(t *testing.T) {
				rec := createAccessKey(t, e, "tenant-1", body)
				require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
			})
		}
	})
}

func TestListAccessKeysHandler(t *testing.T) {
	e, _ := setupAccessKeys(t)
	require.Equal(t, http.StatusCreated, createAccessKey(t, e, "tenant-1", api.CreateAccessKeyRequest{Name: "a", Permissions: []string{"s3:GetObject"}, Buckets: []string{"bucket-a"}}).Code)
	require.Equal(t, http.StatusCreated, createAccessKey(t, e, "tenant-1", api.CreateAccessKeyRequest{Name: "b", Permissions: []string{"s3:PutObject"}}).Code)

	t.Run("lists keys without secrets", func(t *testing.T) {
		rec := doRequest(t, e, http.MethodGet, "/tenants/tenant-1/access-keys", nil)
		require.Equal(t, http.StatusOK, rec.Code)
		require.NotContains(t, rec.Body.String(), "secretAccessKey")

		var list api.AccessKeyList
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
		require.Len(t, list.Items, 2)
		names := map[string][]string{}
		for _, k := range list.Items {
			names[k.Name] = k.Buckets
		}
		require.Equal(t, []string{"bucket-a"}, names["a"]) // bucket DID resolved back to name
		require.Empty(t, names["b"])
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

		again := doRequest(t, e, http.MethodDelete, "/tenants/tenant-1/access-keys/"+ck.AccessKeyID, nil)
		require.Equal(t, http.StatusNotFound, again.Code)
	})

	t.Run("unknown tenant is 404", func(t *testing.T) {
		e, _ := setupAccessKeys(t)
		rec := doRequest(t, e, http.MethodDelete, "/tenants/missing/access-keys/z6MkWhatever", nil)
		require.Equal(t, http.StatusNotFound, rec.Code)
	})
}
