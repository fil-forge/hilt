package tenantqueue_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	tenantstore "github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/hilt/pkg/tasks"
	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue"
	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue/datamodel"
	"github.com/fil-forge/hilt/pkg/vault"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/libforge/testutil"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/stretchr/testify/require"
)

// run runs the task and waits for it.
func (w *world) run(t *testing.T, spec taskrunner.Spec) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), htestutil.WaitTimeout)
	defer cancel()
	_, err := w.runner.Run(ctx, spec)
	return err
}

// createSpec returns the queue-tenant.create-key task for the key.
func createSpec(t *testing.T, key accesskey.Input) taskrunner.Spec {
	t.Helper()
	spec, err := tenantqueue.CreateKeySpec(key)
	require.NoError(t, err)
	return spec
}

func (w *world) serviceKeyInput(t *testing.T, name string, buckets []did.DID, permissions ...string) accesskey.Input {
	return accesskey.Input{ID: testutil.RandomDID(t), Tenant: w.tenant.DID(), Name: name, Buckets: buckets, Permissions: permissions}
}

func (w *world) principalKeyInput(t *testing.T, name, who string) accesskey.Input {
	return accesskey.Input{ID: testutil.RandomDID(t), Tenant: w.tenant.DID(), Name: name, Principal: &who}
}

func TestCreateKeySpec(t *testing.T) {
	tenant := testutil.RandomDID(t)
	who := "alice"
	// Finer than the microsecond the arguments keep.
	created := time.Date(2026, 11, 26, 12, 0, 0, 123_456_789, time.UTC)
	expires := created.Add(time.Hour)

	t.Run("the arguments decode to the key given, to the microsecond", func(t *testing.T) {
		for name, key := range map[string]accesskey.Input{
			"service key": {
				ID: testutil.RandomDID(t), Tenant: tenant, Name: "ci",
				Buckets: []did.DID{testutil.RandomDID(t)}, Permissions: []string{"s3:GetObject", "s3:PutObject"},
				ExpiresAt: &expires, CreatedAt: created,
			},
			"principal-bound key": {ID: testutil.RandomDID(t), Tenant: tenant, Name: "laptop", Principal: &who, CreatedAt: created},
		} {
			t.Run(name, func(t *testing.T) {
				spec, err := tenantqueue.CreateKeySpec(key)
				require.NoError(t, err)
				require.Equal(t, tasks.QueueTenant, spec.Queue)
				require.Equal(t, tasks.ActionCreateKey, spec.Action)
				require.Equal(t, tenant.String(), spec.Subject)

				got, err := tenantqueue.DecodeCreateKey(tenant, spec.Args)
				require.NoError(t, err)
				want := key
				want.CreatedAt = created.Truncate(time.Microsecond)
				if key.ExpiresAt != nil {
					e := expires.Truncate(time.Microsecond)
					want.ExpiresAt = &e
					require.True(t, e.Equal(*got.ExpiresAt))
					got.ExpiresAt = want.ExpiresAt
				}
				require.True(t, want.CreatedAt.Equal(got.CreatedAt))
				got.CreatedAt = want.CreatedAt
				require.Equal(t, want, got)
			})
		}
	})

	t.Run("a zero creation time is the time of the call", func(t *testing.T) {
		spec, err := tenantqueue.CreateKeySpec(accesskey.Input{ID: testutil.RandomDID(t), Tenant: tenant, Name: "k", Permissions: []string{"s3:GetObject"}})
		require.NoError(t, err)
		got, err := tenantqueue.DecodeCreateKey(tenant, spec.Args)
		require.NoError(t, err)
		require.WithinDuration(t, time.Now(), got.CreatedAt, time.Minute)
	})

	t.Run("refuses an inconsistent key", func(t *testing.T) {
		_, err := tenantqueue.CreateKeySpec(accesskey.Input{Tenant: tenant, Name: "k"})
		require.ErrorIs(t, err, store.ErrInvalidArgument)
	})

	t.Run("refuses arguments that are not a key", func(t *testing.T) {
		_, err := tenantqueue.DecodeCreateKey(tenant, []byte("not a key"))
		require.Error(t, err)
	})
}

func TestCreateKey(t *testing.T) {
	t.Run("creates a service key with the grants of its permissions and buckets", func(t *testing.T) {
		w := setup(t)
		expires := time.Now().Add(time.Hour)
		key := w.serviceKeyInput(t, "ci", []did.DID{w.bucket}, "s3:GetObject", "s3:DeleteObject")
		key.ExpiresAt = &expires
		key.CreatedAt = time.Now().Add(-time.Minute)
		require.NoError(t, w.run(t, createSpec(t, key)))

		rec, err := w.accessKeys.Get(t.Context(), key.ID)
		require.NoError(t, err)
		require.Equal(t, w.tenant.DID(), rec.Tenant)
		require.Equal(t, "ci", rec.Name)
		require.Equal(t, key.Buckets, rec.Buckets)
		require.Equal(t, key.Permissions, rec.Permissions)
		require.Nil(t, rec.Principal)
		require.Equal(t, key.CreatedAt.UnixMicro(), rec.CreatedAt.UnixMicro())
		require.Equal(t, expires.UnixMicro(), rec.ExpiresAt.UnixMicro())

		want, err := grant.ForKey(w.tenant, tenantstore.Active, rec, nil)
		require.NoError(t, err)
		require.NotEmpty(t, want)
		require.Equal(t, shapes(want), shapes(w.held(t, key.ID)))
		require.Empty(t, w.owedLinks(t), "a creation revokes nothing")
	})

	t.Run("creates a principal-bound key with the grants the policies give its principal", func(t *testing.T) {
		w := setup(t)
		key := w.principalKeyInput(t, "laptop", principal)
		require.NoError(t, w.run(t, createSpec(t, key)))

		rec, err := w.accessKeys.Get(t.Context(), key.ID)
		require.NoError(t, err)
		require.Equal(t, principal, *rec.Principal)
		require.Nil(t, rec.Permissions)
		require.Nil(t, rec.Buckets)
		named, err := w.policies.ListByPrincipal(t.Context(), w.tenant.DID(), principal)
		require.NoError(t, err)
		want, err := grant.ForKey(w.tenant, tenantstore.Active, rec, named)
		require.NoError(t, err)
		require.NotEmpty(t, want)
		require.Equal(t, shapes(want), shapes(w.held(t, key.ID)))
	})

	t.Run("refuses for good, and writes nothing", func(t *testing.T) {
		w := setup(t)
		ctx := t.Context()
		pool := w.pool
		// A second tenant with a bucket and a principal of its own, and a
		// removed principal of the first.
		other := testutil.RandomDID(t)
		require.NoError(t, w.tenants.Add(ctx, other, "tenant-2", tenantstore.Active))
		providerID, otherBucket := testutil.RandomDID(t), testutil.RandomDID(t)
		require.NoError(t, providerpostgres.New(pool).Add(ctx, providerID, "region-2", nil))
		require.NoError(t, bucketpostgres.New(pool).Add(ctx, otherBucket, other, providerID, "their-bucket"))
		principals := principalpostgres.New(pool)
		require.NoError(t, principals.Add(ctx, other, "carol"))
		require.NoError(t, principals.Add(ctx, w.tenant.DID(), "gone"))
		gone := principals.TombstoneStatement(w.tenant.DID(), "gone")
		_, err := pool.Exec(ctx, gone.SQL, gone.Args...)
		require.NoError(t, err)
		missing := testutil.RandomDID(t)
		long := make([]byte, tenantqueue.MaxKeyNameLength+1)
		for i := range long {
			long[i] = 'n'
		}

		for name, tc := range map[string]struct {
			key  accesskey.Input
			want error
		}{
			"a name that is too long":                  {w.serviceKeyInput(t, string(long), nil, "s3:GetObject"), tenantqueue.ErrInvalidKeyName},
			"a service key with no permissions":        {w.serviceKeyInput(t, "k", nil), tenantqueue.ErrNoPermissions},
			"a permission that is not one":             {w.serviceKeyInput(t, "k", nil, "s3:GetObject", "s3:Bogus"), tenantqueue.ErrInvalidPermission},
			"a bucket the tenant does not have":        {w.serviceKeyInput(t, "k", []did.DID{w.bucket, missing}, "s3:GetObject"), tenantqueue.ErrUnknownBucket},
			"another tenant's bucket":                  {w.serviceKeyInput(t, "k", []did.DID{otherBucket}, "s3:GetObject"), tenantqueue.ErrUnknownBucket},
			"a service key's name already taken":       {w.serviceKeyInput(t, "service", nil, "s3:GetObject"), tenantqueue.ErrKeyNameTaken},
			"a principal's key's name already taken":   {w.principalKeyInput(t, "bound", principal), tenantqueue.ErrKeyNameTaken},
			"a principal the tenant does not have":     {w.principalKeyInput(t, "k", "nobody"), tenantqueue.ErrUnknownPrincipal},
			"another tenant's principal":               {w.principalKeyInput(t, "k", "carol"), tenantqueue.ErrUnknownPrincipal},
			"a principal that was removed":             {w.principalKeyInput(t, "k", "gone"), tenantqueue.ErrUnknownPrincipal},
			"a tenant that does not exist":             {accesskey.Input{ID: testutil.RandomDID(t), Tenant: missing, Name: "k", Permissions: []string{"s3:GetObject"}}, tenantqueue.ErrTenantNotFound},
			"a name free among the principal's is not": {w.principalKeyInput(t, "service", principal), nil},
		} {
			t.Run(name, func(t *testing.T) {
				err := w.run(t, createSpec(t, tc.key))
				if tc.want == nil {
					require.NoError(t, err)
					return
				}
				require.ErrorIs(t, err, tc.want)
				require.True(t, taskrunner.IsPermanent(err), "the refusal is final")
				_, err = w.accessKeys.Get(ctx, tc.key.ID)
				require.ErrorIs(t, err, store.ErrRecordNotFound)
				require.Empty(t, w.held(t, tc.key.ID))
			})
		}

		t.Run("an unknown bucket is named", func(t *testing.T) {
			err := w.run(t, createSpec(t, w.serviceKeyInput(t, "k", []did.DID{missing}, "s3:GetObject")))
			var unknown *tenantqueue.UnknownBucketError
			require.ErrorAs(t, err, &unknown)
			require.Equal(t, missing, unknown.Bucket)
		})

		t.Run("arguments no spec builds", func(t *testing.T) {
			// CreateKeySpec refuses these keys itself, so the arguments are
			// encoded as a caller that skipped it would send them.
			who := principal
			for name, tc := range map[string]struct {
				args datamodel.CreateKeyArgs
				want error
			}{
				"an empty name":                           {datamodel.CreateKeyArgs{Key: testutil.RandomDID(t), Permissions: []string{"s3:GetObject"}}, tenantqueue.ErrInvalidKeyName},
				"a principal-bound key with permissions":  {datamodel.CreateKeyArgs{Key: testutil.RandomDID(t), Name: "k", Principal: &who, Permissions: []string{"s3:GetObject"}}, tenantqueue.ErrPrincipalScoped},
				"a principal-bound key scoped to buckets": {datamodel.CreateKeyArgs{Key: testutil.RandomDID(t), Name: "k", Principal: &who, Buckets: []did.DID{w.bucket}}, tenantqueue.ErrPrincipalScoped},
			} {
				t.Run(name, func(t *testing.T) {
					var args bytes.Buffer
					require.NoError(t, tc.args.MarshalCBOR(&args))
					err := w.run(t, taskrunner.Spec{Queue: tasks.QueueTenant, Subject: w.tenant.DID().String(), Action: tasks.ActionCreateKey, Args: args.Bytes()})
					require.ErrorIs(t, err, tc.want)
					require.True(t, taskrunner.IsPermanent(err))
					_, err = w.accessKeys.Get(ctx, tc.args.Key)
					require.ErrorIs(t, err, store.ErrRecordNotFound)
				})
			}
		})

		t.Run("arguments that are not a key", func(t *testing.T) {
			err := w.run(t, taskrunner.Spec{Queue: tasks.QueueTenant, Subject: w.tenant.DID().String(), Action: tasks.ActionCreateKey, Args: []byte("junk")})
			require.Error(t, err)
			require.True(t, taskrunner.IsPermanent(err))
		})
	})

	t.Run("refuses a disabled tenant", func(t *testing.T) {
		w := setup(t)
		require.NoError(t, w.setStatus(t, tenantstore.Disabled))
		for _, key := range []accesskey.Input{
			w.serviceKeyInput(t, "k", nil, "s3:GetObject"),
			w.principalKeyInput(t, "k", principal),
		} {
			err := w.run(t, createSpec(t, key))
			require.ErrorIs(t, err, tenantqueue.ErrTenantDisabled)
			require.True(t, taskrunner.IsPermanent(err))
			_, err = w.accessKeys.Get(t.Context(), key.ID)
			require.ErrorIs(t, err, store.ErrRecordNotFound)
			require.Empty(t, w.held(t, key.ID))
		}
	})

	t.Run("fails for good when the tenant's signing key is not in the vault", func(t *testing.T) {
		w := setup(t)
		require.NoError(t, w.secrets.Delete(t.Context(), vault.TenantKeyPath(w.tenant.DID())))
		key := w.serviceKeyInput(t, "k", nil, "s3:GetObject")
		err := w.run(t, createSpec(t, key))
		require.ErrorIs(t, err, vault.ErrNotFound)
		require.True(t, taskrunner.IsPermanent(err))
		_, err = w.accessKeys.Get(t.Context(), key.ID)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})
}

func TestDeleteKey(t *testing.T) {
	t.Run("withdraws the key's grants, records them as owed, deletes the key and publishes", func(t *testing.T) {
		w := setup(t)
		w.swarf.holding.Store(true)
		gone, kept := w.held(t, w.principalKey), w.held(t, w.serviceKey)
		require.NotEmpty(t, gone)
		require.NotEmpty(t, kept)

		require.NoError(t, w.run(t, tenantqueue.DeleteKeySpec(w.tenant.DID(), w.principalKey)))

		_, err := w.accessKeys.Get(t.Context(), w.principalKey)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		require.Empty(t, w.held(t, w.principalKey))
		require.ElementsMatch(t, links(gone), w.owedLinks(t), "every grant of the key is owed a revocation")
		require.Empty(t, w.swarf.Revoked())
		// The tenant's other key, and the bucket's root, are left alone.
		_, err = w.accessKeys.Get(t.Context(), w.serviceKey)
		require.NoError(t, err)
		require.Equal(t, links(kept), links(w.held(t, w.serviceKey)))
		require.Equal(t, links([]ucan.Delegation{w.root}), links(w.held(t, w.tenant.DID())))

		w.swarf.holding.Store(false)
		w.awaitPublished(t)
		require.ElementsMatch(t, links(gone), w.swarf.Revoked())
		for _, r := range w.swarf.Revocations() {
			require.Equal(t, w.tenant.DID(), r.Revoker)
		}
	})

	t.Run("withdraws a grant stored for the key after it was created", func(t *testing.T) {
		w := setup(t)
		w.swarf.holding.Store(true)
		stray := w.stray(t, w.serviceKey)
		held := w.held(t, w.serviceKey)
		require.Contains(t, links(held), stray.Link())

		require.NoError(t, w.run(t, tenantqueue.DeleteKeySpec(w.tenant.DID(), w.serviceKey)))
		require.Empty(t, w.held(t, w.serviceKey))
		require.ElementsMatch(t, links(held), w.owedLinks(t))
	})

	t.Run("a second run is a no-op", func(t *testing.T) {
		w := setup(t)
		require.NoError(t, w.run(t, tenantqueue.DeleteKeySpec(w.tenant.DID(), w.serviceKey)))
		w.awaitPublished(t)
		htestutil.AwaitPublished(t, w.runner, w.tenant.DID())
		revoked := w.swarf.Revoked()
		kept := w.held(t, w.principalKey)

		require.NoError(t, w.run(t, tenantqueue.DeleteKeySpec(w.tenant.DID(), w.serviceKey)))
		pending, err := w.runner.PendingOn(t.Context(), tasks.QueueRevocation, w.tenant.DID().String())
		require.NoError(t, err)
		require.Empty(t, pending, "a deletion that finds no key queues nothing")
		require.Empty(t, w.owedLinks(t))
		require.Equal(t, revoked, w.swarf.Revoked())
		require.Equal(t, links(kept), links(w.held(t, w.principalKey)))
	})

	t.Run("leaves a key that is not the tenant's alone", func(t *testing.T) {
		w := setup(t)
		other := testutil.RandomDID(t)
		require.NoError(t, w.tenants.Add(t.Context(), other, "tenant-2", tenantstore.Active))
		held := w.held(t, w.serviceKey)

		require.NoError(t, w.run(t, tenantqueue.DeleteKeySpec(other, w.serviceKey)))
		_, err := w.accessKeys.Get(t.Context(), w.serviceKey)
		require.NoError(t, err)
		require.Equal(t, links(held), links(w.held(t, w.serviceKey)))

		require.NoError(t, w.run(t, tenantqueue.DeleteKeySpec(w.tenant.DID(), testutil.RandomDID(t))), "a key that never existed")
	})

	t.Run("fails for good on arguments that are not a key", func(t *testing.T) {
		w := setup(t)
		err := w.run(t, taskrunner.Spec{Queue: tasks.QueueTenant, Subject: w.tenant.DID().String(), Action: tasks.ActionDeleteKey, Args: []byte("junk")})
		require.Error(t, err)
		require.True(t, taskrunner.IsPermanent(err))
	})
}
