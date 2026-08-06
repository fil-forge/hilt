package accesskey_test

import (
	"context"
	"errors"
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	accesskeysvc "github.com/fil-forge/hilt/pkg/api/service/accesskey"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
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

// revocation records one published revocation.
type revocation struct {
	revoker did.DID
	revoked cid.Cid
	path    []ucan.Delegation
}

// fakeSwarf is a stub of the revocation service, recording what it was asked to
// publish.
type fakeSwarf struct {
	err         error
	revocations []revocation
}

func (f *fakeSwarf) Publish(_ context.Context, revoker ucan.Issuer, revoked cid.Cid, path []ucan.Delegation) error {
	if f.err != nil {
		return f.err
	}
	f.revocations = append(f.revocations, revocation{revoker: revoker.DID(), revoked: revoked, path: path})
	return nil
}

type deps struct {
	svc         *accesskeysvc.Service
	delegations *delegationmemory.Store
	buckets     *bucketmemory.Store
	secrets     *vaultmemory.Store
	swarf       *fakeSwarf
	tenantID    did.DID
	bucketID    did.DID
	bucketRoot  ucan.Delegation
}

// setup wires the service over memory stores with one tenant ("tenant-1") whose
// secp256k1 key is in the vault, owning one bucket ("bucket-a") that has issued
// the tenant top authority over itself — the root of every proof chain through
// the bucket, as [bucket.Service.Create] would have stored it.
func setup(t *testing.T) deps {
	t.Helper()
	ctx := t.Context()
	tenants, accessKeys := tenantmemory.New(), accesskeymemory.New()
	buckets, delegations, secrets := bucketmemory.New(), delegationmemory.New(), vaultmemory.New()

	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	tenantID := signer.KeyDID()
	require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", testutil.RandomDID(t), tenant.Active))
	require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), signer.Bytes()))

	// The bucket key is ephemeral: it signs the bucket→tenant root and is discarded.
	bucketSigner, err := ed25519.Generate()
	require.NoError(t, err)
	bucketID := bucketSigner.KeyDID()
	require.NoError(t, buckets.Add(ctx, bucketID, tenantID, "bucket-a"))
	root, err := delegation.Delegate(
		multikey.NewIssuer(bucketID, bucketSigner), tenantID, bucketID, command.Top(), delegation.WithNoExpiration())
	require.NoError(t, err)
	require.NoError(t, delegations.PutBatch(ctx, []ucan.Delegation{root}))

	swarf := &fakeSwarf{}
	return deps{
		svc:         accesskeysvc.New(zap.NewNop(), tenants, accessKeys, buckets, delegations, secrets, swarf),
		delegations: delegations,
		buckets:     buckets,
		secrets:     secrets,
		swarf:       swarf,
		tenantID:    tenantID,
		bucketID:    bucketID,
		bucketRoot:  root,
	}
}

func TestCreate(t *testing.T) {
	ctx := t.Context()

	t.Run("creates a bucket-scoped key", func(t *testing.T) {
		d := setup(t)
		rec, secret, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, []string{"bucket-a"}, nil)
		require.NoError(t, err)
		require.NotEmpty(t, secret)
		require.Equal(t, "k1", rec.Name)
		require.Equal(t, []did.DID{d.bucketID}, rec.Buckets)
	})

	t.Run("rejects an empty name", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "", []string{"s3:GetObject"}, nil, nil)
		require.ErrorIs(t, err, accesskeysvc.ErrInvalidName)
	})

	t.Run("rejects no permissions", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "k1", nil, nil, nil)
		require.ErrorIs(t, err, accesskeysvc.ErrNoPermissions)
	})

	t.Run("rejects an unknown permission", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:Bogus"}, nil, nil)
		require.ErrorIs(t, err, accesskeysvc.ErrInvalidPermission)
	})

	t.Run("rejects an unknown bucket", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, []string{"nope"}, nil)
		require.ErrorIs(t, err, accesskeysvc.ErrUnknownBucket)
	})

	t.Run("rejects an unknown tenant", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "missing", "k1", []string{"s3:GetObject"}, nil, nil)
		require.ErrorIs(t, err, accesskeysvc.ErrTenantNotFound)
	})

	t.Run("rejects a duplicate name", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "dup", []string{"s3:GetObject"}, nil, nil)
		require.NoError(t, err)
		_, _, err = d.svc.Create(ctx, "tenant-1", "dup", []string{"s3:GetObject"}, nil, nil)
		require.ErrorIs(t, err, accesskeysvc.ErrNameConflict)
	})
}

func TestListGetDelete(t *testing.T) {
	ctx := t.Context()

	t.Run("list returns the tenant's keys with bucket names", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, []string{"bucket-a"}, nil)
		require.NoError(t, err)
		recs, names, err := d.svc.List(ctx, "tenant-1")
		require.NoError(t, err)
		require.Len(t, recs, 1)
		require.Equal(t, "bucket-a", names[d.bucketID])
	})

	t.Run("list rejects an unknown tenant", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.List(ctx, "missing")
		require.ErrorIs(t, err, accesskeysvc.ErrTenantNotFound)
	})

	t.Run("get returns a created key", func(t *testing.T) {
		d := setup(t)
		created, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, nil, nil)
		require.NoError(t, err)
		got, _, err := d.svc.Get(ctx, "tenant-1", created.ID.Identifier())
		require.NoError(t, err)
		require.Equal(t, created.ID, got.ID)
	})

	t.Run("get rejects an unknown access key", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Get(ctx, "tenant-1", testutil.RandomDID(t).Identifier())
		require.ErrorIs(t, err, accesskeysvc.ErrAccessKeyNotFound)
	})

	t.Run("delete removes a key", func(t *testing.T) {
		d := setup(t)
		created, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, nil, nil)
		require.NoError(t, err)
		require.NoError(t, d.svc.Delete(ctx, "tenant-1", created.ID.Identifier()))
		_, _, err = d.svc.Get(ctx, "tenant-1", created.ID.Identifier())
		require.ErrorIs(t, err, accesskeysvc.ErrAccessKeyNotFound)
	})

	t.Run("delete rejects an unknown access key", func(t *testing.T) {
		d := setup(t)
		err := d.svc.Delete(ctx, "tenant-1", testutil.RandomDID(t).Identifier())
		require.ErrorIs(t, err, accesskeysvc.ErrAccessKeyNotFound)
	})
}

func TestDeleteRevokes(t *testing.T) {
	ctx := t.Context()

	t.Run("revokes every bucket-scoped delegation, witnessed from the bucket root", func(t *testing.T) {
		d := setup(t)
		// s3:PutObject maps to several commands, so the key gets several delegations.
		created, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:PutObject"}, []string{"bucket-a"}, nil)
		require.NoError(t, err)
		issued, err := d.delegations.ListByAudience(ctx, created.ID)
		require.NoError(t, err)
		require.Greater(t, len(issued.Results), 1)

		require.NoError(t, d.svc.Delete(ctx, "tenant-1", created.ID.Identifier()))

		require.Len(t, d.swarf.revocations, len(issued.Results))
		revoked := map[cid.Cid]bool{}
		for _, r := range d.swarf.revocations {
			// The tenant issued the delegations, so the tenant revokes them.
			require.Equal(t, d.tenantID, r.revoker)
			// Path witness: root first, revoked delegation last.
			require.Len(t, r.path, 2)
			require.Equal(t, d.bucketRoot.Link(), r.path[0].Link())
			require.Equal(t, r.revoked, r.path[1].Link())
			require.Equal(t, d.bucketID, r.path[1].Subject())
			revoked[r.revoked] = true
		}
		for _, dlg := range issued.Results {
			require.True(t, revoked[dlg.Link()], "delegation %s was not revoked", dlg.Link())
		}
	})

	t.Run("witnesses a powerline delegation with a tenant bucket root", func(t *testing.T) {
		d := setup(t)
		created, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, nil, nil)
		require.NoError(t, err)

		require.NoError(t, d.svc.Delete(ctx, "tenant-1", created.ID.Identifier()))

		require.Len(t, d.swarf.revocations, 1)
		r := d.swarf.revocations[0]
		require.Equal(t, d.tenantID, r.revoker)
		require.Len(t, r.path, 2)
		require.Equal(t, d.bucketRoot.Link(), r.path[0].Link())
		require.Equal(t, r.revoked, r.path[1].Link())
		// Powerline: the revoked delegation has no subject of its own.
		require.False(t, r.path[1].Subject().Defined())
	})

	t.Run("skips a powerline delegation when the tenant owns no bucket", func(t *testing.T) {
		d := setup(t)
		created, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, nil, nil)
		require.NoError(t, err)
		// Drop the only bucket: nothing is left to witness a subject-less chain, and
		// the delegation grants access to nothing either.
		require.NoError(t, d.buckets.Delete(ctx, d.bucketID))

		require.NoError(t, d.svc.Delete(ctx, "tenant-1", created.ID.Identifier()))
		require.Empty(t, d.swarf.revocations)
		_, _, err = d.svc.Get(ctx, "tenant-1", created.ID.Identifier())
		require.ErrorIs(t, err, accesskeysvc.ErrAccessKeyNotFound)
	})

	t.Run("a revocation failure leaves the key intact", func(t *testing.T) {
		d := setup(t)
		created, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, []string{"bucket-a"}, nil)
		require.NoError(t, err)
		d.swarf.err = errors.New("swarf is down")

		err = d.svc.Delete(ctx, "tenant-1", created.ID.Identifier())
		require.ErrorContains(t, err, "publishing revocation")

		// Nothing was removed, so the call can simply be retried.
		_, _, err = d.svc.Get(ctx, "tenant-1", created.ID.Identifier())
		require.NoError(t, err)
		remaining, err := d.delegations.ListByAudience(ctx, created.ID)
		require.NoError(t, err)
		require.NotEmpty(t, remaining.Results)
		_, err = d.secrets.Read(ctx, vault.AccessKeyPath(d.tenantID, created.ID))
		require.NoError(t, err)
	})
}
