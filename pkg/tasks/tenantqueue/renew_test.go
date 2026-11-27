package tenantqueue_test

import (
	"context"
	"testing"
	"time"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/s3perm"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	tenantstore "github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/hilt/pkg/tasks"
	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/libforge/testutil"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/stretchr/testify/require"
)

// age moves the expiry of every grant the tenant has issued so far to the
// given time from now, as the delegation store sees it. The delegations
// themselves are signed and keep the expiry they were issued with.
func (w *world) age(t *testing.T, in time.Duration) {
	t.Helper()
	_, err := w.pool.Exec(t.Context(), `UPDATE delegation SET expires_at = $2 WHERE issuer = $1`, w.tenant.DID().String(), time.Now().Add(in))
	require.NoError(t, err)
}

// renewDue runs RenewDue and waits for the renewals it queued.
func (w *world) renewDue(t *testing.T) (queued int, deleted int64) {
	t.Helper()
	queued, deleted, err := w.queue.RenewDue(t.Context(), w.runner)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		pending, err := w.runner.Pending(t.Context(), tasks.QueueTenant, []string{w.tenant.DID().String()}, taskrunner.WithActions(tasks.ActionRenewGrants))
		require.NoError(t, err)
		return len(pending) == 0
	}, htestutil.WaitTimeout, 10*time.Millisecond, "the renewal did not finish")
	return queued, deleted
}

// chain returns the links of the service key's proof chain for reads of the
// bucket.
func (w *world) chain(t *testing.T) []ucan.Delegation {
	t.Helper()
	read := s3perm.CommandsFor("s3:GetObject")[0]
	proofs, _, err := w.delegations.ProofChain(t.Context(), w.serviceKey, read, w.bucket)
	require.NoError(t, err)
	return proofs
}

func TestRenewingGrants(t *testing.T) {
	t.Run("grants with their lifetime ahead of them are left alone", func(t *testing.T) {
		w := setup(t)
		service := w.held(t, w.serviceKey)

		queued, deleted := w.renewDue(t)

		require.Zero(t, queued)
		require.Zero(t, deleted)
		require.Equal(t, links(service), links(w.held(t, w.serviceKey)))
	})

	t.Run("issues each key with grants close to expiring the next set, and revokes nothing", func(t *testing.T) {
		w := setup(t)
		service, bound := w.held(t, w.serviceKey), w.held(t, w.principalKey)
		w.age(t, grant.RenewBefore-time.Hour)

		queued, _ := w.renewDue(t)

		require.Equal(t, 1, queued)
		wantService, wantBound := w.wantGrants(t, tenantstore.Active)
		for _, c := range []struct {
			before []ucan.Delegation
			held   []ucan.Delegation
			want   []string
		}{
			{service, w.held(t, w.serviceKey), wantService},
			{bound, w.held(t, w.principalKey), wantBound},
		} {
			var fresh []ucan.Delegation
			for _, d := range c.held {
				if !containsLink(c.before, d) {
					fresh = append(fresh, d)
				}
			}
			require.Len(t, c.held, len(c.before)+len(fresh), "the grants the key held are still stored")
			require.Equal(t, c.want, shapes(fresh))
		}
		require.Empty(t, w.owedLinks(t))
		require.Empty(t, w.swarf.Revoked())

		// The key's chain goes through the new grant.
		chain := w.chain(t)
		require.Len(t, chain, 2)
		require.False(t, containsLink(service, chain[1]))

		// With the next set stored, nothing is due.
		queued, _ = w.renewDue(t)
		require.Zero(t, queued)
	})

	t.Run("a change that withdraws a key's grants revokes the set it renewed too", func(t *testing.T) {
		w := setup(t)
		w.age(t, grant.RenewBefore-time.Hour)
		w.renewDue(t)
		all := append(w.held(t, w.serviceKey), w.held(t, w.principalKey)...)

		require.NoError(t, w.setStatus(t, tenantstore.Disabled))
		w.awaitPublished(t)

		require.ElementsMatch(t, links(all), w.swarf.Revoked())
	})

	t.Run("deleting a key revokes the set it renewed too", func(t *testing.T) {
		w := setup(t)
		w.age(t, grant.RenewBefore-time.Hour)
		w.renewDue(t)
		all, kept := w.held(t, w.principalKey), w.held(t, w.serviceKey)

		require.NoError(t, w.run(t, tenantqueue.DeleteKeySpec(w.tenant.DID(), w.principalKey)))
		w.awaitPublished(t)

		require.ElementsMatch(t, links(all), w.swarf.Revoked())
		require.Equal(t, links(kept), links(w.held(t, w.serviceKey)))
	})

	t.Run("a policy write revokes the set a key renewed too, and leaves it one set", func(t *testing.T) {
		w := setup(t)
		w.age(t, grant.RenewBefore-time.Hour)
		w.renewDue(t)
		all, kept := w.held(t, w.principalKey), w.held(t, w.serviceKey)
		spec, err := tenantqueue.PutPolicySpec(w.tenant.DID(), w.bucket, bucketName, policyOf("s3:GetObject", "s3:PutObject"), tenantqueue.PolicyCondition{})
		require.NoError(t, err)

		require.NoError(t, w.run(t, spec))
		w.awaitPublished(t)

		require.ElementsMatch(t, links(all), w.swarf.Revoked())
		_, wantBound := w.wantGrants(t, tenantstore.Active)
		require.Equal(t, wantBound, shapes(w.held(t, w.principalKey)))
		// The policy names the principal alone, so the service key keeps both
		// of its sets.
		require.Equal(t, links(kept), links(w.held(t, w.serviceKey)))
	})

	t.Run("deletes the grants that expired once their keys hold the next set", func(t *testing.T) {
		w := setup(t)
		w.age(t, grant.RenewBefore-time.Hour)
		w.renewDue(t)
		renewed := len(w.held(t, w.serviceKey)) / 2
		_, err := w.pool.Exec(t.Context(), `UPDATE delegation SET expires_at = now() - interval '1 minute' WHERE issuer = $1 AND expires_at < $2`,
			w.tenant.DID().String(), time.Now().Add(grant.RenewBefore))
		require.NoError(t, err)

		_, deleted := w.renewDue(t)

		require.Positive(t, deleted)
		require.Len(t, w.held(t, w.serviceKey), renewed)
		require.Empty(t, w.owedLinks(t))
	})

	t.Run("renews grants that expired before a renewal ran", func(t *testing.T) {
		w := setup(t)
		w.age(t, -time.Hour)
		require.Empty(t, w.chain(t))

		queued, deleted := w.renewDue(t)

		require.Equal(t, 1, queued)
		require.Zero(t, deleted, "an expired grant that is due is what the renewal is issued from")
		require.Len(t, w.chain(t), 2)
	})

	t.Run("a key that has expired is issued nothing", func(t *testing.T) {
		w := setup(t)
		w.age(t, grant.RenewBefore-time.Hour)
		_, err := w.pool.Exec(t.Context(), `UPDATE access_key SET expires_at = now() - interval '1 hour' WHERE id = $1`, w.serviceKey.String())
		require.NoError(t, err)
		service := w.held(t, w.serviceKey)

		w.renewDue(t)

		require.Equal(t, links(service), links(w.held(t, w.serviceKey)))
		require.Greater(t, len(w.held(t, w.principalKey)), 1)
	})

	t.Run("a service key is issued nothing over a bucket deleted since its creation", func(t *testing.T) {
		w := setup(t)
		other := w.addBucket(t, "bucket-b")
		both := w.createKey(t, "both", []string{"s3:GetObject"}, []string{bucketName, "bucket-b"}, nil)
		only := w.createKey(t, "only", []string{"s3:GetObject"}, []string{"bucket-b"}, nil)
		require.NoError(t, w.run(t, tenantqueue.DeleteBucketSpec(w.tenant.DID(), other)))
		w.awaitPublished(t)
		require.Empty(t, w.held(t, only), "the deletion withdrew the grants over the bucket")
		w.age(t, grant.RenewBefore-time.Hour)

		w.renewDue(t)

		for _, d := range w.held(t, both) {
			require.Equal(t, w.bucket, d.Subject(), "a grant over the deleted bucket was issued again")
		}
		require.Empty(t, w.held(t, only))

		// A change of status issues the same way: nothing over the deleted
		// bucket, and no powerline grant for a key whose buckets are all gone.
		require.NoError(t, w.setStatus(t, tenantstore.WriteLocked))
		require.NoError(t, w.setStatus(t, tenantstore.Active))
		require.Empty(t, w.held(t, only))
		require.NotEmpty(t, w.held(t, both))
		for _, d := range w.held(t, both) {
			require.Equal(t, w.bucket, d.Subject())
		}
	})

	t.Run("a tenant that is gone succeeds and writes nothing", func(t *testing.T) {
		w := setup(t)
		gone := tenantqueue.RenewGrantsSpec(testutil.RandomDID(t))
		ctx, cancel := context.WithTimeout(t.Context(), htestutil.WaitTimeout)
		defer cancel()
		_, err := w.runner.Run(ctx, gone)
		require.NoError(t, err)
	})
}

func containsLink(dels []ucan.Delegation, d ucan.Delegation) bool {
	for _, other := range dels {
		if other.Link() == d.Link() {
			return true
		}
	}
	return false
}

// addBucket stores another bucket of the tenant, on the provider of the
// world's bucket, and returns its DID.
func (w *world) addBucket(t *testing.T, name string) did.DID {
	t.Helper()
	first, err := bucketpostgres.New(w.pool).GetByName(t.Context(), bucketName)
	require.NoError(t, err)
	id := testutil.RandomDID(t)
	require.NoError(t, bucketpostgres.New(w.pool).Add(t.Context(), id, w.tenant.DID(), first.Provider, name))
	return id
}
