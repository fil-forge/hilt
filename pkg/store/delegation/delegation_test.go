package delegation_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	dlgstore "github.com/fil-forge/hilt/pkg/store/delegation"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/libforge/testutil"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func makeStore(t *testing.T) dlgstore.Store {
	return delegationpostgres.New(htestutil.PostgresOrSkip(t))
}

// makeDelegation builds a signed delegation from issuer to audience over the
// given subject and command. A [did.Undef] subject yields a powerline
// delegation.
func makeDelegation(t *testing.T, issuer ucan.Issuer, audience, subject did.DID, cmd ucan.Command) ucan.Delegation {
	t.Helper()
	dlg, err := delegation.Delegate(issuer, audience, subject, cmd)
	require.NoError(t, err)
	return dlg
}

func TestDelegationStore(t *testing.T) {
	s := makeStore(t)

	t.Run("stores and lists a delegation by audience", func(t *testing.T) {
		issuer := testutil.RandomIssuer(t)
		audience := testutil.RandomDID(t)
		dlg := makeDelegation(t, issuer, audience, issuer.DID(), command.MustParse("/test/run"))

		require.NoError(t, s.PutBatch(t.Context(), []ucan.Delegation{dlg}))

		page, err := s.ListByAudience(t.Context(), audience)
		require.NoError(t, err)
		require.Len(t, page.Results, 1)
		require.Equal(t, dlg.Link().String(), page.Results[0].Link().String())
	})

	t.Run("ListByAudience returns empty page for unknown audience", func(t *testing.T) {
		page, err := s.ListByAudience(t.Context(), testutil.RandomDID(t))
		require.NoError(t, err)
		require.Empty(t, page.Results)
		require.Nil(t, page.Cursor)
	})

	t.Run("PutBatch is idempotent for the same delegation", func(t *testing.T) {
		issuer := testutil.RandomIssuer(t)
		audience := testutil.RandomDID(t)
		dlg := makeDelegation(t, issuer, audience, issuer.DID(), command.MustParse("/test/run"))

		require.NoError(t, s.PutBatch(t.Context(), []ucan.Delegation{dlg}))
		require.NoError(t, s.PutBatch(t.Context(), []ucan.Delegation{dlg}))

		page, err := s.ListByAudience(t.Context(), audience)
		require.NoError(t, err)
		require.Len(t, page.Results, 1)
	})

	t.Run("PutBatch stores a delegation the batch lists twice once", func(t *testing.T) {
		issuer := testutil.RandomIssuer(t)
		audience := testutil.RandomDID(t)
		dlg := makeDelegation(t, issuer, audience, issuer.DID(), command.MustParse("/test/run"))
		other := makeDelegation(t, issuer, audience, issuer.DID(), command.MustParse("/test/walk"))

		require.NoError(t, s.PutBatch(t.Context(), []ucan.Delegation{dlg, other, dlg}))

		page, err := s.ListByAudience(t.Context(), audience)
		require.NoError(t, err)
		var links []string
		for _, d := range page.Results {
			links = append(links, d.Link().String())
		}
		require.ElementsMatch(t, []string{dlg.Link().String(), other.Link().String()}, links)
	})

	t.Run("PutBatch stores the delegations of several audiences", func(t *testing.T) {
		issuer := testutil.RandomIssuer(t)
		a, b := testutil.RandomDID(t), testutil.RandomDID(t)
		subject := testutil.RandomDID(t)
		forA := makeDelegation(t, issuer, a, subject, command.MustParse("/test/run"))
		forB := makeDelegation(t, issuer, b, did.Undef, command.MustParse("/test/run"))

		require.NoError(t, s.PutBatch(t.Context(), []ucan.Delegation{forA, forB}))

		got := map[did.DID][]string{}
		for _, aud := range []did.DID{a, b} {
			page, err := s.ListByAudience(t.Context(), aud)
			require.NoError(t, err)
			for _, d := range page.Results {
				got[aud] = append(got[aud], d.Link().String())
			}
		}
		require.Equal(t, map[did.DID][]string{a: {forA.Link().String()}, b: {forB.Link().String()}}, got)
	})

	t.Run("DeleteByAudience removes all delegations for an audience", func(t *testing.T) {
		audience := testutil.RandomDID(t)
		for range 3 {
			issuer := testutil.RandomIssuer(t)
			dlg := makeDelegation(t, issuer, audience, testutil.RandomDID(t), command.MustParse("/test/run"))
			require.NoError(t, s.PutBatch(t.Context(), []ucan.Delegation{dlg}))
		}

		require.NoError(t, s.DeleteByAudience(t.Context(), audience))

		page, err := s.ListByAudience(t.Context(), audience)
		require.NoError(t, err)
		require.Empty(t, page.Results)
	})

	t.Run("Replace hands next the current set and stores its result", func(t *testing.T) {
		issuer := testutil.RandomIssuer(t)
		audience := testutil.RandomDID(t)
		cmd := command.MustParse("/test/run")
		old := makeDelegation(t, issuer, audience, issuer.DID(), cmd)
		require.NoError(t, s.PutBatch(t.Context(), []ucan.Delegation{old}))
		fresh := makeDelegation(t, issuer, audience, issuer.DID(), cmd)

		var seen []ucan.Delegation
		require.NoError(t, replaceOne(t.Context(), s, audience, func(_ context.Context, current []ucan.Delegation) ([]ucan.Delegation, error) {
			seen = current
			return []ucan.Delegation{fresh}, nil
		}))

		require.Len(t, seen, 1)
		require.Equal(t, old.Link(), seen[0].Link())
		page, err := s.ListByAudience(t.Context(), audience)
		require.NoError(t, err)
		require.Len(t, page.Results, 1)
		require.Equal(t, fresh.Link(), page.Results[0].Link())
	})

	t.Run("Replace with next returning nil leaves the audience with none", func(t *testing.T) {
		issuer := testutil.RandomIssuer(t)
		audience := testutil.RandomDID(t)
		cmd := command.MustParse("/test/run")
		require.NoError(t, s.PutBatch(t.Context(), []ucan.Delegation{
			makeDelegation(t, issuer, audience, issuer.DID(), cmd),
			makeDelegation(t, issuer, audience, issuer.DID(), cmd),
		}))

		require.NoError(t, replaceOne(t.Context(), s, audience, func(_ context.Context, current []ucan.Delegation) ([]ucan.Delegation, error) {
			require.Len(t, current, 2)
			return nil, nil
		}))

		page, err := s.ListByAudience(t.Context(), audience)
		require.NoError(t, err)
		require.Empty(t, page.Results)
	})

	t.Run("Replace rolls back when next errors", func(t *testing.T) {
		issuer := testutil.RandomIssuer(t)
		audience := testutil.RandomDID(t)
		old := makeDelegation(t, issuer, audience, issuer.DID(), command.MustParse("/test/run"))
		require.NoError(t, s.PutBatch(t.Context(), []ucan.Delegation{old}))
		boom := errors.New("publish failed")

		err := replaceOne(t.Context(), s, audience, func(context.Context, []ucan.Delegation) ([]ucan.Delegation, error) {
			return nil, boom
		})
		require.ErrorIs(t, err, boom)

		page, err := s.ListByAudience(t.Context(), audience)
		require.NoError(t, err)
		require.Len(t, page.Results, 1)
		require.Equal(t, old.Link(), page.Results[0].Link())
	})

	t.Run("Replace stores next's result for an audience holding nothing", func(t *testing.T) {
		issuer := testutil.RandomIssuer(t)
		audience := testutil.RandomDID(t)
		fresh := makeDelegation(t, issuer, audience, issuer.DID(), command.MustParse("/test/run"))

		called := false
		require.NoError(t, replaceOne(t.Context(), s, audience, func(_ context.Context, current []ucan.Delegation) ([]ucan.Delegation, error) {
			called = true
			require.Empty(t, current)
			return []ucan.Delegation{fresh}, nil
		}))

		require.True(t, called, "next is told the audience holds nothing")
		page, err := s.ListByAudience(t.Context(), audience)
		require.NoError(t, err)
		require.Len(t, page.Results, 1)
		require.Equal(t, fresh.Link(), page.Results[0].Link())
	})

	t.Run("PutBatch and DeleteByAudience wait for an in-flight Replace", func(t *testing.T) {
		issuer := testutil.RandomIssuer(t)
		audience := testutil.RandomDID(t)
		cmd := command.MustParse("/test/run")
		require.NoError(t, s.PutBatch(t.Context(), []ucan.Delegation{
			makeDelegation(t, issuer, audience, issuer.DID(), cmd),
		}))
		fresh := makeDelegation(t, issuer, audience, issuer.DID(), cmd)
		other := makeDelegation(t, issuer, audience, issuer.DID(), cmd)

		entered, release := make(chan struct{}), make(chan struct{})
		replaced := make(chan error, 1)
		go func() {
			replaced <- replaceOne(t.Context(), s, audience, func(context.Context, []ucan.Delegation) ([]ucan.Delegation, error) {
				close(entered)
				<-release
				return []ucan.Delegation{fresh}, nil
			})
		}()
		<-entered

		put, deleted := make(chan error, 1), make(chan error, 1)
		go func() { put <- s.PutBatch(t.Context(), []ucan.Delegation{other}) }()
		go func() { deleted <- s.DeleteByAudience(t.Context(), audience) }()

		select {
		case err := <-put:
			t.Fatalf("PutBatch completed while Replace held the audience: %v", err)
		case err := <-deleted:
			t.Fatalf("DeleteByAudience completed while Replace held the audience: %v", err)
		case <-time.After(200 * time.Millisecond):
		}

		close(release)
		require.NoError(t, <-replaced)
		require.NoError(t, <-put)
		require.NoError(t, <-deleted)
	})

	t.Run("Replace swaps several audiences in one call", func(t *testing.T) {
		issuer := testutil.RandomIssuer(t)
		a, b := testutil.RandomDID(t), testutil.RandomDID(t)
		cmd := command.MustParse("/test/run")
		oldA := makeDelegation(t, issuer, a, issuer.DID(), cmd)
		require.NoError(t, s.PutBatch(t.Context(), []ucan.Delegation{oldA}))
		freshA, freshB := makeDelegation(t, issuer, a, issuer.DID(), cmd), makeDelegation(t, issuer, b, issuer.DID(), cmd)

		require.NoError(t, s.Replace(t.Context(), []did.DID{a, b}, func(_ context.Context, current map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error) {
			require.Len(t, current[a], 1)
			require.Equal(t, oldA.Link(), current[a][0].Link())
			require.Empty(t, current[b])
			return map[did.DID][]ucan.Delegation{a: {freshA}, b: {freshB}}, nil
		}))

		for aud, want := range map[did.DID]ucan.Delegation{a: freshA, b: freshB} {
			page, err := s.ListByAudience(t.Context(), aud)
			require.NoError(t, err)
			require.Len(t, page.Results, 1)
			require.Equal(t, want.Link(), page.Results[0].Link())
		}
	})

	t.Run("Replace returns ErrInvalidArgument for a nil delegation from next", func(t *testing.T) {
		issuer := testutil.RandomIssuer(t)
		audience := testutil.RandomDID(t)
		old := makeDelegation(t, issuer, audience, issuer.DID(), command.MustParse("/test/run"))
		require.NoError(t, s.PutBatch(t.Context(), []ucan.Delegation{old}))

		err := replaceOne(t.Context(), s, audience, func(context.Context, []ucan.Delegation) ([]ucan.Delegation, error) {
			return []ucan.Delegation{nil}, nil
		})
		require.ErrorIs(t, err, store.ErrInvalidArgument)

		page, err := s.ListByAudience(t.Context(), audience)
		require.NoError(t, err)
		require.Len(t, page.Results, 1, "the current set is kept")
	})

	t.Run("Replace returns ErrInvalidArgument for a delegation filed under another audience", func(t *testing.T) {
		issuer := testutil.RandomIssuer(t)
		locked, other := testutil.RandomDID(t), testutil.RandomDID(t)
		stray := makeDelegation(t, issuer, other, issuer.DID(), command.MustParse("/test/run"))

		err := replaceOne(t.Context(), s, locked, func(context.Context, []ucan.Delegation) ([]ucan.Delegation, error) {
			return []ucan.Delegation{stray}, nil
		})
		require.ErrorIs(t, err, store.ErrInvalidArgument)

		page, err := s.ListByAudience(t.Context(), other)
		require.NoError(t, err)
		require.Empty(t, page.Results, "nothing is written under an audience the call did not lock")
	})

	t.Run("Replace hands next each audience once when it is listed twice", func(t *testing.T) {
		issuer := testutil.RandomIssuer(t)
		audience, over := testutil.RandomDID(t), testutil.RandomDID(t)
		require.NoError(t, s.PutBatch(t.Context(), []ucan.Delegation{makeDelegation(t, issuer, audience, over, command.MustParse("/test/run"))}))
		keep := func(_ context.Context, current map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error) {
			require.Len(t, current[audience], 1)
			return current, nil
		}

		require.NoError(t, s.Replace(t.Context(), []did.DID{audience, audience}, keep))
	})

	t.Run("DeleteBySubject removes only that subject's delegations", func(t *testing.T) {
		subjectA, subjectB := testutil.RandomDID(t), testutil.RandomDID(t)
		audA1, audA2 := testutil.RandomDID(t), testutil.RandomDID(t)
		audB, audPowerline := testutil.RandomDID(t), testutil.RandomDID(t)
		cmd := command.MustParse("/test/run")

		dA1 := makeDelegation(t, testutil.RandomIssuer(t), audA1, subjectA, cmd)
		dA2 := makeDelegation(t, testutil.RandomIssuer(t), audA2, subjectA, cmd)
		dB := makeDelegation(t, testutil.RandomIssuer(t), audB, subjectB, cmd)
		// Powerline delegation (undefined subject) must be preserved.
		dPowerline := makeDelegation(t, testutil.RandomIssuer(t), audPowerline, did.DID{}, cmd)
		require.NoError(t, s.PutBatch(t.Context(), []ucan.Delegation{dA1, dA2, dB, dPowerline}))

		require.NoError(t, s.DeleteBySubject(t.Context(), subjectA))

		for _, aud := range []did.DID{audA1, audA2} {
			page, err := s.ListByAudience(t.Context(), aud)
			require.NoError(t, err)
			require.Empty(t, page.Results, "subject A delegations should be deleted")
		}
		pageB, err := s.ListByAudience(t.Context(), audB)
		require.NoError(t, err)
		require.Len(t, pageB.Results, 1, "subject B delegation should remain")
		pagePowerline, err := s.ListByAudience(t.Context(), audPowerline)
		require.NoError(t, err)
		require.Len(t, pagePowerline.Results, 1, "powerline delegation should remain")
	})

	t.Run("ListBySubject returns only that subject's delegations", func(t *testing.T) {
		subjectA, subjectB := testutil.RandomDID(t), testutil.RandomDID(t)
		audA1, audA2 := testutil.RandomDID(t), testutil.RandomDID(t)
		audB, audPowerline := testutil.RandomDID(t), testutil.RandomDID(t)
		cmd := command.MustParse("/test/run")

		dA1 := makeDelegation(t, testutil.RandomIssuer(t), audA1, subjectA, cmd)
		dA2 := makeDelegation(t, testutil.RandomIssuer(t), audA2, subjectA, cmd)
		dB := makeDelegation(t, testutil.RandomIssuer(t), audB, subjectB, cmd)
		// Powerline delegation (undefined subject): it grants access to every
		// subject, so it belongs to none of them.
		dPowerline := makeDelegation(t, testutil.RandomIssuer(t), audPowerline, did.DID{}, cmd)
		require.NoError(t, s.PutBatch(t.Context(), []ucan.Delegation{dA1, dA2, dB, dPowerline}))

		page, err := s.ListBySubject(t.Context(), subjectA)
		require.NoError(t, err)
		links := make([]string, 0, len(page.Results))
		for _, d := range page.Results {
			links = append(links, d.Link().String())
		}
		require.ElementsMatch(t, []string{dA1.Link().String(), dA2.Link().String()}, links)
	})

	t.Run("ListBySubject returns empty page for unknown subject", func(t *testing.T) {
		page, err := s.ListBySubject(t.Context(), testutil.RandomDID(t))
		require.NoError(t, err)
		require.Empty(t, page.Results)
	})

	t.Run("ListBySubject paginates results", func(t *testing.T) {
		subject := testutil.RandomDID(t)
		for range 5 {
			dlg := makeDelegation(t, testutil.RandomIssuer(t), testutil.RandomDID(t), subject, command.MustParse("/test/run"))
			require.NoError(t, s.PutBatch(t.Context(), []ucan.Delegation{dlg}))
		}

		all, err := store.Collect(t.Context(), func(ctx context.Context, opts store.PaginationConfig) (store.Page[ucan.Delegation], error) {
			var listOpts []store.PaginationOption
			if opts.Cursor != nil {
				listOpts = append(listOpts, store.WithCursor(*opts.Cursor))
			}
			listOpts = append(listOpts, store.WithLimit(2))
			return s.ListBySubject(ctx, subject, listOpts...)
		})
		require.NoError(t, err)
		require.Len(t, all, 5)
	})

	t.Run("ListBySubject falls back to the default limit for a non-positive limit", func(t *testing.T) {
		subject := testutil.RandomDID(t)
		for range 3 {
			dlg := makeDelegation(t, testutil.RandomIssuer(t), testutil.RandomDID(t), subject, command.MustParse("/test/run"))
			require.NoError(t, s.PutBatch(t.Context(), []ucan.Delegation{dlg}))
		}

		for _, limit := range []int{0, -1} {
			page, err := s.ListBySubject(t.Context(), subject, store.WithLimit(limit))
			require.NoError(t, err)
			require.Len(t, page.Results, 3)
			require.Nil(t, page.Cursor)
		}
	})

	t.Run("ListBySubject returns ErrInvalidArgument for undef subject", func(t *testing.T) {
		_, err := s.ListBySubject(t.Context(), did.Undef)
		require.ErrorIs(t, err, store.ErrInvalidArgument)
	})

	t.Run("PutBatch returns ErrInvalidArgument for a nil delegation", func(t *testing.T) {
		issuer := testutil.RandomIssuer(t)
		audience := testutil.RandomDID(t)
		dlg := makeDelegation(t, issuer, audience, issuer.DID(), command.MustParse("/test/run"))

		err := s.PutBatch(t.Context(), []ucan.Delegation{dlg, nil})
		require.ErrorIs(t, err, store.ErrInvalidArgument)

		// Nothing from the batch is stored.
		page, err := s.ListByAudience(t.Context(), audience)
		require.NoError(t, err)
		require.Empty(t, page.Results)
	})

	t.Run("DeleteBySubject returns ErrInvalidArgument for undef subject", func(t *testing.T) {
		err := s.DeleteBySubject(t.Context(), did.Undef)
		require.ErrorIs(t, err, store.ErrInvalidArgument)
	})

	t.Run("ProofChain returns ErrInvalidArgument for undef subject", func(t *testing.T) {
		_, _, err := s.ProofChain(t.Context(), testutil.RandomDID(t), command.MustParse("/content/retrieve"), did.Undef)
		require.ErrorIs(t, err, store.ErrInvalidArgument)
	})

	t.Run("ListByAudience paginates results", func(t *testing.T) {
		audience := testutil.RandomDID(t)
		for range 5 {
			issuer := testutil.RandomIssuer(t)
			dlg := makeDelegation(t, issuer, audience, testutil.RandomDID(t), command.MustParse("/test/run"))
			require.NoError(t, s.PutBatch(t.Context(), []ucan.Delegation{dlg}))
		}

		all, err := store.Collect(t.Context(), func(ctx context.Context, opts store.PaginationConfig) (store.Page[ucan.Delegation], error) {
			var listOpts []store.PaginationOption
			if opts.Cursor != nil {
				listOpts = append(listOpts, store.WithCursor(*opts.Cursor))
			}
			listOpts = append(listOpts, store.WithLimit(2))
			return s.ListByAudience(ctx, audience, listOpts...)
		})
		require.NoError(t, err)
		require.Len(t, all, 5)
	})

	t.Run("ProofChain builds bucket -> tenant -> access key chain", func(t *testing.T) {
		bucketSigner := testutil.RandomIssuer(t)
		tenantSigner := testutil.RandomIssuer(t)
		accessSigner := testutil.RandomIssuer(t)
		bucket := bucketSigner.DID()
		tenant := tenantSigner.DID()
		access := accessSigner.DID()
		retrieve := command.MustParse("/content/retrieve")

		// Root: bucket delegates top authority to tenant (sub == iss).
		root := makeDelegation(t, bucketSigner, tenant, bucket, command.Top())
		// Intermediate: tenant delegates /content/retrieve over the bucket
		// to the access key.
		inter := makeDelegation(t, tenantSigner, access, bucket, retrieve)

		require.NoError(t, s.PutBatch(t.Context(), []ucan.Delegation{root, inter}))

		proofs, links, err := s.ProofChain(t.Context(), access, retrieve, bucket)
		require.NoError(t, err)
		require.Len(t, proofs, 2)
		require.Len(t, links, 2)

		// Invocation order: root (issued by subject) first.
		require.Equal(t, root.Link().String(), proofs[0].Link().String())
		require.Equal(t, inter.Link().String(), proofs[1].Link().String())
		require.Equal(t, root.Link(), links[0])
		require.Equal(t, inter.Link(), links[1])
	})

	t.Run("ProofChain resolves a powerline intermediate delegation", func(t *testing.T) {
		bucket := testutil.RandomIssuer(t)
		tenant := testutil.RandomIssuer(t)
		access := testutil.RandomIssuer(t)
		retrieve := command.MustParse("/content/retrieve")

		root := makeDelegation(t, bucket, tenant.DID(), bucket.DID(), command.Top())
		// Powerline: subject is undefined, granting access to any bucket.
		powerline := makeDelegation(t, tenant, access.DID(), did.Undef, retrieve)

		require.NoError(t, s.PutBatch(t.Context(), []ucan.Delegation{root, powerline}))

		proofs, _, err := s.ProofChain(t.Context(), access.DID(), retrieve, bucket.DID())
		require.NoError(t, err)
		require.Len(t, proofs, 2)
		require.Equal(t, root.Link().String(), proofs[0].Link().String())
		require.Equal(t, powerline.Link().String(), proofs[1].Link().String())
	})

	t.Run("ProofChain builds a three hop chain", func(t *testing.T) {
		bucket := testutil.RandomIssuer(t)
		tenant := testutil.RandomIssuer(t)
		admin := testutil.RandomIssuer(t)
		access := testutil.RandomIssuer(t)
		retrieve := command.MustParse("/content/retrieve")

		// bucket -> tenant (root) -> admin -> access
		root := makeDelegation(t, bucket, tenant.DID(), bucket.DID(), command.Top())
		mid := makeDelegation(t, tenant, admin.DID(), bucket.DID(), retrieve)
		leaf := makeDelegation(t, admin, access.DID(), bucket.DID(), retrieve)

		require.NoError(t, s.PutBatch(t.Context(), []ucan.Delegation{root, mid, leaf}))

		proofs, links, err := s.ProofChain(t.Context(), access.DID(), retrieve, bucket.DID())
		require.NoError(t, err)
		require.Len(t, proofs, 3)
		require.Len(t, links, 3)
		require.Equal(t, root.Link().String(), proofs[0].Link().String())
		require.Equal(t, mid.Link().String(), proofs[1].Link().String())
		require.Equal(t, leaf.Link().String(), proofs[2].Link().String())
	})

	t.Run("ProofChain returns empty when no chain exists", func(t *testing.T) {
		proofs, links, err := s.ProofChain(t.Context(), testutil.RandomDID(t), command.MustParse("/content/retrieve"), testutil.RandomDID(t))
		require.NoError(t, err)
		require.Empty(t, proofs)
		require.Empty(t, links)
	})
}

// keyFixture is a tenant with two access keys, and a second tenant with one,
// over a database of its own.
type keyFixture struct {
	pool   *pgxpool.Pool
	store  dlgstore.Store
	tenant ucan.Issuer
	// keys are the tenant's access keys.
	keys []did.DID
	// other is another tenant, and otherKey its access key.
	other    ucan.Issuer
	otherKey did.DID
}

func setupKeys(t *testing.T) keyFixture {
	t.Helper()
	pool := htestutil.PostgresOrSkip(t)
	f := keyFixture{pool: pool, store: delegationpostgres.New(pool), tenant: testutil.RandomIssuer(t), other: testutil.RandomIssuer(t)}
	tenants, accessKeys := tenantpostgres.New(pool), accesskeypostgres.New(pool)
	addKey := func(tenantID did.DID, name string) did.DID {
		id := testutil.RandomDID(t)
		require.NoError(t, accessKeys.Add(t.Context(), accesskey.Input{ID: id, Tenant: tenantID, Name: name, Permissions: []string{"s3:GetObject"}}))
		return id
	}
	require.NoError(t, tenants.Add(t.Context(), f.tenant.DID(), "tenant-1", tenant.Active))
	require.NoError(t, tenants.Add(t.Context(), f.other.DID(), "tenant-2", tenant.Active))
	f.keys = []did.DID{addKey(f.tenant.DID(), "k1"), addKey(f.tenant.DID(), "k2")}
	f.otherKey = addKey(f.other.DID(), "k1")
	return f
}

// run executes the statements in order in one transaction, as a task's
// commit does.
func (f keyFixture) run(t *testing.T, statements ...store.Statement) {
	t.Helper()
	tx, err := f.pool.Begin(t.Context())
	require.NoError(t, err)
	defer tx.Rollback(context.Background()) // no-op once committed
	for _, st := range statements {
		_, err := tx.Exec(t.Context(), st.SQL, st.Args...)
		require.NoError(t, err)
	}
	require.NoError(t, tx.Commit(t.Context()))
}

func (f keyFixture) held(t *testing.T, audience did.DID) []string {
	t.Helper()
	page, err := f.store.ListByAudience(t.Context(), audience)
	require.NoError(t, err)
	return linkStrings(page.Results)
}

// owed returns the CIDs of the revocations owed, by tenant.
func (f keyFixture) owed(t *testing.T) map[string][]string {
	t.Helper()
	rows, err := f.pool.Query(t.Context(), `SELECT tenant_id, id FROM revocation_owed ORDER BY id`)
	require.NoError(t, err)
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var tenantID, id string
		require.NoError(t, rows.Scan(&tenantID, &id))
		out[tenantID] = append(out[tenantID], id)
	}
	require.NoError(t, rows.Err())
	return out
}

func TestWithdrawKeyGrantsStatements(t *testing.T) {
	read := command.MustParse("/content/retrieve")

	t.Run("moves what the tenant issued to its keys to the revocations owed, and nothing else", func(t *testing.T) {
		f := setupKeys(t)
		bucket := testutil.RandomIssuer(t)
		grants := []ucan.Delegation{
			makeDelegation(t, f.tenant, f.keys[0], bucket.DID(), read),
			makeDelegation(t, f.tenant, f.keys[0], did.Undef, read),
			makeDelegation(t, f.tenant, f.keys[1], bucket.DID(), read),
		}
		// Left alone: the bucket's root to the tenant, a delegation the
		// tenant issued to something that is not one of its keys, one another
		// party issued to one of its keys, and another tenant's grant.
		root := makeDelegation(t, bucket, f.tenant.DID(), bucket.DID(), command.Top())
		elsewhere := makeDelegation(t, f.tenant, testutil.RandomDID(t), bucket.DID(), read)
		foreign := makeDelegation(t, bucket, f.keys[0], bucket.DID(), read)
		theirs := makeDelegation(t, f.other, f.otherKey, bucket.DID(), read)
		require.NoError(t, f.store.PutBatch(t.Context(), append(grants, root, elsewhere, foreign, theirs)))

		f.run(t, f.store.WithdrawKeyGrantsStatements(f.tenant.DID())...)

		require.Equal(t, linkStrings([]ucan.Delegation{foreign}), f.held(t, f.keys[0]))
		require.Empty(t, f.held(t, f.keys[1]))
		require.Equal(t, linkStrings([]ucan.Delegation{root}), f.held(t, f.tenant.DID()))
		require.Equal(t, linkStrings([]ucan.Delegation{elsewhere}), f.held(t, elsewhere.Audience()))
		require.Equal(t, linkStrings([]ucan.Delegation{theirs}), f.held(t, f.otherKey))
		owed := f.owed(t)
		require.ElementsMatch(t, linkStrings(grants), owed[f.tenant.DID().String()])
		require.Len(t, owed, 1, "only the tenant owes anything")

		// A second run finds nothing left to move.
		f.run(t, f.store.WithdrawKeyGrantsStatements(f.tenant.DID())...)
		require.Equal(t, owed, f.owed(t))
	})

	t.Run("waits for a Replace of one of the keys and withdraws what it stored", func(t *testing.T) {
		f := setupKeys(t)
		late := makeDelegation(t, f.tenant, f.keys[1], testutil.RandomDID(t), read)

		writeErr, withdrawErr := htestutil.RequireWaitsForWriter(t,
			func(entered chan<- struct{}, release <-chan struct{}) error {
				return replaceOne(t.Context(), f.store, f.keys[1], func(context.Context, []ucan.Delegation) ([]ucan.Delegation, error) {
					close(entered)
					<-release
					return []ucan.Delegation{late}, nil
				})
			},
			func() error {
				tx, err := f.pool.Begin(t.Context())
				if err != nil {
					return err
				}
				defer tx.Rollback(context.Background()) // no-op once committed
				for _, st := range f.store.WithdrawKeyGrantsStatements(f.tenant.DID()) {
					if _, err := tx.Exec(t.Context(), st.SQL, st.Args...); err != nil {
						return err
					}
				}
				return tx.Commit(t.Context())
			},
		)
		require.NoError(t, writeErr)
		require.NoError(t, withdrawErr)
		require.Empty(t, f.held(t, f.keys[1]))
		require.Equal(t, []string{late.Link().String()}, f.owed(t)[f.tenant.DID().String()])
	})
}

func TestWithdrawGrantsOverStatements(t *testing.T) {
	read, write := command.MustParse("/content/retrieve"), command.MustParse("/blob/add")

	// principalKeys adds the principals to the fixture's tenant, and one key
	// bound to each, in order.
	principalKeys := func(t *testing.T, f keyFixture, principals ...string) []did.DID {
		t.Helper()
		keys := make([]did.DID, len(principals))
		for i, p := range principals {
			require.NoError(t, principalpostgres.New(f.pool).Add(t.Context(), f.tenant.DID(), p))
			keys[i] = testutil.RandomDID(t)
			require.NoError(t, accesskeypostgres.New(f.pool).Add(t.Context(), accesskey.Input{ID: keys[i], Tenant: f.tenant.DID(), Name: "bound", Principal: &p}))
		}
		return keys
	}

	t.Run("moves what the tenant issued over the subject to the principals' keys to the revocations owed, and nothing else", func(t *testing.T) {
		f := setupKeys(t)
		bound := principalKeys(t, f, "alice", "bob", "carol")
		bucket, elsewhere := testutil.RandomIssuer(t), testutil.RandomDID(t)
		grants := []ucan.Delegation{
			makeDelegation(t, f.tenant, bound[0], bucket.DID(), read),
			makeDelegation(t, f.tenant, bound[0], bucket.DID(), write),
			makeDelegation(t, f.tenant, bound[1], bucket.DID(), read),
		}
		// Left alone: the keys' grants over another bucket, the grant over
		// this one of a principal not named and of a service key, a
		// delegation another party issued to one of the keys, and the
		// bucket's root to the tenant.
		others := []ucan.Delegation{
			makeDelegation(t, f.tenant, bound[0], elsewhere, read),
			makeDelegation(t, f.tenant, bound[1], elsewhere, read),
			makeDelegation(t, f.tenant, bound[2], bucket.DID(), read),
			makeDelegation(t, f.tenant, f.keys[0], bucket.DID(), read),
			makeDelegation(t, bucket, bound[0], bucket.DID(), read),
			makeDelegation(t, bucket, f.tenant.DID(), bucket.DID(), command.Top()),
		}
		require.NoError(t, f.store.PutBatch(t.Context(), append(slices.Clone(grants), others...)))

		f.run(t, f.store.WithdrawGrantsOverStatements(f.tenant.DID(), bucket.DID(), []string{"alice", "bob"})...)

		require.ElementsMatch(t, linkStrings([]ucan.Delegation{others[0], others[4]}), f.held(t, bound[0]))
		require.Equal(t, linkStrings([]ucan.Delegation{others[1]}), f.held(t, bound[1]))
		require.Equal(t, linkStrings([]ucan.Delegation{others[2]}), f.held(t, bound[2]))
		require.Equal(t, linkStrings([]ucan.Delegation{others[3]}), f.held(t, f.keys[0]))
		require.Equal(t, linkStrings([]ucan.Delegation{others[5]}), f.held(t, f.tenant.DID()))
		owed := f.owed(t)
		require.ElementsMatch(t, linkStrings(grants), owed[f.tenant.DID().String()])
		require.Len(t, owed, 1, "only the tenant owes anything")

		// A second run finds nothing left to move.
		f.run(t, f.store.WithdrawGrantsOverStatements(f.tenant.DID(), bucket.DID(), []string{"alice", "bob"})...)
		require.Equal(t, owed, f.owed(t))
	})

	t.Run("waits for a Replace of one of the keys and withdraws what it stored", func(t *testing.T) {
		f := setupKeys(t)
		bound := principalKeys(t, f, "alice")
		bucket := testutil.RandomDID(t)
		late := makeDelegation(t, f.tenant, bound[0], bucket, read)

		writeErr, withdrawErr := htestutil.RequireWaitsForWriter(t,
			func(entered chan<- struct{}, release <-chan struct{}) error {
				return replaceOne(t.Context(), f.store, bound[0], func(context.Context, []ucan.Delegation) ([]ucan.Delegation, error) {
					close(entered)
					select {
					case <-release:
					case <-t.Context().Done():
					}
					return []ucan.Delegation{late}, nil
				})
			},
			func() error {
				tx, err := f.pool.Begin(t.Context())
				if err != nil {
					return err
				}
				defer tx.Rollback(context.Background()) // no-op once committed
				for _, st := range f.store.WithdrawGrantsOverStatements(f.tenant.DID(), bucket, []string{"alice"}) {
					if _, err := tx.Exec(t.Context(), st.SQL, st.Args...); err != nil {
						return err
					}
				}
				return tx.Commit(t.Context())
			},
		)
		require.NoError(t, writeErr)
		require.NoError(t, withdrawErr)
		require.Empty(t, f.held(t, bound[0]))
		require.Equal(t, []string{late.Link().String()}, f.owed(t)[f.tenant.DID().String()])
	})
}

func TestWithdrawGrantsOfKeyStatement(t *testing.T) {
	read := command.MustParse("/content/retrieve")
	f := setupKeys(t)
	bucket := testutil.RandomIssuer(t)
	grants := []ucan.Delegation{
		makeDelegation(t, f.tenant, f.keys[0], bucket.DID(), read),
		makeDelegation(t, f.tenant, f.keys[0], did.Undef, read),
	}
	// Left alone: the tenant's other key's grant, the bucket's root to the
	// tenant, and a delegation another party issued to the key.
	sibling := makeDelegation(t, f.tenant, f.keys[1], bucket.DID(), read)
	root := makeDelegation(t, bucket, f.tenant.DID(), bucket.DID(), command.Top())
	foreign := makeDelegation(t, bucket, f.keys[0], bucket.DID(), read)
	require.NoError(t, f.store.PutBatch(t.Context(), append(grants, sibling, root, foreign)))

	f.run(t, f.store.WithdrawGrantsOfKeyStatement(f.tenant.DID(), f.keys[0]))

	require.Equal(t, linkStrings([]ucan.Delegation{foreign}), f.held(t, f.keys[0]))
	require.Equal(t, linkStrings([]ucan.Delegation{sibling}), f.held(t, f.keys[1]))
	require.Equal(t, linkStrings([]ucan.Delegation{root}), f.held(t, f.tenant.DID()))
	owed := f.owed(t)
	require.ElementsMatch(t, linkStrings(grants), owed[f.tenant.DID().String()])
	require.Len(t, owed, 1, "only the tenant owes anything")

	// A second run finds nothing left to move.
	f.run(t, f.store.WithdrawGrantsOfKeyStatement(f.tenant.DID(), f.keys[0]))
	require.Equal(t, owed, f.owed(t))
}

func TestPutForKeysStatement(t *testing.T) {
	read := command.MustParse("/content/retrieve")
	f := setupKeys(t)
	bucket := testutil.RandomDID(t)
	kept := makeDelegation(t, f.tenant, f.keys[0], bucket, read)
	powerline := makeDelegation(t, f.tenant, f.keys[1], did.Undef, read)
	// Issued to a key that no longer exists by the time the statement runs.
	gone := makeDelegation(t, f.tenant, testutil.RandomDID(t), bucket, read)

	st, err := f.store.PutForKeysStatement([]ucan.Delegation{kept, powerline, gone})
	require.NoError(t, err)
	f.run(t, st)
	require.Equal(t, []string{kept.Link().String()}, f.held(t, f.keys[0]))
	require.Equal(t, []string{powerline.Link().String()}, f.held(t, f.keys[1]))
	require.Empty(t, f.held(t, gone.Audience()))

	// The subject column is stored as PutBatch stores it.
	page, err := f.store.ListBySubject(t.Context(), bucket)
	require.NoError(t, err)
	require.Equal(t, []string{kept.Link().String()}, linkStrings(page.Results))

	// A repeat stores nothing twice.
	f.run(t, st)
	require.Len(t, f.held(t, f.keys[0]), 1)

	_, err = f.store.PutForKeysStatement([]ucan.Delegation{kept, nil})
	require.ErrorIs(t, err, store.ErrInvalidArgument)
}

func replaceOne(ctx context.Context, s dlgstore.Store, audience did.DID, next func(ctx context.Context, current []ucan.Delegation) ([]ucan.Delegation, error)) error {
	return s.Replace(ctx, []did.DID{audience}, func(ctx context.Context, current map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error) {
		out, err := next(ctx, current[audience])
		if err != nil {
			return nil, err
		}
		return map[did.DID][]ucan.Delegation{audience: out}, nil
	})
}

func linkStrings(dels []ucan.Delegation) []string {
	out := make([]string, len(dels))
	for i, d := range dels {
		out[i] = d.Link().String()
	}
	return out
}
