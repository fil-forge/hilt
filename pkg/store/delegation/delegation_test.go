package delegation_test

import (
	"context"
	"runtime"
	"testing"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/store"
	dlgstore "github.com/fil-forge/hilt/pkg/store/delegation"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	"github.com/fil-forge/libforge/testutil"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/stretchr/testify/require"
)

type StoreKind string

const (
	Memory   StoreKind = "memory"
	Postgres StoreKind = "postgres"
)

var storeKinds = []StoreKind{Memory, Postgres}

func makeStore(t *testing.T, k StoreKind) dlgstore.Store {
	switch k {
	case Memory:
		return delegationmemory.New()
	case Postgres:
		return createPostgresStore(t)
	}
	panic("unknown store kind")
}

func createPostgresStore(t *testing.T) dlgstore.Store {
	if htestutil.IsRunningInCI(t) && runtime.GOOS == "linux" {
		if !htestutil.IsDockerAvailable(t) {
			t.Fatalf("docker is expected in CI linux testing environments, but wasn't found")
		}
	}
	if !htestutil.IsDockerAvailable(t) {
		t.SkipNow()
	}
	pool := htestutil.CreatePostgres(t)
	return delegationpostgres.New(pool)
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
	for _, k := range storeKinds {
		t.Run(string(k), func(t *testing.T) {
			s := makeStore(t, k)

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
		})
	}
}
