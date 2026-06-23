package delegation_test

import (
	"context"
	"runtime"
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/store"
	dlgstore "github.com/fil-forge/hilt/pkg/store/delegation"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
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
	if testutil.IsRunningInCI(t) && runtime.GOOS == "linux" {
		if !testutil.IsDockerAvailable(t) {
			t.Fatalf("docker is expected in CI linux testing environments, but wasn't found")
		}
	}
	if !testutil.IsDockerAvailable(t) {
		t.SkipNow()
	}
	pool := testutil.CreatePostgres(t)
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
