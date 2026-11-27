package delegation_test

import (
	"context"
	"slices"
	"testing"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	dlgstore "github.com/fil-forge/hilt/pkg/store/delegation"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/libforge/testutil"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/jackc/pgx/v5"
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

func TestWithdrawKeyGrantsStatement(t *testing.T) {
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

		f.run(t, f.store.WithdrawKeyGrantsStatement(f.tenant.DID()))

		require.Equal(t, linkStrings([]ucan.Delegation{foreign}), f.held(t, f.keys[0]))
		require.Empty(t, f.held(t, f.keys[1]))
		require.Equal(t, linkStrings([]ucan.Delegation{root}), f.held(t, f.tenant.DID()))
		require.Equal(t, linkStrings([]ucan.Delegation{elsewhere}), f.held(t, elsewhere.Audience()))
		require.Equal(t, linkStrings([]ucan.Delegation{theirs}), f.held(t, f.otherKey))
		owed := f.owed(t)
		require.ElementsMatch(t, linkStrings(grants), owed[f.tenant.DID().String()])
		require.Len(t, owed, 1, "only the tenant owes anything")

		// A second run finds nothing left to move.
		f.run(t, f.store.WithdrawKeyGrantsStatement(f.tenant.DID()))
		require.Equal(t, owed, f.owed(t))
	})
}

func TestWithdrawGrantsOverStatement(t *testing.T) {
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

		f.run(t, f.store.WithdrawGrantsOverStatement(f.tenant.DID(), bucket.DID(), []string{"alice", "bob"}))

		require.ElementsMatch(t, linkStrings([]ucan.Delegation{others[0], others[4]}), f.held(t, bound[0]))
		require.Equal(t, linkStrings([]ucan.Delegation{others[1]}), f.held(t, bound[1]))
		require.Equal(t, linkStrings([]ucan.Delegation{others[2]}), f.held(t, bound[2]))
		require.Equal(t, linkStrings([]ucan.Delegation{others[3]}), f.held(t, f.keys[0]))
		require.Equal(t, linkStrings([]ucan.Delegation{others[5]}), f.held(t, f.tenant.DID()))
		owed := f.owed(t)
		require.ElementsMatch(t, linkStrings(grants), owed[f.tenant.DID().String()])
		require.Len(t, owed, 1, "only the tenant owes anything")

		// A second run finds nothing left to move.
		f.run(t, f.store.WithdrawGrantsOverStatement(f.tenant.DID(), bucket.DID(), []string{"alice", "bob"}))
		require.Equal(t, owed, f.owed(t))
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

func TestWithdrawSubjectStatements(t *testing.T) {
	read := command.MustParse("/content/retrieve")
	f := setupKeys(t)
	bucket, elsewhere := testutil.RandomIssuer(t), testutil.RandomDID(t)
	// Every delegation the tenant issued over the bucket, whoever holds it.
	grants := []ucan.Delegation{
		makeDelegation(t, f.tenant, f.keys[0], bucket.DID(), read),
		makeDelegation(t, f.tenant, f.keys[1], bucket.DID(), read),
		makeDelegation(t, f.tenant, testutil.RandomDID(t), bucket.DID(), read),
	}
	// Deleted unrevoked: the bucket's root to the tenant.
	root := makeDelegation(t, bucket, f.tenant.DID(), bucket.DID(), command.Top())
	// Left alone: a powerline grant, a grant over another bucket, and
	// another tenant's.
	powerline := makeDelegation(t, f.tenant, f.keys[0], did.Undef, read)
	other := makeDelegation(t, f.tenant, f.keys[1], elsewhere, read)
	theirs := makeDelegation(t, f.other, f.otherKey, elsewhere, read)
	require.NoError(t, f.store.PutBatch(t.Context(), append(slices.Clone(grants), root, powerline, other, theirs)))

	f.run(t, f.store.WithdrawSubjectStatements(f.tenant.DID(), bucket.DID())...)

	require.Equal(t, linkStrings([]ucan.Delegation{powerline}), f.held(t, f.keys[0]))
	require.Equal(t, linkStrings([]ucan.Delegation{other}), f.held(t, f.keys[1]))
	require.Empty(t, f.held(t, f.tenant.DID()), "the root goes")
	require.Equal(t, linkStrings([]ucan.Delegation{theirs}), f.held(t, f.otherKey))
	owed := f.owed(t)
	require.ElementsMatch(t, linkStrings(grants), owed[f.tenant.DID().String()], "the root is not revoked")
	require.Len(t, owed, 1, "only the tenant owes anything")

	// A second run finds nothing left to move.
	f.run(t, f.store.WithdrawSubjectStatements(f.tenant.DID(), bucket.DID())...)
	require.Equal(t, owed, f.owed(t))
}

func TestPutStatement(t *testing.T) {
	read := command.MustParse("/content/retrieve")
	f := setupKeys(t)
	bucket := testutil.RandomDID(t)
	kept := makeDelegation(t, f.tenant, f.keys[0], bucket, read)
	powerline := makeDelegation(t, f.tenant, f.keys[1], did.Undef, read)

	st, err := f.store.PutStatement([]ucan.Delegation{kept, powerline})
	require.NoError(t, err)
	f.run(t, st)
	require.Equal(t, []string{kept.Link().String()}, f.held(t, f.keys[0]))
	require.Equal(t, []string{powerline.Link().String()}, f.held(t, f.keys[1]))

	// The subject column is stored as PutBatch stores it.
	var overBucket []string
	rows, err := f.pool.Query(t.Context(), `SELECT id FROM delegation WHERE subject = $1`, bucket.String())
	require.NoError(t, err)
	overBucket, err = pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	require.Equal(t, []string{kept.Link().String()}, overBucket)

	// A repeat stores nothing twice.
	f.run(t, st)
	require.Len(t, f.held(t, f.keys[0]), 1)

	_, err = f.store.PutStatement([]ucan.Delegation{kept, nil})
	require.ErrorIs(t, err, store.ErrInvalidArgument)
}

func TestListKeyGrants(t *testing.T) {
	read := command.MustParse("/content/retrieve")
	f := setupKeys(t)
	bucket := testutil.RandomIssuer(t)
	grants := []ucan.Delegation{
		makeDelegation(t, f.tenant, f.keys[0], bucket.DID(), read),
		makeDelegation(t, f.tenant, f.keys[0], did.Undef, read),
		makeDelegation(t, f.tenant, f.keys[1], bucket.DID(), read),
	}
	// Left out: the bucket's root to the tenant, a delegation the tenant
	// issued to something that is not one of its keys, one another party
	// issued to one of its keys, and another tenant's grant.
	root := makeDelegation(t, bucket, f.tenant.DID(), bucket.DID(), command.Top())
	elsewhere := makeDelegation(t, f.tenant, testutil.RandomDID(t), bucket.DID(), read)
	foreign := makeDelegation(t, bucket, f.keys[0], bucket.DID(), read)
	theirs := makeDelegation(t, f.other, f.otherKey, bucket.DID(), read)
	require.NoError(t, f.store.PutBatch(t.Context(), append(slices.Clone(grants), root, elsewhere, foreign, theirs)))

	got, err := f.store.ListKeyGrants(t.Context(), f.tenant.DID())
	require.NoError(t, err)
	require.ElementsMatch(t, linkStrings(grants), linkStrings(got))

	none, err := f.store.ListKeyGrants(t.Context(), testutil.RandomDID(t))
	require.NoError(t, err)
	require.Empty(t, none)
}

func TestDeleteTenantStatement(t *testing.T) {
	read := command.MustParse("/content/retrieve")
	f := setupKeys(t)
	provider := testutil.RandomDID(t)
	require.NoError(t, providerpostgres.New(f.pool).Add(t.Context(), provider, "region-1", nil))
	bucket := testutil.RandomIssuer(t)
	require.NoError(t, bucketpostgres.New(f.pool).Add(t.Context(), bucket.DID(), f.tenant.DID(), provider, "bucket-1"))
	otherBucket := testutil.RandomIssuer(t)
	require.NoError(t, bucketpostgres.New(f.pool).Add(t.Context(), otherBucket.DID(), f.other.DID(), provider, "bucket-2"))

	gone := []ucan.Delegation{
		makeDelegation(t, f.tenant, f.keys[0], bucket.DID(), read),
		makeDelegation(t, f.tenant, f.keys[1], did.Undef, read),
		makeDelegation(t, bucket, f.tenant.DID(), bucket.DID(), command.Top()),
		makeDelegation(t, f.tenant, testutil.RandomDID(t), bucket.DID(), read),
		makeDelegation(t, testutil.RandomIssuer(t), f.keys[0], testutil.RandomDID(t), read),
		makeDelegation(t, testutil.RandomIssuer(t), testutil.RandomDID(t), bucket.DID(), read),
	}
	kept := []ucan.Delegation{
		makeDelegation(t, otherBucket, f.other.DID(), otherBucket.DID(), command.Top()),
		makeDelegation(t, f.other, f.otherKey, otherBucket.DID(), read),
	}
	require.NoError(t, f.store.PutBatch(t.Context(), append(slices.Clone(gone), kept...)))

	f.run(t, f.store.DeleteTenantStatement(f.tenant.DID()))

	var left []string
	rows, err := f.pool.Query(t.Context(), `SELECT id FROM delegation`)
	require.NoError(t, err)
	left, err = pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	require.ElementsMatch(t, linkStrings(kept), left)
	require.Empty(t, f.owed(t), "nothing is recorded as owed")
}

func linkStrings(dels []ucan.Delegation) []string {
	out := make([]string, len(dels))
	for i, d := range dels {
		out[i] = d.Link().String()
	}
	return out
}
