package delegation_test

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

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

			t.Run("ReplaceOver hands next only the delegations over the subject and keeps the rest", func(t *testing.T) {
				issuer := testutil.RandomIssuer(t)
				audience := testutil.RandomDID(t)
				over, other := testutil.RandomDID(t), testutil.RandomDID(t)
				cmd := command.MustParse("/test/run")
				old := makeDelegation(t, issuer, audience, over, cmd)
				kept := makeDelegation(t, issuer, audience, other, cmd)
				require.NoError(t, s.PutBatch(t.Context(), []ucan.Delegation{old, kept}))
				fresh := makeDelegation(t, issuer, audience, over, cmd)

				var seen []ucan.Delegation
				require.NoError(t, s.ReplaceOver(t.Context(), []did.DID{audience}, over, func(_ context.Context, current map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error) {
					seen = current[audience]
					return map[did.DID][]ucan.Delegation{audience: {fresh}}, nil
				}))

				require.Len(t, seen, 1)
				require.Equal(t, old.Link(), seen[0].Link())
				page, err := s.ListByAudience(t.Context(), audience)
				require.NoError(t, err)
				require.ElementsMatch(t, []string{fresh.Link().String(), kept.Link().String()}, linkStrings(page.Results))
			})

			t.Run("ReplaceOver with next returning nil leaves the audience with nothing over the subject", func(t *testing.T) {
				issuer := testutil.RandomIssuer(t)
				audience := testutil.RandomDID(t)
				over, other := testutil.RandomDID(t), testutil.RandomDID(t)
				cmd := command.MustParse("/test/run")
				kept := makeDelegation(t, issuer, audience, other, cmd)
				require.NoError(t, s.PutBatch(t.Context(), []ucan.Delegation{makeDelegation(t, issuer, audience, over, cmd), kept}))

				require.NoError(t, s.ReplaceOver(t.Context(), []did.DID{audience}, over, func(context.Context, map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error) {
					return nil, nil
				}))

				page, err := s.ListByAudience(t.Context(), audience)
				require.NoError(t, err)
				require.Equal(t, []string{kept.Link().String()}, linkStrings(page.Results))
			})

			t.Run("ReplaceOver rolls back when next errors", func(t *testing.T) {
				issuer := testutil.RandomIssuer(t)
				audience, over := testutil.RandomDID(t), testutil.RandomDID(t)
				old := makeDelegation(t, issuer, audience, over, command.MustParse("/test/run"))
				require.NoError(t, s.PutBatch(t.Context(), []ucan.Delegation{old}))
				boom := errors.New("publish failed")

				err := s.ReplaceOver(t.Context(), []did.DID{audience}, over, func(context.Context, map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error) {
					return nil, boom
				})
				require.ErrorIs(t, err, boom)

				page, err := s.ListByAudience(t.Context(), audience)
				require.NoError(t, err)
				require.Equal(t, []string{old.Link().String()}, linkStrings(page.Results))
			})

			t.Run("ReplaceOver returns ErrInvalidArgument for a delegation over another subject", func(t *testing.T) {
				issuer := testutil.RandomIssuer(t)
				audience := testutil.RandomDID(t)
				over, other := testutil.RandomDID(t), testutil.RandomDID(t)
				stray := makeDelegation(t, issuer, audience, other, command.MustParse("/test/run"))

				err := s.ReplaceOver(t.Context(), []did.DID{audience}, over, func(context.Context, map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error) {
					return map[did.DID][]ucan.Delegation{audience: {stray}}, nil
				})
				require.ErrorIs(t, err, store.ErrInvalidArgument)

				page, err := s.ListByAudience(t.Context(), audience)
				require.NoError(t, err)
				require.Empty(t, page.Results)
			})

			t.Run("ReplaceOver swaps several audiences in one call", func(t *testing.T) {
				issuer := testutil.RandomIssuer(t)
				a, b := testutil.RandomDID(t), testutil.RandomDID(t)
				over, other := testutil.RandomDID(t), testutil.RandomDID(t)
				cmd := command.MustParse("/test/run")
				oldA := makeDelegation(t, issuer, a, over, cmd)
				keptA := makeDelegation(t, issuer, a, other, cmd)
				keptB := makeDelegation(t, issuer, b, other, cmd)
				require.NoError(t, s.PutBatch(t.Context(), []ucan.Delegation{oldA, keptA, keptB}))
				freshA, freshB := makeDelegation(t, issuer, a, over, cmd), makeDelegation(t, issuer, b, over, cmd)

				var seen map[did.DID][]ucan.Delegation
				require.NoError(t, s.ReplaceOver(t.Context(), []did.DID{a, b}, over, func(_ context.Context, current map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error) {
					seen = current
					return map[did.DID][]ucan.Delegation{a: {freshA}, b: {freshB}}, nil
				}))

				require.Equal(t, []string{oldA.Link().String()}, linkStrings(seen[a]))
				require.Empty(t, seen[b], "b holds nothing over the subject")
				pageA, err := s.ListByAudience(t.Context(), a)
				require.NoError(t, err)
				require.ElementsMatch(t, []string{freshA.Link().String(), keptA.Link().String()}, linkStrings(pageA.Results))
				pageB, err := s.ListByAudience(t.Context(), b)
				require.NoError(t, err)
				require.ElementsMatch(t, []string{freshB.Link().String(), keptB.Link().String()}, linkStrings(pageB.Results))
			})

			t.Run("Replace and ReplaceOver hand next each audience once when it is listed twice", func(t *testing.T) {
				issuer := testutil.RandomIssuer(t)
				audience, over := testutil.RandomDID(t), testutil.RandomDID(t)
				require.NoError(t, s.PutBatch(t.Context(), []ucan.Delegation{makeDelegation(t, issuer, audience, over, command.MustParse("/test/run"))}))
				keep := func(_ context.Context, current map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error) {
					require.Len(t, current[audience], 1)
					return current, nil
				}

				require.NoError(t, s.Replace(t.Context(), []did.DID{audience, audience}, keep))
				require.NoError(t, s.ReplaceOver(t.Context(), []did.DID{audience, audience}, over, keep))
			})

			t.Run("ReplaceOver waits for an in-flight Replace of the same audience", func(t *testing.T) {
				issuer := testutil.RandomIssuer(t)
				audience, over := testutil.RandomDID(t), testutil.RandomDID(t)
				cmd := command.MustParse("/test/run")
				fresh := makeDelegation(t, issuer, audience, over, cmd)

				var seen []ucan.Delegation
				writeErr, waitErr := htestutil.RequireWaitsForWriter(t,
					func(entered chan<- struct{}, release <-chan struct{}) error {
						return replaceOne(t.Context(), s, audience, func(context.Context, []ucan.Delegation) ([]ucan.Delegation, error) {
							close(entered)
							<-release
							return []ucan.Delegation{fresh}, nil
						})
					},
					func() error {
						return s.ReplaceOver(t.Context(), []did.DID{audience}, over, func(_ context.Context, current map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error) {
							seen = current[audience]
							return current, nil
						})
					},
				)
				require.NoError(t, writeErr)
				require.NoError(t, waitErr)
				require.Equal(t, []string{fresh.Link().String()}, linkStrings(seen), "ReplaceOver sees the settled result of the Replace it waited on")
			})

			t.Run("ReplaceOver returns ErrInvalidArgument for undef subject", func(t *testing.T) {
				err := s.ReplaceOver(t.Context(), []did.DID{testutil.RandomDID(t)}, did.Undef, func(context.Context, map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error) {
					t.Fatal("next must not run")
					return nil, nil
				})
				require.ErrorIs(t, err, store.ErrInvalidArgument)
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
		})
	}
}

// TestDelegationStoreMemoryLockTimeout: a write that waits out a Replace in
// flight gives up with [store.ErrLockTimeout] instead of wedging against it,
// as lock_timeout bounds the advisory lock wait on Postgres.
func TestDelegationStoreMemoryLockTimeout(t *testing.T) {
	delegationmemory.LockWait = 100 * time.Millisecond
	t.Cleanup(func() { delegationmemory.LockWait = store.LockTimeout })

	s := delegationmemory.New()
	issuer := testutil.RandomIssuer(t)
	audience := testutil.RandomDID(t)
	fresh := makeDelegation(t, issuer, audience, issuer.DID(), command.MustParse("/test/run"))

	entered, release := make(chan struct{}), make(chan struct{})
	replaced := make(chan error, 1)
	go func() {
		replaced <- replaceOne(context.Background(), s, audience, func(context.Context, []ucan.Delegation) ([]ucan.Delegation, error) {
			close(entered)
			<-release
			return []ucan.Delegation{fresh}, nil
		})
	}()
	<-entered

	// The second Replace waits on the audience the first holds and gives up.
	waited := make(chan error, 1)
	go func() {
		waited <- replaceOne(context.Background(), s, audience, func(context.Context, []ucan.Delegation) ([]ucan.Delegation, error) {
			return nil, errors.New("next must not run while the first Replace holds the audience")
		})
	}()
	select {
	case err := <-waited:
		require.ErrorIs(t, err, store.ErrLockTimeout)
	case <-time.After(htestutil.WaitTimeout):
		t.Fatal("the second Replace waited on the first without a bound")
	}

	close(release)
	require.NoError(t, <-replaced)
	page, err := s.ListByAudience(t.Context(), audience)
	require.NoError(t, err)
	require.Len(t, page.Results, 1)
	require.Equal(t, fresh.Link(), page.Results[0].Link())
}

// replaceOne calls Replace over one audience, the shape most tests need.
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
