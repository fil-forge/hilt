package exportsession_test

import (
	"encoding/json"
	"fmt"
	"runtime"
	"testing"
	"time"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/exportsession"
	exportsessionmemory "github.com/fil-forge/hilt/pkg/store/exportsession/memory"
	exportsessionpostgres "github.com/fil-forge/hilt/pkg/store/exportsession/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/libforge/testutil"
	"github.com/fil-forge/ucantone/did"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

type StoreKind string

const (
	Memory   StoreKind = "memory"
	Postgres StoreKind = "postgres"
)

var storeKinds = []StoreKind{Memory, Postgres}

// seedFunc ensures the parent tenant (and its provider) exist so the
// export_session.tenant_id foreign key is satisfied. It is a no-op for the
// memory store, which does not enforce referential integrity.
type seedFunc func(t *testing.T, tenantID did.DID)

func makeStore(t *testing.T, k StoreKind) (exportsession.Store, seedFunc) {
	switch k {
	case Memory:
		return exportsessionmemory.New(), func(*testing.T, did.DID) {}
	case Postgres:
		pool := createPostgresPool(t)
		providers := providerpostgres.New(pool)
		tenants := tenantpostgres.New(pool)
		seed := func(t *testing.T, tenantID did.DID) {
			providerID := testutil.RandomDID(t)
			require.NoError(t, providers.Add(t.Context(), providerID, tenantID.String(), nil))
			require.NoError(t, tenants.Add(t.Context(), tenantID, "ext-"+tenantID.String(), providerID, tenant.Active))
		}
		return exportsessionpostgres.New(pool), seed
	}
	panic("unknown store kind")
}

func createPostgresPool(t *testing.T) *pgxpool.Pool {
	if htestutil.IsRunningInCI(t) && runtime.GOOS == "linux" {
		if !htestutil.IsDockerAvailable(t) {
			t.Fatalf("docker is expected in CI linux testing environments, but wasn't found")
		}
	}
	if !htestutil.IsDockerAvailable(t) {
		t.SkipNow()
	}
	return htestutil.CreatePostgres(t)
}

// customerKey is a placeholder X25519 multikey; the store only requires a
// non-empty string.
const customerKey = "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"

// openSession seeds a tenant and opens a session for a fresh bucket.
func openSession(t *testing.T, s exportsession.Store, seed seedFunc) exportsession.Input {
	t.Helper()
	input := exportsession.Input{
		ID:          fmt.Sprintf("session-%s", testutil.RandomCID(t)),
		Tenant:      testutil.RandomDID(t),
		Bucket:      testutil.RandomDID(t),
		CustomerKey: customerKey,
		ExpiresAt:   time.Now().Add(time.Hour).Truncate(time.Microsecond),
	}
	seed(t, input.Tenant)
	require.NoError(t, s.Add(t.Context(), input))
	return input
}

// path is the forward walk through the state machine.
var path = []exportsession.State{
	exportsession.Opened, exportsession.PoPVerified, exportsession.Pinned, exportsession.Acked,
	exportsession.ManifestBuilt, exportsession.CarReady, exportsession.Validated, exportsession.Released,
}

// advance walks a session forward from its current state, from, to target.
func advance(t *testing.T, s exportsession.Store, id string, from, target exportsession.State) {
	t.Helper()
	started := false
	for i := 1; i < len(path) && path[i-1] != target; i++ {
		if path[i-1] == from {
			started = true
		}
		if !started {
			continue
		}
		if path[i] == exportsession.Pinned {
			require.NoError(t, s.Pin(t.Context(), id, testutil.RandomCID(t)))
			continue
		}
		require.NoError(t, s.Transition(t.Context(), id, path[i-1], path[i]))
	}
}

func TestValidTransition(t *testing.T) {
	forward := map[exportsession.State]exportsession.State{
		exportsession.Opened:        exportsession.PoPVerified,
		exportsession.PoPVerified:   exportsession.Pinned,
		exportsession.Pinned:        exportsession.Acked,
		exportsession.Acked:         exportsession.ManifestBuilt,
		exportsession.ManifestBuilt: exportsession.CarReady,
		exportsession.CarReady:      exportsession.Validated,
		exportsession.Validated:     exportsession.Released,
	}
	all := []exportsession.State{
		exportsession.Opened, exportsession.PoPVerified, exportsession.Pinned, exportsession.Acked,
		exportsession.ManifestBuilt, exportsession.CarReady, exportsession.Validated,
		exportsession.Released, exportsession.Aborted, "", "bogus",
	}
	for _, from := range all {
		_, open := forward[from]
		require.Equal(t, open, from.Open(), "%q.Open()", from)
		for _, to := range all {
			want := open && (to == exportsession.Aborted || forward[from] == to)
			require.Equal(t, want, exportsession.ValidTransition(from, to), "ValidTransition(%q, %q)", from, to)
		}
	}
}

func TestExportSessionStore(t *testing.T) {
	for _, k := range storeKinds {
		t.Run(string(k), func(t *testing.T) {
			s, seed := makeStore(t, k)

			t.Run("opens a session in opened", func(t *testing.T) {
				input := openSession(t, s, seed)

				rec, err := s.Get(t.Context(), input.ID)
				require.NoError(t, err)
				require.Equal(t, input.ID, rec.ID)
				require.Equal(t, input.Tenant, rec.Tenant)
				require.Equal(t, input.Bucket, rec.Bucket)
				require.Equal(t, customerKey, rec.CustomerKey)
				require.Equal(t, exportsession.Opened, rec.State)
				require.False(t, rec.Root.Defined())
				require.True(t, rec.PinnedAt.IsZero())
				require.JSONEq(t, `[]`, string(rec.Audit))
				require.False(t, rec.CreatedAt.IsZero())
				require.True(t, input.ExpiresAt.Equal(rec.ExpiresAt))
			})

			t.Run("rejects a duplicate id", func(t *testing.T) {
				input := openSession(t, s, seed)
				require.ErrorIs(t, s.Add(t.Context(), input), store.ErrRecordExists)
			})

			t.Run("rejects an empty id or customer key", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				noKey := exportsession.Input{ID: "no-key", Tenant: tenantID, Bucket: testutil.RandomDID(t), ExpiresAt: time.Now()}
				require.ErrorIs(t, s.Add(t.Context(), noKey), store.ErrInvalidArgument)
				noID := exportsession.Input{Tenant: tenantID, Bucket: testutil.RandomDID(t), CustomerKey: customerKey, ExpiresAt: time.Now()}
				require.ErrorIs(t, s.Add(t.Context(), noID), store.ErrInvalidArgument)
			})

			t.Run("returns ErrRecordNotFound for an unknown id", func(t *testing.T) {
				_, err := s.Get(t.Context(), "missing")
				require.ErrorIs(t, err, store.ErrRecordNotFound)
			})

			t.Run("walks forward to released and records the pin", func(t *testing.T) {
				input := openSession(t, s, seed)
				require.NoError(t, s.Transition(t.Context(), input.ID, exportsession.Opened, exportsession.PoPVerified))

				root := testutil.RandomCID(t)
				require.NoError(t, s.Pin(t.Context(), input.ID, root))
				rec, err := s.Get(t.Context(), input.ID)
				require.NoError(t, err)
				require.Equal(t, exportsession.Pinned, rec.State)
				require.Equal(t, root, rec.Root)
				require.False(t, rec.PinnedAt.IsZero())

				advance(t, s, input.ID, exportsession.Pinned, exportsession.Released)
				rec, err = s.Get(t.Context(), input.ID)
				require.NoError(t, err)
				require.Equal(t, exportsession.Released, rec.State)
				require.Equal(t, root, rec.Root, "the pinned root outlives the session")
			})

			t.Run("transition is a compare-and-set", func(t *testing.T) {
				input := openSession(t, s, seed)
				require.NoError(t, s.Transition(t.Context(), input.ID, exportsession.Opened, exportsession.PoPVerified))
				require.ErrorIs(t, s.Transition(t.Context(), input.ID, exportsession.Opened, exportsession.PoPVerified), store.ErrRecordNotFound)
				require.ErrorIs(t, s.Transition(t.Context(), "missing", exportsession.Opened, exportsession.PoPVerified), store.ErrRecordNotFound)
			})

			t.Run("rejects transitions outside the machine", func(t *testing.T) {
				input := openSession(t, s, seed)
				for _, tc := range []struct{ from, to exportsession.State }{
					{exportsession.Opened, exportsession.Acked},          // skips a step
					{exportsession.PoPVerified, exportsession.Pinned},    // pinning goes through Pin
					{exportsession.Released, exportsession.Aborted},      // from a terminal state
					{"bogus", exportsession.Aborted},                     // from an unknown state
					{exportsession.Opened, exportsession.State("bogus")}, // to an unknown state
				} {
					require.ErrorIs(t, s.Transition(t.Context(), input.ID, tc.from, tc.to), store.ErrInvalidArgument, "%s -> %s", tc.from, tc.to)
				}
				rec, err := s.Get(t.Context(), input.ID)
				require.NoError(t, err)
				require.Equal(t, exportsession.Opened, rec.State)
			})

			t.Run("pins only from pop_verified", func(t *testing.T) {
				input := openSession(t, s, seed)
				require.ErrorIs(t, s.Pin(t.Context(), input.ID, testutil.RandomCID(t)), store.ErrRecordNotFound)
				require.NoError(t, s.Transition(t.Context(), input.ID, exportsession.Opened, exportsession.PoPVerified))
				require.NoError(t, s.Pin(t.Context(), input.ID, testutil.RandomCID(t)))
				require.ErrorIs(t, s.Pin(t.Context(), input.ID, testutil.RandomCID(t)), store.ErrRecordNotFound)
			})

			t.Run("aborts from every open state", func(t *testing.T) {
				for _, state := range []exportsession.State{
					exportsession.Opened, exportsession.PoPVerified, exportsession.Pinned, exportsession.Acked,
					exportsession.ManifestBuilt, exportsession.CarReady, exportsession.Validated,
				} {
					input := openSession(t, s, seed)
					advance(t, s, input.ID, exportsession.Opened, state)
					require.NoError(t, s.Transition(t.Context(), input.ID, state, exportsession.Aborted), "abort from %s", state)
					open, err := s.HasOpen(t.Context(), input.Tenant)
					require.NoError(t, err)
					require.False(t, open, "tenant still open after abort from %s", state)
				}
			})

			t.Run("appends to the audit log", func(t *testing.T) {
				input := openSession(t, s, seed)
				require.NoError(t, s.AppendAudit(t.Context(), input.ID, []byte(`{"event":"pop","ok":true}`)))
				require.NoError(t, s.AppendAudit(t.Context(), input.ID, []byte(`"ack"`)))
				require.ErrorIs(t, s.AppendAudit(t.Context(), input.ID, []byte(`not json`)), store.ErrInvalidArgument)
				require.ErrorIs(t, s.AppendAudit(t.Context(), "missing", []byte(`{}`)), store.ErrRecordNotFound)

				rec, err := s.Get(t.Context(), input.ID)
				require.NoError(t, err)
				var audit []any
				require.NoError(t, json.Unmarshal(rec.Audit, &audit))
				require.Equal(t, []any{map[string]any{"event": "pop", "ok": true}, "ack"}, audit)
			})

			t.Run("reports open sessions by tenant and bucket", func(t *testing.T) {
				input := openSession(t, s, seed)
				for _, check := range []func() (bool, error){
					func() (bool, error) { return s.HasOpen(t.Context(), input.Tenant) },
					func() (bool, error) { return s.HasOpenForBucket(t.Context(), input.Bucket) },
				} {
					open, err := check()
					require.NoError(t, err)
					require.True(t, open)
				}

				other, err := s.HasOpen(t.Context(), testutil.RandomDID(t))
				require.NoError(t, err)
				require.False(t, other)
				other, err = s.HasOpenForBucket(t.Context(), testutil.RandomDID(t))
				require.NoError(t, err)
				require.False(t, other)

				advance(t, s, input.ID, exportsession.Opened, exportsession.Released)
				open, err := s.HasOpen(t.Context(), input.Tenant)
				require.NoError(t, err)
				require.False(t, open)
				open, err = s.HasOpenForBucket(t.Context(), input.Bucket)
				require.NoError(t, err)
				require.False(t, open)
			})

			t.Run("deletes every session of a tenant", func(t *testing.T) {
				input := openSession(t, s, seed)
				advance(t, s, input.ID, exportsession.Opened, exportsession.Released)
				second := exportsession.Input{
					ID: input.ID + "-2", Tenant: input.Tenant, Bucket: testutil.RandomDID(t),
					CustomerKey: customerKey, ExpiresAt: time.Now().Add(time.Hour),
				}
				require.NoError(t, s.Add(t.Context(), second))
				bystander := openSession(t, s, seed)

				require.NoError(t, s.DeleteByTenant(t.Context(), input.Tenant))
				for _, id := range []string{input.ID, second.ID} {
					_, err := s.Get(t.Context(), id)
					require.ErrorIs(t, err, store.ErrRecordNotFound)
				}
				_, err := s.Get(t.Context(), bystander.ID)
				require.NoError(t, err)
				require.NoError(t, s.DeleteByTenant(t.Context(), input.Tenant), "idempotent")
			})
		})
	}
}
