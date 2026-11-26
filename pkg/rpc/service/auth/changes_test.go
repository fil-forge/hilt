package auth_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	bucketpolicypostgres "github.com/fil-forge/hilt/pkg/store/bucketpolicy/postgres"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/hilt/pkg/tasks"
	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	s3 "github.com/fil-forge/libforge/commands/s3"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/libforge/testutil"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// fakeChanges stands in for the task runner's view of queue-tenant.
type fakeChanges struct {
	// pending is what PendingOn returns.
	pending []taskrunner.TaskID
	// wait is what WaitAll does, given the ctx it was called with.
	wait func(ctx context.Context) error

	mu sync.Mutex
	// asked is the queue and subject of each PendingOn call.
	asked [][2]string
	// waited is the task IDs of each WaitAll call.
	waited [][]taskrunner.TaskID
}

func (f *fakeChanges) PendingOn(_ context.Context, queueName, subject string) ([]taskrunner.TaskID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, [2]string{queueName, subject})
	return f.pending, nil
}

func (f *fakeChanges) WaitAll(ctx context.Context, queueName string, ids ...taskrunner.TaskID) (map[taskrunner.TaskID]taskrunner.Completion, error) {
	f.mu.Lock()
	f.waited = append(f.waited, ids)
	f.mu.Unlock()
	if err := f.wait(ctx); err != nil {
		return nil, err
	}
	return map[taskrunner.TaskID]taskrunner.Completion{}, nil
}

// changesEnv is a tenant with one bucket and one service key that may read
// it, and a request signed by the key that is authorized when nothing is
// pending.
type changesEnv struct {
	pool     *pgxpool.Pool
	tenants  *tenantpostgres.Store
	tenant   did.DID
	provider did.DID
	request  func() s3.Request
	// authorizer builds an Authorizer over the stores with the given options.
	authorizer func(opts ...auth.Option) *auth.Authorizer
}

func setupChanges(t *testing.T) changesEnv {
	t.Helper()
	ctx := t.Context()
	const region = "us-east-1"
	pool := htestutil.PostgresOrSkip(t)
	accessKeys, tenants := accesskeypostgres.New(pool), tenantpostgres.New(pool)
	providers, buckets, secrets := providerpostgres.New(pool), bucketpostgres.New(pool), vaultmemory.New()
	principals, policies := principalpostgres.New(pool), bucketpolicypostgres.New(pool)

	accessKey, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	providerID, tenantID := testutil.RandomDID(t), testutil.RandomDID(t)
	require.NoError(t, providers.Add(ctx, providerID, region, nil))
	require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", tenant.Active))
	require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, providerID, "bucket"))
	seedKey(t, accessKeys, secrets, delegationpostgres.New(pool), accessKey, tenantID, nil)

	return changesEnv{
		pool:     pool,
		tenants:  tenants,
		tenant:   tenantID,
		provider: providerID,
		request:  func() s3.Request { return signedObjectRequest(t, accessKey, "bucket", region) },
		authorizer: func(opts ...auth.Option) *auth.Authorizer {
			return auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets, principals, policies, secrets, opts...)
		},
	}
}

func TestAuthorizeWaitsForTenantChanges(t *testing.T) {
	t.Run("answers at once when no change is pending", func(t *testing.T) {
		env := setupChanges(t)
		changes := &fakeChanges{}
		az := env.authorizer(auth.WithTenantChanges(changes))

		authz, err := az.Authorize(t.Context(), env.provider, env.request())
		require.NoError(t, err)
		require.Equal(t, env.tenant, authz.Tenant.ID)
		require.Equal(t, [][2]string{{"queue-tenant", env.tenant.String()}}, changes.asked)
		require.Empty(t, changes.waited, "nothing to wait for")
	})

	t.Run("an unauthenticated request does not ask", func(t *testing.T) {
		env := setupChanges(t)
		changes := &fakeChanges{}
		az := env.authorizer(auth.WithTenantChanges(changes))

		stranger, err := ed25519.GenerateIssuer()
		require.NoError(t, err)
		_, err = az.Authorize(t.Context(), env.provider, signedObjectRequest(t, stranger, "bucket", "us-east-1"))
		require.ErrorIs(t, err, auth.ErrUnknownAccessKey)
		require.Empty(t, changes.asked)
	})

	t.Run("waits for every pending change, then answers from the state they leave", func(t *testing.T) {
		env := setupChanges(t)
		pending := []taskrunner.TaskID{uuid.New(), uuid.New()}
		entered, release := make(chan struct{}), make(chan struct{})
		changes := &fakeChanges{pending: pending, wait: func(ctx context.Context) error {
			close(entered)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}}
		az := env.authorizer(auth.WithTenantChanges(changes))

		answered := make(chan error, 1)
		go func() {
			_, err := az.Authorize(t.Context(), env.provider, env.request())
			answered <- err
		}()
		select {
		case <-entered:
		case err := <-answered:
			t.Fatalf("authorization answered without waiting: %v", err)
		case <-time.After(htestutil.WaitTimeout):
			t.Fatal("authorization did not wait for the pending changes")
		}
		select {
		case err := <-answered:
			t.Fatalf("authorization answered while a change was pending: %v", err)
		case <-time.After(htestutil.MinBlock):
		}

		// The change the request waited for disables the tenant. The answer
		// shows the status was read after the wait.
		require.NoError(t, env.tenants.SetStatus(t.Context(), env.tenant, tenant.Disabled))
		close(release)
		select {
		case err := <-answered:
			require.ErrorIs(t, err, auth.ErrTenantDisabled)
		case <-time.After(htestutil.WaitTimeout):
			t.Fatal("authorization did not answer once the changes finished")
		}
		require.Equal(t, [][]taskrunner.TaskID{pending}, changes.waited)
	})

	t.Run("is temporarily unavailable when the wait runs out", func(t *testing.T) {
		env := setupChanges(t)
		var bound time.Duration
		changes := &fakeChanges{pending: []taskrunner.TaskID{uuid.New()}, wait: func(ctx context.Context) error {
			// The deadline is checked and reported as passed, so the test
			// does not sit through it.
			deadline, ok := ctx.Deadline()
			require.True(t, ok, "the wait is bounded")
			bound = time.Until(deadline)
			return context.DeadlineExceeded
		}}
		az := env.authorizer(auth.WithTenantChanges(changes))

		_, err := az.Authorize(t.Context(), env.provider, env.request())
		require.ErrorIs(t, err, auth.ErrTemporarilyUnavailable)
		require.LessOrEqual(t, bound, store.LockTimeout)
		require.Greater(t, bound, store.LockTimeout-time.Second)
	})

	t.Run("a caller that gives up is not told to retry", func(t *testing.T) {
		env := setupChanges(t)
		ctx, cancel := context.WithCancel(t.Context())
		changes := &fakeChanges{pending: []taskrunner.TaskID{uuid.New()}, wait: func(wait context.Context) error {
			cancel()
			<-wait.Done()
			return wait.Err()
		}}
		az := env.authorizer(auth.WithTenantChanges(changes))

		_, err := az.Authorize(ctx, env.provider, env.request())
		require.ErrorIs(t, err, context.Canceled)
		require.NotErrorIs(t, err, auth.ErrTemporarilyUnavailable)
	})

	t.Run("waits for a task on the real runner's queue-tenant", func(t *testing.T) {
		env := setupChanges(t)
		started, release := make(chan struct{}), make(chan struct{})
		runner := htestutil.StartTaskRunner(t, env.pool, func(r *taskrunner.Runner) {
			// A change that disables the tenant in its commit, once released.
			require.NoError(t, r.Handle(tasks.QueueTenant, "disable", func(ctx context.Context, ex *taskrunner.Exec, task taskrunner.Task) ([]byte, error) {
				close(started)
				select {
				case <-release:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				return nil, ex.Write(ctx, `UPDATE tenant SET status = 'disabled' WHERE id = $1`, task.Subject)
			}))
			require.NoError(t, r.Handle(tasks.QueueRevocation, tasks.ActionPublish, func(context.Context, *taskrunner.Exec, taskrunner.Task) ([]byte, error) {
				return nil, nil
			}))
		})
		az := env.authorizer(auth.WithTenantChanges(runner))

		// A change pending for another tenant holds nothing up, and neither
		// does a task of this tenant on the revocation queue. Both are
		// delayed, so they stay pending throughout.
		later := time.Now().Add(time.Hour)
		for _, spec := range []taskrunner.Spec{
			{Queue: tasks.QueueTenant, Subject: testutil.RandomDID(t).String(), Action: "disable", NotBefore: &later},
			{Queue: tasks.QueueRevocation, Subject: env.tenant.String(), Action: tasks.ActionPublish, NotBefore: &later},
		} {
			_, err := runner.Submit(t.Context(), spec)
			require.NoError(t, err)
		}
		_, err := az.Authorize(t.Context(), env.provider, env.request())
		require.NoError(t, err)

		_, err = runner.Submit(t.Context(), taskrunner.Spec{Queue: tasks.QueueTenant, Subject: env.tenant.String(), Action: "disable"})
		require.NoError(t, err)
		select {
		case <-started:
		case <-time.After(htestutil.WaitTimeout):
			t.Fatal("the change did not start")
		}

		answered := make(chan error, 1)
		go func() {
			_, err := az.Authorize(t.Context(), env.provider, env.request())
			answered <- err
		}()
		select {
		case err := <-answered:
			t.Fatalf("authorization answered while the change was running: %v", err)
		case <-time.After(htestutil.MinBlock):
		}

		close(release)
		select {
		case err := <-answered:
			require.ErrorIs(t, err, auth.ErrTenantDisabled, "answered from the state the change left")
		case <-time.After(htestutil.WaitTimeout):
			t.Fatal("authorization did not answer once the change finished")
		}
	})
}

// TestAuthorizeWaitsForPolicyWrite runs the real policy tasks. A request by
// a principal-bound key that arrives while a write or a removal of the
// bucket's policy is queued or running waits for it, and is answered from
// the policy it leaves.
func TestAuthorizeWaitsForPolicyWrite(t *testing.T) {
	ctx := t.Context()
	const region = "us-east-1"
	pool := htestutil.PostgresOrSkip(t)
	accessKeys, tenants := accesskeypostgres.New(pool), tenantpostgres.New(pool)
	providers, buckets, secrets := providerpostgres.New(pool), bucketpostgres.New(pool), vaultmemory.New()
	principals, policies := principalpostgres.New(pool), bucketpolicypostgres.New(pool)

	accessKey, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	tenantSigner, err := secp256k1.Generate()
	require.NoError(t, err)
	providerID, tenantID, bucketID := testutil.RandomDID(t), tenantSigner.KeyDID(), testutil.RandomDID(t)
	require.NoError(t, providers.Add(ctx, providerID, region, nil))
	require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", tenant.Active))
	require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), tenantSigner.Bytes()))
	require.NoError(t, buckets.Add(ctx, bucketID, tenantID, providerID, "bucket"))
	require.NoError(t, principals.Add(ctx, tenantID, "user-1"))
	seedKey(t, accessKeys, secrets, delegationpostgres.New(pool), accessKey, tenantID, &setupConfig{principalBound: true})

	// hold, when set, parks the next policy task once it has read everything
	// it reads: closed entered says it is there, and it goes on at release.
	var hold atomic.Pointer[struct{ entered, release chan struct{} }]
	runner := htestutil.StartServiceTasks(t, pool, secrets, &htestutil.FakeSwarf{}, htestutil.BeforePolicyCommit(func() {
		if h := hold.Swap(nil); h != nil {
			close(h.entered)
			select {
			case <-h.release:
			case <-t.Context().Done():
			}
		}
	}))
	az := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets, principals, policies, secrets, auth.WithTenantChanges(runner))
	request := func() s3.Request { return signedObjectRequest(t, accessKey, "bucket", region) }

	// during runs the task parked, requires that a request made meanwhile
	// waits for it, and returns the request's answer once the task is done.
	during := func(t *testing.T, spec taskrunner.Spec) (*auth.AuthorizedRequest, error) {
		t.Helper()
		var authz *auth.AuthorizedRequest
		ran, answered := htestutil.RequireWaitsForWriter(t,
			func(entered chan<- struct{}, release <-chan struct{}) error {
				h := &struct{ entered, release chan struct{} }{make(chan struct{}), make(chan struct{})}
				hold.Store(h)
				go func() { <-h.entered; close(entered) }()
				go func() { <-release; close(h.release) }()
				_, err := runner.Run(context.Background(), spec)
				return err
			},
			func() (err error) {
				authz, err = az.Authorize(context.Background(), providerID, request())
				return err
			})
		require.NoError(t, ran)
		return authz, answered
	}

	_, err = az.Authorize(ctx, providerID, request())
	require.ErrorIs(t, err, auth.ErrUnknownBucket, "no policy reaches the principal yet")

	document := s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: []s3bkt.Statement{{
		Effect: s3bkt.Allow, Principal: s3bkt.Only("user-1"), Actions: s3bkt.NewStringSet("s3:GetObject"),
		Resources: s3bkt.NewStringSet(s3bkt.BucketARN("bucket"), s3bkt.ObjectsARN("bucket")),
	}}}
	put, err := tenantqueue.PutPolicySpec(tenantID, bucketID, "bucket", document, tenantqueue.PolicyCondition{})
	require.NoError(t, err)
	authz, err := during(t, put)
	require.NoError(t, err, "answered from the policy the write stored")
	require.Equal(t, []string{"s3:GetObject"}, authz.Permissions)

	remove, err := tenantqueue.DeletePolicySpec(tenantID, bucketID, "bucket", nil)
	require.NoError(t, err)
	_, err = during(t, remove)
	require.ErrorIs(t, err, auth.ErrUnknownBucket, "answered from the bucket without its policy")
}
