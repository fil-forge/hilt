//go:build itest

// Package itest boots the full Forge network with smelt (Docker) and
// exercises hilt end to end against real services: the working tree's hilt
// is compiled and mounted over the published image, tenants and access keys
// are provisioned through the real management client against hilt's partner
// REST API, S3 requests are signed with the real AWS SDK against the real
// ingot gateway (which stores through the real sprue and piri), and
// revocations are read back from the real swarf firehose.
//
// The suite runs only under the itest build tag — `make itest`, not
// `go test ./...` — and needs Docker. One itest run per Docker host at a
// time: TestMain sweeps every smeltery- compose project, including another
// run's live containers.
package itest

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/fil-forge/hilt/pkg/api"
	"github.com/fil-forge/hilt/pkg/client/management"
	"github.com/fil-forge/smelt/pkg/stack"
	swarfapi "github.com/fil-forge/swarf/pkg/api"
	swarfclient "github.com/fil-forge/swarf/pkg/client"
	swarfstore "github.com/fil-forge/swarf/pkg/store"
	"github.com/fil-forge/ucantone/did"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/require"
)

// forgeRegion must match the provider region hilt's post_start hook in smelt
// registers ingot under (INGOT_REGION) — tenants are provisioned per region.
const forgeRegion = "us-west-1"

// hiltServiceDID must match the identity smelt's hilt service runs under
// (HILT_IDENTITY_SERVICE_ID) — swarf accepts a principal invalidation only
// from a publisher it is configured to trust, and hilt self-signs it.
const hiltServiceDID = "did:web:hilt"

// swarfPublishersConfig writes the swarf config file that trusts this stack's
// hilt as a principal-invalidation publisher and returns its path, for
// mounting over the container's /etc/swarf/config.yaml. Swarf reads that path
// when it is given no --config, and every other setting stays in the
// environment smelt provides.
func swarfPublishersConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "swarf-config.yaml")
	body := "principal:\n  publishers:\n    - " + hiltServiceDID + "\n"
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

// TestMain sweeps containers/volumes leaked by prior crashed itest runs (same
// smeltery- project prefix as any smelt-SDK stack). Best-effort: a missing
// docker only matters once a test actually boots a stack.
func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	if err := stack.CleanupLeaked(ctx); err != nil {
		log.Printf("itest: pre-test sweep warning: %v", err)
	}
	cancel()
	os.Exit(m.Run())
}

var (
	buildOnce   sync.Once
	builtBinary string
	buildErr    error
)

// localHiltBinary compiles the working tree's hilt once per test run as a
// static linux binary suitable for bind-mounting over the published image's
// /usr/bin/hilt. GOARCH follows the test host so the binary matches the
// Docker host's container platform; GOWORK=off keeps the build hermetic (a
// parent go.work may resolve sibling repos to unmerged working trees).
func localHiltBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "hilt-itest-bin-")
		if err != nil {
			buildErr = err
			return
		}
		out := filepath.Join(dir, "hilt")
		cmd := exec.Command("go", "build", "-o", out, "./cmd")
		cmd.Dir = ".." // tests run in itest/; build from the module root
		cmd.Env = append(os.Environ(),
			"CGO_ENABLED=0",
			"GOOS=linux",
			"GOARCH="+runtime.GOARCH,
			"GOWORK=off",
		)
		if outb, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("go build ./cmd: %v\n%s", err, outb)
			return
		}
		builtBinary = out
	})
	if buildErr != nil {
		t.Fatalf("build local hilt binary: %v", buildErr)
	}
	return builtBinary
}

// forgeNet is the running network as the tests see it: the smelt stack plus
// the real clients used to drive it — hilt's management client for the
// partner REST API and swarf's client for reading revocations back.
type forgeNet struct {
	stack   *stack.Stack
	console *console
	swarf   *swarfclient.Client
	s3URL   string
}

// startForge boots the smelt stack with the working tree's hilt injected,
// waits for hilt and ingot to serve health, and returns the network with its
// clients wired up. The stack lives until the calling test — including all
// of its subtests — completes.
func startForge(t *testing.T) *forgeNet {
	t.Helper()
	t.Logf("booting the smelt Forge stack (~1-2 min; first run also compiles hilt and pulls images)")
	opts := []stack.Option{
		// Postgres-backed piri: piri:main's curio PDP pipeline refuses
		// sqlite ("curio PDP pipeline requires Postgres").
		stack.WithPiriNodes(stack.PiriNodeConfig{Postgres: true}),
		stack.WithServiceBinary("hilt", localHiltBinary(t)),
	}
	// Local-dev escape hatches: run against sprue / piri / ingot images the
	// registry doesn't have yet — e.g. built from an unmerged branch. Unset
	// (CI) uses the published defaults.
	if img := os.Getenv("HILT_ITEST_UPLOAD_IMAGE"); img != "" {
		t.Logf("using upload-service image override: %s", img)
		opts = append(opts, stack.WithUploadImage(img))
	}
	if img := os.Getenv("HILT_ITEST_PIRI_IMAGE"); img != "" {
		t.Logf("using piri image override: %s", img)
		opts = append(opts, stack.WithPiriImage(img))
	}
	if img := os.Getenv("HILT_ITEST_INGOT_IMAGE"); img != "" {
		t.Logf("using ingot image override: %s", img)
		opts = append(opts, stack.WithIngotImage(img))
	}
	if img := os.Getenv("HILT_ITEST_SWARF_IMAGE"); img != "" {
		t.Logf("using swarf image override: %s", img)
		opts = append(opts, stack.WithSwarfImage(img))
	}
	// Same idea one step earlier in the pipeline: mount a locally-built piri
	// binary (linux, static) over the image's /usr/bin/piri.
	if bin := os.Getenv("HILT_ITEST_PIRI_BINARY"); bin != "" {
		t.Logf("using piri binary override: %s", bin)
		opts = append(opts, stack.WithPiriBinary(bin))
	}
	if bin := os.Getenv("HILT_ITEST_SWARF_BINARY"); bin != "" {
		t.Logf("using swarf binary override: %s", bin)
		opts = append(opts, stack.WithServiceBinary("swarf", bin))
	}
	if bin := os.Getenv("HILT_ITEST_INGOT_BINARY"); bin != "" {
		t.Logf("using ingot binary override: %s", bin)
		opts = append(opts, stack.WithServiceBinary("ingot", bin))
	}
	// Swarf accepts /principal/invalidate only from a configured publisher,
	// and smelt's swarf service definition sets no publisher list. Mount one
	// naming this stack's hilt over swarf's config path so the principal
	// scenarios can publish.
	opts = append(opts, stack.WithServiceConfig("swarf", swarfPublishersConfig(t)))
	s := stack.MustNewStack(t, opts...)
	waitHTTPOK(t, s.HiltEndpoint()+"/health", 2*time.Minute)
	waitHTTPOK(t, s.IngotEndpoint()+"/health", 2*time.Minute)

	hiltURL, err := url.Parse(s.HiltEndpoint())
	require.NoError(t, err)
	swarfURL, err := url.Parse(s.SwarfEndpoint())
	require.NoError(t, err)
	// Get/Stream never invoke the service DID, so the compose-internal
	// did:web identity is fine for a read-only client.
	swarfDID, err := did.Parse("did:web:swarf")
	require.NoError(t, err)
	swarf, err := swarfclient.New(swarfDID, *swarfURL)
	require.NoError(t, err)

	return &forgeNet{
		stack:   s,
		console: &console{client: management.NewClient(*hiltURL, s.HiltPartnerKey())},
		swarf:   swarf,
		s3URL:   s.IngotEndpoint(),
	}
}

// TestForge boots the stack once and runs every scenario as a subtest
// against it. Subtests run sequentially and each provisions its own tenant
// (and unique bucket names), so they share the stack without sharing state.
func TestForge(t *testing.T) {
	net := startForge(t)
	t.Run("HappyPath", func(t *testing.T) { testHappyPath(t, net) })
	t.Run("DeleteAccessKeyRevokes", func(t *testing.T) { testDeleteAccessKeyRevokes(t, net) })
	t.Run("DeleteBucketRevokes", func(t *testing.T) { testDeleteBucketRevokes(t, net) })
	t.Run("DeleteBucketRevokesOnlyThatBucket", func(t *testing.T) { testDeleteBucketRevokesOnlyThatBucket(t, net) })
	// The IAM scenarios need a swarf that accepts principal invalidations and
	// an ingot that enforces the effective action set. Until the published
	// :main images carry both, they run only against the binary overrides
	// (or when HILT_ITEST_IAM=1 says the images do); drop this guard then.
	iam := func(name string, fn func(*testing.T, *forgeNet)) {
		t.Run(name, func(t *testing.T) {
			if os.Getenv("HILT_ITEST_IAM") != "1" &&
				(os.Getenv("HILT_ITEST_SWARF_BINARY") == "" || os.Getenv("HILT_ITEST_INGOT_BINARY") == "") {
				t.Skip("IAM scenarios need HILT_ITEST_SWARF_BINARY and HILT_ITEST_INGOT_BINARY (or HILT_ITEST_IAM=1) until the :main images carry the IAM changes")
			}
			fn(t, net)
		})
	}
	iam("PrincipalPolicyScopesToOneBucket", testPrincipalPolicyScopesToOneBucket)
	iam("DenyBeatsAllow", testDenyBeatsAllow)
	iam("NarrowingInvalidatesPrincipal", testNarrowingInvalidatesPrincipal)
	iam("DeletePrincipalRemovesKeysAndPolicies", testDeletePrincipalRemovesKeysAndPolicies)
	iam("PresignedGetFollowsPolicy", testPresignedGetFollowsPolicy)
	iam("PrincipalKeyCreateRejectsBadRequests", testPrincipalKeyCreateRejectsBadRequests)
}

// s3Client builds a real AWS S3 SDK client pointed at the real ingot
// gateway, signing with the given access key credentials (id = the bare
// did:key identifier, secret = the multibase secret returned by
// CreateAccessKey).
func (n *forgeNet) s3Client(t *testing.T, accessKeyID, secret string) *s3.Client {
	t.Helper()
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(forgeRegion),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(accessKeyID, secret, "")),
	)
	require.NoError(t, err)
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = &n.s3URL
		o.UsePathStyle = true
	})
}

// awaitRevocations reads the revocation firehose from the beginning and
// returns the first count records whose revoked delegation was issued to
// audience, failing the test if they do not arrive in time. The firehose is
// stack-global — other subtests' revocations share it — so records are
// filtered by the revoked delegation's audience, which is unique per access
// key.
func (n *forgeNet) awaitRevocations(t *testing.T, ctx context.Context, count int, audience string) []swarfstore.RevocationRecord {
	t.Helper()
	streamCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	var records []swarfstore.RevocationRecord
	for fh, err := range n.swarf.Stream(streamCtx, time.Time{}) {
		require.NoError(t, err, "reading the revocation firehose")
		record, err := n.swarf.Get(streamCtx, fh.Revoke)
		require.NoError(t, err, "fetching revocation record")
		if len(record.Path) == 0 || record.Path[len(record.Path)-1].Audience().String() != audience {
			continue
		}
		records = append(records, record)
		if len(records) == count {
			break
		}
	}
	require.Len(t, records, count, "expected %d revocations for %s on the firehose", count, audience)
	return records
}

// principalEventCauses returns the causes of every principal revocation for
// the given principal already on the firehose. Callers take it just before the
// write whose event they expect and pass it to awaitPrincipalEvents, so an
// earlier event for the same principal (a policy create publishes one too) is
// not mistaken for the new one. The firehose is the clock here rather than the
// test host: records carry the Postgres container's time, and the Docker VM's
// clock drifts from the host's by up to a second, which is more than the gap
// between two consecutive writes. Swarf emits a stored record within its
// one-second poll, so a three-second read sees everything published before
// the call.
func (n *forgeNet) principalEventCauses(t *testing.T, ctx context.Context, principal string) map[cid.Cid]struct{} {
	t.Helper()
	streamCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	seen := map[cid.Cid]struct{}{}
	for event, err := range n.swarf.StreamEvents(streamCtx, time.Time{}) {
		if err != nil {
			break // the deadline ends the read; anything else surfaces on the next stream
		}
		if event.PrincipalRevocation != nil && event.PrincipalRevocation.Principal == principal {
			seen[event.PrincipalRevocation.Cause] = struct{}{}
		}
	}
	return seen
}

// awaitPrincipalEvents reads the firehose from the beginning and returns the
// first count principal events naming the given principal whose cause is not
// in exclude (see principalEventCauses), failing the test if they do not
// arrive in time. Like the revocation firehose it is stack-global, and a
// principal id unique to the calling scenario is what separates one subtest's
// events from another's.
func (n *forgeNet) awaitPrincipalEvents(t *testing.T, ctx context.Context, exclude map[cid.Cid]struct{}, count int, principal string) []swarfapi.FirehosePrincipalRevocation {
	t.Helper()
	streamCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	var events []swarfapi.FirehosePrincipalRevocation
	for event, err := range n.swarf.StreamEvents(streamCtx, time.Time{}) {
		require.NoError(t, err, "reading the firehose")
		if event.PrincipalRevocation == nil || event.PrincipalRevocation.Principal != principal {
			continue
		}
		if _, known := exclude[event.PrincipalRevocation.Cause]; known {
			continue
		}
		events = append(events, *event.PrincipalRevocation)
		if len(events) == count {
			break
		}
	}
	require.Len(t, events, count, "expected %d principal events for %s on the firehose", count, principal)
	return events
}

// console drives hilt's partner-facing REST management API using the real
// management client, authenticating with smelt's partner key.
type console struct {
	client *management.Client
}

// ProvisionTenant creates (or returns the existing) tenant for the given
// external id and region.
func (c *console) ProvisionTenant(ctx context.Context, tenantID, region string) (api.Tenant, error) {
	return c.client.ProvisionTenant(ctx, tenantID, api.ProvisionTenantRequest{Region: region})
}

// CreateAccessKey creates an S3 access key and returns it, including the
// one-time secret access key. Without a principal it is a service key carrying
// the permissions in the request, scoped to the buckets it names (with none,
// tenant-wide powerline access). With PrincipalID it is bound to that
// principal, takes no permissions or buckets, and is issued no delegation.
func (c *console) CreateAccessKey(ctx context.Context, tenantID string, req api.CreateAccessKeyRequest) (api.CreatedAccessKey, error) {
	return c.client.CreateAccessKey(ctx, tenantID, req)
}

// DeleteAccessKey revokes and removes an access key.
func (c *console) DeleteAccessKey(ctx context.Context, tenantID, accessKeyID string) error {
	return c.client.DeleteAccessKey(ctx, tenantID, accessKeyID)
}

// GetAccessKey returns a single access key.
func (c *console) GetAccessKey(ctx context.Context, tenantID, accessKeyID string) (api.AccessKey, error) {
	return c.client.GetAccessKey(ctx, tenantID, accessKeyID)
}

// CreatePrincipal records a console user of the tenant. A principal holds no
// key material and no delegation: its access comes from the bucket policies
// naming it.
func (c *console) CreatePrincipal(ctx context.Context, tenantID, userID string) (api.Principal, error) {
	return c.client.CreatePrincipal(ctx, tenantID, userID)
}

// DeletePrincipal removes the principal, its access keys and its place in
// every policy of the tenant.
func (c *console) DeletePrincipal(ctx context.Context, tenantID, userID string) error {
	return c.client.DeletePrincipal(ctx, tenantID, userID)
}

// ListPrincipalAccessKeys returns the keys bound to the principal.
func (c *console) ListPrincipalAccessKeys(ctx context.Context, tenantID, userID string) ([]api.AccessKey, error) {
	return c.client.ListPrincipalAccessKeys(ctx, tenantID, userID)
}

// CreateBucketPolicy writes a bucket's first policy and returns its ETag.
func (c *console) CreateBucketPolicy(ctx context.Context, tenantID, bucket string, doc api.BucketPolicy) (string, error) {
	return c.client.CreateBucketPolicy(ctx, tenantID, bucket, doc)
}

// ReplaceBucketPolicy replaces a bucket's policy, conditioned on etag, and
// returns the new one.
func (c *console) ReplaceBucketPolicy(ctx context.Context, tenantID, bucket string, doc api.BucketPolicy, etag string) (string, error) {
	return c.client.ReplaceBucketPolicy(ctx, tenantID, bucket, doc, etag)
}

// GetBucketPolicy reads a bucket's policy and the ETag its next write
// conditions on.
func (c *console) GetBucketPolicy(ctx context.Context, tenantID, bucket string) (api.BucketPolicy, string, error) {
	return c.client.GetBucketPolicy(ctx, tenantID, bucket)
}

// DeleteBucketPolicy removes a bucket's policy, conditioned on etag. Every
// principal it named loses its access to the bucket.
func (c *console) DeleteBucketPolicy(ctx context.Context, tenantID, bucket, etag string) error {
	return c.client.DeleteBucketPolicy(ctx, tenantID, bucket, etag)
}

// ListPrincipalPolicies lists every policy of the tenant naming the principal.
func (c *console) ListPrincipalPolicies(ctx context.Context, tenantID, userID string) ([]api.PrincipalPolicy, error) {
	return c.client.ListPrincipalPolicies(ctx, tenantID, userID)
}

// GetPrincipalAccess returns the principal's effective actions per bucket.
func (c *console) GetPrincipalAccess(ctx context.Context, tenantID, userID string) ([]api.BucketAccess, error) {
	return c.client.GetPrincipalAccess(ctx, tenantID, userID)
}

// waitHTTPOK polls url until it returns 2xx or the timeout elapses.
func waitHTTPOK(t *testing.T, url string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 5 * time.Second}
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("%s not healthy after %s", url, timeout)
}
