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
	swarfclient "github.com/fil-forge/swarf/pkg/client"
	swarfstore "github.com/fil-forge/swarf/pkg/store"
	"github.com/fil-forge/ucantone/did"
	"github.com/stretchr/testify/require"
)

// forgeRegion must match the provider region hilt's post_start hook in smelt
// registers ingot under (INGOT_REGION) — tenants are provisioned per region.
const forgeRegion = "us-west-1"

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
	t.Run("WriteLockBlocksWrites", func(t *testing.T) { testWriteLockBlocksWrites(t, net) })
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

// SetTenantStatus moves the tenant to the given status (active, write-locked
// or disabled).
func (c *console) SetTenantStatus(ctx context.Context, tenantID string, status api.TenantStatus) error {
	return c.client.UpdateTenantStatus(ctx, tenantID, status)
}

// CreateAccessKey creates an S3 access key with the given permissions and
// returns it, including the one-time secret access key. Naming buckets
// scopes the key's delegations to them; with none it gets tenant-wide
// (powerline) access.
func (c *console) CreateAccessKey(ctx context.Context, tenantID, name string, perms, buckets []string) (api.CreatedAccessKey, error) {
	return c.client.CreateAccessKey(ctx, tenantID, api.CreateAccessKeyRequest{
		Name:        name,
		Permissions: perms,
		Buckets:     buckets,
	})
}

// DeleteAccessKey revokes and removes an access key.
func (c *console) DeleteAccessKey(ctx context.Context, tenantID, accessKeyID string) error {
	return c.client.DeleteAccessKey(ctx, tenantID, accessKeyID)
}

// GetAccessKey returns a single access key.
func (c *console) GetAccessKey(ctx context.Context, tenantID, accessKeyID string) (api.AccessKey, error) {
	return c.client.GetAccessKey(ctx, tenantID, accessKeyID)
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
