package metrics_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	metricssvc "github.com/fil-forge/hilt/pkg/api/service/metrics"
	"github.com/fil-forge/hilt/pkg/client/upload"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	metricscmds "github.com/fil-forge/libforge/commands/metrics"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/binding"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// sampled records the subject of each /metrics/sample invocation the stub Sprue
// served, so a test can tell which space was asked about.
type sampled struct {
	subjects []did.DID
}

// setup wires the metrics service over memory stores against an in-process Sprue
// that serves /metrics/sample, mirroring production: one tenant whose secp256k1
// key is in the vault, owning one bucket that has issued the tenant top
// authority over itself. That root lives only in the delegation store, as
// bucket.Service.Create puts it there — the upload client's base proofs are the
// static set loaded from config and never contain it.
func setup(t *testing.T) (*metricssvc.Service, did.DID, *sampled) {
	t.Helper()
	ctx := t.Context()
	tenants, buckets := tenantmemory.New(), bucketmemory.New()
	delegations, secrets := delegationmemory.New(), vaultmemory.New()

	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	tenantID := signer.KeyDID()
	require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", tenantID, tenant.Active))
	require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), signer.Bytes()))

	bucketSigner, err := ed25519.Generate()
	require.NoError(t, err)
	bucketID := bucketSigner.KeyDID()
	require.NoError(t, buckets.Add(ctx, bucketID, tenantID, "bucket-a"))
	root, err := delegation.Delegate(
		multikey.NewIssuer(bucketID, bucketSigner), tenantID, bucketID, command.Top(), delegation.WithNoExpiration())
	require.NoError(t, err)
	require.NoError(t, delegations.PutBatch(ctx, []ucan.Delegation{root}))

	sprueSigner, err := ed25519.Generate()
	require.NoError(t, err)
	sprue := multikey.NewIssuer(sprueSigner.KeyDID(), sprueSigner)

	seen := &sampled{}
	srv := server.NewHTTP(sprue)
	srv.Handle(metricscmds.Sample.Command, metricscmds.Sample.Handler(
		func(req *binding.Request[*metricscmds.SampleArguments], res *binding.Response[*metricscmds.SampleOK]) error {
			args := req.Task().Arguments()
			seen.subjects = append(seen.subjects, req.Task().Subject())
			return res.SetSuccess(&metricscmds.SampleOK{
				From: args.From, To: args.To, Window: args.Window,
				Samples: []metricscmds.SampleItem{{
					Timestamp: args.To, BytesStored: 1024, BytesIngested: 512, UploadCount: 3,
				}},
			})
		}))

	sprueURL, err := url.Parse("http://sprue.test")
	require.NoError(t, err)
	client, err := upload.NewClient(sprue.DID(), *sprueURL, multikey.NewIssuer(tenantID, signer),
		upload.WithHTTPClient(&http.Client{Transport: srv}))
	require.NoError(t, err)

	return metricssvc.New(zap.NewNop(), tenants, buckets, secrets, client, delegations), bucketID, seen
}

// A bucket's proof chain is rooted in the delegation the bucket issued at
// creation, which lives in the delegation store. Sampling must search that
// store, not the client's static config proofs, or every tenant's metrics fail
// before the request is made.
func TestSampleUsesThePersistedProofChain(t *testing.T) {
	svc, bucketID, seen := setup(t)
	from := time.Now().Add(-2 * time.Hour).UTC()

	samples, err := svc.Bucket(t.Context(), "tenant-1", "bucket-a", from, from.Add(time.Hour), time.Hour)
	require.NoError(t, err)
	require.Len(t, samples, 1)
	require.Equal(t, uint64(1024), samples[0].BytesStored)
	require.Equal(t, uint64(3), samples[0].ObjectCount)
	require.Equal(t, []did.DID{bucketID}, seen.subjects)
}
