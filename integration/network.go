// Package integration contains an end-to-end test harness that stands up a real
// Hilt in-process alongside mocks of the services it talks to — a management
// console (REST), the Ingot S3 gateway (UCAN RPC), and the Sprue upload service
// (UCAN RPC) plus a mock did:plc directory — so the REST and RPC APIs can be
// exercised together with the real AWS S3 SDK.
package integration

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/fil-forge/hilt/pkg/client"
	"github.com/fil-forge/hilt/pkg/config"
	appfx "github.com/fil-forge/hilt/pkg/fx"
	customercmds "github.com/fil-forge/libforge/commands/customer"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	s3req "github.com/fil-forge/libforge/commands/s3/request"
	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/libforge/testutil"
	ucanlib "github.com/fil-forge/libforge/ucan"
	ucanclient "github.com/fil-forge/ucantone/client"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
	"go.uber.org/zap"
)

// Region is the region the mock Ingot provider serves and tenants are created in.
const Region = "us-east-1"

// partnerKey is the pre-shared key the mock console authenticates with.
const partnerKey = "test-partner-key"

// Network is the running integration network: a real Hilt plus the mocks and the
// clients needed to drive it. All resources are torn down via t.Cleanup.
type Network struct {
	HiltURL string
	HiltDID did.DID

	IngotDID did.DID

	Admin   *client.AdminClient
	Console *Console
	Ingot   *mockIngot
	Sprue   *mockSprue
	PLC     *mockPLC
}

// Start brings up the whole network in-process and returns a ready [Network]. The
// order matters: the Sprue and PLC mocks come up first because Hilt's config points
// at them (and embeds a Sprue→Hilt delegation), then Hilt boots, then the Ingot
// (whose Hilt client needs Hilt's DID and Hilt→Ingot delegations).
func Start(t *testing.T) *Network {
	t.Helper()
	logger := zap.NewNop()
	dir := t.TempDir()

	// Identities. Hilt runs from a fixed key file so its DID is known before boot —
	// required to build the delegations Hilt (Sprue→Hilt) and the Ingot (Hilt→Ingot)
	// rely on. These are ephemeral per-test keys; never logged.
	hiltSigner, err := ed25519.Generate()
	require.NoError(t, err)
	hiltIssuer := multikey.KeyIssuer(hiltSigner)
	hiltDID := hiltIssuer.DID()

	sprueIssuer, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	sprueDID := sprueIssuer.DID()

	ingotIssuer, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	ingotDID := ingotIssuer.DID()

	// Write Hilt's identity to a PEM key file for its config.
	pemBytes, err := identity.EncodeSignerToPEM(hiltSigner)
	require.NoError(t, err)
	pemPath := filepath.Join(dir, "hilt.pem")
	require.NoError(t, os.WriteFile(pemPath, pemBytes, 0o600))

	// Hilt presents a Sprue→Hilt /customer/add delegation to Sprue during tenant
	// provisioning; encode it into the upload proofs file Hilt loads.
	custDlg, err := customercmds.Add.Delegate(sprueIssuer, hiltDID, sprueDID)
	require.NoError(t, err)
	proofsBytes, err := container.Encode(container.Raw, container.New(container.WithDelegations(custDlg)))
	require.NoError(t, err)
	proofsPath := filepath.Join(dir, "upload-proofs")
	require.NoError(t, os.WriteFile(proofsPath, proofsBytes, 0o600))

	// Mock PLC directory + mock Sprue (Sprue needs the PLC-backed resolver to verify
	// the tenant's did:plc issued /provider/add during bucket provisioning).
	plc := newMockPLC()
	t.Cleanup(plc.Close)
	sprue := newMockSprue(sprueIssuer, plc.resolver())
	t.Cleanup(sprue.Close)

	// Boot the real Hilt (memory storage + vault) on a free port.
	port := freePort(t)
	cfg := &config.Config{
		Identity: config.IdentityConfig{KeyFile: pemPath},
		Server:   config.ServerConfig{Host: "127.0.0.1", Port: port},
		Storage:  config.StorageConfig{Type: config.StorageTypeMemory},
		Vault:    config.VaultConfig{Type: config.VaultTypeMemory},
		PLC:      config.PLCConfig{Directory: plc.URL()},
		Upload: config.UploadConfig{
			ServiceID:  sprueDID.String(),
			ServiceURL: sprue.URL(),
			ProductID:  testutil.RandomDID(t).String(),
			Proofs:     proofsPath,
		},
		Auth: config.AuthConfig{PartnerKey: partnerKey},
		Log:  config.LogConfig{Level: "error"},
	}
	app := fxtest.New(t, appfx.AppModule(cfg), fx.NopLogger)
	app.RequireStart()
	t.Cleanup(app.RequireStop)

	hiltURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	waitForHealth(t, hiltURL)
	hiltU, err := url.Parse(hiltURL)
	require.NoError(t, err)

	// Admin client issues as Hilt's own identity (admin commands are self-issued).
	admin, err := client.NewAdminClient(hiltIssuer, *hiltU, logger)
	require.NoError(t, err)

	// The Ingot's Hilt client issues as the provider identity and carries the
	// Hilt→Ingot delegations the UCAN validator requires for the S3 commands.
	authDlg, err := s3req.Authorize.Delegate(hiltIssuer, ingotDID, hiltDID)
	require.NoError(t, err)
	createDlg, err := s3bkt.Create.Delegate(hiltIssuer, ingotDID, hiltDID)
	require.NoError(t, err)
	infoDlg, err := s3bkt.Info.Delegate(hiltIssuer, ingotDID, hiltDID)
	require.NoError(t, err)
	ingotProofs := ucanlib.NewContainerProofStore(container.New(container.WithDelegations(authDlg, createDlg, infoDlg)))
	hiltClient, err := client.New(hiltDID, *hiltU, ingotIssuer, client.WithBaseProofs(ingotProofs), client.WithLogger(logger))
	require.NoError(t, err)

	// The Ingot also calls Sprue directly (/blob/add on object upload), issuing as
	// the provider identity with the bucket as subject.
	sprueU, err := url.Parse(sprue.URL())
	require.NoError(t, err)
	sprueExec, err := ucanclient.NewHTTP(sprueU)
	require.NoError(t, err)

	ingot := newMockIngot(hiltClient, ingotIssuer, sprueDID, sprueExec)
	t.Cleanup(ingot.Close)

	return &Network{
		HiltURL:  hiltURL,
		HiltDID:  hiltDID,
		IngotDID: ingotDID,
		Admin:    admin,
		Console:  newConsole(t, hiltURL, partnerKey),
		Ingot:    ingot,
		Sprue:    sprue,
		PLC:      plc,
	}
}

// S3Client builds a real AWS S3 SDK client pointed at the mock Ingot, signing with
// the given access key credentials (id = the bare did:key identifier, secret = the
// multibase secret returned by CreateAccessKey).
func (n *Network) S3Client(t *testing.T, accessKeyID, secret string) *s3.Client {
	t.Helper()
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(Region),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(accessKeyID, secret, "")),
	)
	require.NoError(t, err)
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		endpoint := n.Ingot.URL()
		o.BaseEndpoint = &endpoint
		o.UsePathStyle = true
	})
}

// freePort returns a currently-free TCP port on the loopback interface.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitForHealth(t *testing.T, baseURL string) {
	t.Helper()

	httpc := &http.Client{Timeout: 250 * time.Millisecond}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := httpc.Get(baseURL + "/health")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("hilt did not become healthy at %s", baseURL)
}
