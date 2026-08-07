package integration

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fil-forge/libforge/identity"
	swarfclient "github.com/fil-forge/swarf/pkg/client"
	swarfconfig "github.com/fil-forge/swarf/pkg/config"
	swarffx "github.com/fil-forge/swarf/pkg/fx"
	swarfstore "github.com/fil-forge/swarf/pkg/store"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/ipfs/go-cid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
)

// swarfService is a real Swarf revocation service running in-process over its
// memory store — not a mock, so the revocations Hilt publishes are checked by the
// service's own path-witness verification and can be read back through its API.
// Its did:plc resolver is pointed at the mock PLC directory, which is how it
// verifies the tenant-signed revocations and the delegations they witness.
type swarfService struct {
	DID    did.DID
	URL    string
	client *swarfclient.Client
}

// startSwarf boots Swarf on a kernel-assigned port, writing its identity key to
// dir and resolving did:plc through plcDirectory. Torn down via t.Cleanup.
func startSwarf(t *testing.T, dir, plcDirectory string) *swarfService {
	t.Helper()

	// Swarf runs from a key file so its DID is known before boot — Hilt's
	// revocation.service_id must match it. Ephemeral per-test key; never logged.
	signer, err := ed25519.Generate()
	require.NoError(t, err)
	pemBytes, err := identity.EncodeSignerToPEM(signer)
	require.NoError(t, err)
	keyFile := filepath.Join(dir, "swarf.pem")
	require.NoError(t, os.WriteFile(keyFile, pemBytes, 0o600))

	// Port 0 lets the kernel assign a free port, avoiding the race in picking one
	// ourselves. Swarf binds its listener while starting up (only serving is
	// backgrounded), so the assigned port is readable from the echo server as soon
	// as startup returns.
	var server *echo.Echo
	app := fxtest.New(t, swarffx.AppModule(&swarfconfig.Config{
		Identity: swarfconfig.IdentityConfig{KeyFile: keyFile},
		Server:   swarfconfig.ServerConfig{Host: "127.0.0.1", Port: 0},
		PLC:      swarfconfig.PLCConfig{Directory: plcDirectory},
		Storage:  swarfconfig.StorageConfig{Type: swarfconfig.StorageTypeMemory},
		Log:      swarfconfig.LogConfig{Level: "error"},
	}), fx.Populate(&server), fx.NopLogger)
	app.RequireStart()
	t.Cleanup(app.RequireStop)

	addr := server.ListenerAddr()
	require.NotNil(t, addr, "swarf did not bind a listener")
	baseURL := "http://" + addr.String()
	u, err := url.Parse(baseURL)
	require.NoError(t, err)
	serviceDID := signer.KeyDID()
	client, err := swarfclient.New(serviceDID, *u)
	require.NoError(t, err)

	return &swarfService{DID: serviceDID, URL: baseURL, client: client}
}

// revocation returns the stored revocation record for a delegation.
func (s *swarfService) revocation(ctx context.Context, delegation cid.Cid) (swarfstore.RevocationRecord, error) {
	return s.client.Get(ctx, delegation)
}

// awaitRevocations reads the revocation firehose from the beginning and returns the
// first count records, failing the test if they do not arrive in time.
func (s *swarfService) awaitRevocations(t *testing.T, ctx context.Context, count int) []cid.Cid {
	t.Helper()
	streamCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var revoked []cid.Cid
	for record, err := range s.client.Stream(streamCtx, time.Time{}) {
		require.NoError(t, err, "reading the revocation firehose")
		revoked = append(revoked, record.Revoke)
		if len(revoked) == count {
			break
		}
	}
	require.Len(t, revoked, count, "expected %d revocations on the firehose", count)
	return revoked
}
