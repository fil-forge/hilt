package grant_test

import (
	"context"
	"testing"
	"time"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/libforge/testutil"

	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// deadlinePublisher records how long each publish had left on its deadline,
// zero when it had none.
type deadlinePublisher struct {
	*htestutil.FakeSwarf
	remaining []time.Duration
}

func (p *deadlinePublisher) PublishBatch(ctx context.Context, revoker ucan.Issuer, revoked []ucan.Delegation) error {
	var left time.Duration
	if deadline, ok := ctx.Deadline(); ok {
		left = time.Until(deadline)
	}
	p.remaining = append(p.remaining, left)
	return p.FakeSwarf.PublishBatch(ctx, revoker, revoked)
}

// PublishRevocations bounds its own publish, so a caller that holds a
// delegation lock with no deadline of its own still releases it at BatchTimeout.
func TestPublishRevocationsUnderBatchTimeout(t *testing.T) {
	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	tenant := multikey.NewIssuer(signer.KeyDID(), signer)
	held, err := grant.Issue(tenant, testutil.RandomDID(t), []did.DID{testutil.RandomDID(t)}, []string{"s3:GetObject"}, nil)
	require.NoError(t, err)
	require.NotEmpty(t, held)

	pub := &deadlinePublisher{FakeSwarf: &htestutil.FakeSwarf{}}
	require.NoError(t, grant.PublishRevocations(context.Background(), zap.NewNop(), pub, tenant, held))
	require.Len(t, pub.remaining, 1)
	require.Greater(t, pub.remaining[0], time.Duration(0))
	require.LessOrEqual(t, pub.remaining[0], grant.BatchTimeout)
}
