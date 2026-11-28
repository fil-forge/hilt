//go:build itest

package itest

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/fil-forge/hilt/pkg/api"
	"github.com/fil-forge/hilt/pkg/s3perm"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/fil-forge/smelt/pkg/stack"
	"github.com/stretchr/testify/require"
)

// The grant timing TestGrantRenewal runs hilt with: grants last two minutes
// and are renewed in their last fifty seconds, looked for every five. The
// window is under half the lifetime, so a key holds at most two live sets.
// Production runs on the defaults (168h, 72h and 1h).
const (
	renewalLifetime = 120 * time.Second
	renewalWindow   = 50 * time.Second
	renewalInterval = 5 * time.Second
)

// TestGrantRenewal runs hilt with grants that last two minutes, on a stack of
// its own, and checks renewal end to end against the real gateway and
// revocation service, for a service key and a principal-bound key alike:
//
//   - A key keeps working after the grants it was issued have expired. The
//     gateway drops a grant from its cache when it expires, asks hilt again,
//     and reads the renewed grant from bucket info; nothing else would give
//     the request a proof chain.
//   - Deleting a key whose grants were renewed, before the first set expires,
//     revokes both sets at the revocation service.
//
// The delegation hilt issues the gateway on authorize lasts until the next
// UTC midnight, far longer than these grants, so the gateway logs that hilt's
// renewal is late on every request it takes to hilt. That is expected here.
func TestGrantRenewal(t *testing.T) {
	net := startForge(t, stack.WithServiceEnv("hilt", map[string]string{
		"HILT_GRANTS_LIFETIME":         renewalLifetime.String(),
		"HILT_GRANTS_RENEW_BEFORE":     renewalWindow.String(),
		"HILT_GRANTS_RENEWAL_INTERVAL": renewalInterval.String(),
	}))
	ctx := t.Context()

	const bucket = "renewal-bucket"
	m := newMember(t, net, "tenant-renewal", "renewer", bucket)
	putPolicy(t, ctx, m.service, bucket, allow(bucket, s3bkt.Only(m.principal), writeActions...))

	// Each kind of key reads and writes before its first grants expire, so
	// the gateway has them cached.
	keys := map[string]*s3.Client{"service": m.service, "principal-bound": m.s3}
	for kind, client := range keys {
		putAndRead(t, ctx, client, bucket, kind+"-before", []byte("written by the "+kind+" key"))
	}

	// A second key of each kind, deleted once its grants have been renewed.
	service2, err := net.console.CreateAccessKey(ctx, m.tenantID, api.CreateAccessKeyRequest{Name: "service-2", Permissions: allPermissions})
	require.NoError(t, err)
	bound2, err := net.console.CreateAccessKey(ctx, m.tenantID, api.CreateAccessKeyRequest{Name: "bound-2", PrincipalID: new(m.principal)})
	require.NoError(t, err)
	issued := time.Now()

	// Renewal starts once a grant has renewalWindow left; halfway between
	// that and the first set's expiry, both sets are live. Both keys are
	// deleted before either's revocations are awaited, while both sets are.
	sleepUntil(t, issued.Add(renewalLifetime-renewalWindow/2))
	deleted := []struct {
		kind     string
		key      api.CreatedAccessKey
		commands int
	}{
		{"service", service2, len(s3perm.CommandsFor(allPermissions...))},
		{"principal-bound", bound2, len(s3perm.CommandsFor(writeActions...))},
	}
	for _, c := range deleted {
		require.NoError(t, net.console.DeleteAccessKey(ctx, m.tenantID, c.key.AccessKeyID), "deleting the %s key", c.kind)
	}
	for _, c := range deleted {
		records := net.awaitRevocations(t, ctx, 2*c.commands, "did:key:"+c.key.AccessKeyID)
		byExpiry := map[int64]int{}
		for _, record := range records {
			revoked := record.Path[len(record.Path)-1]
			require.NotNil(t, revoked.Expiration(), "every grant expires")
			byExpiry[int64(*revoked.Expiration())]++
		}
		require.Len(t, byExpiry, 2, "the %s key's first and renewed grants are both revoked: %v", c.kind, byExpiry)
		for exp, n := range byExpiry {
			require.Equal(t, c.commands, n, "the %s key's set expiring at %d", c.kind, exp)
		}
	}

	// Past the first keys' original grants, both kinds still work.
	sleepUntil(t, issued.Add(renewalLifetime+10*time.Second))
	for kind, client := range keys {
		_, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(kind + "-before")})
		require.NoError(t, err, "the %s key reads after its first grants expired", kind)
		putAndRead(t, ctx, client, bucket, kind+"-after", []byte("written by the "+kind+" key after renewal"))
	}
}

// putAndRead writes an object with client and waits until it reads back.
func putAndRead(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string, body []byte) {
	t.Helper()
	_, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Body: strings.NewReader(string(body))})
	require.NoError(t, err, "PutObject %s/%s", bucket, key)
	awaitObject(t, ctx, client, bucket, key, body)
}

// sleepUntil waits until deadline, or fails the test if its context ends
// first.
func sleepUntil(t *testing.T, deadline time.Time) {
	t.Helper()
	t.Logf("waiting %s for the grants' clock", time.Until(deadline).Round(time.Second))
	select {
	case <-time.After(time.Until(deadline)):
	case <-t.Context().Done():
		t.Fatal("test ended while waiting")
	}
}
