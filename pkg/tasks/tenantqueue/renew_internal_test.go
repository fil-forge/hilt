package tenantqueue

import (
	"testing"
	"time"

	"github.com/fil-forge/hilt/pkg/store/accesskey"
	"github.com/fil-forge/hilt/pkg/store/delegation"
	"github.com/fil-forge/libforge/testutil"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	ucandelegation "github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestWarnUnrenewed(t *testing.T) {
	tenant := testutil.RandomIssuer(t)
	key, gone := testutil.RandomDID(t), testutil.RandomDID(t)
	renewed, dropped := testutil.RandomDID(t), testutil.RandomDID(t)
	past := time.Now().Add(-time.Hour)
	keys := []accesskey.Record{{ID: key}, {ID: gone, ExpiresAt: &past}}
	due := []delegation.DueGrant{
		{Key: key, Subject: renewed},
		{Key: key, Subject: dropped},
		// An expired key is issued nothing, and that is not worth a warning.
		{Key: gone, Subject: renewed},
	}
	fresh, err := ucandelegation.Delegate(tenant, key, renewed, command.MustParse("/content/retrieve"))
	require.NoError(t, err)

	core, logs := observer.New(zap.WarnLevel)
	warnUnrenewed(zap.New(core), keys, due, []ucan.Delegation{fresh})

	warned := logs.FilterMessage("grants due for renewal were not issued again").All()
	require.Len(t, warned, 1)
	require.Equal(t, key.String(), warned[0].ContextMap()["access_key"])
	require.Equal(t, dropped.String(), warned[0].ContextMap()["subject"])
}
