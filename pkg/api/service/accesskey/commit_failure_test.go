package accesskey_test

import (
	"context"
	"errors"
	"testing"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/hilt/pkg/vault"
	"github.com/fil-forge/ucantone/did"
	"github.com/stretchr/testify/require"
)

type failedTenantCommit struct {
	tenant.Store
	failure  error
	rollback bool
	enabled  bool
}

func (s *failedTenantCommit) WithReadLock(ctx context.Context, id did.DID, fn func(context.Context, tenant.Record) error) error {
	err := s.Store.WithReadLock(ctx, id, func(locked context.Context, current tenant.Record) error {
		if err := fn(locked, current); err != nil {
			return err
		}
		if s.enabled && s.rollback {
			return s.failure
		}
		return nil
	})
	if err != nil {
		return err
	}
	if s.enabled {
		return s.failure
	} // Commit may have succeeded before its acknowledgement was lost.
	return nil
}

type insertedKeyRecorder struct {
	accesskey.Store
	last did.DID
}

func (s *insertedKeyRecorder) Add(ctx context.Context, in accesskey.Input) error {
	s.last = in.ID
	return s.Store.Add(ctx, in)
}

func TestCreateCleansUpAfterOuterCommitFailure(t *testing.T) {
	for _, postgres := range []bool{false, true} {
		t.Run(map[bool]string{false: "memory", true: "postgres"}[postgres], func(t *testing.T) {
			for _, rollback := range []bool{false, true} {
				t.Run(map[bool]string{false: "lost_commit_ack", true: "rolled_back"}[rollback], func(t *testing.T) {
					b := memoryBackend(t)
					if postgres {
						b = postgresBackend(t)
					}
					failure := errors.New("outer transaction commit unavailable")
					fence := &failedTenantCommit{Store: b.tenants, failure: failure, rollback: rollback}
					b.tenants = fence
					recorder := &insertedKeyRecorder{}
					d := setupWith(t, b, func(s accesskey.Store) accesskey.Store { recorder.Store = s; return recorder })
					control, controlSecret, err := d.svc.Create(t.Context(), "tenant-1", "acknowledged-control", []string{"s3:GetObject"}, nil, nil, nil)
					require.NoError(t, err)
					require.NotEmpty(t, controlSecret)
					controlVault, err := d.secrets.Read(t.Context(), vault.AccessKeyPath(d.tenantID, control.ID))
					require.NoError(t, err)
					fence.enabled = true
					created, secret, err := d.svc.Create(t.Context(), "tenant-1", "unacknowledged", []string{"s3:GetObject"}, nil, nil, nil)
					require.ErrorIs(t, err, failure)
					require.False(t, created.ID.Defined())
					require.Empty(t, secret)
					_, err = d.accessKeys.Get(t.Context(), recorder.last)
					require.ErrorIs(t, err, store.ErrRecordNotFound)
					_, err = d.secrets.Read(t.Context(), vault.AccessKeyPath(d.tenantID, recorder.last))
					require.ErrorIs(t, err, vault.ErrNotFound)
					page, err := d.delegations.ListByAudience(t.Context(), recorder.last)
					require.NoError(t, err)
					require.Empty(t, page.Results)
					_, err = d.accessKeys.Get(t.Context(), control.ID)
					require.NoError(t, err)
					after, err := d.secrets.Read(t.Context(), vault.AccessKeyPath(d.tenantID, control.ID))
					require.NoError(t, err)
					require.True(t, string(controlVault) == string(after), "acknowledged key material changed")
				})
			}
		})
	}
}
