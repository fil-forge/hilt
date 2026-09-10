// Package iammigrate removes the access keys that predate the tenant IAM model
// (principals, bucket policies, principal-bound keys and service credentials).
// It backs the one-shot `hilt migrate iam` command, which runs against a
// network's database before the Hilt release whose schema migration drops the
// key's permissions and buckets columns; that migration refuses to run while
// any access_key row remains.
//
// For every key the migrator publishes a revocation for each of the key's
// unexpired delegations, signed by the tenant that issued them, then deletes
// the delegations, the key's vault entry and its row. Revocations go first, so
// a revocation service failure leaves the key intact and the run retryable.
// Each key is handled independently: a failure stops the run, and a rerun
// continues with the keys that remain.
//
// The migrator refuses a database whose IAM schema migration has already run:
// every access_key row there is a service credential or a principal-bound key,
// stored under different vault paths, and removing them would break every
// tenant's traffic while leaving their keys in the vault.
package iammigrate

import (
	"context"
	"fmt"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	delegationstore "github.com/fil-forge/hilt/pkg/store/delegation"
	"github.com/fil-forge/hilt/pkg/vault"
	swarfclient "github.com/fil-forge/swarf/pkg/client"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/errors"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/validator"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// RevocationPublisher is the subset of the revocation service (Swarf) the
// migration needs. It is satisfied by [*swarfclient.Client]; the interface lets
// the migration be tested without a live revocation service.
type RevocationPublisher interface {
	// Publish submits a /ucan/revoke invocation self-signed by revoker for the
	// revoked delegation, which revoker must have issued unless a witness path is
	// supplied with [swarfclient.WithWitnessPath].
	Publish(ctx context.Context, revoker ucan.Issuer, revoked ucan.Delegation, opts ...swarfclient.PublishOption) error
}

// Report summarizes a completed run.
type Report struct {
	// Keys is the number of access keys removed.
	Keys int
	// Revocations is the number of revocations published.
	Revocations int
}

// Migrator removes pre-IAM access keys from a Postgres-backed Hilt.
type Migrator struct {
	logger      *zap.Logger
	pool        *pgxpool.Pool
	delegations delegationstore.Store
	secrets     vault.Vault
	revocations RevocationPublisher
}

// New constructs a migrator. The pool must not have had the IAM schema
// migration applied through it: the migrator reads the access_key table
// directly and needs only its id and tenant_id columns, which exist on both
// sides of that migration.
func New(
	logger *zap.Logger,
	pool *pgxpool.Pool,
	delegations delegationstore.Store,
	secrets vault.Vault,
	revocations RevocationPublisher,
) *Migrator {
	return &Migrator{
		logger:      logger,
		pool:        pool,
		delegations: delegations,
		secrets:     secrets,
		revocations: revocations,
	}
}

// SchemaMigratedErrorName is the name of [ErrSchemaMigrated].
const SchemaMigratedErrorName = "SchemaMigrated"

// ErrSchemaMigrated is returned by [Migrator.Run] when the database has already
// had the IAM schema migration applied, so there are no pre-IAM keys to remove
// and the rows that exist must not be touched.
var ErrSchemaMigrated = errors.New(SchemaMigratedErrorName, "the IAM schema migration has already run: access_key has no permissions column and holds no pre-IAM keys")

// accessKey is the part of an access_key row the migration needs.
type accessKey struct {
	id     did.DID
	tenant did.DID
}

// Run removes every access key. It returns the report of the keys removed so
// far together with the first error; the keys already removed stay removed and
// the failed key is left intact, so the run can be repeated.
func (m *Migrator) Run(ctx context.Context) (Report, error) {
	if err := m.checkSchema(ctx); err != nil {
		return Report{}, err
	}
	keys, err := m.listKeys(ctx)
	if err != nil {
		return Report{}, err
	}
	m.logger.Info("migrating access keys", zap.Int("keys", len(keys)))

	var report Report
	for _, key := range keys {
		revoked, err := m.removeKey(ctx, key)
		report.Revocations += revoked
		if err != nil {
			return report, fmt.Errorf("removing access key %s: %w", key.id, err)
		}
		report.Keys++
	}
	return report, nil
}

// checkSchema confirms the pre-IAM access_key shape by the presence of its
// permissions column, which the IAM schema migration drops.
func (m *Migrator) checkSchema(ctx context.Context) error {
	var preIAM bool
	err := m.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = current_schema()
			  AND table_name = 'access_key'
			  AND column_name = 'permissions'
		)`).Scan(&preIAM)
	if err != nil {
		return fmt.Errorf("inspecting access_key schema: %w", err)
	}
	if !preIAM {
		return ErrSchemaMigrated
	}
	return nil
}

// listKeys reads every access key's id and tenant. The query names only the
// columns the IAM schema migration keeps, so it works before and after it.
func (m *Migrator) listKeys(ctx context.Context) ([]accessKey, error) {
	rows, err := m.pool.Query(ctx, `SELECT id, tenant_id FROM access_key ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("listing access keys: %w", err)
	}
	defer rows.Close()

	var keys []accessKey
	for rows.Next() {
		var idStr, tenantStr string
		if err := rows.Scan(&idStr, &tenantStr); err != nil {
			return nil, fmt.Errorf("scanning access key: %w", err)
		}
		id, err := did.Parse(idStr)
		if err != nil {
			return nil, fmt.Errorf("parsing access key DID: %w", err)
		}
		tenant, err := did.Parse(tenantStr)
		if err != nil {
			return nil, fmt.Errorf("parsing tenant DID of access key %s: %w", id, err)
		}
		keys = append(keys, accessKey{id: id, tenant: tenant})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating access keys: %w", err)
	}
	return keys, nil
}

// removeKey publishes revocations for the key's unexpired delegations, then
// deletes its delegations, vault entry and row. It returns the number of
// revocations published, which is meaningful even when it also returns an
// error.
func (m *Migrator) removeKey(ctx context.Context, key accessKey) (int, error) {
	log := m.logger.With(zap.Stringer("tenant", key.tenant), zap.Stringer("access_key", key.id))

	revoked, err := m.revokeDelegations(ctx, log, key)
	if err != nil {
		return revoked, err
	}

	if err := m.delegations.DeleteByAudience(ctx, key.id); err != nil {
		return revoked, fmt.Errorf("deleting delegations: %w", err)
	}
	if err := m.secrets.Delete(ctx, vault.AccessKeyPath(key.tenant, key.id)); err != nil {
		return revoked, fmt.Errorf("deleting vault entry: %w", err)
	}
	if _, err := m.pool.Exec(ctx, `DELETE FROM access_key WHERE id = $1`, key.id.String()); err != nil {
		return revoked, fmt.Errorf("deleting row: %w", err)
	}
	log.Info("removed access key", zap.Int("revocations", revoked))
	return revoked, nil
}

// revokeDelegations publishes a revocation for every unexpired delegation
// issued to the key, signed by the tenant. The tenant issued them all, so no
// witness path is needed. An expired delegation is skipped: the revocation
// service rejects it and it is unusable regardless.
func (m *Migrator) revokeDelegations(ctx context.Context, log *zap.Logger, key accessKey) (int, error) {
	dels, err := store.Collect(ctx, func(ctx context.Context, opts store.PaginationConfig) (store.Page[ucan.Delegation], error) {
		var listOpts []store.PaginationOption
		if opts.Cursor != nil {
			listOpts = append(listOpts, store.WithCursor(*opts.Cursor))
		}
		return m.delegations.ListByAudience(ctx, key.id, listOpts...)
	})
	if err != nil {
		return 0, fmt.Errorf("listing delegations: %w", err)
	}

	now := ucan.UnixTimestamp(time.Now().Unix())
	var live []ucan.Delegation
	for _, d := range dels {
		if err := validator.ValidateNotExpired(d, now); err != nil {
			log.Info("skipping revocation of expired delegation", zap.Stringer("delegation", d.Link()))
			continue
		}
		live = append(live, d)
	}
	if len(live) == 0 {
		return 0, nil
	}

	issuer, err := m.tenantIssuer(ctx, key.tenant)
	if err != nil {
		return 0, err
	}
	revoked := 0
	for _, d := range live {
		if err := m.revocations.Publish(ctx, issuer, d); err != nil {
			return revoked, fmt.Errorf("publishing revocation for %s: %w", d.Link(), err)
		}
		revoked++
		log.Info("published revocation", zap.Stringer("delegation", d.Link()))
	}
	return revoked, nil
}

// tenantIssuer loads the tenant's secp256k1 signing key from the vault and
// returns an issuer that signs as the tenant.
func (m *Migrator) tenantIssuer(ctx context.Context, tenantID did.DID) (ucan.Issuer, error) {
	keyBytes, err := m.secrets.Read(ctx, vault.TenantKeyPath(tenantID))
	if err != nil {
		return nil, fmt.Errorf("reading tenant key: %w", err)
	}
	signer, err := secp256k1.Decode(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("decoding tenant key: %w", err)
	}
	return multikey.NewIssuer(tenantID, signer), nil
}
