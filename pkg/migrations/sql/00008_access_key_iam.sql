-- +goose Up
-- +goose StatementBegin
-- A key with no principal is a service key, authorized from its own
-- permissions and buckets. A key with one carries no authority of its own and
-- is authorized from the bucket policies, so it holds neither. Existing rows
-- have no principal and need no backfill.
ALTER TABLE access_key
    ADD COLUMN principal TEXT,                            -- console userId
    ADD CONSTRAINT access_key_principal_fkey
        FOREIGN KEY (tenant_id, principal) REFERENCES principal(tenant_id, external_id) ON DELETE RESTRICT,
    ADD CONSTRAINT access_key_principal_unscoped
        CHECK (principal IS NULL OR (permissions = '{}' AND COALESCE(buckets, '{}') = '{}'));

-- A service key's name stays unique within the tenant; a principal-bound key's
-- name is unique within its principal. access_key_tenant_id_name_key is the
-- name Postgres generated for the original UNIQUE (tenant_id, name).
ALTER TABLE access_key DROP CONSTRAINT access_key_tenant_id_name_key;
CREATE UNIQUE INDEX access_key_service_name_idx ON access_key (tenant_id, name)
    WHERE principal IS NULL;
CREATE UNIQUE INDEX access_key_principal_name_idx ON access_key (tenant_id, principal, name)
    WHERE principal IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS access_key_principal_name_idx;
DROP INDEX IF EXISTS access_key_service_name_idx;
-- The pre-IAM schema holds at most one key per (tenant_id, name), so two
-- principal-bound keys of one tenant sharing a name cannot be represented.
-- Refuse with the colliding pairs rather than a bare duplicate-key error:
-- renaming or deleting a tenant's keys would not be a rollback.
DO $$
DECLARE
    collisions TEXT;
BEGIN
    SELECT string_agg(format('(%s, %s)', tenant_id, name), ', ')
        INTO collisions
        FROM (
            SELECT tenant_id, name
            FROM access_key
            GROUP BY tenant_id, name
            HAVING COUNT(*) > 1
            ORDER BY tenant_id, name
        ) AS duplicates;
    IF collisions IS NOT NULL THEN
        RAISE EXCEPTION 'access_key has duplicate (tenant_id, name): %; the pre-IAM schema cannot hold two keys of one tenant with the same name', collisions;
    END IF;
END
$$;
ALTER TABLE access_key ADD CONSTRAINT access_key_tenant_id_name_key UNIQUE (tenant_id, name);
ALTER TABLE access_key
    DROP CONSTRAINT IF EXISTS access_key_principal_unscoped,
    DROP CONSTRAINT IF EXISTS access_key_principal_fkey,
    DROP COLUMN IF EXISTS principal;
-- +goose StatementEnd
