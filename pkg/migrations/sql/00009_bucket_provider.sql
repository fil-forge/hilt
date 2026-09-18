-- +goose Up
-- +goose StatementBegin
-- A bucket is served by one provider (the region its data lives in); a tenant
-- is region-free and may own buckets across providers. Move the provider
-- binding from tenant to bucket, backfilling each bucket from its owner.
ALTER TABLE bucket ADD COLUMN provider_id TEXT REFERENCES provider(id) ON DELETE RESTRICT; -- DID
UPDATE bucket SET provider_id = tenant.provider_id FROM tenant WHERE bucket.tenant_id = tenant.id;
ALTER TABLE bucket ALTER COLUMN provider_id SET NOT NULL;
ALTER TABLE tenant DROP COLUMN provider_id;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Best effort: a tenant is re-bound to the provider of its oldest bucket. A
-- tenant with no buckets has no provider to recover, so the column is left
-- nullable.
ALTER TABLE tenant ADD COLUMN provider_id TEXT REFERENCES provider(id) ON DELETE RESTRICT; -- DID
UPDATE tenant SET provider_id = (
    SELECT provider_id FROM bucket WHERE bucket.tenant_id = tenant.id ORDER BY created_at, id LIMIT 1
);
ALTER TABLE bucket DROP COLUMN provider_id;
-- +goose StatementEnd
