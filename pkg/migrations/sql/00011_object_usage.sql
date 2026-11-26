-- +goose Up
-- +goose StatementBegin
-- The objects a bucket has gained and lost over its life, as of one hour, as
-- the gateway serving it reported them. Each total only grows, so a row keeps
-- the largest of each reported for its hour, and the objects the bucket held
-- at an instant are added less removed in the latest hour before it. An
-- hour in which the bucket did not change has no row.
--
-- A bucket is served by one provider for its whole life, so the provider is
-- recorded beside the row and is no part of its key.
CREATE TABLE object_usage (
    bucket_id   TEXT        NOT NULL, -- DID; no foreign key, the bucket may be deleted
    hour        TIMESTAMPTZ NOT NULL, -- start of the hour
    provider_id TEXT        NOT NULL REFERENCES provider(id) ON DELETE RESTRICT, -- DID
    tenant_id   TEXT        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE, -- DID
    added       BIGINT      NOT NULL CONSTRAINT object_usage_added_valid CHECK (added >= 0),
    removed     BIGINT      NOT NULL CONSTRAINT object_usage_removed_valid CHECK (removed >= 0),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (bucket_id, hour)
);

CREATE INDEX object_usage_tenant_idx ON object_usage (tenant_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS object_usage;
-- +goose StatementEnd
