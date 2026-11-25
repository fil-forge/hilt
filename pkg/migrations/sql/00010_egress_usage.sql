-- +goose Up
-- +goose StatementBegin
-- Who a deleted bucket belonged to. A gateway reports a bucket's egress after
-- the fact, so counts for its last hours can arrive once the bucket row is
-- gone; this is what they are attributed to and checked against. It lasts as
-- long as the tenant does.
CREATE TABLE deleted_bucket (
    id          TEXT        PRIMARY KEY, -- DID
    tenant_id   TEXT        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE, -- DID
    provider_id TEXT        NOT NULL REFERENCES provider(id) ON DELETE RESTRICT, -- DID
    deleted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The bytes of object data a provider's gateway sent to its clients from a
-- bucket in one hour, as the gateway reported them. A report replaces the
-- count, so the row always holds the hour's latest total.
CREATE TABLE egress_usage (
    provider_id TEXT        NOT NULL REFERENCES provider(id) ON DELETE RESTRICT, -- DID
    bucket_id   TEXT        NOT NULL, -- DID; no foreign key, the bucket may be deleted
    hour        TIMESTAMPTZ NOT NULL, -- start of the hour
    tenant_id   TEXT        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE, -- DID
    bytes_sent  BIGINT      NOT NULL CONSTRAINT egress_usage_bytes_sent_valid CHECK (bytes_sent >= 0),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (provider_id, bucket_id, hour)
);

CREATE INDEX egress_usage_bucket_hour_idx ON egress_usage (bucket_id, hour);
CREATE INDEX egress_usage_tenant_hour_idx ON egress_usage (tenant_id, hour);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS egress_usage;
DROP TABLE IF EXISTS deleted_bucket;
-- +goose StatementEnd
