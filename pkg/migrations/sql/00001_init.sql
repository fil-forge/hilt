-- +goose Up
-- +goose StatementBegin
CREATE TABLE provider (
    id         TEXT        PRIMARY KEY, -- DID
    region     TEXT        UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ
);

CREATE TABLE tenant (
    id          TEXT        PRIMARY KEY, -- DID (did:plc)
    external_id TEXT        UNIQUE,      -- external Tenant API id ({tenantId})
    provider_id TEXT        NOT NULL REFERENCES provider(id) ON DELETE RESTRICT, -- DID
    status      TEXT        NOT NULL CONSTRAINT tenant_status_valid CHECK (status IN ('active', 'write-locked', 'disabled')), -- active, write-locked, disabled
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ
);

CREATE TABLE bucket (
    id         TEXT        PRIMARY KEY, -- DID
    tenant_id  TEXT        NOT NULL REFERENCES tenant(id) ON DELETE RESTRICT, -- DID
    name       TEXT        UNIQUE CONSTRAINT bucket_name_valid CHECK (char_length(name) BETWEEN 3 AND 63 AND name ~ '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE access_key (
    id          TEXT        PRIMARY KEY, -- DID
    tenant_id   TEXT        NOT NULL REFERENCES tenant(id) ON DELETE RESTRICT, -- DID
    name        TEXT        NOT NULL,
    buckets     TEXT[], -- bucket DIDs; NULL/empty = all buckets (powerline)
    permissions TEXT[]      NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL  DEFAULT NOW(),
    expires_at  TIMESTAMPTZ,
    UNIQUE (tenant_id, name)
);

CREATE TABLE delegation (
    id         TEXT        PRIMARY KEY, -- CID of delegation
    issuer     TEXT        NOT NULL,    -- DID
    audience   TEXT        NOT NULL,    -- DID
    subject    TEXT,                    -- DID, NULL for powerline
    command    TEXT        NOT NULL,
    data       BYTEA       NOT NULL,
    expires_at TIMESTAMPTZ
);

CREATE INDEX delegation_aud_sub_cmd_idx ON delegation (audience, subject, command);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS delegation;
DROP TABLE IF EXISTS access_key;
DROP TABLE IF EXISTS bucket;
DROP TABLE IF EXISTS tenant;
DROP TABLE IF EXISTS provider;
-- +goose StatementEnd
