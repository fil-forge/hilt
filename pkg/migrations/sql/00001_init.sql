-- +goose Up
-- +goose StatementBegin
CREATE TABLE provider (
    id         TEXT        PRIMARY KEY, -- DID
    region     TEXT        UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ
);

CREATE TABLE tenant (
    id          TEXT        PRIMARY KEY, -- DID (did:plc)
    external_id TEXT        UNIQUE,      -- external Tenant API id ({tenantId})
    provider_id TEXT,                    -- DID
    name        TEXT,
    status      TEXT        NOT NULL, -- active, write-locked, disabled
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ
);

CREATE TABLE bucket (
    id         TEXT        PRIMARY KEY, -- DID
    tenant_id  TEXT,                    -- DID
    name       TEXT        UNIQUE,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE access_key (
    id          TEXT        PRIMARY KEY, -- DID
    tenant_id   TEXT,                    -- DID
    name        TEXT,
    buckets     TEXT[],
    permissions TEXT[]      NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE delegation (
    id         TEXT  PRIMARY KEY, -- CID of delegation
    issuer     TEXT  NOT NULL,    -- DID
    audience   TEXT  NOT NULL,    -- DID
    subject    TEXT,              -- DID, NULL for powerline
    command    TEXT,
    data       BYTEA NOT NULL,
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
