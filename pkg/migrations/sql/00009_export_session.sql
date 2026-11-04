-- +goose Up
-- +goose StatementBegin
-- export_session is Hilt's record of a credible-exit ceremony (fil-one/RFC #24,
-- Tier 1): a customer exporting one bucket to a key they hold. Hilt owns the
-- session and the customer-facing steps (opened, pop_verified, acked,
-- released); the gateway serving the bucket reports the steps it performs
-- (pinned, manifest_built, car_ready, validated) and keeps its own pin keyed
-- by id. While a session is open (any state but released/aborted) neither the
-- tenant nor the bucket may be deleted.
--
-- States only move forward, with aborted reachable from any open state.
-- root_cid and pinned_at are set together by the pinned step: the root the
-- customer acknowledges and the export is built from.
CREATE TABLE export_session (
    id           TEXT        PRIMARY KEY,
    tenant_id    TEXT        NOT NULL REFERENCES tenant(id) ON DELETE RESTRICT, -- DID (did:plc)
    bucket_id    TEXT        NOT NULL, -- DID; no FK, so the record outlives the bucket it exported
    customer_key TEXT        NOT NULL CHECK (customer_key <> ''), -- receiving X25519 public key, multikey
    state        TEXT        NOT NULL
                 CHECK (state IN ('opened', 'pop_verified', 'pinned', 'acked', 'manifest_built',
                                  'car_ready', 'validated', 'released', 'aborted')),
    root_cid     TEXT,        -- pinned bucket root; NULL before pinned
    pinned_at    TIMESTAMPTZ, -- NULL before pinned
    audit        JSONB       NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(audit) = 'array'),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL, -- an open session past this is an abort candidate
    CHECK ((root_cid IS NULL) = (pinned_at IS NULL))
);

-- The deletion gates ask whether a tenant or a bucket has an open session.
CREATE INDEX export_session_open_tenant ON export_session (tenant_id)
    WHERE state NOT IN ('released', 'aborted');
CREATE INDEX export_session_open_bucket ON export_session (bucket_id)
    WHERE state NOT IN ('released', 'aborted');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS export_session;
-- +goose StatementEnd
