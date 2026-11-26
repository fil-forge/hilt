-- +goose Up
-- +goose StatementBegin
-- The revocations still to publish: one row per delegation that was taken out
-- of the delegation table and whose revocation the revocation service has not
-- been sent yet. A row is deleted once its revocation is published, or once
-- the delegation has expired and needs none.
CREATE TABLE revocation_owed (
    id          TEXT        PRIMARY KEY, -- CID of the delegation to revoke
    tenant_id   TEXT        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE, -- DID; the delegation's issuer, which signs the revocation
    data        BYTEA       NOT NULL, -- the encoded delegation
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- A tenant's rows, oldest first.
CREATE INDEX revocation_owed_tenant_recorded_idx ON revocation_owed (tenant_id, recorded_at, id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS revocation_owed;
-- +goose StatementEnd
