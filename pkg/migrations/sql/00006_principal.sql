-- +goose Up
-- +goose StatementBegin
-- principal is a console user within a tenant, identified by the console's
-- principalId. A principal holds no key material and no delegations: its access
-- is computed from bucket policies at request time. Removal sets deleted_at
-- rather than deleting the row, so a later PUT for the same id revives it and
-- an id reused by the console never inherits anything.
CREATE TABLE principal (
    tenant_id   TEXT        NOT NULL REFERENCES tenant(id) ON DELETE RESTRICT, -- DID (did:plc)
    external_id TEXT        NOT NULL,                                          -- console principalId
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at  TIMESTAMPTZ,                                                   -- set by removal; cleared by revive
    PRIMARY KEY (tenant_id, external_id)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS principal;
-- +goose StatementEnd
