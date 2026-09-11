-- +goose Up
-- +goose StatementBegin
-- principal is a console user within a tenant, identified by the console's
-- userId. A principal holds no key material and no delegations: its access is
-- computed from bucket policies at request time.
CREATE TABLE principal (
    tenant_id   TEXT        NOT NULL REFERENCES tenant(id) ON DELETE RESTRICT, -- DID (did:plc)
    external_id TEXT        NOT NULL,                                          -- console userId
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, external_id)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS principal;
-- +goose StatementEnd
