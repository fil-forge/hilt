-- +goose Up
-- +goose StatementBegin
-- wrap_key is the per-tenant X25519 wrap-key registry. Each row is one version
-- of a tenant's FEE recipient wrap key. The private half never lives here: it is
-- sealed in the vault and referenced by vault_key. Archived rows are retained
-- indefinitely (archive-don't-destroy) so historic envelopes stay unwrappable.
CREATE TABLE wrap_key (
    tenant_id   TEXT        NOT NULL,           -- tenant DID (did:plc)
    version     INTEGER     NOT NULL,           -- 1-based; increments on rotation
    kid         TEXT        NOT NULL,           -- DID URL, e.g. did:plc:abc#wrap-1
    public_key  TEXT        NOT NULL,           -- multibase X25519 public key
    status      TEXT        NOT NULL,           -- active, archived
    epoch       INTEGER     NOT NULL DEFAULT 0, -- at-rest protection epoch (Tier-0 groundwork)
    vault_key   TEXT        NOT NULL,           -- vault path of the sealed private half
    created_at  TIMESTAMPTZ NOT NULL,
    archived_at TIMESTAMPTZ,                    -- NULL while active
    PRIMARY KEY (tenant_id, version)
);

-- At most one active wrap key per tenant.
CREATE UNIQUE INDEX wrap_key_one_active ON wrap_key (tenant_id) WHERE status = 'active';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS wrap_key;
-- +goose StatementEnd
