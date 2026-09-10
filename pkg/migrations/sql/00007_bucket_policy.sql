-- +goose Up
-- +goose StatementBegin
-- bucket_policy holds a bucket's policy document (see pkg/policy) with the
-- strong ETag of its canonical encoding, which PUT and DELETE compare against
-- If-Match. The row goes with the bucket.
CREATE TABLE bucket_policy (
    bucket_id  TEXT        PRIMARY KEY REFERENCES bucket(id) ON DELETE CASCADE, -- DID
    document   JSONB       NOT NULL,
    etag       TEXT        NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Which principals a policy names; '*' statements are indexed as NULL principal.
CREATE TABLE bucket_policy_principal (
    bucket_id  TEXT NOT NULL REFERENCES bucket(id) ON DELETE CASCADE, -- DID
    tenant_id  TEXT NOT NULL,                                          -- DID (did:plc)
    principal  TEXT,                                                   -- console userId; NULL for '*'
    FOREIGN KEY (tenant_id, principal) REFERENCES principal(tenant_id, external_id) ON DELETE CASCADE
);
-- Postgres treats NULLs as distinct in a UNIQUE constraint, so the wildcard row gets its own index.
CREATE UNIQUE INDEX bucket_policy_principal_named_idx ON bucket_policy_principal (bucket_id, principal) WHERE principal IS NOT NULL;
CREATE UNIQUE INDEX bucket_policy_principal_wildcard_idx ON bucket_policy_principal (bucket_id) WHERE principal IS NULL;
CREATE INDEX bucket_policy_principal_idx ON bucket_policy_principal (tenant_id, principal, bucket_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS bucket_policy_principal;
DROP TABLE IF EXISTS bucket_policy;
-- +goose StatementEnd
