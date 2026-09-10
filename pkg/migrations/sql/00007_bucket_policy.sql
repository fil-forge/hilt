-- +goose Up
-- +goose StatementBegin
-- bucket_policy holds a bucket's policy document (see pkg/bucketpolicy) with the
-- strong ETag of its canonical encoding, which PUT and DELETE compare against
-- If-Match. The row goes with the bucket.
CREATE TABLE bucket_policy (
    bucket_id  TEXT        PRIMARY KEY REFERENCES bucket(id) ON DELETE CASCADE, -- DID
    document   JSONB       NOT NULL,
    etag       TEXT        NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- An index row carries the bucket and the tenant whose principals it names, and
-- the pair has to be the bucket's own. The foreign key below says so, and needs
-- (id, tenant_id) to be a key of bucket; the primary key on id alone is not one.
ALTER TABLE bucket ADD CONSTRAINT bucket_id_tenant_key UNIQUE (id, tenant_id);

-- Which principals a policy names; '*' statements are indexed as NULL principal.
CREATE TABLE bucket_policy_principal (
    bucket_id  TEXT NOT NULL, -- DID
    tenant_id  TEXT NOT NULL, -- DID (did:plc)
    principal  TEXT,          -- console userId; NULL for '*'
    -- The bucket is the tenant's own. The store maps a violation of this key,
    -- which it tells apart by name, to an invalid-argument error.
    CONSTRAINT bucket_policy_principal_bucket_fkey FOREIGN KEY (bucket_id, tenant_id) REFERENCES bucket (id, tenant_id) ON DELETE CASCADE,
    -- A NULL principal satisfies this key without a principal row, which is what
    -- the wildcard row needs.
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
-- The unique key goes last: the index table's foreign key depends on it.
ALTER TABLE bucket DROP CONSTRAINT IF EXISTS bucket_id_tenant_key;
-- +goose StatementEnd
