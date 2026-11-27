-- +goose Up
-- +goose StatementBegin
-- The hourly renewal pass finds the grants due for renewal, and deletes the
-- delegations that have expired, by expires_at. Delegations that never
-- expire, such as a bucket's root delegation to its tenant, are left out.
CREATE INDEX delegation_expires_at_idx ON delegation (expires_at) WHERE expires_at IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS delegation_expires_at_idx;
-- +goose StatementEnd
