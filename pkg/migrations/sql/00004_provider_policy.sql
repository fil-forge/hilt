-- +goose Up
-- +goose StatementBegin
-- provider.policy is the DID of the routing policy the provider's buckets use.
-- Hilt issues the policy when the provider is registered; the upload service
-- holds the policy's candidate set (its storage nodes).
ALTER TABLE provider ADD COLUMN policy TEXT NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE provider DROP COLUMN policy;
-- +goose StatementEnd
