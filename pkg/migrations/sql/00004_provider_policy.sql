-- +goose Up
-- +goose StatementBegin
-- provider.policy is the DID of the routing policy the provider's buckets use.
-- Hilt issues the policy when the provider is registered; the upload service
-- holds the policy's candidate set (its storage nodes). NULL means the
-- provider has no policy and its buckets use the upload service's default
-- routing.
ALTER TABLE provider ADD COLUMN policy TEXT;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE provider DROP COLUMN policy;
-- +goose StatementEnd
