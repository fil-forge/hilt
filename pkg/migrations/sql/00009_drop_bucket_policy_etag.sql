-- +goose Up
-- +goose StatementBegin
-- Bucket policy writes are unconditional, so nothing compares against a stored
-- ETag any more.
ALTER TABLE bucket_policy DROP COLUMN etag;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- The tags a rollback restores are empty; the next write of each policy sets
-- its real tag.
ALTER TABLE bucket_policy ADD COLUMN etag TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd
