-- +goose Up
-- +goose StatementBegin
-- updated_at is set by the database: NOW() on insert by default and NOW() in
-- every update statement, so it is always present and equals created_at until
-- the row is first updated.
ALTER TABLE provider ALTER COLUMN updated_at SET DEFAULT NOW();
UPDATE provider SET updated_at = created_at WHERE updated_at IS NULL;
ALTER TABLE provider ALTER COLUMN updated_at SET NOT NULL;

ALTER TABLE tenant ALTER COLUMN updated_at SET DEFAULT NOW();
UPDATE tenant SET updated_at = created_at WHERE updated_at IS NULL;
ALTER TABLE tenant ALTER COLUMN updated_at SET NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE tenant ALTER COLUMN updated_at DROP NOT NULL;
ALTER TABLE tenant ALTER COLUMN updated_at DROP DEFAULT;
ALTER TABLE provider ALTER COLUMN updated_at DROP NOT NULL;
ALTER TABLE provider ALTER COLUMN updated_at DROP DEFAULT;
-- +goose StatementEnd
