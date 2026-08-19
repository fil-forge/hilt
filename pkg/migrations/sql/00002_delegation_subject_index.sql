-- +goose Up
-- +goose StatementBegin
-- ListBySubject / DeleteBySubject filter on subject alone, which the
-- audience-leading delegation_aud_sub_cmd_idx cannot serve. Including id covers
-- the keyset pagination ORDER BY.
CREATE INDEX delegation_sub_id_idx ON delegation (subject, id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS delegation_sub_id_idx;
-- +goose StatementEnd
