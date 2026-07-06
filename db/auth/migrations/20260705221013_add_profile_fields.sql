-- Profile fields on the canonical user record. These are the mutable,
-- user-facing attributes that ProfileService reads/updates; they live on the
-- same row as the identity link (a true 1:1 with the user) rather than a
-- separate table. `username` is a unique discovery handle used to find other
-- users on the platform; `updated_at` tracks profile mutations.

-- +goose Up
-- +goose StatementBegin
ALTER TABLE "user"
  ADD COLUMN username           citext,
  ADD COLUMN display_name       text,
  ADD COLUMN preferred_currency text,
  ADD COLUMN locale             text,
  ADD COLUMN timezone           text,
  ADD COLUMN updated_at         timestamptz NOT NULL DEFAULT now();

-- Named so the repository can map a unique violation to a clean AlreadyExists,
-- mirroring user_email_key. Partial: existing rows have a NULL username until
-- the user picks one, and multiple NULLs must not collide.
CREATE UNIQUE INDEX user_username_key ON "user" (username) WHERE username IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS user_username_key;
ALTER TABLE "user"
  DROP COLUMN IF EXISTS username,
  DROP COLUMN IF EXISTS display_name,
  DROP COLUMN IF EXISTS preferred_currency,
  DROP COLUMN IF EXISTS locale,
  DROP COLUMN IF EXISTS timezone,
  DROP COLUMN IF EXISTS updated_at;
-- +goose StatementEnd
