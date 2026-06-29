-- Canonical user record (ADR-4): keyed by a stable internal id; the external
-- OIDC identity (issuer + subject) and email only LINK to it. Storing `issuer`
-- rather than a `workos_*` column is what keeps the source swappable.

-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
  id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(), -- stable internal id
  oidc_issuer  text        NOT NULL,                              -- OIDC `iss` (provider-agnostic)
  oidc_subject text        NOT NULL,                              -- OIDC `sub`
  email        citext      NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),

  UNIQUE (oidc_issuer, oidc_subject), -- one canonical user per external identity
  UNIQUE (email)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS users;
-- +goose StatementEnd
