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

  -- Constraints are named so the repository can tell which one a unique
  -- violation hit (the identity race vs. an email already linked elsewhere).
  CONSTRAINT users_identity_key UNIQUE (oidc_issuer, oidc_subject),
  CONSTRAINT users_email_key UNIQUE (email)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS users;
-- +goose StatementEnd
