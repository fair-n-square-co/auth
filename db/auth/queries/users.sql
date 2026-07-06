-- sqlc query definitions for the canonical user record. Run `just generate`
-- to (re)generate typed Go into internal/auth/db/sqlc. Mirrors core's naming
-- (CreateUser :one, GetUserBy... :one).

-- name: CreateUser :one
INSERT INTO "user" (oidc_issuer, oidc_subject, email)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetUserByIssuerSubject :one
SELECT * FROM "user"
WHERE oidc_issuer = $1 AND oidc_subject = $2;

-- name: UpdateUserProfile :one
-- Full-replace of the caller's mutable profile attributes, keyed by the
-- token-verified identity (issuer, subject). Matching no row (unprovisioned
-- caller) yields no RETURNING row, which the repository maps to ErrNotFound.
UPDATE "user"
SET username           = $3,
    display_name       = $4,
    email              = $5,
    preferred_currency = $6,
    locale             = $7,
    timezone           = $8,
    updated_at         = now()
WHERE oidc_issuer = $1 AND oidc_subject = $2
RETURNING *;
