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
