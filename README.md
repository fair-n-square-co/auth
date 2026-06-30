# auth — Fair N Square Auth (Authx) Service

Go service that owns the **canonical user record** and **JIT provisioning** (FNS-92). WorkOS AuthKit
is the authentication source; this service keeps the stable internal `users` record and treats the
OIDC provider as swappable (ADR-4). Layout and conventions mirror the `core` service.

It exposes a connectRPC `IdentityService.ResolveUser` RPC: given verified OIDC claims (issuer,
subject, email) it returns the canonical user, JIT-provisioning one on first login and resolving the
same internal id idempotently thereafter. Token *signature* verification (JWKS) is out of scope here
and lands in FNS-95 — until then the service trusts claims already verified by the BFF and must be
reachable only by trusted callers.

## Layout

```text
cmd/auth/            entrypoint + config (embedded YAML + AUTH_-prefixed env via viper)
db/auth/             goose migrations + sqlc queries (users)
internal/
  auth/db/           pgx pool + generated sqlc (do not hand-edit sqlc/)
  identity/          domain module: api -> service -> repository
  oidc/              generic provider seam (interfaces/structs only)
    workos/          WorkOS implementation of oidc.Provider
pkg/logger/          slog setup
pkg/middleware/      connect interceptors (sanitize, logging, recovery)
pkg/pgerr/           pgx error classification (twin of core/pkg/pgerr)
```

## Develop

Common tasks are `just` recipes — `just build`, `just test`, `just test-integration` (Docker),
`just lint`, `just generate` (sqlc + mocks), `just run` (hot reload), `just docker-up`.
