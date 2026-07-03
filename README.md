# auth — Fair N Square Auth (Authx) Service

Go service that owns the **canonical user record** and **JIT provisioning**. WorkOS AuthKit
is the authentication source; this service keeps the stable internal `user` record and treats the
OIDC provider as swappable (ADR-4). Layout and conventions mirror the `core` service.

It exposes a connectRPC `IdentityService.ResolveUser` RPC. The BFF calls it with the caller's WorkOS
access token in the `Authorization: Bearer` metadata and the user's `email` in the request body. The
service derives the identity key (`iss`/`sub`) from the token — **not** from the body (ADR-4 "Zero trust
between services") — while `email`, a non-identity attribute kept off the token to avoid PII, is taken
from the body. On first login it JIT-provisions the canonical user, resolving the same internal id
idempotently thereafter.

Token *signature* verification (JWKS) is out of scope here and is a follow-up: for now the service
**decodes** the token without checking its signature, so it must be reachable only by trusted callers
(network isolation / mTLS) until then.

## Layout

```text
cmd/auth/            entrypoint + config (embedded YAML + AUTH_-prefixed env via viper)
db/auth/             goose migrations + sqlc queries (user)
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
