# auth — Fair N Square Auth (Authx) Service

Go service that owns the **canonical user record** and **JIT provisioning** (FNS-92). WorkOS AuthKit
is the authentication source; this service keeps the stable internal `users` record and treats the
OIDC provider as swappable (ADR-4). Layout and conventions mirror the `core` service.

> **Status: skeleton** — structs and interfaces with `TODO(impl)` markers; no logic yet.
> This README is a placeholder to be rewritten once the service is implemented.

## Layout

```
cmd/auth/            entrypoint + config (embedded YAML + AUTH_-prefixed env via viper)
db/auth/             goose migrations + sqlc queries (users)
internal/
  auth/db/           pgx pool + generated sqlc (do not hand-edit sqlc/)
  identity/          domain module: api -> service -> repository
  oidc/              generic provider seam (interfaces/structs only)
    workos/          WorkOS implementation of oidc.Provider
pkg/logger/          slog setup
```
