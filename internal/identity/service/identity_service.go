// Package service holds the identity module's business logic: the canonical
// user record and JIT (just-in-time) provisioning/linking on first login.
package service

import (
	"context"
	"errors"

	"github.com/fair-n-square-co/auth/internal/identity/repository"
	"github.com/fair-n-square-co/auth/internal/oidc"
)

// ErrInvalidClaims is returned when the incoming identity claims are missing a
// required field (issuer, subject, or email). It maps to a 4xx at the api layer.
var ErrInvalidClaims = errors.New("invalid identity claims")

// User is the service-level view of the canonical user record: our stable
// internal id plus the linked external identity.
type User struct {
	ID      string // stable internal UUID — the canonical key other services use
	Email   string
	Issuer  string
	Subject string
}

// Repository is the data-access surface the identity service depends on. It is
// an interface so the service can be unit-tested with a generated mock.
//
//go:generate go run go.uber.org/mock/mockgen -destination=mocks/repository.go -package=mocks . Repository
type Repository interface {
	// GetByIssuerSubject returns the user linked to (issuer, subject), or a
	// not-found error the service can detect.
	GetByIssuerSubject(ctx context.Context, issuer, subject string) (repository.User, error)
	// Create inserts a new canonical user with the given identity link.
	Create(ctx context.Context, issuer, subject, email string) (repository.User, error)
}

// IdentityService owns the canonical user record and JIT provisioning.
type IdentityService struct {
	repo Repository
}

// NewIdentityService constructs an IdentityService backed by repo.
func NewIdentityService(repo Repository) *IdentityService {
	return &IdentityService{repo: repo}
}

// ResolveOrProvision returns the canonical user for the given verified identity,
// creating or linking it on first login (JIT). It MUST be idempotent: the same
// claims always resolve to the same internal id.
//
// Intended algorithm (TODO(impl)):
//  1. Validate claims (issuer, subject, email non-empty) -> ErrInvalidClaims.
//  2. Look up by (issuer, subject); if found, return it.
//  3. Else Create a new canonical user.
//  4. On a UNIQUE violation from a concurrent first login, re-read by
//     (issuer, subject) so the call stays idempotent.
//
// Note: the "existing email, new subject" re-link path is intentionally out of
// scope for now (we don't need UpdateUserIdentity yet). With Google-via-WorkOS
// the `sub` is stable, so re-provisioning under a new sub is not a real case
// until we add more OIDC connections — revisit then.
func (s *IdentityService) ResolveOrProvision(ctx context.Context, claims oidc.IdentityClaims) (User, error) {
	// TODO(impl): implement the steps above.
	return User{}, errors.New("not implemented")
}
