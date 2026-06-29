// Package service holds the identity module's business logic: the canonical
// user record and JIT (just-in-time) provisioning/linking on first login.
package service

import (
	"context"
	"errors"
	"fmt"

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
//go:generate go tool mockgen -destination=mocks/repository.go -package=mocks . Repository
type Repository interface {
	// GetByIssuerSubject returns the user linked to (issuer, subject), or
	// repository.ErrNotFound when none exists.
	GetByIssuerSubject(ctx context.Context, issuer, subject string) (repository.User, error)
	// Create inserts a new canonical user, returning repository.ErrConflict on a
	// concurrent unique-constraint collision.
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
// creating it on first login (JIT). It is idempotent: the same claims always
// resolve to the same internal id. The returned bool is true only when this
// call provisioned a new user.
//
// Note: the "existing email, new subject" re-link path is intentionally out of
// scope for now. With Google-via-WorkOS the `sub` is stable, so re-provisioning
// under a new sub is not a real case until we add more OIDC connections —
// revisit then.
func (s *IdentityService) ResolveOrProvision(ctx context.Context, claims oidc.IdentityClaims) (User, bool, error) {
	if err := claims.Validate(); err != nil {
		return User{}, false, fmt.Errorf("%w: %w", ErrInvalidClaims, err)
	}

	// Fast path: the user already exists.
	existing, err := s.repo.GetByIssuerSubject(ctx, claims.Issuer, claims.Subject)
	if err == nil {
		return toServiceUser(existing), false, nil
	}
	if !errors.Is(err, repository.ErrNotFound) {
		return User{}, false, err
	}

	// First login: provision the canonical user.
	created, err := s.repo.Create(ctx, claims.Issuer, claims.Subject, claims.Email)
	if err == nil {
		return toServiceUser(created), true, nil
	}
	// A concurrent first login won the race; the row now exists, so re-read it
	// and report it as not-newly-created. This keeps the call idempotent.
	if errors.Is(err, repository.ErrConflict) {
		raced, getErr := s.repo.GetByIssuerSubject(ctx, claims.Issuer, claims.Subject)
		if getErr != nil {
			return User{}, false, fmt.Errorf("re-read after create conflict: %w", getErr)
		}
		return toServiceUser(raced), false, nil
	}
	return User{}, false, err
}

// toServiceUser maps a repository user into the service-level view.
func toServiceUser(u repository.User) User {
	return User{
		ID:      u.ID,
		Email:   u.Email,
		Issuer:  u.Issuer,
		Subject: u.Subject,
	}
}
