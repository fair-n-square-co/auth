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

// ErrEmailAlreadyLinked is returned when the email belongs to a different OIDC
// identity than the one being resolved. We do not auto-relink (out of scope for
// now), so this is a clean conflict the api layer maps to AlreadyExists.
var ErrEmailAlreadyLinked = errors.New("email already linked to another identity")

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
	// GetByIssuerSubject returns the user linked to (issuer, subject), or
	// repository.ErrNotFound when none exists.
	GetByIssuerSubject(ctx context.Context, issuer, subject string) (repository.User, error)
	// Create inserts a new canonical user. On a unique-constraint collision it
	// returns repository.ErrConflict for the (issuer, subject) identity or
	// repository.ErrEmailTaken for the email.
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
	// Normalize before lookup or persistence so a stray space can't fragment one
	// identity across two rows.
	claims = claims.Normalized()
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
	switch {
	case err == nil:
		return toServiceUser(created), true, nil
	case errors.Is(err, repository.ErrConflict), errors.Is(err, repository.ErrEmailTaken):
		// A concurrent insert collided on a unique constraint. Postgres reports only
		// one of the violated constraints and the choice is non-deterministic, so we
		// can't trust which one we were handed: an identical concurrent first login
		// can lose on the email index even though it's the *same* (issuer, subject).
		// Re-read by identity to stay idempotent — return the existing row when it's
		// ours, and only treat it as a real email conflict when no row exists for us.
		raced, getErr := s.repo.GetByIssuerSubject(ctx, claims.Issuer, claims.Subject)
		switch {
		case getErr == nil:
			return toServiceUser(raced), false, nil
		case !errors.Is(getErr, repository.ErrNotFound):
			return User{}, false, fmt.Errorf("re-read after unique conflict: %w", getErr)
		case errors.Is(err, repository.ErrEmailTaken):
			// No row for our identity: the email is linked to a different identity.
			// We don't auto-relink (out of scope), so reject cleanly rather than 500.
			return User{}, false, ErrEmailAlreadyLinked
		default:
			// Identity conflict but no row on re-read — shouldn't happen (we never
			// delete users). Surface it rather than masking.
			return User{}, false, fmt.Errorf("identity conflict but no row on re-read: %w", err)
		}
	default:
		return User{}, false, err
	}
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
