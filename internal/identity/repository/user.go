// Package repository owns data access for the identity module, wrapping the
// sqlc-generated queries and translating between database (pgtype) values and
// the plain Go types the service layer consumes.
package repository

import (
	"context"
	"errors"
)

// ErrNotFound is returned when a lookup matches no row. The service layer
// detects it (errors.Is) to decide whether to provision a new user.
//
// TODO(impl): map pgx.ErrNoRows to this in each query wrapper.
var ErrNotFound = errors.New("user not found")

// User is the repository-level view of a users row. Identifiers are canonical
// UUID strings so layers above never depend on pgtype.
type User struct {
	ID      string
	Issuer  string
	Subject string
	Email   string
}

// Repository provides identity data access backed by the sqlc query layer.
//
// TODO(impl): hold a *sqlc.Queries (and a *pgxpool.Pool for the BeginTx used by
// the ResolveOrProvision transaction) once sqlc code is generated from
// db/auth/queries.
type Repository struct {
	// q *sqlc.Queries
}

// New builds a Repository over any sqlc.DBTX (e.g. a *pgxpool.Pool).
//
// TODO(impl): accept sqlc.DBTX and construct sqlc.New(db), mirroring core.
func New( /* db sqlc.DBTX */ ) *Repository {
	return &Repository{}
}

// GetByIssuerSubject returns the user linked to (issuer, subject).
func (r *Repository) GetByIssuerSubject(ctx context.Context, issuer, subject string) (User, error) {
	// TODO(impl): call sqlc GetUserByIssuerSubject; translate ErrNoRows -> ErrNotFound.
	return User{}, errors.New("not implemented")
}

// Create inserts a new canonical user with the given identity link.
func (r *Repository) Create(ctx context.Context, issuer, subject, email string) (User, error) {
	// TODO(impl): call sqlc CreateUser; decode pgtype.UUID -> string.
	return User{}, errors.New("not implemented")
}
