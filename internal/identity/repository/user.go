// Package repository owns data access for the identity module, wrapping the
// sqlc-generated queries and translating between database (pgtype) values and
// the plain Go types the service layer consumes.
package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/fair-n-square-co/auth/internal/auth/db/sqlc"
)

// ErrNotFound is returned when a lookup matches no row. The service layer
// detects it (errors.Is) to decide whether to provision a new user.
var ErrNotFound = errors.New("user not found")

// ErrConflict is returned when an insert collides on the (issuer, subject)
// identity — e.g. a concurrent first login created the same identity first. The
// service treats it as a signal to re-read and stay idempotent.
var ErrConflict = errors.New("user identity already exists")

// ErrEmailTaken is returned when an insert collides on the email — the same
// email is already linked to a *different* OIDC identity. Distinct from
// ErrConflict so the service can reject it cleanly rather than re-reading.
var ErrEmailTaken = errors.New("email already linked to another identity")

// uniqueViolation is the Postgres SQLSTATE for unique_violation. The constraint
// names are declared in the users migration so we can tell the two apart.
const (
	uniqueViolation    = "23505"
	constraintIdentity = "users_identity_key"
	constraintEmail    = "users_email_key"
)

// User is the repository-level view of a users row. Identifiers are canonical
// UUID strings so layers above never depend on pgtype.
type User struct {
	ID      string
	Issuer  string
	Subject string
	Email   string
}

// Repository provides identity data access backed by the sqlc query layer.
type Repository struct {
	q *sqlc.Queries
}

// New builds a Repository over any sqlc.DBTX (e.g. a *pgxpool.Pool).
func New(db sqlc.DBTX) *Repository {
	return &Repository{q: sqlc.New(db)}
}

// GetByIssuerSubject returns the user linked to (issuer, subject), or ErrNotFound.
func (r *Repository) GetByIssuerSubject(ctx context.Context, issuer, subject string) (User, error) {
	row, err := r.q.GetUserByIssuerSubject(ctx, sqlc.GetUserByIssuerSubjectParams{
		OidcIssuer:  issuer,
		OidcSubject: subject,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("get user by issuer/subject: %w", err)
	}
	return toUser(row)
}

// Create inserts a new canonical user with the given identity link. A unique
// violation (concurrent insert) is returned as ErrConflict.
func (r *Repository) Create(ctx context.Context, issuer, subject, email string) (User, error) {
	row, err := r.q.CreateUser(ctx, sqlc.CreateUserParams{
		OidcIssuer:  issuer,
		OidcSubject: subject,
		Email:       email,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			switch pgErr.ConstraintName {
			case constraintEmail:
				return User{}, ErrEmailTaken
			case constraintIdentity:
				return User{}, ErrConflict
			default:
				// Unknown unique constraint: surface it rather than masking.
				return User{}, fmt.Errorf("create user: unexpected unique violation on %q: %w", pgErr.ConstraintName, err)
			}
		}
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return toUser(row)
}

// toUser maps a generated sqlc row into the repository-level User, rendering the
// UUID as its canonical string.
func toUser(row sqlc.User) (User, error) {
	id, err := fromPgUUID(row.ID)
	if err != nil {
		return User{}, fmt.Errorf("decode user id: %w", err)
	}
	return User{
		ID:      id,
		Issuer:  row.OidcIssuer,
		Subject: row.OidcSubject,
		Email:   row.Email,
	}, nil
}

// fromPgUUID renders a pgtype.UUID as its canonical string. It errors rather
// than silently emitting "" so bad/NULL row data surfaces as a repository error
// instead of an apparently valid user with a blank id.
func fromPgUUID(u pgtype.UUID) (string, error) {
	v, err := u.Value()
	if err != nil {
		return "", err
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("unexpected uuid value %T (NULL or invalid)", v)
	}
	return s, nil
}
