// Package repository owns data access for the identity module, wrapping the
// sqlc-generated queries and translating between database (pgtype) values and
// the plain Go types the service layer consumes.
package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/fair-n-square-co/auth/internal/identity/repository/auth/db/query"
	"github.com/fair-n-square-co/auth/pkg/pgerr"
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

// ErrUsernameTaken is returned when a profile update collides on the username —
// the handle is already in use by another user. The service maps it to a clean
// conflict rather than a 500.
var ErrUsernameTaken = errors.New("username already taken")

// The unique constraint/index names are declared in the users migrations; we map
// each to a distinct domain error so the service can tell an identity collision
// apart from an email or username already in use.
const (
	constraintIdentity = "user_identity_key"
	constraintEmail    = "user_email_key"
	constraintUsername = "user_username_key"
)

// User is the repository-level view of a users row. Identifiers are canonical
// UUID strings so layers above never depend on pgtype. The profile fields below
// are nullable columns; a NULL is surfaced as the empty string
// so callers never handle pgtype.
type User struct {
	ID      string
	Issuer  string
	Subject string
	Email   string

	// Mutable profile attributes (empty string == unset/NULL in the DB).
	Username          string
	DisplayName       string
	PreferredCurrency string
	Locale            string
	Timezone          string
}

// ProfileUpdate is the set of mutable profile attributes a UpdateProfile writes,
// addressed by the token-verified identity (Issuer, Subject). Full-replace: every
// field is written. Username and Email are required (non-empty) by the service
// before it calls here; the remaining fields are optional and an empty string is
// persisted as NULL.
type ProfileUpdate struct {
	Issuer            string
	Subject           string
	Username          string
	DisplayName       string
	Email             string
	PreferredCurrency string
	Locale            string
	Timezone          string
}

// Repository provides identity data access backed by the sqlc query layer.
type Repository struct {
	q *query.Queries
}

// New builds a Repository over any query.DBTX (e.g. a *pgxpool.Pool).
func New(db query.DBTX) *Repository {
	return &Repository{q: query.New(db)}
}

// GetByIssuerSubject returns the user linked to (issuer, subject), or ErrNotFound.
func (r *Repository) GetByIssuerSubject(ctx context.Context, issuer, subject string) (User, error) {
	row, err := r.q.GetUserByIssuerSubject(ctx, query.GetUserByIssuerSubjectParams{
		OidcIssuer:  issuer,
		OidcSubject: subject,
	})
	if err != nil {
		if errors.Is(pgerr.Classify(err), pgerr.ErrNotFound) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("get user by issuer/subject: %w", err)
	}
	return toUser(row)
}

// Create inserts a new canonical user with the given identity link. A unique
// violation on (oidc_issuer, oidc_subject) is returned as ErrConflict; a
// violation on email is returned as ErrEmailTaken.
func (r *Repository) Create(ctx context.Context, issuer, subject, email string) (User, error) {
	row, err := r.q.CreateUser(ctx, query.CreateUserParams{
		OidcIssuer:  issuer,
		OidcSubject: subject,
		Email:       email,
	})
	if err != nil {
		if errors.Is(pgerr.Classify(err), pgerr.ErrUniqueViolation) {
			switch name := pgerr.ConstraintName(err); name {
			case constraintEmail:
				return User{}, ErrEmailTaken
			case constraintIdentity:
				return User{}, ErrConflict
			default:
				// Unknown unique constraint: surface it rather than masking.
				return User{}, fmt.Errorf("create user: unexpected unique violation on %q: %w", name, err)
			}
		}
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return toUser(row)
}

// UpdateProfile writes the caller's mutable profile attributes in full,
// addressed by (issuer, subject). It returns ErrNotFound when no user matches
// that identity (an unprovisioned caller — UpdateProfile never creates a user),
// ErrUsernameTaken / ErrEmailTaken when the handle or email is already in use by
// another user. Optional fields left empty are stored as NULL.
func (r *Repository) UpdateProfile(ctx context.Context, p ProfileUpdate) (User, error) {
	row, err := r.q.UpdateUserProfile(ctx, query.UpdateUserProfileParams{
		OidcIssuer:        p.Issuer,
		OidcSubject:       p.Subject,
		Username:          toPgText(p.Username),
		DisplayName:       toPgText(p.DisplayName),
		Email:             p.Email,
		PreferredCurrency: toPgText(p.PreferredCurrency),
		Locale:            toPgText(p.Locale),
		Timezone:          toPgText(p.Timezone),
	})
	if err != nil {
		if errors.Is(pgerr.Classify(err), pgerr.ErrNotFound) {
			return User{}, ErrNotFound
		}
		if errors.Is(pgerr.Classify(err), pgerr.ErrUniqueViolation) {
			switch name := pgerr.ConstraintName(err); name {
			case constraintUsername:
				return User{}, ErrUsernameTaken
			case constraintEmail:
				return User{}, ErrEmailTaken
			default:
				return User{}, fmt.Errorf("update profile: unexpected unique violation on %q: %w", name, err)
			}
		}
		return User{}, fmt.Errorf("update profile: %w", err)
	}
	return toUser(row)
}

// toUser maps a generated sqlc row into the repository-level User, rendering the
// UUID as its canonical string and NULL profile columns as empty strings.
func toUser(row query.User) (User, error) {
	id, err := fromPgUUID(row.ID)
	if err != nil {
		return User{}, fmt.Errorf("decode user id: %w", err)
	}
	return User{
		ID:                id.String(),
		Issuer:            row.OidcIssuer,
		Subject:           row.OidcSubject,
		Email:             row.Email,
		Username:          row.Username.String,
		DisplayName:       row.DisplayName.String,
		PreferredCurrency: row.PreferredCurrency.String,
		Locale:            row.Locale.String,
		Timezone:          row.Timezone.String,
	}, nil
}

// toPgText maps a Go string to a pgtype.Text, treating the empty string as SQL
// NULL so optional profile fields round-trip as "unset" rather than "".
func toPgText(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}

// fromPgUUID converts a pgtype.UUID into a uuid.UUID. It errors rather than
// silently returning the nil UUID so bad/NULL row data surfaces as a repository
// error instead of an apparently valid user with a blank id.
func fromPgUUID(u pgtype.UUID) (uuid.UUID, error) {
	if !u.Valid {
		return uuid.Nil, errors.New("uuid is NULL or invalid")
	}
	return uuid.UUID(u.Bytes), nil
}
