// Package pgerr classifies low-level Postgres/pgx errors into domain-neutral
// sentinel errors, so repository layers can recognize conditions like a unique
// violation or a missing row without each one re-deriving SQLSTATE codes or
// importing pgconn directly. The *specific* mapping (which constraint maps to
// which domain error) stays in each repository, which knows its own constraint
// names; this package only answers "what kind of database error is this".
//
// TWIN PACKAGE: this file is duplicated verbatim in the `core` and `auth` repos
// (core/pkg/pgerr, auth/pkg/pgerr). Keep the two copies identical — any change
// here must be mirrored in the other repo. We intend to merge them into a shared
// module later; until then treat the other copy as the source of truth alongside
// this one.
package pgerr

import (
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// SQLSTATE class 23 (integrity constraint violation) codes we classify.
// https://www.postgresql.org/docs/current/errcodes-appendix.html
const (
	codeUniqueViolation     = "23505"
	codeForeignKeyViolation = "23503"
	codeNotNullViolation    = "23502"
	codeCheckViolation      = "23514"
)

// Domain-neutral sentinels returned by Classify. Callers match them with
// errors.Is. The original error is always retained (joined) so callers can still
// errors.As to *pgconn.PgError — e.g. via ConstraintName — to disambiguate.
var (
	// ErrNotFound indicates a query matched no row (wraps pgx.ErrNoRows).
	ErrNotFound = errors.New("not found")
	// ErrUniqueViolation indicates an insert/update collided with a unique constraint.
	ErrUniqueViolation = errors.New("unique violation")
	// ErrForeignKeyViolation indicates a referenced row is missing.
	ErrForeignKeyViolation = errors.New("foreign key violation")
	// ErrNotNullViolation indicates a NOT NULL column was given NULL.
	ErrNotNullViolation = errors.New("not null violation")
	// ErrCheckViolation indicates a CHECK constraint failed.
	ErrCheckViolation = errors.New("check violation")
)

// Classify maps a database error to one of this package's sentinels, joined with
// the original error so callers can both errors.Is the sentinel and errors.As to
// *pgconn.PgError (e.g. to read the constraint name). Errors it does not
// recognize — including nil — are returned unchanged.
func Classify(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return errors.Join(ErrNotFound, err)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case codeUniqueViolation:
			return errors.Join(ErrUniqueViolation, err)
		case codeForeignKeyViolation:
			return errors.Join(ErrForeignKeyViolation, err)
		case codeNotNullViolation:
			return errors.Join(ErrNotNullViolation, err)
		case codeCheckViolation:
			return errors.Join(ErrCheckViolation, err)
		}
	}
	return err
}

// ConstraintName returns the Postgres constraint name attached to err (e.g.
// "user_email_key"), or "" if err carries no PgError. Use it after Classify
// reports a unique or foreign-key violation to pick a specific domain error.
func ConstraintName(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.ConstraintName
	}
	return ""
}
