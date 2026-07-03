// TWIN TEST: kept in sync with core/pkg/pgerr/pgerr_test.go. Mirror any change.
package pgerr_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"

	"github.com/fair-n-square-co/auth/pkg/pgerr"
)

func TestClassify(t *testing.T) {
	cases := map[string]struct {
		in   error
		want error // sentinel we expect errors.Is to match, or nil for "unchanged"
	}{
		"nil":            {in: nil, want: nil},
		"no rows":        {in: pgx.ErrNoRows, want: pgerr.ErrNotFound},
		"unique":         {in: &pgconn.PgError{Code: "23505"}, want: pgerr.ErrUniqueViolation},
		"foreign key":    {in: &pgconn.PgError{Code: "23503"}, want: pgerr.ErrForeignKeyViolation},
		"not null":       {in: &pgconn.PgError{Code: "23502"}, want: pgerr.ErrNotNullViolation},
		"check":          {in: &pgconn.PgError{Code: "23514"}, want: pgerr.ErrCheckViolation},
		"other pg error": {in: &pgconn.PgError{Code: "42P01"}, want: nil}, // undefined_table: unchanged
		"plain error":    {in: errors.New("boom"), want: nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := pgerr.Classify(tc.in)
			if tc.want == nil {
				assert.Equal(t, tc.in, got, "unrecognized error should be returned unchanged")
				return
			}
			assert.ErrorIs(t, got, tc.want)
			// The original error is retained so callers can still inspect it.
			assert.ErrorIs(t, got, tc.in)
		})
	}
}

// TestClassify_PreservesPgErrorThroughWrapping asserts the classified error can
// still be unwrapped to *pgconn.PgError even after further fmt.Errorf wrapping,
// which is how ConstraintName recovers the constraint downstream.
func TestClassify_PreservesPgErrorThroughWrapping(t *testing.T) {
	in := &pgconn.PgError{Code: "23505", ConstraintName: "users_email_key"}
	wrapped := fmt.Errorf("create user: %w", pgerr.Classify(in))

	assert.ErrorIs(t, wrapped, pgerr.ErrUniqueViolation)
	assert.Equal(t, "users_email_key", pgerr.ConstraintName(wrapped))
}

func TestConstraintName(t *testing.T) {
	assert.Equal(t, "users_email_key", pgerr.ConstraintName(&pgconn.PgError{ConstraintName: "users_email_key"}))
	assert.Empty(t, pgerr.ConstraintName(errors.New("not a pg error")))
	assert.Empty(t, pgerr.ConstraintName(nil))
}
