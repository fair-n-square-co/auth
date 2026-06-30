package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/fair-n-square-co/auth/internal/identity/repository"
	"github.com/fair-n-square-co/auth/internal/identity/service"
	"github.com/fair-n-square-co/auth/internal/identity/service/mocks"
	"github.com/fair-n-square-co/auth/internal/oidc"
)

const (
	issuer  = "https://example.workos.com"
	subject = "user_01J0"
	email   = "alice@example.com"
	userID  = "11111111-1111-1111-1111-111111111111"
)

func validClaims() oidc.IdentityClaims {
	return oidc.IdentityClaims{Issuer: issuer, Subject: subject, Email: email}
}

func storedUser() repository.User {
	return repository.User{ID: userID, Issuer: issuer, Subject: subject, Email: email}
}

func TestResolveOrProvision_InvalidClaims(t *testing.T) {
	cases := map[string]oidc.IdentityClaims{
		"missing issuer":  {Subject: subject, Email: email},
		"missing subject": {Issuer: issuer, Email: email},
		"missing email":   {Issuer: issuer, Subject: subject},
		"blank":           {},
	}
	for name, claims := range cases {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			repo := mocks.NewMockRepository(ctrl)
			// The repository must never be touched for invalid claims.

			svc := service.NewIdentityService(repo)
			_, created, err := svc.ResolveOrProvision(context.Background(), claims)

			require.ErrorIs(t, err, service.ErrInvalidClaims)
			assert.False(t, created)
		})
	}
}

func TestResolveOrProvision_ExistingUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mocks.NewMockRepository(ctrl)

	repo.EXPECT().GetByIssuerSubject(gomock.Any(), issuer, subject).Return(storedUser(), nil)
	// No Create call expected when the user already exists.

	svc := service.NewIdentityService(repo)
	got, created, err := svc.ResolveOrProvision(context.Background(), validClaims())

	require.NoError(t, err)
	assert.False(t, created)
	assert.Equal(t, service.User{ID: userID, Email: email, Issuer: issuer, Subject: subject}, got)
}

func TestResolveOrProvision_FirstLoginCreates(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mocks.NewMockRepository(ctrl)

	repo.EXPECT().GetByIssuerSubject(gomock.Any(), issuer, subject).Return(repository.User{}, repository.ErrNotFound)
	repo.EXPECT().Create(gomock.Any(), issuer, subject, email).Return(storedUser(), nil)

	svc := service.NewIdentityService(repo)
	got, created, err := svc.ResolveOrProvision(context.Background(), validClaims())

	require.NoError(t, err)
	assert.True(t, created)
	assert.Equal(t, userID, got.ID)
}

// TestResolveOrProvision_ConcurrentRace covers the idempotency guard: a
// concurrent first login inserts the row between our lookup and our create, so
// Create returns ErrConflict and we re-read the now-existing user.
func TestResolveOrProvision_ConcurrentRace(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mocks.NewMockRepository(ctrl)

	gomock.InOrder(
		repo.EXPECT().GetByIssuerSubject(gomock.Any(), issuer, subject).Return(repository.User{}, repository.ErrNotFound),
		repo.EXPECT().Create(gomock.Any(), issuer, subject, email).Return(repository.User{}, repository.ErrConflict),
		repo.EXPECT().GetByIssuerSubject(gomock.Any(), issuer, subject).Return(storedUser(), nil),
	)

	svc := service.NewIdentityService(repo)
	got, created, err := svc.ResolveOrProvision(context.Background(), validClaims())

	require.NoError(t, err)
	assert.False(t, created, "a racing winner provisioned the user, so this call did not")
	assert.Equal(t, userID, got.ID)
}

// TestResolveOrProvision_EmailTakenByDifferentIdentity covers a first login
// whose email already belongs to a *different* identity: Create reports
// ErrEmailTaken, the re-read by (issuer, subject) finds no row of ours, so the
// service rejects cleanly with ErrEmailAlreadyLinked (mapped to AlreadyExists).
func TestResolveOrProvision_EmailTakenByDifferentIdentity(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mocks.NewMockRepository(ctrl)

	gomock.InOrder(
		repo.EXPECT().GetByIssuerSubject(gomock.Any(), issuer, subject).Return(repository.User{}, repository.ErrNotFound),
		repo.EXPECT().Create(gomock.Any(), issuer, subject, email).Return(repository.User{}, repository.ErrEmailTaken),
		// Re-read confirms the email belongs to someone else, not us.
		repo.EXPECT().GetByIssuerSubject(gomock.Any(), issuer, subject).Return(repository.User{}, repository.ErrNotFound),
	)

	svc := service.NewIdentityService(repo)
	_, created, err := svc.ResolveOrProvision(context.Background(), validClaims())

	require.ErrorIs(t, err, service.ErrEmailAlreadyLinked)
	assert.False(t, created)
}

// TestResolveOrProvision_ConcurrentRaceReportedAsEmail covers the subtle case
// where an identical concurrent first login loses the insert, violating BOTH
// unique indexes, and Postgres happens to report the email constraint. The
// service must still re-read and resolve idempotently to the racing winner
// rather than wrongly rejecting it as an email conflict.
func TestResolveOrProvision_ConcurrentRaceReportedAsEmail(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mocks.NewMockRepository(ctrl)

	gomock.InOrder(
		repo.EXPECT().GetByIssuerSubject(gomock.Any(), issuer, subject).Return(repository.User{}, repository.ErrNotFound),
		repo.EXPECT().Create(gomock.Any(), issuer, subject, email).Return(repository.User{}, repository.ErrEmailTaken),
		repo.EXPECT().GetByIssuerSubject(gomock.Any(), issuer, subject).Return(storedUser(), nil),
	)

	svc := service.NewIdentityService(repo)
	got, created, err := svc.ResolveOrProvision(context.Background(), validClaims())

	require.NoError(t, err)
	assert.False(t, created, "the racing winner provisioned the user, so this call did not")
	assert.Equal(t, userID, got.ID)
}

// TestResolveOrProvision_NormalizesClaims asserts surrounding whitespace is
// trimmed before lookup/persistence so a padded claim resolves the same identity.
func TestResolveOrProvision_NormalizesClaims(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mocks.NewMockRepository(ctrl)

	// Padded claims must reach the repository trimmed.
	repo.EXPECT().GetByIssuerSubject(gomock.Any(), issuer, subject).Return(storedUser(), nil)

	svc := service.NewIdentityService(repo)
	_, _, err := svc.ResolveOrProvision(context.Background(), oidc.IdentityClaims{
		Issuer:  "  " + issuer + "  ",
		Subject: subject + "\n",
		Email:   "  " + email,
	})

	require.NoError(t, err)
}

func TestResolveOrProvision_LookupError(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mocks.NewMockRepository(ctrl)

	wantErr := errors.New("db down")
	repo.EXPECT().GetByIssuerSubject(gomock.Any(), issuer, subject).Return(repository.User{}, wantErr)

	svc := service.NewIdentityService(repo)
	_, created, err := svc.ResolveOrProvision(context.Background(), validClaims())

	require.ErrorIs(t, err, wantErr)
	assert.False(t, created)
}

func TestResolveOrProvision_CreateError(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mocks.NewMockRepository(ctrl)

	wantErr := errors.New("insert failed")
	repo.EXPECT().GetByIssuerSubject(gomock.Any(), issuer, subject).Return(repository.User{}, repository.ErrNotFound)
	repo.EXPECT().Create(gomock.Any(), issuer, subject, email).Return(repository.User{}, wantErr)

	svc := service.NewIdentityService(repo)
	_, created, err := svc.ResolveOrProvision(context.Background(), validClaims())

	require.ErrorIs(t, err, wantErr)
	assert.False(t, created)
}
