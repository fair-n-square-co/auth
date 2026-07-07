package service_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/fair-n-square-co/auth/internal/identity/repository"
	"github.com/fair-n-square-co/auth/internal/identity/service"
	"github.com/fair-n-square-co/auth/internal/identity/service/mocks"
	"github.com/fair-n-square-co/auth/internal/oidc"
)

func tokenIdent() oidc.TokenIdentity {
	return oidc.TokenIdentity{Issuer: issuer, Subject: subject}
}

// storedProfile is a fully-populated user row as the repository would return it.
func storedProfile() repository.User {
	return repository.User{
		ID:                userID,
		Issuer:            issuer,
		Subject:           subject,
		Email:             email,
		Username:          "alice_01",
		DisplayName:       "Alice",
		PreferredCurrency: "AUD",
		Locale:            "en-AU",
		Timezone:          "Australia/Sydney",
	}
}

func validProfileInput() service.ProfileInput {
	return service.ProfileInput{
		Username:          "alice_01",
		DisplayName:       "Alice",
		Email:             email,
		PreferredCurrency: "AUD",
		Locale:            "en-AU",
		Timezone:          "Australia/Sydney",
	}
}

func TestGetProfile_Found(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mocks.NewMockProfileRepository(ctrl)
	repo.EXPECT().GetByIssuerSubject(gomock.Any(), issuer, subject).Return(storedProfile(), nil)

	got, err := service.NewProfileService(repo).GetProfile(context.Background(), tokenIdent())

	require.NoError(t, err)
	assert.Equal(t, service.Profile{
		UserID:            userID,
		Username:          "alice_01",
		DisplayName:       "Alice",
		Email:             email,
		PreferredCurrency: "AUD",
		Locale:            "en-AU",
		Timezone:          "Australia/Sydney",
	}, got)
}

func TestGetProfile_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mocks.NewMockProfileRepository(ctrl)
	repo.EXPECT().GetByIssuerSubject(gomock.Any(), issuer, subject).Return(repository.User{}, repository.ErrNotFound)

	_, err := service.NewProfileService(repo).GetProfile(context.Background(), tokenIdent())

	require.ErrorIs(t, err, service.ErrUserNotFound)
}

// TestUpdateProfile_NormalizesAndPersists asserts the service canonicalizes the
// input (trim, lower-case username/email, upper-case currency) before handing it
// to the repository, addressed by the token identity.
func TestUpdateProfile_NormalizesAndPersists(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := mocks.NewMockProfileRepository(ctrl)

	in := service.ProfileInput{
		Username:          "  Alice_01 ",
		DisplayName:       "  Alice  ",
		Email:             " Alice@Example.com ",
		PreferredCurrency: "aud",
		Locale:            " en-AU ",
		Timezone:          " Australia/Sydney ",
	}
	repo.EXPECT().UpdateProfile(gomock.Any(), repository.ProfileUpdate{
		Issuer:            issuer,
		Subject:           subject,
		Username:          "alice_01",
		DisplayName:       "Alice",
		Email:             email,
		PreferredCurrency: "AUD",
		Locale:            "en-AU",
		Timezone:          "Australia/Sydney",
	}).Return(storedProfile(), nil)

	got, err := service.NewProfileService(repo).UpdateProfile(context.Background(), tokenIdent(), in)

	require.NoError(t, err)
	assert.Equal(t, "alice_01", got.Username)
	assert.Equal(t, "AUD", got.PreferredCurrency)
}

// TestUpdateProfile_Invalid covers inputs the service rejects before any DB call.
func TestUpdateProfile_Invalid(t *testing.T) {
	base := validProfileInput()
	mutate := func(f func(*service.ProfileInput)) service.ProfileInput {
		in := base
		f(&in)
		return in
	}
	cases := map[string]struct {
		in   service.ProfileInput
		want error
	}{
		"username too short": {mutate(func(in *service.ProfileInput) { in.Username = "ab" }), service.ErrInvalidProfile},
		"username bad chars": {mutate(func(in *service.ProfileInput) { in.Username = "alice!" }), service.ErrInvalidProfile},
		"username reserved":  {mutate(func(in *service.ProfileInput) { in.Username = "admin" }), service.ErrUsernameReserved},
		"email malformed":    {mutate(func(in *service.ProfileInput) { in.Email = "notanemail" }), service.ErrInvalidProfile},
		"email empty":        {mutate(func(in *service.ProfileInput) { in.Email = "" }), service.ErrInvalidProfile},
		"currency bad":       {mutate(func(in *service.ProfileInput) { in.PreferredCurrency = "AUDD" }), service.ErrInvalidProfile},
		"timezone unknown":   {mutate(func(in *service.ProfileInput) { in.Timezone = "Mars/Phobos" }), service.ErrInvalidTimezone},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			repo := mocks.NewMockProfileRepository(ctrl)
			// Repository must never be touched for invalid input.

			_, err := service.NewProfileService(repo).UpdateProfile(context.Background(), tokenIdent(), tc.in)

			require.ErrorIs(t, err, tc.want)
			// The specific sentinel still satisfies the umbrella.
			require.ErrorIs(t, err, service.ErrInvalidProfile)
		})
	}
}

// TestUpdateProfile_ConflictsAndMissing maps repository conflict/not-found errors
// to the service's domain errors.
func TestUpdateProfile_ConflictsAndMissing(t *testing.T) {
	cases := map[string]struct {
		repoErr error
		want    error
	}{
		"username taken": {repository.ErrUsernameTaken, service.ErrUsernameAlreadyTaken},
		"email taken":    {repository.ErrEmailTaken, service.ErrEmailAlreadyLinked},
		"not found":      {repository.ErrNotFound, service.ErrUserNotFound},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			repo := mocks.NewMockProfileRepository(ctrl)
			repo.EXPECT().UpdateProfile(gomock.Any(), gomock.Any()).Return(repository.User{}, tc.repoErr)

			_, err := service.NewProfileService(repo).UpdateProfile(context.Background(), tokenIdent(), validProfileInput())

			require.ErrorIs(t, err, tc.want)
		})
	}
}
