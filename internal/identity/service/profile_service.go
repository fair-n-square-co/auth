package service

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/fair-n-square-co/auth/internal/identity/repository"
	"github.com/fair-n-square-co/auth/internal/oidc"
)

// ErrInvalidProfile is the umbrella for a profile that fails validation; it maps
// to InvalidArgument. Most malformed-field cases (username shape, email,
// currency, display-name length) are already rejected at the wire by
// protovalidate, so the service surfaces them under this umbrella for
// defense-in-depth without a distinct client-facing reason.
var ErrInvalidProfile = errors.New("invalid profile")

// Sentinels for the two validations that DO carry a distinct client-facing
// reason: a reserved username (indistinguishable from taken to the caller) and
// an invalid timezone (the one check protovalidate cannot express). Each wraps
// ErrInvalidProfile, so errors.Is(err, ErrInvalidProfile) stays true.
var (
	ErrUsernameReserved = fmt.Errorf("%w: username is reserved", ErrInvalidProfile)
	ErrInvalidTimezone  = fmt.Errorf("%w: unknown timezone", ErrInvalidProfile)
)

// ErrUserNotFound is returned when the token-verified caller has no canonical
// user yet — a profile op was made before the first ResolveUser. Profile
// updates never provision, so this is a clean NotFound rather than a create.
var ErrUserNotFound = errors.New("user not found")

// ErrUsernameAlreadyTaken is returned when the requested username is in use by
// another user. Maps to AlreadyExists.
var ErrUsernameAlreadyTaken = errors.New("username already taken")

// usernamePattern is the normalized (already lower-cased) form: 3-30 chars of
// lowercase letters, digits, or underscore. Kept in sync with the protovalidate
// constraint on UpdateProfileRequest.username (which allows mixed case on the
// wire; we lower-case before matching).
var usernamePattern = regexp.MustCompile(`^[a-z0-9_]{3,30}$`)

// reservedUsernames are handles we refuse to hand out because they invite
// impersonation or collide with routes. Compared after normalization.
var reservedUsernames = map[string]struct{}{
	"admin": {}, "administrator": {}, "root": {}, "support": {},
	"help": {}, "api": {}, "system": {}, "fairnsquare": {}, "fns": {},
}

// Profile is the service-level view of a user's mutable profile attributes.
type Profile struct {
	UserID            string
	Username          string
	DisplayName       string
	Email             string
	PreferredCurrency string
	Locale            string
	Timezone          string
}

// ProfileInput is the caller-supplied desired profile state for an update
// (full-replace). It is normalized and validated before persistence.
type ProfileInput struct {
	Username          string
	DisplayName       string
	Email             string
	PreferredCurrency string
	Locale            string
	Timezone          string
}

// ProfileRepository is the data-access surface the profile service depends on.
// Consumer-defined so the service can be unit-tested against a generated mock.
//
//go:generate go run go.uber.org/mock/mockgen -destination=mocks/profile_repository.go -package=mocks . ProfileRepository
type ProfileRepository interface {
	// GetByIssuerSubject returns the user linked to (issuer, subject), or
	// repository.ErrNotFound when none exists.
	GetByIssuerSubject(ctx context.Context, issuer, subject string) (repository.User, error)
	// UpdateProfile writes the caller's mutable profile attributes, returning
	// repository.ErrNotFound (no such user), repository.ErrUsernameTaken, or
	// repository.ErrEmailTaken on the respective conflicts.
	UpdateProfile(ctx context.Context, p repository.ProfileUpdate) (repository.User, error)
}

// ProfileService reads and updates the mutable profile on the canonical user
// record. It never provisions — resolution/JIT is IdentityService's job.
type ProfileService struct {
	repo ProfileRepository
}

// NewProfileService constructs a ProfileService backed by repo.
func NewProfileService(repo ProfileRepository) *ProfileService {
	return &ProfileService{repo: repo}
}

// GetProfile returns the profile for the token-verified identity, or
// ErrUserNotFound when the caller has not been provisioned yet.
func (s *ProfileService) GetProfile(ctx context.Context, ident oidc.TokenIdentity) (Profile, error) {
	issuer, subject := strings.TrimSpace(ident.Issuer), strings.TrimSpace(ident.Subject)
	if issuer == "" || subject == "" {
		// The verifier should never yield a blank identity; guard anyway so a bug
		// upstream surfaces as an explicit error rather than a global lookup.
		return Profile{}, fmt.Errorf("%w: blank identity", ErrInvalidProfile)
	}

	user, err := s.repo.GetByIssuerSubject(ctx, issuer, subject)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return Profile{}, ErrUserNotFound
		}
		return Profile{}, err
	}
	return toProfile(user), nil
}

// UpdateProfile validates and writes the caller's full profile, returning the
// persisted result. Errors: ErrInvalidProfile (bad input), ErrUserNotFound
// (unprovisioned caller), ErrUsernameAlreadyTaken / ErrEmailAlreadyLinked
// (conflicts with another user).
func (s *ProfileService) UpdateProfile(ctx context.Context, ident oidc.TokenIdentity, in ProfileInput) (Profile, error) {
	issuer, subject := strings.TrimSpace(ident.Issuer), strings.TrimSpace(ident.Subject)
	if issuer == "" || subject == "" {
		return Profile{}, fmt.Errorf("%w: blank identity", ErrInvalidProfile)
	}

	norm, err := normalizeAndValidate(in)
	if err != nil {
		return Profile{}, err
	}

	user, err := s.repo.UpdateProfile(ctx, repository.ProfileUpdate{
		Issuer:            issuer,
		Subject:           subject,
		Username:          norm.Username,
		DisplayName:       norm.DisplayName,
		Email:             norm.Email,
		PreferredCurrency: norm.PreferredCurrency,
		Locale:            norm.Locale,
		Timezone:          norm.Timezone,
	})
	switch {
	case err == nil:
		return toProfile(user), nil
	case errors.Is(err, repository.ErrNotFound):
		return Profile{}, ErrUserNotFound
	case errors.Is(err, repository.ErrUsernameTaken):
		return Profile{}, ErrUsernameAlreadyTaken
	case errors.Is(err, repository.ErrEmailTaken):
		return Profile{}, ErrEmailAlreadyLinked
	default:
		return Profile{}, err
	}
}

// normalizeAndValidate trims/canonicalizes the input and enforces the business
// rules the wire-level protovalidate constraints can't (reserved handles, a
// real timezone). It mirrors those constraints so the service is safe even when
// exercised without the validating interceptor (unit tests, future callers).
func normalizeAndValidate(in ProfileInput) (ProfileInput, error) {
	out := ProfileInput{
		Username:          strings.ToLower(strings.TrimSpace(in.Username)),
		DisplayName:       strings.TrimSpace(in.DisplayName),
		Email:             strings.ToLower(strings.TrimSpace(in.Email)),
		PreferredCurrency: strings.ToUpper(strings.TrimSpace(in.PreferredCurrency)),
		Locale:            strings.TrimSpace(in.Locale),
		Timezone:          strings.TrimSpace(in.Timezone),
	}

	if !usernamePattern.MatchString(out.Username) {
		return ProfileInput{}, fmt.Errorf("%w: username must be 3-30 chars of a-z, 0-9, underscore", ErrInvalidProfile)
	}
	if _, reserved := reservedUsernames[out.Username]; reserved {
		return ProfileInput{}, fmt.Errorf("%w (%q)", ErrUsernameReserved, out.Username)
	}

	// Require a bare, parseable address (mail.ParseAddress also accepts the
	// "Name <a@b>" form, so reject anything whose address isn't the whole input).
	if addr, err := mail.ParseAddress(out.Email); err != nil || addr.Address != out.Email {
		return ProfileInput{}, fmt.Errorf("%w: invalid email", ErrInvalidProfile)
	}

	if len(out.DisplayName) > 100 {
		return ProfileInput{}, fmt.Errorf("%w: display name is too long", ErrInvalidProfile)
	}

	// Currency and timezone are optional; validate only when set.
	if out.PreferredCurrency != "" && !currencyPattern.MatchString(out.PreferredCurrency) {
		return ProfileInput{}, fmt.Errorf("%w: currency must be an ISO-4217 code", ErrInvalidProfile)
	}
	if out.Timezone != "" {
		if _, err := time.LoadLocation(out.Timezone); err != nil {
			return ProfileInput{}, fmt.Errorf("%w (%q)", ErrInvalidTimezone, out.Timezone)
		}
	}

	return out, nil
}

var currencyPattern = regexp.MustCompile(`^[A-Z]{3}$`)

// toProfile maps a repository user into the service-level Profile.
func toProfile(u repository.User) Profile {
	return Profile{
		UserID:            u.ID,
		Username:          u.Username,
		DisplayName:       u.DisplayName,
		Email:             u.Email,
		PreferredCurrency: u.PreferredCurrency,
		Locale:            u.Locale,
		Timezone:          u.Timezone,
	}
}
