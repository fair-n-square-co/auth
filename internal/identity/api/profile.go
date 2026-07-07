package api

import (
	"context"
	"errors"
	"net/http"

	"connectrpc.com/connect"

	authxerrorspb "github.com/fair-n-square-co/apis/gen/pkg/fairnsquare/errors/authx/v1alpha1"
	authxpb "github.com/fair-n-square-co/apis/gen/pkg/fairnsquare/service/authx/v1alpha1"
	"github.com/fair-n-square-co/apis/gen/pkg/fairnsquare/service/authx/v1alpha1/authxpbconnect"

	"github.com/fair-n-square-co/auth/internal/identity/service"
	"github.com/fair-n-square-co/auth/internal/oidc"
)

// ProfileService is the slice of the profile service the handler depends on.
//
//go:generate go run go.uber.org/mock/mockgen -destination=mocks/profile.go -package=mocks . ProfileService
type ProfileService interface {
	GetProfile(ctx context.Context, identity oidc.TokenIdentity) (service.Profile, error)
	UpdateProfile(ctx context.Context, identity oidc.TokenIdentity, in service.ProfileInput) (service.Profile, error)
}

// ProfileServer implements the connect ProfileService handler: the user-facing
// CRUD over the caller's own profile on the canonical user record.
//
// TRUST BOUNDARY (ADR-4 "Zero trust between services"): as with IdentityServer,
// the caller's identity (issuer + subject) comes solely from the WorkOS access
// token in the `Authorization: Bearer` header via the Verifier — never from a
// request field. Every RPC therefore operates on the caller's OWN record; the
// body carries only the attributes being read or written.
//
// Current gap: the Verifier only decodes the token without checking its
// signature (see IdentityServer), so the service must be reachable only by
// trusted callers until JWKS verification lands.
type ProfileServer struct {
	authxpbconnect.UnimplementedProfileServiceHandler
	svc      ProfileService
	verifier oidc.Verifier
}

// NewProfileServer constructs a ProfileServer backed by svc, using verifier to
// authenticate the caller's access token.
func NewProfileServer(svc ProfileService, verifier oidc.Verifier) *ProfileServer {
	return &ProfileServer{svc: svc, verifier: verifier}
}

// GetProfile returns the caller's own profile, identified by the access token.
func (s *ProfileServer) GetProfile(
	ctx context.Context,
	req *connect.Request[authxpb.GetProfileRequest],
) (*connect.Response[authxpb.GetProfileResponse], error) {
	identity, err := s.identify(ctx, req.Header())
	if err != nil {
		return nil, err
	}

	profile, err := s.svc.GetProfile(ctx, identity)
	if err != nil {
		return nil, profileError(err)
	}

	return connect.NewResponse(&authxpb.GetProfileResponse{
		Profile: toProtoProfile(profile),
	}), nil
}

// UpdateProfile replaces the caller's mutable profile attributes and returns the
// persisted result. Identity comes from the token; the body carries the desired
// state (full-replace).
func (s *ProfileServer) UpdateProfile(
	ctx context.Context,
	req *connect.Request[authxpb.UpdateProfileRequest],
) (*connect.Response[authxpb.UpdateProfileResponse], error) {
	identity, err := s.identify(ctx, req.Header())
	if err != nil {
		return nil, err
	}

	prefs := req.Msg.GetPreferences()
	in := service.ProfileInput{
		Username:          req.Msg.GetUsername(),
		DisplayName:       req.Msg.GetDisplayName(),
		Email:             req.Msg.GetEmail(),
		PreferredCurrency: prefs.GetPreferredCurrency(),
		Locale:            prefs.GetLocale(),
		Timezone:          prefs.GetTimezone(),
	}

	profile, err := s.svc.UpdateProfile(ctx, identity, in)
	if err != nil {
		return nil, profileError(err)
	}

	return connect.NewResponse(&authxpb.UpdateProfileResponse{
		Profile: toProtoProfile(profile),
	}), nil
}

// identify extracts and verifies the caller's identity from the Authorization
// header, returning a CodeUnauthenticated error when the token is missing or
// invalid.
func (s *ProfileServer) identify(ctx context.Context, header http.Header) (oidc.TokenIdentity, error) {
	token, err := bearerToken(header)
	if err != nil {
		return oidc.TokenIdentity{}, connect.NewError(connect.CodeUnauthenticated, err)
	}
	identity, err := s.verifier.Verify(ctx, token)
	if err != nil {
		return oidc.TokenIdentity{}, connect.NewError(connect.CodeUnauthenticated, err)
	}
	return identity, nil
}

// profileError maps a profile service error to the appropriate connect code and,
// for client-fault cases, attaches a typed ErrorDetail (machine-readable reason
// + offending field) the client can branch on. The full cause is passed to
// connect.NewError so the logging interceptor records it; the sanitizer replaces
// the message on server faults but leaves client-fault codes and their details
// intact.
//
// Specific validation sentinels are matched before the ErrInvalidProfile
// umbrella they wrap, so each maps to its precise reason/field.
func profileError(err error) error {
	const (
		usernameTaken   = authxerrorspb.ErrorReason_ERROR_REASON_PROFILE_USERNAME_TAKEN
		emailTaken      = authxerrorspb.ErrorReason_ERROR_REASON_PROFILE_EMAIL_TAKEN
		invalidTimezone = authxerrorspb.ErrorReason_ERROR_REASON_PROFILE_INVALID_TIMEZONE
	)

	switch {
	case errors.Is(err, service.ErrUsernameAlreadyTaken), errors.Is(err, service.ErrUsernameReserved):
		// Taken and reserved are the same to the caller: the username is
		// unavailable. Same code and reason so they're indistinguishable.
		return authxError(connect.CodeAlreadyExists, usernameTaken, "username", "username is not available", err)
	case errors.Is(err, service.ErrEmailAlreadyLinked):
		return authxError(connect.CodeAlreadyExists, emailTaken, "email", "email is already in use", err)
	case errors.Is(err, service.ErrInvalidTimezone):
		return authxError(connect.CodeInvalidArgument, invalidTimezone, "timezone", "timezone is not a valid IANA name", err)
	case errors.Is(err, service.ErrInvalidProfile):
		// Umbrella for the malformed-field cases protovalidate normally rejects at
		// the wire (and the blank-identity guard): a client fault with no distinct
		// reason or single offending field.
		return authxError(connect.CodeInvalidArgument, authxerrorspb.ErrorReason_ERROR_REASON_UNSPECIFIED, "", "invalid profile", err)
	case errors.Is(err, service.ErrUserNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}

// authxError builds a connect error carrying a typed ErrorDetail (reason, the
// offending field, and a client-safe message). cause is retained for logging;
// the detail is what clients read to branch on the reason, highlight the field,
// or show the message.
func authxError(code connect.Code, reason authxerrorspb.ErrorReason, field, message string, cause error) error {
	e := connect.NewError(code, cause)
	if detail, derr := connect.NewErrorDetail(&authxerrorspb.ErrorDetail{
		Reason:  reason,
		Field:   field,
		Message: message,
	}); derr == nil {
		e.AddDetail(detail)
	}
	return e
}

// toProtoProfile maps a service Profile into its protobuf representation.
func toProtoProfile(p service.Profile) *authxpb.Profile {
	return &authxpb.Profile{
		UserId:      p.UserID,
		Username:    p.Username,
		DisplayName: p.DisplayName,
		Email:       p.Email,
		Preferences: &authxpb.Preferences{
			PreferredCurrency: p.PreferredCurrency,
			Locale:            p.Locale,
			Timezone:          p.Timezone,
		},
	}
}
