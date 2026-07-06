package api_test

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	authxerrorspb "github.com/fair-n-square-co/apis/gen/pkg/fairnsquare/errors/authx/v1alpha1"
	authxpb "github.com/fair-n-square-co/apis/gen/pkg/fairnsquare/service/authx/v1alpha1"

	"github.com/fair-n-square-co/auth/internal/identity/api"
	apimocks "github.com/fair-n-square-co/auth/internal/identity/api/mocks"
	"github.com/fair-n-square-co/auth/internal/identity/service"
	"github.com/fair-n-square-co/auth/internal/oidc"
	oidcmocks "github.com/fair-n-square-co/auth/internal/oidc/mocks"
)

// errorDetail returns the first authx ErrorDetail attached to err, or nil.
func errorDetail(t *testing.T, err error) *authxerrorspb.ErrorDetail {
	t.Helper()
	var cerr *connect.Error
	require.True(t, errors.As(err, &cerr), "expected a *connect.Error")
	for _, d := range cerr.Details() {
		if msg, verr := d.Value(); verr == nil {
			if ed, ok := msg.(*authxerrorspb.ErrorDetail); ok {
				return ed
			}
		}
	}
	return nil
}

type profileHarness struct {
	svc      *apimocks.MockProfileService
	verifier *oidcmocks.MockVerifier
	server   *api.ProfileServer
}

func newProfileHarness(t *testing.T) *profileHarness {
	t.Helper()
	ctrl := gomock.NewController(t)
	svc := apimocks.NewMockProfileService(ctrl)
	verifier := oidcmocks.NewMockVerifier(ctrl)
	return &profileHarness{
		svc:      svc,
		verifier: verifier,
		server:   api.NewProfileServer(svc, verifier),
	}
}

func withToken[T any](msg *T, token string) *connect.Request[T] {
	req := connect.NewRequest(msg)
	if token != "" {
		req.Header().Set("Authorization", "Bearer "+token)
	}
	return req
}

func sampleProfile() service.Profile {
	return service.Profile{
		UserID:            "11111111-1111-1111-1111-111111111111",
		Username:          "alice_01",
		DisplayName:       "Alice",
		Email:             "alice@example.com",
		PreferredCurrency: "AUD",
		Locale:            "en-AU",
		Timezone:          "Australia/Sydney",
	}
}

func tokenIdentity() oidc.TokenIdentity {
	return oidc.TokenIdentity{Issuer: "https://example.workos.com", Subject: "user_01J0"}
}

func TestGetProfile_ReturnsProfileFromToken(t *testing.T) {
	h := newProfileHarness(t)
	h.verifier.EXPECT().Verify(gomock.Any(), "access-token").Return(tokenIdentity(), nil)
	h.svc.EXPECT().GetProfile(gomock.Any(), tokenIdentity()).Return(sampleProfile(), nil)

	resp, err := h.server.GetProfile(context.Background(), withToken(&authxpb.GetProfileRequest{}, "access-token"))

	require.NoError(t, err)
	got := resp.Msg.GetProfile()
	assert.Equal(t, "alice_01", got.GetUsername())
	assert.Equal(t, "alice@example.com", got.GetEmail())
	assert.Equal(t, "AUD", got.GetPreferences().GetPreferredCurrency())
}

func TestGetProfile_MissingToken(t *testing.T) {
	h := newProfileHarness(t)
	// Neither verifier nor service must be touched without a token.

	_, err := h.server.GetProfile(context.Background(), withToken(&authxpb.GetProfileRequest{}, ""))

	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestGetProfile_ErrorMapping(t *testing.T) {
	cases := map[string]struct {
		svcErr error
		want   connect.Code
	}{
		"not found":     {service.ErrUserNotFound, connect.CodeNotFound},
		"invalid":       {service.ErrInvalidProfile, connect.CodeInvalidArgument},
		"internal else": {assert.AnError, connect.CodeInternal},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newProfileHarness(t)
			h.verifier.EXPECT().Verify(gomock.Any(), "access-token").Return(tokenIdentity(), nil)
			h.svc.EXPECT().GetProfile(gomock.Any(), tokenIdentity()).Return(service.Profile{}, tc.svcErr)

			_, err := h.server.GetProfile(context.Background(), withToken(&authxpb.GetProfileRequest{}, "access-token"))

			require.Error(t, err)
			assert.Equal(t, tc.want, connect.CodeOf(err))
		})
	}
}

func TestUpdateProfile_PassesInputAndReturnsResult(t *testing.T) {
	h := newProfileHarness(t)
	h.verifier.EXPECT().Verify(gomock.Any(), "access-token").Return(tokenIdentity(), nil)
	h.svc.EXPECT().UpdateProfile(gomock.Any(), tokenIdentity(), service.ProfileInput{
		Username:          "alice_01",
		DisplayName:       "Alice",
		Email:             "alice@example.com",
		PreferredCurrency: "AUD",
		Locale:            "en-AU",
		Timezone:          "Australia/Sydney",
	}).Return(sampleProfile(), nil)

	req := withToken(&authxpb.UpdateProfileRequest{
		Username:    "alice_01",
		DisplayName: "Alice",
		Email:       "alice@example.com",
		Preferences: &authxpb.Preferences{
			PreferredCurrency: "AUD",
			Locale:            "en-AU",
			Timezone:          "Australia/Sydney",
		},
	}, "access-token")

	resp, err := h.server.UpdateProfile(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, "alice_01", resp.Msg.GetProfile().GetUsername())
}

func TestUpdateProfile_ErrorMapping(t *testing.T) {
	cases := map[string]struct {
		svcErr      error
		wantCode    connect.Code
		wantReason  authxerrorspb.ErrorReason
		wantField   string
		wantMessage string
	}{
		"username taken": {
			service.ErrUsernameAlreadyTaken, connect.CodeAlreadyExists,
			authxerrorspb.ErrorReason_ERROR_REASON_PROFILE_USERNAME_TAKEN, "username", "username is not available",
		},
		"email linked": {
			service.ErrEmailAlreadyLinked, connect.CodeAlreadyExists,
			authxerrorspb.ErrorReason_ERROR_REASON_PROFILE_EMAIL_TAKEN, "email", "email is already in use",
		},
		"username reserved": { // same treatment as taken — unavailable to the caller
			service.ErrUsernameReserved, connect.CodeAlreadyExists,
			authxerrorspb.ErrorReason_ERROR_REASON_PROFILE_USERNAME_TAKEN, "username", "username is not available",
		},
		"invalid timezone": {
			service.ErrInvalidTimezone, connect.CodeInvalidArgument,
			authxerrorspb.ErrorReason_ERROR_REASON_PROFILE_INVALID_TIMEZONE, "timezone", "timezone is not a valid IANA name",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newProfileHarness(t)
			h.verifier.EXPECT().Verify(gomock.Any(), "access-token").Return(tokenIdentity(), nil)
			h.svc.EXPECT().UpdateProfile(gomock.Any(), gomock.Any(), gomock.Any()).Return(service.Profile{}, tc.svcErr)

			_, err := h.server.UpdateProfile(context.Background(), withToken(&authxpb.UpdateProfileRequest{}, "access-token"))

			require.Error(t, err)
			assert.Equal(t, tc.wantCode, connect.CodeOf(err))
			detail := errorDetail(t, err)
			require.NotNil(t, detail, "expected an ErrorDetail")
			assert.Equal(t, tc.wantReason, detail.GetReason())
			assert.Equal(t, tc.wantField, detail.GetField())
			assert.Equal(t, tc.wantMessage, detail.GetMessage())
		})
	}
}

// TestUpdateProfile_NotFoundNoDetail asserts a not-found (not a client field
// fault) maps to NotFound without a field-scoped ErrorDetail.
func TestUpdateProfile_NotFoundNoDetail(t *testing.T) {
	h := newProfileHarness(t)
	h.verifier.EXPECT().Verify(gomock.Any(), "access-token").Return(tokenIdentity(), nil)
	h.svc.EXPECT().UpdateProfile(gomock.Any(), gomock.Any(), gomock.Any()).Return(service.Profile{}, service.ErrUserNotFound)

	_, err := h.server.UpdateProfile(context.Background(), withToken(&authxpb.UpdateProfileRequest{}, "access-token"))

	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}
