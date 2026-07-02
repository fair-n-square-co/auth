package api_test

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	authxpb "github.com/fair-n-square-co/apis/gen/pkg/fairnsquare/service/authx/v1alpha1"

	"github.com/fair-n-square-co/auth/internal/identity/api"
	apimocks "github.com/fair-n-square-co/auth/internal/identity/api/mocks"
	"github.com/fair-n-square-co/auth/internal/identity/service"
	"github.com/fair-n-square-co/auth/internal/oidc"
	oidcmocks "github.com/fair-n-square-co/auth/internal/oidc/mocks"
)

// harness wires the handler with gomock doubles for its collaborators.
type harness struct {
	svc      *apimocks.MockIdentityService
	verifier *oidcmocks.MockVerifier
	server   *api.IdentityServer
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctrl := gomock.NewController(t)
	svc := apimocks.NewMockIdentityService(ctrl)
	verifier := oidcmocks.NewMockVerifier(ctrl)
	return &harness{
		svc:      svc,
		verifier: verifier,
		server:   api.NewIdentityServer(svc, verifier),
	}
}

// request builds a ResolveUser request: identity comes from the bearer token
// (Authorization metadata), email from the body.
func request(token, email string) *connect.Request[authxpb.ResolveUserRequest] {
	req := connect.NewRequest(&authxpb.ResolveUserRequest{Email: email})
	if token != "" {
		req.Header().Set("Authorization", "Bearer "+token)
	}
	return req
}

func TestResolveUser_ProvisionsFromTokenAndBody(t *testing.T) {
	h := newHarness(t)

	h.verifier.EXPECT().Verify(gomock.Any(), "access-token").
		Return(oidc.TokenIdentity{Issuer: "https://example.workos.com", Subject: "user_01J0"}, nil)
	// Identity from the token, email from the body.
	h.svc.EXPECT().ResolveOrProvision(gomock.Any(), oidc.IdentityClaims{
		Issuer:  "https://example.workos.com",
		Subject: "user_01J0",
		Email:   "alice@example.com",
	}).Return(service.User{ID: "uuid-1", Email: "alice@example.com"}, true, nil)

	resp, err := h.server.ResolveUser(context.Background(), request("access-token", "alice@example.com"))

	require.NoError(t, err)
	assert.True(t, resp.Msg.GetCreated())
	assert.Equal(t, "uuid-1", resp.Msg.GetUser().GetId())
	assert.Equal(t, "alice@example.com", resp.Msg.GetUser().GetEmail())
}

func TestResolveUser_MissingBearerIsUnauthenticated(t *testing.T) {
	h := newHarness(t)

	// No token: the handler must short-circuit before touching any collaborator
	// (gomock fails the test if Verify/ResolveOrProvision are called).
	_, err := h.server.ResolveUser(context.Background(), request("", "alice@example.com"))

	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestResolveUser_InvalidTokenIsUnauthenticated(t *testing.T) {
	h := newHarness(t)

	h.verifier.EXPECT().Verify(gomock.Any(), "bad").
		Return(oidc.TokenIdentity{}, oidc.ErrInvalidToken)

	_, err := h.server.ResolveUser(context.Background(), request("bad", "alice@example.com"))

	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestResolveUser_ServiceErrorMapping(t *testing.T) {
	cases := map[string]struct {
		svcErr error
		want   connect.Code
	}{
		"email linked elsewhere": {service.ErrEmailAlreadyLinked, connect.CodeAlreadyExists},
		"invalid claims":         {service.ErrInvalidClaims, connect.CodeInvalidArgument},
		"unexpected":             {errors.New("boom"), connect.CodeInternal},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.verifier.EXPECT().Verify(gomock.Any(), "tok").
				Return(oidc.TokenIdentity{Issuer: "i", Subject: "s"}, nil)
			h.svc.EXPECT().ResolveOrProvision(gomock.Any(), gomock.Any()).
				Return(service.User{}, false, tc.svcErr)

			_, err := h.server.ResolveUser(context.Background(), request("tok", "alice@example.com"))

			require.Error(t, err)
			assert.Equal(t, tc.want, connect.CodeOf(err))
		})
	}
}
