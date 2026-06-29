// Package api holds the identity module's connectRPC handlers: they translate
// protobuf requests to/from the service layer and map service errors to connect
// codes. No business logic lives here.
package api

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	authxpb "github.com/fair-n-square-co/apis/gen/pkg/fairnsquare/service/authx/v1alpha1"
	"github.com/fair-n-square-co/apis/gen/pkg/fairnsquare/service/authx/v1alpha1/authxpbconnect"

	"github.com/fair-n-square-co/auth/internal/identity/service"
	"github.com/fair-n-square-co/auth/internal/oidc"
)

// IdentityService is the slice of the identity service the handler depends on.
type IdentityService interface {
	ResolveOrProvision(ctx context.Context, claims oidc.IdentityClaims) (service.User, bool, error)
}

// IdentityServer implements the connect IdentityService handler. It exposes the
// JIT entrypoint the BFF calls after a successful WorkOS login. Methods not yet
// implemented fall through to UnimplementedIdentityServiceHandler.
type IdentityServer struct {
	authxpbconnect.UnimplementedIdentityServiceHandler
	svc IdentityService
}

// NewIdentityServer constructs an IdentityServer backed by svc.
func NewIdentityServer(svc IdentityService) *IdentityServer {
	return &IdentityServer{svc: svc}
}

// ResolveUser resolves (and JIT-provisions on first login) the canonical user
// for the verified identity claims supplied by the BFF, returning our stable
// internal user id.
func (s *IdentityServer) ResolveUser(
	ctx context.Context,
	req *connect.Request[authxpb.ResolveUserRequest],
) (*connect.Response[authxpb.ResolveUserResponse], error) {
	msg := req.Msg
	claims := oidc.IdentityClaims{
		Issuer:  msg.GetIssuer(),
		Subject: msg.GetSubject(),
		Email:   msg.GetEmail(),
	}

	user, created, err := s.svc.ResolveOrProvision(ctx, claims)
	if err != nil {
		if errors.Is(err, service.ErrInvalidClaims) {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&authxpb.ResolveUserResponse{
		User: &authxpb.User{
			Id:      user.ID,
			Email:   user.Email,
			Issuer:  user.Issuer,
			Subject: user.Subject,
		},
		Created: created,
	}), nil
}
