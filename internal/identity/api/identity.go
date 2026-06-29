// Package api holds the identity module's connectRPC handlers: they translate
// protobuf requests to/from the service layer and map service errors to connect
// codes. No business logic lives here.
package api

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	"github.com/fair-n-square-co/auth/internal/identity/service"
	"github.com/fair-n-square-co/auth/internal/oidc"
	// TODO(FNS-92 proto): import once the authx proto is generated in `apis`:
	//   authxpb ".../fairnsquare/service/authx/v1alpha1"
	//   ".../fairnsquare/service/authx/v1alpha1/authxpbconnect"
)

// IdentityService is the slice of the identity service the handler depends on.
type IdentityService interface {
	ResolveOrProvision(ctx context.Context, claims oidc.IdentityClaims) (service.User, error)
}

// IdentityServer implements the connect IdentityService handler. It exposes the
// JIT entrypoint the BFF calls after a successful WorkOS login.
//
// TODO(impl): embed authxpbconnect.UnimplementedIdentityServiceHandler once the
// proto is generated, so unimplemented RPCs fall through cleanly.
type IdentityServer struct {
	svc IdentityService
}

// NewIdentityServer constructs an IdentityServer backed by svc.
func NewIdentityServer(svc IdentityService) *IdentityServer {
	return &IdentityServer{svc: svc}
}

// ResolveUser resolves (and JIT-provisions/links on first login) the canonical
// user for the verified identity claims supplied by the BFF, returning our
// stable internal user id.
//
// TODO(impl): change the signature to the generated proto types:
//
//	func (s *IdentityServer) ResolveUser(
//	    ctx context.Context,
//	    req *connect.Request[authxpb.ResolveUserRequest],
//	) (*connect.Response[authxpb.ResolveUserResponse], error)
//
// Body: build oidc.IdentityClaims from the request, call ResolveOrProvision,
// map ErrInvalidClaims -> CodeInvalidArgument and the rest -> CodeInternal,
// and return the user id (+ a `created` flag).
func (s *IdentityServer) ResolveUser(ctx context.Context /*, req */) error {
	// Sketch of the error mapping the real handler will use:
	_ = func(err error) error {
		if errors.Is(err, service.ErrInvalidClaims) {
			return connect.NewError(connect.CodeInvalidArgument, err)
		}
		return connect.NewError(connect.CodeInternal, err)
	}
	return errors.New("not implemented")
}
