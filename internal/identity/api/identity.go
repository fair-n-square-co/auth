// Package api holds the identity module's connectRPC handlers: they translate
// protobuf requests to/from the service layer and map service errors to connect
// codes. No business logic lives here.
package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"connectrpc.com/connect"

	authxpb "github.com/fair-n-square-co/apis/gen/pkg/fairnsquare/service/authx/v1alpha1"
	"github.com/fair-n-square-co/apis/gen/pkg/fairnsquare/service/authx/v1alpha1/authxpbconnect"

	"github.com/fair-n-square-co/auth/internal/identity/service"
	"github.com/fair-n-square-co/auth/internal/oidc"
)

// IdentityService is the slice of the identity service the handler depends on.
//
//go:generate go run go.uber.org/mock/mockgen -destination=mocks/identity.go -package=mocks . IdentityService
type IdentityService interface {
	ResolveOrProvision(ctx context.Context, claims oidc.IdentityClaims) (service.User, bool, error)
}

// IdentityServer implements the connect IdentityService handler. It exposes the
// JIT entrypoint the BFF calls after a successful WorkOS login. Methods not yet
// implemented fall through to UnimplementedIdentityServiceHandler.
//
// TRUST BOUNDARY (ADR-4 "Zero trust between services"): the external identity
// — issuer + subject, the record's key — comes solely from the caller's WorkOS
// access token, presented as an `Authorization: Bearer` header. The Verifier
// yields that trusted identity; the caller cannot assert it. Email is a
// non-identity profile attribute supplied in the request body (kept out of the
// token to avoid PII); a caller can only attach an email to its own verified
// identity, and the users_email_key constraint blocks reusing another's.
//
// FNS-92 gap: the Verifier currently *decodes* the token without checking its
// signature — JWKS verification lands in FNS-95 — so until then the service must
// be reachable only by trusted callers (network isolation / mTLS).
type IdentityServer struct {
	authxpbconnect.UnimplementedIdentityServiceHandler
	svc      IdentityService
	verifier oidc.Verifier
}

// NewIdentityServer constructs an IdentityServer backed by svc, using verifier
// to authenticate the caller's access token.
func NewIdentityServer(svc IdentityService, verifier oidc.Verifier) *IdentityServer {
	return &IdentityServer{svc: svc, verifier: verifier}
}

// ResolveUser resolves (and JIT-provisions on first login) the canonical user
// for the identity carried by the caller's WorkOS access token, returning our
// stable internal user id.
func (s *IdentityServer) ResolveUser(
	ctx context.Context,
	req *connect.Request[authxpb.ResolveUserRequest],
) (*connect.Response[authxpb.ResolveUserResponse], error) {
	token, err := bearerToken(req.Header())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}

	// Trusted identity from the token (signature check is TODO(FNS-95)).
	ident, err := s.verifier.Verify(ctx, token)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}

	// Email is not on the access token (PII); the caller supplies it in the
	// request body. It attaches only to the token-verified identity above, so an
	// empty/blank email surfaces as ErrInvalidClaims from the service below.
	claims := oidc.IdentityClaims{
		Issuer:  ident.Issuer,
		Subject: ident.Subject,
		Email:   req.Msg.GetEmail(),
	}

	user, created, err := s.svc.ResolveOrProvision(ctx, claims)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidClaims):
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		case errors.Is(err, service.ErrEmailAlreadyLinked):
			return nil, connect.NewError(connect.CodeAlreadyExists, err)
		default:
			// Pass the full cause: the logging interceptor records it and the
			// sanitizer interceptor strips it from the client-facing response.
			return nil, connect.NewError(connect.CodeInternal, err)
		}
	}

	resolution := authxpb.ResolveUserResponse_RESOLUTION_FOUND
	if created {
		resolution = authxpb.ResolveUserResponse_RESOLUTION_CREATED
	}

	return connect.NewResponse(&authxpb.ResolveUserResponse{
		// Return only the canonical id and normalized email; issuer/subject are
		// the caller's own token claims, so we don't echo them back (see User proto).
		User: &authxpb.User{
			Id:    user.ID,
			Email: user.Email,
		},
		Resolution: resolution,
	}), nil
}

// errMissingBearer is returned when the Authorization header is absent or not a
// non-empty Bearer token. It stays deliberately vague — the client only needs to
// know it must present a valid token.
var errMissingBearer = errors.New("missing or malformed bearer token")

// bearerToken extracts the token from an `Authorization: Bearer <token>` header,
// matching the scheme case-insensitively. It returns errMissingBearer when the
// header is absent, uses another scheme, or carries an empty token.
func bearerToken(h http.Header) (string, error) {
	const scheme = "bearer "
	authz := h.Get("Authorization")
	if len(authz) < len(scheme) || !strings.EqualFold(authz[:len(scheme)], scheme) {
		return "", errMissingBearer
	}
	token := strings.TrimSpace(authz[len(scheme):])
	if token == "" {
		return "", errMissingBearer
	}
	return token, nil
}
