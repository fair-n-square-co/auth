// Package workos is the WorkOS AuthKit implementation of oidc.Provider. It is
// the only package that knows WorkOS claim names; everything above the seam
// consumes the provider-neutral oidc.IdentityClaims.
package workos

import (
	"context"
	"errors"

	"github.com/fair-n-square-co/auth/internal/oidc"
)

// Provider is the WorkOS implementation of oidc.Provider.
type Provider struct {
	// TODO(FNS-95): issuer, clientID, and a JWKS-backed verifier for token
	// signature checks. Not needed for FNS-92 (claims arrive pre-verified).
}

// New constructs a WorkOS Provider.
func New() *Provider {
	// TODO(impl): accept OIDC config (issuer, client id) once it exists.
	return &Provider{}
}

// Normalize maps WorkOS claims into provider-neutral oidc.IdentityClaims.
func (p *Provider) Normalize(ctx context.Context, raw oidc.RawClaims) (oidc.IdentityClaims, error) {
	// TODO(impl): read iss/sub/email from `raw`, trim, validate non-empty,
	// return oidc.ErrMissingClaim on any missing field.
	return oidc.IdentityClaims{}, errors.New("not implemented")
}

// compile-time check that *Provider satisfies oidc.Provider.
var _ oidc.Provider = (*Provider)(nil)
