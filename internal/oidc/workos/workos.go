// Package workos is the WorkOS AuthKit implementation of oidc.Provider. It is
// the only package that knows WorkOS claim names; everything above the seam
// consumes the provider-neutral oidc.IdentityClaims.
package workos

import (
	"context"

	"github.com/fair-n-square-co/auth/internal/oidc"
)

// Standard OIDC claim names carried in a WorkOS ID token.
const (
	claimIssuer  = "iss"
	claimSubject = "sub"
	claimEmail   = "email"
)

// Provider is the WorkOS implementation of oidc.Provider.
type Provider struct {
	// TODO(FNS-95): issuer, clientID, and a JWKS-backed verifier for token
	// signature checks. Not needed for FNS-92 (claims arrive pre-verified).
}

// New constructs a WorkOS Provider.
func New() *Provider {
	return &Provider{}
}

// Normalize maps WorkOS claims into provider-neutral oidc.IdentityClaims,
// trimming whitespace and validating that the required fields are present.
func (p *Provider) Normalize(ctx context.Context, raw oidc.RawClaims) (oidc.IdentityClaims, error) {
	claims := oidc.IdentityClaims{
		Issuer:  stringClaim(raw, claimIssuer),
		Subject: stringClaim(raw, claimSubject),
		Email:   stringClaim(raw, claimEmail),
	}.Normalized()
	if err := claims.Validate(); err != nil {
		return oidc.IdentityClaims{}, err
	}
	return claims, nil
}

// stringClaim reads key from raw as a string, returning "" when absent or not a
// string so validation (not a type assertion panic) reports the problem.
func stringClaim(raw oidc.RawClaims, key string) string {
	if v, ok := raw[key].(string); ok {
		return v
	}
	return ""
}

// compile-time check that *Provider satisfies oidc.Provider.
var _ oidc.Provider = (*Provider)(nil)
