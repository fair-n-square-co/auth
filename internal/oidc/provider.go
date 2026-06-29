// Package oidc is the swappable-identity-source seam. The rest of the auth
// service depends only on the provider-neutral IdentityClaims and the Provider
// interface — never on WorkOS types directly — so the OIDC source (WorkOS today,
// Clerk/Cognito/Better Auth tomorrow) can be replaced without a data migration
// or changes above this package (ADR-4: "WorkOS treated as a swappable OIDC
// source, no hard coupling").
package oidc

import (
	"context"
	"errors"
)

// ErrMissingClaim is returned by a Provider when a required claim (issuer,
// subject, or email) is absent or empty after normalization.
var ErrMissingClaim = errors.New("oidc: missing required claim")

// IdentityClaims is the normalized, provider-neutral identity of an
// authenticated principal. Issuer + Subject together uniquely identify the
// external identity that links to our canonical user record.
type IdentityClaims struct {
	// Issuer is the OIDC `iss` (e.g. the WorkOS issuer URL). Stored alongside
	// Subject so the same `sub` from two different providers never collide.
	Issuer string
	// Subject is the OIDC `sub` — the provider's stable user identifier.
	Subject string
	// Email is the user's email at the provider. Used as the JIT link key when
	// an identity is re-provisioned under a new Subject.
	Email string
}

// Provider turns provider-specific input into normalized IdentityClaims.
//
// FNS-92 scope: Normalize only — the BFF has already verified the token, so we
// just map its claims into IdentityClaims.
//
// TODO(FNS-95): add `Verify(ctx, rawToken) (IdentityClaims, error)` that checks
// the token signature against the provider JWKS before normalization. It slots
// in *front* of the resolver without reshaping it.
type Provider interface {
	// Normalize maps already-verified provider claims into IdentityClaims and
	// validates that the required fields (issuer, subject, email) are present.
	Normalize(ctx context.Context, raw RawClaims) (IdentityClaims, error)
}

// RawClaims is the loosely-typed claim set handed to a Provider before
// normalization. The concrete shape is provider-defined; this keeps the seam
// from leaking WorkOS-specific types upward.
//
// TODO(impl): decide the carrier — a map[string]any decoded from the ID token,
// or a small typed struct populated by the BFF. Keep it provider-neutral.
type RawClaims map[string]any
