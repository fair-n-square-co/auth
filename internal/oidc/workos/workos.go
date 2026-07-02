// Package workos is the WorkOS AuthKit implementation of the oidc seam. It is
// the only package that knows WorkOS specifics (claim names, and from FNS-95 the
// JWKS URL); everything above the seam consumes the provider-neutral
// oidc.Verifier.
package workos

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fair-n-square-co/auth/internal/oidc"
)

// Standard OIDC claim names carried in a WorkOS access token.
const (
	claimIssuer  = "iss"
	claimSubject = "sub"
)

// Verifier extracts the identity carried by a WorkOS access token.
//
// FNS-92: this decodes the JWT payload WITHOUT verifying the signature — the
// token is trusted because the caller (the BFF) is on a trusted path. The
// service must therefore be reachable only by trusted callers until FNS-95.
//
// TODO(FNS-95): verify the signature against the WorkOS JWKS and check
// iss/aud/exp before returning. Sketch:
//   - fetch + cache the JWKS from cfg.Workos.Issuer's well-known metadata
//     (`<issuer>/.well-known/jwks.json`), keyed by the token header `kid`;
//   - parse with a JWKS-backed keyfunc (e.g. github.com/golang-jwt/jwt/v5 +
//     github.com/MicahParks/keyfunc, or lestrrat-go/jwx), allow-list RS256/ES256,
//     reject `alg: none`;
//   - validate `iss` == v.issuer, `aud` == expected audience, and `exp`/`nbf`
//     with a small leeway.
//
// The interface and every caller stay unchanged; only this method gets stricter.
type Verifier struct {
	// issuer is the expected WorkOS issuer. Unused in FNS-92 (decode only);
	// enforced once signature verification lands (FNS-95).
	issuer string
}

// NewVerifier constructs a WorkOS Verifier. issuer is the expected OIDC issuer,
// used from FNS-95 on to validate the token's `iss` and locate the JWKS.
func NewVerifier(issuer string) *Verifier {
	return &Verifier{issuer: issuer}
}

// Verify decodes the WorkOS access token and returns its issuer and subject.
// FNS-92: signature is NOT checked (see the type doc). Returns
// oidc.ErrInvalidToken when the token is absent, malformed, or missing a subject.
func (v *Verifier) Verify(_ context.Context, rawToken string) (oidc.TokenIdentity, error) {
	claims, err := decodeClaims(rawToken)
	if err != nil {
		return oidc.TokenIdentity{}, err
	}

	ident := oidc.TokenIdentity{
		Issuer:  strings.TrimSpace(stringClaim(claims, claimIssuer)),
		Subject: strings.TrimSpace(stringClaim(claims, claimSubject)),
	}
	if ident.Subject == "" {
		return oidc.TokenIdentity{}, fmt.Errorf("%w: missing subject", oidc.ErrInvalidToken)
	}
	return ident, nil
}

// decodeClaims base64url-decodes and JSON-parses a JWT's payload segment without
// any signature check. Replaced by a verifying parse in FNS-95.
func decodeClaims(rawToken string) (map[string]any, error) {
	parts := strings.Split(strings.TrimSpace(rawToken), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: not a JWT (want 3 segments, got %d)", oidc.ErrInvalidToken, len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: decode payload: %v", oidc.ErrInvalidToken, err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: parse payload: %v", oidc.ErrInvalidToken, err)
	}
	return claims, nil
}

// stringClaim reads key from claims as a string, returning "" when absent or not
// a string so validation (not a type assertion panic) reports the problem.
func stringClaim(claims map[string]any, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

// compile-time check that *Verifier satisfies oidc.Verifier.
var _ oidc.Verifier = (*Verifier)(nil)
