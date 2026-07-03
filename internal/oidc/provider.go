// Package oidc is the swappable-identity-source seam. The rest of the auth
// service depends only on the provider-neutral IdentityClaims and the Verifier
// interface — never on WorkOS types directly — so the OIDC source (WorkOS today,
// Clerk/Cognito/Better Auth tomorrow) can be replaced without a data migration
// or changes above this package (ADR-4: "WorkOS treated as a swappable OIDC
// source, no hard coupling").
//
// Zero trust (ADR-4 "Zero trust between services"): the external identity
// (issuer + subject) is derived from the caller's verified access token via
// Verifier, never from asserted request fields. Email — a non-identity profile
// attribute, and PII we keep out of the token — is supplied separately (the BFF
// passes it in the request body); it is not part of the trust-critical identity,
// and the user_email_key unique constraint prevents linking an email already
// tied to a different identity.
package oidc

import (
	"context"
	"errors"
	"net/mail"
	"strings"
)

// ErrMissingClaim is returned when a required claim (issuer, subject, or email)
// is absent or empty.
var ErrMissingClaim = errors.New("oidc: missing required claim")

// ErrInvalidEmail is returned when the email claim is present but not a valid
// address, so malformed input is rejected before it reaches the canonical record.
var ErrInvalidEmail = errors.New("oidc: invalid email")

// ErrInvalidToken is returned by a Verifier when the presented token is absent,
// malformed, or (once signature verification lands) fails
// signature/issuer/audience/expiry checks.
var ErrInvalidToken = errors.New("oidc: invalid token")

// TokenIdentity is what a Verifier extracts from an access token: the external
// identity (issuer + subject) that links to our canonical user record. Email is
// deliberately absent — it is not the identity key and is supplied by the caller
// in the request body, not carried on the token.
type TokenIdentity struct {
	// Issuer is the OIDC `iss` (e.g. the WorkOS issuer URL). Stored alongside
	// Subject so the same `sub` from two different providers never collide.
	Issuer string
	// Subject is the OIDC `sub` — the provider's stable user identifier.
	Subject string
}

// IdentityClaims is the normalized, provider-neutral identity of an
// authenticated principal, assembled from a verified TokenIdentity plus the
// email supplied by the caller.
type IdentityClaims struct {
	Issuer  string
	Subject string
	Email   string
}

//go:generate go run go.uber.org/mock/mockgen -destination=mocks/oidc.go -package=mocks . Verifier

// Verifier turns a raw access token into a trusted TokenIdentity.
//
// Current scope: the WorkOS implementation *decodes* the token without checking
// its signature — the caller (the BFF) is on a trusted path — so the service
// must be reachable only by trusted callers for now.
//
// TODO: verify the token signature against the provider JWKS and check
// iss/aud/exp before returning. This is a drop-in behind this interface: no
// handler or wiring change, only the impl gets stricter.
type Verifier interface {
	// Verify returns the TokenIdentity carried by rawToken, or ErrInvalidToken.
	Verify(ctx context.Context, rawToken string) (TokenIdentity, error)
}

// Normalized returns a copy with surrounding whitespace trimmed from every
// field, and email lower-cased. Callers should normalize before persisting or
// looking up so a stray space — or a differently-cased email like
// Alice@Example.com vs alice@example.com — can't fragment one identity across
// two rows. (The email column is citext, so the DB already compares
// case-insensitively; lower-casing here makes the stored/returned form canonical
// and keeps the rule consistent across providers.)
func (c IdentityClaims) Normalized() IdentityClaims {
	return IdentityClaims{
		Issuer:  strings.TrimSpace(c.Issuer),
		Subject: strings.TrimSpace(c.Subject),
		Email:   strings.ToLower(strings.TrimSpace(c.Email)),
	}
}

// Validate reports whether the claims carry the required fields, returning
// ErrMissingClaim when issuer, subject, or email is blank and ErrInvalidEmail
// when the email is present but malformed. It trims only for these checks; call
// Normalized first if you intend to persist the values.
func (c IdentityClaims) Validate() error {
	email := strings.TrimSpace(c.Email)
	if strings.TrimSpace(c.Issuer) == "" ||
		strings.TrimSpace(c.Subject) == "" ||
		email == "" {
		return ErrMissingClaim
	}
	// Require a bare, parseable address: mail.ParseAddress also accepts the
	// "Name <a@b>" form, so reject anything whose address isn't the whole input.
	if addr, err := mail.ParseAddress(email); err != nil || addr.Address != email {
		return ErrInvalidEmail
	}
	return nil
}
