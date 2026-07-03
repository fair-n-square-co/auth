package workos_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fair-n-square-co/auth/internal/oidc"
	"github.com/fair-n-square-co/auth/internal/oidc/workos"
)

// mintToken builds a JWT-shaped string (header.payload.signature) carrying the
// given claims. The signature is bogus on purpose: the verifier decodes without
// checking it, so tests must not depend on a real signature.
func mintToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		require.NoError(t, err)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := enc(map[string]any{"alg": "RS256", "typ": "JWT"})
	return strings.Join([]string{header, enc(claims), "not-a-real-signature"}, ".")
}

func TestVerify_DecodesIssuerAndSubject(t *testing.T) {
	v := workos.NewVerifier("https://example.workos.com")
	token := mintToken(t, map[string]any{
		"iss":   "  https://example.workos.com  ",
		"sub":   "user_01J0",
		"email": "not-read-from-token@example.com", // access token email is ignored
	})

	ident, err := v.Verify(context.Background(), token)

	require.NoError(t, err)
	assert.Equal(t, oidc.TokenIdentity{
		Issuer:  "https://example.workos.com",
		Subject: "user_01J0",
	}, ident)
}

func TestVerify_DoesNotCheckSignature(t *testing.T) {
	// Documents the current trust gap: a token with a garbage signature still
	// decodes. Signature verification will make this fail.
	v := workos.NewVerifier("")
	token := mintToken(t, map[string]any{"iss": "i", "sub": "s"})

	ident, err := v.Verify(context.Background(), token)

	require.NoError(t, err)
	assert.Equal(t, "s", ident.Subject)
}

func TestVerify_Invalid(t *testing.T) {
	v := workos.NewVerifier("")
	cases := map[string]string{
		"empty":            "",
		"not a jwt":        "abc",
		"two segments":     "aaa.bbb",
		"bad base64":       "aaa.!!!not-base64!!!.ccc",
		"missing subject":  mintToken(t, map[string]any{"iss": "i"}),
		"blank subject":    mintToken(t, map[string]any{"iss": "i", "sub": "  "}),
		"non-string subno": mintToken(t, map[string]any{"iss": "i", "sub": 123}),
		"missing issuer":   mintToken(t, map[string]any{"sub": "s"}),
		"blank issuer":     mintToken(t, map[string]any{"iss": "  ", "sub": "s"}),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := v.Verify(context.Background(), token)
			require.ErrorIs(t, err, oidc.ErrInvalidToken)
		})
	}
}
