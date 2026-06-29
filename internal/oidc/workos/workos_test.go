package workos_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fair-n-square-co/auth/internal/oidc"
	"github.com/fair-n-square-co/auth/internal/oidc/workos"
)

func TestNormalize_MapsAndTrims(t *testing.T) {
	p := workos.New()
	got, err := p.Normalize(context.Background(), oidc.RawClaims{
		"iss":   "  https://example.workos.com  ",
		"sub":   "user_01J0",
		"email": "alice@example.com",
		"extra": "ignored",
	})

	require.NoError(t, err)
	assert.Equal(t, oidc.IdentityClaims{
		Issuer:  "https://example.workos.com",
		Subject: "user_01J0",
		Email:   "alice@example.com",
	}, got)
}

func TestNormalize_MissingOrWrongType(t *testing.T) {
	cases := map[string]oidc.RawClaims{
		"missing email":   {"iss": "i", "sub": "s"},
		"empty subject":   {"iss": "i", "sub": "  ", "email": "e"},
		"non-string sub":  {"iss": "i", "sub": 123, "email": "e"},
		"empty raw claim": {},
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			p := workos.New()
			_, err := p.Normalize(context.Background(), raw)
			require.ErrorIs(t, err, oidc.ErrMissingClaim)
		})
	}
}
