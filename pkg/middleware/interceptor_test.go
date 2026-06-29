// TWIN TEST: the sanitizer cases are kept in sync with core/pkg/middleware.
package middleware_test

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fair-n-square-co/auth/pkg/middleware"
)

// sanitize runs the error-sanitizer interceptor over a handler that returns err
// and reports the error a client would observe.
func sanitize(t *testing.T, err error) error {
	t.Helper()
	interceptor := middleware.NewErrorSanitizerInterceptor()
	handler := interceptor(func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
		return nil, err
	})
	_, got := handler(context.Background(), connect.NewRequest(&struct{}{}))
	return got
}

func TestErrorSanitizer_HidesServerFaults(t *testing.T) {
	// A server-fault error carrying internal detail must not reach the client.
	leaky := connect.NewError(connect.CodeInternal,
		errors.New(`create user: ERROR: duplicate key value violates unique constraint "users_email_key"`))

	got := sanitize(t, leaky)

	require.Error(t, got)
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(got))
	assert.Equal(t, "internal: internal error", got.Error())
	assert.NotContains(t, got.Error(), "users_email_key")
}

func TestErrorSanitizer_PassesClientFaultsThrough(t *testing.T) {
	// Client-fault messages are author-controlled and safe, so they survive.
	for _, code := range []connect.Code{
		connect.CodeInvalidArgument,
		connect.CodeAlreadyExists,
		connect.CodeNotFound,
		connect.CodeUnauthenticated,
	} {
		orig := connect.NewError(code, errors.New("email already linked to another identity"))
		got := sanitize(t, orig)

		require.Error(t, got)
		assert.Equal(t, code, connect.CodeOf(got))
		assert.Contains(t, got.Error(), "email already linked to another identity")
	}
}

func TestErrorSanitizer_PassesSuccessThrough(t *testing.T) {
	assert.NoError(t, sanitize(t, nil))
}
