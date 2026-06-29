// Package middleware provides connect interceptors shared across the Auth
// service: structured request logging and panic recovery.
package middleware

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"connectrpc.com/connect"
)

// NewLoggingInterceptor logs one structured line per unary RPC, recording the
// procedure, duration, and — on failure — the connect error code.
func NewLoggingInterceptor(logger *slog.Logger) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			start := time.Now()
			resp, err := next(ctx, req)

			attrs := []any{
				"procedure", req.Spec().Procedure,
				"duration_ms", time.Since(start).Milliseconds(),
			}
			if err != nil {
				attrs = append(attrs, "code", connect.CodeOf(err).String(), "error", err.Error())
				logger.LogAttrs(ctx, slog.LevelError, "rpc failed", asAttrs(attrs)...)
				return resp, err
			}
			logger.LogAttrs(ctx, slog.LevelInfo, "rpc handled", asAttrs(attrs)...)
			return resp, nil
		}
	}
}

// NewRecoveryInterceptor converts panics in unary handlers into a connect
// CodeInternal error so a single bad request cannot crash the server.
func NewRecoveryInterceptor(logger *slog.Logger) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (resp connect.AnyResponse, err error) {
			defer func() {
				if r := recover(); r != nil {
					logger.LogAttrs(ctx, slog.LevelError, "panic recovered",
						slog.String("procedure", req.Spec().Procedure),
						slog.Any("panic", r),
					)
					resp = nil
					err = connect.NewError(connect.CodeInternal, errors.New("internal error"))
				}
			}()
			return next(ctx, req)
		}
	}
}

// asAttrs converts an alternating key/value slice into slog.Attr values.
func asAttrs(kv []any) []slog.Attr {
	attrs := make([]slog.Attr, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		key, _ := kv[i].(string)
		attrs = append(attrs, slog.Any(key, kv[i+1]))
	}
	return attrs
}
