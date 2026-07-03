package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/grpchealth"
	"connectrpc.com/grpcreflect"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sync/errgroup"

	"github.com/fair-n-square-co/apis/gen/pkg/fairnsquare/service/authx/v1alpha1/authxpbconnect"
	"github.com/fair-n-square-co/auth/cmd/auth/config"
	"github.com/fair-n-square-co/auth/internal/identity/api"
	"github.com/fair-n-square-co/auth/internal/identity/repository"
	"github.com/fair-n-square-co/auth/internal/identity/service"
	"github.com/fair-n-square-co/auth/internal/oidc"
	"github.com/fair-n-square-co/auth/internal/oidc/workos"
	"github.com/fair-n-square-co/auth/pkg/middleware"
)

// shutdownTimeout bounds how long graceful shutdown waits for in-flight RPCs.
const shutdownTimeout = 10 * time.Second

// server serves the connect/gRPC API on the configured port using the given
// connection pool until ctx is cancelled. The pool is owned by the caller.
func server(ctx context.Context, cfg *config.Config, pool *pgxpool.Pool) error {
	logger := slog.Default()

	addr := fmt.Sprintf(":%d", cfg.Port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	// WorkOS seam: verifier authenticates the access token. It currently decodes
	// the token without verifying its signature (TODO: add JWKS verification).
	verifier := workos.NewVerifier(cfg.Workos.Issuer)

	srv := newHTTPServer(newMux(pool, logger, verifier), cfg.TLS)

	scheme := "http"
	if cfg.TLS.Enabled() {
		scheme = "https"
	}
	logger.Info("listening", "addr", addr, "scheme", scheme)
	return serve(ctx, srv, lis, cfg.TLS)
}

// newMux builds the HTTP mux exposing the identity service, gRPC health, and
// gRPC reflection, all wrapped with the shared logging/recovery interceptors.
// verifier is the OIDC seam the identity handler uses to authenticate the
// caller's access token.
func newMux(pool *pgxpool.Pool, logger *slog.Logger, verifier oidc.Verifier) *http.ServeMux {
	// Order matters: the sanitizer is outermost so it has the final say on the
	// client-facing error; logging runs inside it so it still records the full
	// error; recovery is innermost, closest to the handler, to catch panics.
	interceptors := connect.WithInterceptors(
		middleware.NewErrorSanitizerInterceptor(),
		middleware.NewLoggingInterceptor(logger),
		middleware.NewRecoveryInterceptor(logger),
	)

	identitySrv := api.NewIdentityServer(service.NewIdentityService(repository.New(pool)), verifier)

	mux := http.NewServeMux()
	mux.Handle(authxpbconnect.NewIdentityServiceHandler(identitySrv, interceptors))

	checker := grpchealth.NewStaticChecker(authxpbconnect.IdentityServiceName)
	mux.Handle(grpchealth.NewHandler(checker))

	reflector := grpcreflect.NewStaticReflector(authxpbconnect.IdentityServiceName)
	mux.Handle(grpcreflect.NewHandlerV1(reflector))
	mux.Handle(grpcreflect.NewHandlerV1Alpha(reflector))

	return mux
}

// newHTTPServer builds the HTTP server for handler.
//
// With TLS configured it serves HTTPS and HTTP/2 is negotiated via ALPN — the
// standard way to serve the gRPC protocol over the network, no extra setup.
//
// Without TLS (local development) it enables cleartext HTTP/2 (h2c) so
// gRPC-protocol clients — health probes, grpcurl reflection — can still connect;
// connect and grpc-web clients already work over plain HTTP/1.1. This uses the
// stdlib http.Protocols knobs (Go 1.24+), so no golang.org/x/net/http2/h2c
// wrapper is needed.
func newHTTPServer(handler http.Handler, tlsCfg config.TLSConfig) *http.Server {
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if !tlsCfg.Enabled() {
		protocols := new(http.Protocols)
		protocols.SetHTTP1(true)
		protocols.SetUnencryptedHTTP2(true)
		srv.Protocols = protocols
	}
	return srv
}

// serve runs srv on lis — over TLS when configured — and shuts it down
// gracefully when ctx is cancelled.
func serve(ctx context.Context, srv *http.Server, lis net.Listener, tlsCfg config.TLSConfig) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		var err error
		if tlsCfg.Enabled() {
			err = srv.ServeTLS(lis, tlsCfg.CertFile, tlsCfg.KeyFile)
		} else {
			err = srv.Serve(lis)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})

	g.Go(func() error {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	})

	return g.Wait()
}
