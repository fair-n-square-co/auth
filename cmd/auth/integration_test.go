//go:build integration

package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver for goose
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	authxpb "github.com/fair-n-square-co/apis/gen/pkg/fairnsquare/service/authx/v1alpha1"
	"github.com/fair-n-square-co/apis/gen/pkg/fairnsquare/service/authx/v1alpha1/authxpbconnect"
	authdb "github.com/fair-n-square-co/auth/internal/auth/db"
	"github.com/fair-n-square-co/auth/internal/oidc/workos"
)

const migrationsDir = "../../db/auth/migrations"

// mintToken builds a JWT-shaped access token carrying iss/sub. The signature is
// bogus: the service decodes without verifying (JWKS verification is a follow-up).
func mintToken(t *testing.T, issuer, subject string) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		require.NoError(t, err)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := enc(map[string]any{"alg": "RS256", "typ": "JWT"})
	payload := enc(map[string]any{"iss": issuer, "sub": subject})
	return strings.Join([]string{header, payload, "sig"}, ".")
}

// TestResolveUser_RoundTrip is the acceptance test: ResolveUser is callable over
// HTTP and JIT-provisions a canonical user on first login, then
// resolves the same internal id idempotently on subsequent calls. Identity is
// carried by the access token (Authorization metadata); the email travels in the
// request body.
func TestResolveUser_RoundTrip(t *testing.T) {
	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx,
		"postgres:17-alpine",
		postgres.WithDatabase("auth"),
		postgres.WithUsername("auth"),
		postgres.WithPassword("auth"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = testcontainers.TerminateContainer(pgContainer) })

	dsn, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	runMigrations(t, dsn)

	pool, err := authdb.NewPool(ctx, authdb.DBConfig{
		ConnString:        dsn,
		MaxConns:          10,
		MinConns:          2,
		MaxConnLifetime:   time.Hour,
		MaxConnIdleTime:   30 * time.Minute,
		HealthCheckPeriod: time.Minute,
		PingTimeout:       5 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	const issuer = "https://example.workos.com"
	mux := newMux(pool, slog.New(slog.NewTextHandler(io.Discard, nil)), workos.NewVerifier(issuer))
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	client := authxpbconnect.NewIdentityServiceClient(http.DefaultClient, ts.URL)
	call := func(subject, email string) (*connect.Response[authxpb.ResolveUserResponse], error) {
		req := connect.NewRequest(&authxpb.ResolveUserRequest{Email: email})
		req.Header().Set("Authorization", "Bearer "+mintToken(t, issuer, subject))
		return client.ResolveUser(ctx, req)
	}

	// First login provisions the canonical user.
	first, err := call("user_01J0", "alice@example.com")
	require.NoError(t, err)
	assert.Equal(t, authxpb.ResolveUserResponse_RESOLUTION_CREATED, first.Msg.GetResolution(), "first login should provision a new user")
	require.NotEmpty(t, first.Msg.GetUser().GetId())
	assert.Equal(t, "alice@example.com", first.Msg.GetUser().GetEmail())

	// Second login resolves the same id and does not re-provision (idempotent).
	second, err := call("user_01J0", "alice@example.com")
	require.NoError(t, err)
	assert.Equal(t, authxpb.ResolveUserResponse_RESOLUTION_FOUND, second.Msg.GetResolution(), "second login should not re-provision")
	assert.Equal(t, first.Msg.GetUser().GetId(), second.Msg.GetUser().GetId())

	// A different identity (new subject) reusing the same email must be rejected
	// cleanly as AlreadyExists, not surface as a 500. This exercises the real
	// constraint-name detection (user_email_key) against Postgres.
	conflict, err := call("user_DIFFERENT", "alice@example.com")
	require.Nil(t, conflict)
	require.Error(t, err)
	assert.Equal(t, connect.CodeAlreadyExists, connect.CodeOf(err))
}

// TestResolveUser_MissingToken asserts a request without a bearer token is
// rejected as Unauthenticated before any provisioning is attempted.
func TestResolveUser_MissingToken(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mux := newMux(nil, logger, workos.NewVerifier(""))
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	client := authxpbconnect.NewIdentityServiceClient(http.DefaultClient, ts.URL)
	_, err := client.ResolveUser(ctx, connect.NewRequest(&authxpb.ResolveUserRequest{Email: "alice@example.com"}))

	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func runMigrations(t *testing.T, dsn string) {
	t.Helper()
	sqlDB, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	defer func() { _ = sqlDB.Close() }()

	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.Up(sqlDB, migrationsDir))
}
