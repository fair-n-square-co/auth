//go:build integration

package main

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
)

const migrationsDir = "../../db/auth/migrations"

// TestResolveUser_RoundTrip is the acceptance test for FNS-92: ResolveUser is
// callable over HTTP and JIT-provisions a canonical user on first login, then
// resolves the same internal id idempotently on subsequent calls. It spins a
// throwaway Postgres, applies the goose migrations, and calls through the same
// mux the binary serves.
func TestResolveUser_RoundTrip(t *testing.T) {
	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
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
	})
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	ts := httptest.NewServer(newMux(pool, slog.New(slog.NewTextHandler(io.Discard, nil))))
	t.Cleanup(ts.Close)

	client := authxpbconnect.NewIdentityServiceClient(http.DefaultClient, ts.URL)
	req := func() *connect.Request[authxpb.ResolveUserRequest] {
		return connect.NewRequest(&authxpb.ResolveUserRequest{
			Issuer:  "https://example.workos.com",
			Subject: "user_01J0",
			Email:   "alice@example.com",
		})
	}

	// First login provisions the canonical user.
	first, err := client.ResolveUser(ctx, req())
	require.NoError(t, err)
	assert.True(t, first.Msg.GetCreated(), "first login should provision a new user")
	require.NotEmpty(t, first.Msg.GetUser().GetId())
	assert.Equal(t, "alice@example.com", first.Msg.GetUser().GetEmail())

	// Second login resolves the same id and does not re-provision (idempotent).
	second, err := client.ResolveUser(ctx, req())
	require.NoError(t, err)
	assert.False(t, second.Msg.GetCreated(), "second login should not re-provision")
	assert.Equal(t, first.Msg.GetUser().GetId(), second.Msg.GetUser().GetId())
}

// TestResolveUser_InvalidClaims asserts missing claims map to InvalidArgument.
func TestResolveUser_InvalidClaims(t *testing.T) {
	ctx := context.Background()
	ts := httptest.NewServer(newMux(nil, slog.New(slog.NewTextHandler(io.Discard, nil))))
	t.Cleanup(ts.Close)

	client := authxpbconnect.NewIdentityServiceClient(http.DefaultClient, ts.URL)
	_, err := client.ResolveUser(ctx, connect.NewRequest(&authxpb.ResolveUserRequest{
		Issuer: "https://example.workos.com",
		// subject + email omitted
	}))

	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func runMigrations(t *testing.T, dsn string) {
	t.Helper()
	sqlDB, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	defer func() { _ = sqlDB.Close() }()

	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.Up(sqlDB, migrationsDir))
}
