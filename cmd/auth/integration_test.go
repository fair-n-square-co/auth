//go:build integration

package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
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

	authxerrorspb "github.com/fair-n-square-co/apis/gen/pkg/fairnsquare/errors/authx/v1alpha1"
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

// startAuthServer spins a Postgres container, runs migrations, opens a pool, and
// serves the full mux (identity + profile, with the validate interceptor) over
// httptest. It returns the base URL and the issuer the verifier expects. All
// resources are torn down via t.Cleanup.
func startAuthServer(t *testing.T) (baseURL, issuer string) {
	t.Helper()
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

	issuer = "https://example.workos.com"
	mux := newMux(pool, slog.New(slog.NewTextHandler(io.Discard, nil)), workos.NewVerifier(issuer))
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	return ts.URL, issuer
}

// TestProfile_RoundTrip provisions a user, then updates and reads back the
// profile over HTTP through the full interceptor stack, and asserts a username
// already taken by another user is rejected as AlreadyExists.
func TestProfile_RoundTrip(t *testing.T) {
	ctx := context.Background()
	baseURL, issuer := startAuthServer(t)

	identity := authxpbconnect.NewIdentityServiceClient(http.DefaultClient, baseURL)
	profiles := authxpbconnect.NewProfileServiceClient(http.DefaultClient, baseURL)

	// Helper to call an RPC as a given subject (its access token).
	provision := func(subject, email string) {
		req := connect.NewRequest(&authxpb.ResolveUserRequest{Email: email})
		req.Header().Set("Authorization", "Bearer "+mintToken(t, issuer, subject))
		_, err := identity.ResolveUser(ctx, req)
		require.NoError(t, err)
	}
	update := func(subject string, msg *authxpb.UpdateProfileRequest) (*connect.Response[authxpb.UpdateProfileResponse], error) {
		req := connect.NewRequest(msg)
		req.Header().Set("Authorization", "Bearer "+mintToken(t, issuer, subject))
		return profiles.UpdateProfile(ctx, req)
	}

	provision("user_alice", "alice@example.com")

	// Update the profile with a username and preferences.
	updated, err := update("user_alice", &authxpb.UpdateProfileRequest{
		Username:    "alice_01",
		DisplayName: "Alice",
		Email:       "alice@example.com",
		Preferences: &authxpb.Preferences{
			PreferredCurrency: "AUD",
			Locale:            "en-AU",
			Timezone:          "Australia/Sydney",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "alice_01", updated.Msg.GetProfile().GetUsername())
	assert.Equal(t, "Alice", updated.Msg.GetProfile().GetDisplayName())
	assert.Equal(t, "AUD", updated.Msg.GetProfile().GetPreferences().GetPreferredCurrency())

	// Read it back — identity comes from the token, no id in the request.
	getReq := connect.NewRequest(&authxpb.GetProfileRequest{})
	getReq.Header().Set("Authorization", "Bearer "+mintToken(t, issuer, "user_alice"))
	got, err := profiles.GetProfile(ctx, getReq)
	require.NoError(t, err)
	assert.Equal(t, "alice_01", got.Msg.GetProfile().GetUsername())
	assert.Equal(t, "Australia/Sydney", got.Msg.GetProfile().GetPreferences().GetTimezone())

	// A second user cannot claim the same username — real user_username_key.
	provision("user_bob", "bob@example.com")
	_, err = update("user_bob", &authxpb.UpdateProfileRequest{
		Username:    "alice_01",
		Email:       "bob@example.com",
		Preferences: &authxpb.Preferences{},
	})
	require.Error(t, err)
	assert.Equal(t, connect.CodeAlreadyExists, connect.CodeOf(err))
	// The typed ErrorDetail survives the wire so the client can pin the failure
	// to the username field.
	var cerr *connect.Error
	require.True(t, errors.As(err, &cerr))
	detail := firstErrorDetail(t, cerr)
	require.NotNil(t, detail)
	assert.Equal(t, authxerrorspb.ErrorReason_ERROR_REASON_PROFILE_USERNAME_TAKEN, detail.GetReason())
	assert.Equal(t, "username", detail.GetField())
	assert.Equal(t, "username is not available", detail.GetMessage())
}

// firstErrorDetail returns the first authx ErrorDetail on a connect error, or nil.
func firstErrorDetail(t *testing.T, cerr *connect.Error) *authxerrorspb.ErrorDetail {
	t.Helper()
	for _, d := range cerr.Details() {
		if msg, verr := d.Value(); verr == nil {
			if ed, ok := msg.(*authxerrorspb.ErrorDetail); ok {
				return ed
			}
		}
	}
	return nil
}

// TestProfile_ValidationRejected asserts the protovalidate interceptor rejects a
// malformed request (bad username shape) as InvalidArgument before it reaches the
// handler.
func TestProfile_ValidationRejected(t *testing.T) {
	ctx := context.Background()
	baseURL, issuer := startAuthServer(t)
	profiles := authxpbconnect.NewProfileServiceClient(http.DefaultClient, baseURL)

	req := connect.NewRequest(&authxpb.UpdateProfileRequest{
		Username:    "a", // too short + below min_len
		Email:       "alice@example.com",
		Preferences: &authxpb.Preferences{},
	})
	req.Header().Set("Authorization", "Bearer "+mintToken(t, issuer, "user_alice"))
	_, err := profiles.UpdateProfile(ctx, req)

	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

// TestGetProfile_NotProvisioned asserts a profile read for an identity that has
// never called ResolveUser returns NotFound (profile ops never provision).
func TestGetProfile_NotProvisioned(t *testing.T) {
	ctx := context.Background()
	baseURL, issuer := startAuthServer(t)
	profiles := authxpbconnect.NewProfileServiceClient(http.DefaultClient, baseURL)

	req := connect.NewRequest(&authxpb.GetProfileRequest{})
	req.Header().Set("Authorization", "Bearer "+mintToken(t, issuer, "ghost"))
	_, err := profiles.GetProfile(ctx, req)

	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

func runMigrations(t *testing.T, dsn string) {
	t.Helper()
	sqlDB, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	defer func() { _ = sqlDB.Close() }()

	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.Up(sqlDB, migrationsDir))
}
