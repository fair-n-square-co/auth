package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DBConfig holds database connection settings. It is composed into the
// application config and passed to NewPool after loading.
//
// The pool-tuning fields are the single source of truth: their defaults live in
// the embedded YAML config (see cmd/auth/config) and are passed straight through
// to the pgx pool. A bad value surfaces as an error from NewPool rather than
// being silently corrected here.
type DBConfig struct {
	ConnString string

	// MaxConns caps the total number of connections in the pool.
	MaxConns int32
	// MinConns is the number of idle connections the pool keeps warm.
	MinConns int32
	// MaxConnLifetime is how long a connection may live before it is recycled.
	MaxConnLifetime time.Duration
	// MaxConnIdleTime is how long an idle connection is kept before it is closed.
	MaxConnIdleTime time.Duration
	// HealthCheckPeriod is how often the pool checks the health of idle connections.
	HealthCheckPeriod time.Duration
	// PingTimeout bounds the connectivity check NewPool runs after opening the pool.
	PingTimeout time.Duration
}

// NewPool opens a pgx connection pool from c and verifies connectivity with a
// ping. The pool-tuning values are applied as-is; pgx rejects invalid settings
// (e.g. MaxConns < 1), so a misconfigured pool fails here rather than being
// papered over. The returned *pgxpool.Pool satisfies the generated sqlc DBTX
// interface, so it can be injected directly into module repositories.
func NewPool(ctx context.Context, c DBConfig) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(c.ConnString)
	if err != nil {
		return nil, fmt.Errorf("parse db conn string: %w", err)
	}
	cfg.MaxConns = c.MaxConns
	cfg.MinConns = c.MinConns
	cfg.MaxConnLifetime = c.MaxConnLifetime
	cfg.MaxConnIdleTime = c.MaxConnIdleTime
	cfg.HealthCheckPeriod = c.HealthCheckPeriod

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create db pool: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, c.PingTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}
	return pool, nil
}
