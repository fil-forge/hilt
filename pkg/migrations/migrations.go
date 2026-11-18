// Package migrations embeds the hilt Postgres migrations and exposes a runner
// that applies them via goose.
package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"go.uber.org/zap"
)

//go:embed sql/*.sql
var FS embed.FS

// Up applies all pending migrations embedded in FS to the database behind pool.
func Up(ctx context.Context, pool *pgxpool.Pool, logger *zap.Logger) error {
	db := stdlib.OpenDBFromPool(pool)
	defer db.Close()
	return runUp(ctx, db, logger)
}

// UpDB is equivalent to Up but takes a *sql.DB directly. Useful in tests where
// a pool is not available.
func UpDB(ctx context.Context, db *sql.DB, logger *zap.Logger) error {
	return runUp(ctx, db, logger)
}

// UpTo applies the migrations up to and including version, leaving later ones
// pending. It is how a test gets the schema as of one migration.
func UpTo(ctx context.Context, db *sql.DB, version int64, logger *zap.Logger) error {
	if err := configure(logger); err != nil {
		return err
	}
	if err := goose.UpToContext(ctx, db, "sql", version); err != nil {
		return fmt.Errorf("running goose migrations: %w", err)
	}
	return nil
}

// Down rolls back the most recently applied migration.
func Down(ctx context.Context, db *sql.DB, logger *zap.Logger) error {
	if err := configure(logger); err != nil {
		return err
	}
	if err := goose.DownContext(ctx, db, "sql"); err != nil {
		return fmt.Errorf("rolling back goose migration: %w", err)
	}
	return nil
}

func runUp(ctx context.Context, db *sql.DB, logger *zap.Logger) error {
	if err := configure(logger); err != nil {
		return err
	}
	if err := goose.UpContext(ctx, db, "sql"); err != nil {
		return fmt.Errorf("running goose migrations: %w", err)
	}
	return nil
}

func configure(logger *zap.Logger) error {
	goose.SetBaseFS(FS)
	goose.SetLogger(&zapGooseLogger{logger: logger})
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("setting goose dialect: %w", err)
	}
	return nil
}

type zapGooseLogger struct {
	logger *zap.Logger
}

func (l *zapGooseLogger) Fatalf(format string, v ...interface{}) {
	l.logger.Sugar().Fatalf(format, v...)
}

func (l *zapGooseLogger) Printf(format string, v ...interface{}) {
	l.logger.Sugar().Infof(format, v...)
}
