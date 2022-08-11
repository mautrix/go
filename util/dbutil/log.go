package dbutil

import (
	"context"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/maulogger/v2"
)

type DatabaseLogger interface {
	QueryTiming(ctx context.Context, method, query string, duration time.Duration)
	WarnUnsupportedVersion(current, latest int)
	PrepareUpgrade(current, latest int)
	DoUpgrade(from, to int, message string)
	// Deprecated: legacy warning method, return errors instead
	Warn(msg string, args ...interface{})
}

type noopLogger struct{}

var NoopLogger DatabaseLogger = &noopLogger{}

func (n noopLogger) WarnUnsupportedVersion(_, _ int)                             {}
func (n noopLogger) PrepareUpgrade(_, _ int)                                     {}
func (n noopLogger) DoUpgrade(_, _ int, _ string)                                {}
func (n noopLogger) QueryTiming(_ context.Context, _, _ string, _ time.Duration) {}
func (n noopLogger) Warn(msg string, args ...interface{})                        {}

type mauLogger struct {
	l maulogger.Logger
}

func MauLogger(log maulogger.Logger) DatabaseLogger {
	return &mauLogger{l: log}
}

func (m mauLogger) WarnUnsupportedVersion(current, latest int) {
	m.l.Warnfln("Unsupported database schema version: currently on v%d, latest known: v%d - continuing anyway", current, latest)
}

func (m mauLogger) PrepareUpgrade(current, latest int) {
	m.l.Infofln("Database currently on v%d, latest: v%d", current, latest)
}

func (m mauLogger) DoUpgrade(from, to int, message string) {
	m.l.Infofln("Upgrading database from v%d to v%d: %s", from, to, message)
}

func (m mauLogger) QueryTiming(_ context.Context, method, query string, duration time.Duration) {
	if duration > 1*time.Second {
		m.l.Warnfln("%s(%s) took %.3f seconds", method, query, duration.Seconds())
	}
}

func (m mauLogger) Warn(msg string, args ...interface{}) {
	m.l.Warnfln(msg, args...)
}

type zeroLogger struct {
	l *zerolog.Logger
}

func ZeroLogger(log zerolog.Logger) DatabaseLogger {
	return &zeroLogger{l: &log}
}

func (z zeroLogger) WarnUnsupportedVersion(current, latest int) {
	z.l.Warn().
		Int("current_db_version", current).
		Int("latest_known_version", latest).
		Msg("Unsupported database schema version, continuing anyway")
}

func (z zeroLogger) PrepareUpgrade(current, latest int) {
	evt := z.l.Info().
		Int("current_db_version", current).
		Int("latest_known_version", latest)
	if current == latest {
		evt.Msg("Database is up to date")
	} else {
		evt.Msg("Preparing to update database schema")
	}
}

func (z zeroLogger) DoUpgrade(from, to int, message string) {
	z.l.Info().
		Int("from", from).
		Int("to", to).
		Str("description", message).
		Msg("Upgrading database")
}

func (z zeroLogger) QueryTiming(ctx context.Context, method, query string, duration time.Duration) {
	var evt *zerolog.Event
	var msg string
	log := zerolog.Ctx(ctx)
	if log.GetLevel() == zerolog.Disabled {
		log = z.l
	}
	if duration > 1*time.Second {
		evt = log.Warn()
		msg = "Unusually long query"
	} else {
		evt = log.Trace()
		msg = "Query duration"
	}
	evt.
		Int64("duration_µs", duration.Microseconds()).
		Str("method", method).
		Str("query", query).
		Msg(msg)
}

func (z zeroLogger) Warn(msg string, args ...interface{}) {
	z.l.Warn().Msgf(msg, args...)
}
