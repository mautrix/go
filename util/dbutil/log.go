package dbutil

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/maulogger/v2"
)

type DatabaseLogger interface {
	QueryTiming(ctx context.Context, method, query string, args []interface{}, nrows int, duration time.Duration, err error)
	WarnUnsupportedVersion(current, compat, latest int)
	PrepareUpgrade(current, compat, latest int)
	DoUpgrade(from, to int, message string, txn bool)
	// Deprecated: legacy warning method, return errors instead
	Warn(msg string, args ...interface{})
}

type noopLogger struct{}

var NoopLogger DatabaseLogger = &noopLogger{}

func (n noopLogger) WarnUnsupportedVersion(_, _, _ int)   {}
func (n noopLogger) PrepareUpgrade(_, _, _ int)           {}
func (n noopLogger) DoUpgrade(_, _ int, _ string, _ bool) {}
func (n noopLogger) Warn(msg string, args ...interface{}) {}

func (n noopLogger) QueryTiming(_ context.Context, _, _ string, _ []interface{}, _ int, _ time.Duration, _ error) {
}

type mauLogger struct {
	l maulogger.Logger
}

// Deprecated: Use zerolog instead
func MauLogger(log maulogger.Logger) DatabaseLogger {
	return &mauLogger{l: log}
}

func (m mauLogger) WarnUnsupportedVersion(current, compat, latest int) {
	m.l.Warnfln("Unsupported database schema version: currently on v%d (compatible down to v%d), latest known: v%d - continuing anyway", current, compat, latest)
}

func (m mauLogger) PrepareUpgrade(current, compat, latest int) {
	m.l.Infofln("Database currently on v%d (compat: v%d), latest known: v%d", current, compat, latest)
}

func (m mauLogger) DoUpgrade(from, to int, message string, _ bool) {
	m.l.Infofln("Upgrading database from v%d to v%d: %s", from, to, message)
}

func (m mauLogger) QueryTiming(_ context.Context, method, query string, _ []interface{}, _ int, duration time.Duration, _ error) {
	if duration > 1*time.Second {
		m.l.Warnfln("%s(%s) took %.3f seconds", method, query, duration.Seconds())
	}
}

func (m mauLogger) Warn(msg string, args ...interface{}) {
	m.l.Warnfln(msg, args...)
}

type zeroLogger struct {
	l *zerolog.Logger
	ZeroLogSettings
}

type ZeroLogSettings struct {
	CallerSkipFrame int
	Caller          bool
}

func ZeroLogger(log zerolog.Logger, cfg ...ZeroLogSettings) DatabaseLogger {
	return ZeroLoggerPtr(&log, cfg...)
}

func ZeroLoggerPtr(log *zerolog.Logger, cfg ...ZeroLogSettings) DatabaseLogger {
	wrapped := &zeroLogger{l: log}
	if len(cfg) > 0 {
		wrapped.ZeroLogSettings = cfg[0]
	} else {
		wrapped.ZeroLogSettings = ZeroLogSettings{
			CallerSkipFrame: 2, // Skip LoggingExecable.ExecContext and zeroLogger.QueryTiming
			Caller:          true,
		}
	}
	return wrapped
}

func (z zeroLogger) WarnUnsupportedVersion(current, compat, latest int) {
	z.l.Warn().
		Int("current_version", current).
		Int("oldest_compatible_version", compat).
		Int("latest_known_version", latest).
		Msg("Unsupported database schema version, continuing anyway")
}

func (z zeroLogger) PrepareUpgrade(current, compat, latest int) {
	evt := z.l.Info().
		Int("current_version", current).
		Int("oldest_compatible_version", compat).
		Int("latest_known_version", latest)
	if current >= latest {
		evt.Msg("Database is up to date")
	} else {
		evt.Msg("Preparing to update database schema")
	}
}

func (z zeroLogger) DoUpgrade(from, to int, message string, txn bool) {
	z.l.Info().
		Int("from", from).
		Int("to", to).
		Bool("single_txn", txn).
		Str("description", message).
		Msg("Upgrading database")
}

var whitespaceRegex = regexp.MustCompile(`\s+`)

func (z zeroLogger) QueryTiming(ctx context.Context, method, query string, args []interface{}, nrows int, duration time.Duration, err error) {
	log := zerolog.Ctx(ctx)
	if log.GetLevel() == zerolog.Disabled || log == zerolog.DefaultContextLogger {
		log = z.l
	}
	if log.GetLevel() != zerolog.TraceLevel && duration < 1*time.Second {
		return
	}
	if nrows > -1 {
		rowLog := log.With().Int("rows", nrows).Logger()
		log = &rowLog
	}
	query = strings.TrimSpace(whitespaceRegex.ReplaceAllLiteralString(query, " "))
	log.Trace().
		Err(err).
		Int64("duration_µs", duration.Microseconds()).
		Str("method", method).
		Str("query", query).
		Interface("query_args", args).
		Msg("Query")
	if duration >= 1*time.Second {
		evt := log.Warn().
			Float64("duration_seconds", duration.Seconds()).
			Str("method", method).
			Str("query", query)
		if z.Caller {
			evt = evt.Caller(z.CallerSkipFrame)
		}
		evt.Msg("Query took long")
	}
}

func (z zeroLogger) Warn(msg string, args ...interface{}) {
	z.l.Warn().Msgf(msg, args...)
}
