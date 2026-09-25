package certs

import (
	"context"
	"log/slog"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// newZapLogger returns a zap logger (which certmagic requires) that writes
// to logger, so ACME activity shows up in the relay's own logs.
func newZapLogger(logger *slog.Logger) *zap.Logger {
	return zap.New(&slogCore{logger: logger})
}

// slogCore is a zapcore.Core that forwards entries to slog.
type slogCore struct {
	logger *slog.Logger
	fields []zapcore.Field
}

func slogLevel(l zapcore.Level) slog.Level {
	switch {
	case l >= zapcore.ErrorLevel:
		return slog.LevelError
	case l >= zapcore.WarnLevel:
		return slog.LevelWarn
	case l >= zapcore.InfoLevel:
		return slog.LevelInfo
	}
	return slog.LevelDebug
}

func (c *slogCore) Enabled(l zapcore.Level) bool {
	return c.logger.Enabled(context.Background(), slogLevel(l))
}

func (c *slogCore) With(fields []zapcore.Field) zapcore.Core {
	all := make([]zapcore.Field, 0, len(c.fields)+len(fields))
	all = append(all, c.fields...)
	all = append(all, fields...)
	return &slogCore{logger: c.logger, fields: all}
}

func (c *slogCore) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(e.Level) {
		return ce.AddCore(e, c)
	}
	return ce
}

func (c *slogCore) Write(e zapcore.Entry, fields []zapcore.Field) error {
	enc := zapcore.NewMapObjectEncoder()
	for _, f := range c.fields {
		f.AddTo(enc)
	}
	for _, f := range fields {
		f.AddTo(enc)
	}
	args := make([]interface{}, 0, 2*len(enc.Fields)+2)
	if e.LoggerName != "" {
		args = append(args, "logger", e.LoggerName)
	}
	for k, v := range enc.Fields {
		args = append(args, k, v)
	}
	c.logger.Log(context.Background(), slogLevel(e.Level), e.Message, args...)
	return nil
}

func (c *slogCore) Sync() error {
	return nil
}
