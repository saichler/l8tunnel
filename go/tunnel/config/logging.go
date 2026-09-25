package config

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// LogFile is the log block of server.yaml and agent.yaml.
type LogFile struct {
	// Format is text (default) or json.
	Format string `yaml:"format"`
	// Level is debug, info (default), warn or error.
	Level string `yaml:"level"`
}

// NewLogger builds the process logger.
func (l LogFile) NewLogger(w io.Writer) (*slog.Logger, error) {
	var level slog.Level
	switch strings.ToLower(l.Level) {
	case "", "info":
		level = slog.LevelInfo
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return nil, fmt.Errorf("log.level %q must be debug, info, warn or error", l.Level)
	}
	opts := &slog.HandlerOptions{Level: level}
	switch strings.ToLower(l.Format) {
	case "", "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	}
	return nil, fmt.Errorf("log.format %q must be text or json", l.Format)
}
