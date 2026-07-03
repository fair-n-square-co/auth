package logger

import (
	"log/slog"
	"os"
)

// LogConfig controls how the default slog logger is configured.
type LogConfig struct {
	Level  slog.Level
	Format string // "text" or "json"
}

// InitLogger builds a slog handler from config and installs it as the default.
func InitLogger(config *LogConfig) {
	var handler slog.Handler
	switch config.Format {
	case "text":
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: config.Level,
		})
	default:
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: config.Level,
		})
	}
	slog.SetDefault(slog.New(handler))
}

// GetLogger returns the default slog logger.
func GetLogger() *slog.Logger {
	return slog.Default()
}
