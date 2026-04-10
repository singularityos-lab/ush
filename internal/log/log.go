// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package log provides structured logging for ush via slog.
package log

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

var defaultLogger *slog.Logger

func init() {
	defaultLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
}

// Init initializes the global logger with the specified level.
func Init(level string, w io.Writer) {
	if w == nil {
		w = os.Stderr
	}
	l := parseLevel(level)
	defaultLogger = slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level:     l,
		AddSource: l == slog.LevelDebug,
	}))
	slog.SetDefault(defaultLogger)
}

// Debug logs at debug level.
func Debug(msg string, args ...any) {
	defaultLogger.Debug(msg, args...)
}

// Info logs at info level.
func Info(msg string, args ...any) {
	defaultLogger.Info(msg, args...)
}

// Warn logs at warning level.
func Warn(msg string, args ...any) {
	defaultLogger.Warn(msg, args...)
}

// Error logs at error level.
func Error(msg string, args ...any) {
	defaultLogger.Error(msg, args...)
}

// With returns a logger with additional attributes.
func With(args ...any) *slog.Logger {
	return defaultLogger.With(args...)
}

// Logger returns the global logger.
func Logger() *slog.Logger {
	return defaultLogger
}

// LogCtx logs with context.
func LogCtx(ctx context.Context, level slog.Level, msg string, args ...any) {
	defaultLogger.Log(ctx, level, msg, args...)
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
