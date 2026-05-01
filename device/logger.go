/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Modifications Copyright (C) 2026 AsciiMoth
 */

package device

import (
	"fmt"
	"log"
	"os"
)

// Logger provides logging for a Device.
// Implementations must be safe for concurrent use.
type Logger interface {
	Debug(args ...any)
	Debugf(format string, args ...any)
	Info(args ...any)
	Infof(format string, args ...any)
	Warn(args ...any)
	Warnf(format string, args ...any)
	Err(args ...any)
	Errf(format string, args ...any)
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

// Log levels for use with NewLogger.
type LogLevel int

const (
	LogLevelSilent LogLevel = iota
	LogLevelError
	LogLevelWarn
	LogLevelInfo
	LogLevelDebug
)

// Backward-compatible alias for the old verbose level.
const LogLevelVerbose = LogLevelDebug

// NopLogger discards all log output.
type NopLogger struct{}

func (NopLogger) Debug(args ...any)                 {}
func (NopLogger) Debugf(format string, args ...any) {}
func (NopLogger) Info(args ...any)                  {}
func (NopLogger) Infof(format string, args ...any)  {}
func (NopLogger) Warn(args ...any)                  {}
func (NopLogger) Warnf(format string, args ...any)  {}
func (NopLogger) Err(args ...any)                   {}
func (NopLogger) Errf(format string, args ...any)   {}
func (NopLogger) Fatal(args ...any)                 {}
func (NopLogger) Fatalf(format string, args ...any) {}

// DefaultLogger writes log lines to stdout with a severity prefix.
type DefaultLogger struct {
	level   LogLevel
	loggers map[LogLevel]*log.Logger
}

// NewLogger constructs the default stdout logger.
// It logs at the specified log level and above.
// It decorates log lines with the log level, date, time, and prepend.
func NewLogger(level LogLevel, prepend string) Logger {
	makeLogger := func(prefix string) *log.Logger {
		return log.New(os.Stdout, prefix+": "+prepend, log.Ldate|log.Ltime)
	}
	return &DefaultLogger{
		level: level,
		loggers: map[LogLevel]*log.Logger{
			LogLevelError: makeLogger("ERROR"),
			LogLevelWarn:  makeLogger("WARN"),
			LogLevelInfo:  makeLogger("INFO"),
			LogLevelDebug: makeLogger("DEBUG"),
		},
	}
}

func loggerOrNop(logger Logger) Logger {
	if logger == nil {
		return NopLogger{}
	}
	return logger
}

func (l *DefaultLogger) enabled(level LogLevel) bool {
	return l != nil && l.level >= level && level != LogLevelSilent
}

func (l *DefaultLogger) output(level LogLevel, message string) {
	if !l.enabled(level) {
		return
	}
	_ = l.loggers[level].Output(3, message)
}

func (l *DefaultLogger) outputf(level LogLevel, format string, args ...any) {
	if !l.enabled(level) {
		return
	}
	_ = l.loggers[level].Output(3, fmt.Sprintf(format, args...))
}

func (l *DefaultLogger) Debug(args ...any) { l.output(LogLevelDebug, fmt.Sprint(args...)) }
func (l *DefaultLogger) Debugf(format string, args ...any) {
	l.outputf(LogLevelDebug, format, args...)
}

func (l *DefaultLogger) Info(args ...any) { l.output(LogLevelInfo, fmt.Sprint(args...)) }
func (l *DefaultLogger) Infof(format string, args ...any) {
	l.outputf(LogLevelInfo, format, args...)
}

func (l *DefaultLogger) Warn(args ...any) { l.output(LogLevelWarn, fmt.Sprint(args...)) }
func (l *DefaultLogger) Warnf(format string, args ...any) {
	l.outputf(LogLevelWarn, format, args...)
}

func (l *DefaultLogger) Err(args ...any) { l.output(LogLevelError, fmt.Sprint(args...)) }
func (l *DefaultLogger) Errf(format string, args ...any) {
	l.outputf(LogLevelError, format, args...)
}

func (l *DefaultLogger) Fatal(args ...any) {
	l.output(LogLevelError, fmt.Sprint(args...))
	os.Exit(1)
}

func (l *DefaultLogger) Fatalf(format string, args ...any) {
	l.outputf(LogLevelError, format, args...)
	os.Exit(1)
}
