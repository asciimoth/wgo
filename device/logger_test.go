package device

import (
	"io"
	"os"
	"strings"
	"testing"
)

func captureStdout(tb testing.TB, fn func()) string {
	tb.Helper()

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		tb.Fatalf("os.Pipe() error = %v", err)
	}
	os.Stdout = w
	defer func() {
		os.Stdout = old
	}()

	fn()

	if err := w.Close(); err != nil {
		tb.Fatalf("Close() error = %v", err)
	}

	out, err := io.ReadAll(r)
	if err != nil {
		tb.Fatalf("ReadAll() error = %v", err)
	}
	if err := r.Close(); err != nil {
		tb.Fatalf("Close() error = %v", err)
	}
	return string(out)
}

func TestNewLoggerLevels(t *testing.T) {
	out := captureStdout(t, func() {
		logger := NewLogger(LogLevelInfo, "test: ")
		logger.Debug("debug hidden")
		logger.Infof("hello %s", "info")
		logger.Warn("warn shown")
		logger.Err("err shown")
	})

	if strings.Contains(out, "debug hidden") {
		t.Fatalf("debug log unexpectedly present in %q", out)
	}
	for _, want := range []string{
		"INFO: test:",
		"hello info",
		"WARN: test:",
		"warn shown",
		"ERROR: test:",
		"err shown",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("log output %q missing %q", out, want)
		}
	}
}

func TestNopLoggerIsSilent(t *testing.T) {
	out := captureStdout(t, func() {
		var logger Logger = NopLogger{}
		logger.Debug("debug")
		logger.Info("info")
		logger.Warn("warn")
		logger.Err("err")
	})

	if out != "" {
		t.Fatalf("NopLogger output = %q, want empty", out)
	}
}
