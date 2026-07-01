/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 AsciiMoth
 */

package device

import (
	"fmt"
	"sync"
	"testing"
)

type recordingLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *recordingLogger) append(args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprint(args...))
}

func (l *recordingLogger) appendf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *recordingLogger) Debug(args ...any)                 { l.append(args...) }
func (l *recordingLogger) Debugf(format string, args ...any) { l.appendf(format, args...) }
func (l *recordingLogger) Info(args ...any)                  { l.append(args...) }
func (l *recordingLogger) Infof(format string, args ...any)  { l.appendf(format, args...) }
func (l *recordingLogger) Warn(args ...any)                  { l.append(args...) }
func (l *recordingLogger) Warnf(format string, args ...any)  { l.appendf(format, args...) }
func (l *recordingLogger) Err(args ...any)                   { l.append(args...) }
func (l *recordingLogger) Errf(format string, args ...any)   { l.appendf(format, args...) }
func (l *recordingLogger) Fatal(args ...any)                 { l.append(args...) }
func (l *recordingLogger) Fatalf(format string, args ...any) { l.appendf(format, args...) }

func (l *recordingLogger) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.lines)
}

func TestLogWorkerLifecycleSuppressedWhenSpawnerConfigured(t *testing.T) {
	logger := &recordingLogger{}
	device := &Device{log: logger, spawner: &recordingSpawner{}}

	device.logWorkerLifecyclef("Routine: %s - started", "test")

	if got := logger.len(); got != 0 {
		t.Fatalf("logger received %d lines, want none", got)
	}
}

func TestLogWorkerLifecyclePreservedWithoutSpawner(t *testing.T) {
	logger := &recordingLogger{}
	device := &Device{log: logger}

	device.logWorkerLifecyclef("Routine: %s - started", "test")

	if got := logger.len(); got != 1 {
		t.Fatalf("logger received %d lines, want one", got)
	}
}
