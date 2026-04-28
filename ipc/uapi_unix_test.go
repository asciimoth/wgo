//go:build linux || darwin || freebsd || openbsd

package ipc

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withSocketDirectory(tb testing.TB) string {
	tb.Helper()

	dir := tb.TempDir()
	old := socketDirectory
	socketDirectory = dir
	tb.Cleanup(func() {
		socketDirectory = old
	})
	return dir
}

func TestSockPathUsesSocketDirectory(t *testing.T) {
	dir := withSocketDirectory(t)
	got := sockPath("wg-test0")
	want := filepath.Join(dir, "wg-test0.sock")
	if got != want {
		t.Fatalf("sockPath() = %q, want %q", got, want)
	}
}

func TestUAPIOpenRefusesActiveSocket(t *testing.T) {
	withSocketDirectory(t)

	file, err := UAPIOpen("wg0")
	if err != nil {
		t.Fatalf("UAPIOpen() error = %v", err)
	}
	t.Cleanup(func() { _ = file.Close() })

	listener, err := net.FileListener(file)
	if err != nil {
		t.Fatalf("net.FileListener() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	if _, err := os.Stat(sockPath("wg0")); err != nil {
		t.Fatalf("socket path stat error = %v", err)
	}

	other, err := UAPIOpen("wg0")
	if other != nil {
		_ = other.Close()
	}
	if err == nil {
		t.Fatal("UAPIOpen() succeeded for active socket, want error")
	}
	if !strings.Contains(err.Error(), "unix socket in use") {
		t.Fatalf("UAPIOpen() error = %q, want active socket error", err)
	}
}

func TestUAPIOpenRemovesStaleSocket(t *testing.T) {
	withSocketDirectory(t)

	if err := os.WriteFile(sockPath("wg1"), []byte("stale"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	if _, err := os.Stat(sockPath("wg1")); err != nil {
		t.Fatalf("stale path stat error = %v", err)
	}

	file, err := UAPIOpen("wg1")
	if err != nil {
		t.Fatalf("UAPIOpen() error = %v", err)
	}
	t.Cleanup(func() { _ = file.Close() })

	listener, err := net.FileListener(file)
	if err != nil {
		t.Fatalf("net.FileListener() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	if got := listener.Addr().String(); got != sockPath("wg1") {
		t.Fatalf("listener.Addr().String() = %q, want %q", got, sockPath("wg1"))
	}
}
