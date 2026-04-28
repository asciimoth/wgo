//go:build !windows && !wasm

package rwcancel

import (
	"errors"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestRetryAfterError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "eagain", err: syscall.EAGAIN, want: true},
		{name: "eintr", err: syscall.EINTR, want: true},
		{name: "wrapped eagain", err: os.NewSyscallError("read", syscall.EAGAIN), want: true},
		{name: "other", err: syscall.EBADF, want: false},
		{name: "nil", err: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RetryAfterError(tt.err); got != tt.want {
				t.Fatalf("RetryAfterError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestRWCancelRead(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	t.Cleanup(func() { _ = writer.Close() })

	rw, err := NewRWCancel(int(reader.Fd()))
	if err != nil {
		t.Fatalf("NewRWCancel() error = %v", err)
	}
	t.Cleanup(rw.Close)

	done := make(chan error, 1)
	go func() {
		_, err := writer.Write([]byte("ok"))
		done <- err
	}()

	var buf [2]byte
	n, err := rw.Read(buf[:])
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if n != len(buf) || string(buf[:]) != "ok" {
		t.Fatalf("Read() = (%d, %q), want (%d, %q)", n, string(buf[:]), len(buf), "ok")
	}
	if err := <-done; err != nil {
		t.Fatalf("writer.Write() error = %v", err)
	}
}

func TestRWCancelWrite(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	t.Cleanup(func() { _ = writer.Close() })

	rw, err := NewRWCancel(int(writer.Fd()))
	if err != nil {
		t.Fatalf("NewRWCancel() error = %v", err)
	}
	t.Cleanup(rw.Close)

	n, err := rw.Write([]byte("ok"))
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != 2 {
		t.Fatalf("Write() n = %d, want 2", n)
	}

	var buf [2]byte
	n, err = reader.Read(buf[:])
	if err != nil {
		t.Fatalf("reader.Read() error = %v", err)
	}
	if n != len(buf) || string(buf[:]) != "ok" {
		t.Fatalf("reader.Read() = (%d, %q), want (%d, %q)", n, string(buf[:]), len(buf), "ok")
	}
}

func TestRWCancelReadUnblocksOnCancel(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	t.Cleanup(func() { _ = writer.Close() })

	rw, err := NewRWCancel(int(reader.Fd()))
	if err != nil {
		t.Fatalf("NewRWCancel() error = %v", err)
	}
	t.Cleanup(rw.Close)

	errCh := make(chan error, 1)
	go func() {
		var buf [1]byte
		_, err := rw.Read(buf[:])
		errCh <- err
	}()

	time.Sleep(20 * time.Millisecond)

	if err := rw.Cancel(); err != nil {
		t.Fatalf("Cancel() error = %v", err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Read() error = %v, want %v", err, os.ErrClosed)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Read() did not unblock after Cancel()")
	}
}
