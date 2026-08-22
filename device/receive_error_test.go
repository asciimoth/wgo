/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 AsciiMoth
 */

package device

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	conn "github.com/asciimoth/batchudp"
)

type timeoutReceiveError struct{}

func (timeoutReceiveError) Error() string   { return "timeout" }
func (timeoutReceiveError) Timeout() bool   { return true }
func (timeoutReceiveError) Temporary() bool { return true }

type temporaryReceiveError struct{}

func (temporaryReceiveError) Error() string   { return "temporary" }
func (temporaryReceiveError) Timeout() bool   { return false }
func (temporaryReceiveError) Temporary() bool { return true }

func TestReceiveErrorShouldRecover(t *testing.T) {
	if ReceiveErrorShouldRecover(nil) {
		t.Fatal("ReceiveErrorShouldRecover(nil) = true")
	}
	if ReceiveErrorShouldRecover(net.ErrClosed) {
		t.Fatal("ReceiveErrorShouldRecover(net.ErrClosed) = true")
	}
	if ReceiveErrorShouldRecover(timeoutReceiveError{}) {
		t.Fatal("ReceiveErrorShouldRecover(timeout) = true")
	}
	if ReceiveErrorShouldRecover(temporaryReceiveError{}) {
		t.Fatal("ReceiveErrorShouldRecover(temporary) = true")
	}
	if !ReceiveErrorShouldRecover(errors.New("receive failed")) {
		t.Fatal("ReceiveErrorShouldRecover(unexpected) = false")
	}
}

func TestReceiveErrorSubscriptionReportsFatalError(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
	t.Cleanup(dev.Close)

	updates := make(chan ReceiveError, 1)
	unsubscribe := dev.SubscribeReceiveErrors(func(receiveError ReceiveError) {
		updates <- receiveError
	})
	defer unsubscribe()

	receiveErr := errors.New("receive failed")
	recv := conn.ReceiveFunc(func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		return 0, receiveErr
	})
	runReceiveRoutine(t, dev, recv)

	select {
	case receiveError := <-updates:
		if receiveError.Name == "" {
			t.Fatal("ReceiveError.Name is empty")
		}
		if !errors.Is(receiveError.Err, receiveErr) {
			t.Fatalf("ReceiveError.Err = %v, want %v", receiveError.Err, receiveErr)
		}
		if !receiveError.Fatal {
			t.Fatal("ReceiveError.Fatal = false, want true")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for receive error")
	}
}

func TestReceiveErrorSubscriptionReportsTemporaryErrorAsNonFatal(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
	t.Cleanup(dev.Close)

	updates := make(chan ReceiveError, 1)
	unsubscribe := dev.SubscribeReceiveErrors(func(receiveError ReceiveError) {
		updates <- receiveError
	})
	defer unsubscribe()

	recvCalls := 0
	recv := conn.ReceiveFunc(func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		recvCalls++
		if recvCalls == 1 {
			return 0, temporaryReceiveError{}
		}
		return 0, net.ErrClosed
	})
	runReceiveRoutine(t, dev, recv)

	if recvCalls != 2 {
		t.Fatalf("receive calls = %d, want 2", recvCalls)
	}
	select {
	case receiveError := <-updates:
		if _, ok := receiveError.Err.(temporaryReceiveError); !ok {
			t.Fatalf("ReceiveError.Err = %T, want temporaryReceiveError", receiveError.Err)
		}
		if receiveError.Fatal {
			t.Fatal("ReceiveError.Fatal = true, want false")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for receive error")
	}
}

func TestReceiveErrorSubscriptionSkipsClosedError(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
	t.Cleanup(dev.Close)

	updates := make(chan ReceiveError, 1)
	unsubscribe := dev.SubscribeReceiveErrors(func(receiveError ReceiveError) {
		updates <- receiveError
	})
	defer unsubscribe()

	recv := conn.ReceiveFunc(func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		return 0, net.ErrClosed
	})
	runReceiveRoutine(t, dev, recv)

	select {
	case receiveError := <-updates:
		t.Fatalf("unexpected receive error: %+v", receiveError)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestRoutineReceiveIncomingRejectsInvalidBindBatch(t *testing.T) {
	tests := []struct {
		name    string
		recv    conn.ReceiveFunc
		wantErr string
	}{
		{
			name: "negative count",
			recv: conn.ReceiveFunc(func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
				return -1, nil
			}),
			wantErr: "invalid packet count -1",
		},
		{
			name: "too large count",
			recv: conn.ReceiveFunc(func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
				return 2, nil
			}),
			wantErr: "invalid packet count 2",
		},
		{
			name: "too large size",
			recv: conn.ReceiveFunc(func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
				sizes[0] = len(packets[0]) + 1
				eps[0] = fakeBindEndpoint{bindID: "bind0", dst: "127.0.0.1:51820"}
				return 1, nil
			}),
			wantErr: "invalid packet size",
		},
		{
			name: "missing endpoint",
			recv: conn.ReceiveFunc(func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
				sizes[0] = MinMessageSize
				return 1, nil
			}),
			wantErr: "missing endpoint",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
			t.Cleanup(dev.Close)

			updates := make(chan ReceiveError, 1)
			unsubscribe := dev.SubscribeReceiveErrors(func(receiveError ReceiveError) {
				updates <- receiveError
			})
			defer unsubscribe()

			runReceiveRoutine(t, dev, tt.recv)

			select {
			case receiveError := <-updates:
				if !receiveError.Fatal {
					t.Fatal("ReceiveError.Fatal = false, want true")
				}
				if receiveError.Err == nil || !strings.Contains(receiveError.Err.Error(), tt.wantErr) {
					t.Fatalf("ReceiveError.Err = %v, want %q", receiveError.Err, tt.wantErr)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("timeout waiting for receive error")
			}
		})
	}
}

func runReceiveRoutine(tb testing.TB, dev *Device, recv conn.ReceiveFunc) {
	tb.Helper()

	dev.net.stopping.Add(1)
	dev.queue.decryption.wg.Add(1)
	dev.queue.handshake.wg.Add(1)
	done := make(chan struct{})
	go func() {
		dev.RoutineReceiveIncoming(1, recv)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		tb.Fatal("timeout waiting for receive routine")
	}
}
