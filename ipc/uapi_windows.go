/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Modifications Copyright (C) 2026 AsciiMoth
 */

package ipc

import (
	"net"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/wgo/ipc/namedpipe"
	"golang.org/x/sys/windows"
)

// TODO: replace these with actual standard windows error numbers from the win package
const (
	IpcErrorIO        = -int64(5)
	IpcErrorProtocol  = -int64(71)
	IpcErrorInvalid   = -int64(22)
	IpcErrorPortInUse = -int64(98)
	IpcErrorUnknown   = -int64(55)
)

type UAPIListener struct {
	listener net.Listener // unix socket listener
	connNew  chan net.Conn
	connErr  chan error
	kqueueFd int
	keventFd int
}

func (l *UAPIListener) Accept() (net.Conn, error) {
	for {
		select {
		case conn := <-l.connNew:
			return conn, nil

		case err := <-l.connErr:
			return nil, err
		}
	}
}

func (l *UAPIListener) Close() error {
	return l.listener.Close()
}

func (l *UAPIListener) Addr() net.Addr {
	return l.listener.Addr()
}

var UAPISecurityDescriptor *windows.SECURITY_DESCRIPTOR

func init() {
	var err error
	UAPISecurityDescriptor, err = windows.SecurityDescriptorFromString("O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNRNX;;;HI)")
	if err != nil {
		panic(err)
	}
}

// UAPIListen creates a Windows UAPI listener.
//
// Long-lived listener workers are started with spawner when it is non-nil.
func UAPIListen(name string, spawner gonnect.Spawner) (net.Listener, error) {
	listener, err := (&namedpipe.ListenConfig{
		SecurityDescriptor: UAPISecurityDescriptor,
		Spawner:            spawner,
	}).Listen(`\\.\pipe\ProtectedPrefix\Administrators\WireGuard\` + name)
	if err != nil {
		return nil, err
	}

	uapi := &UAPIListener{
		listener: listener,
		connNew:  make(chan net.Conn, 1),
		connErr:  make(chan error, 1),
	}

	spawnWorker(spawner, func() {
		for {
			conn, err := uapi.listener.Accept()
			if err != nil {
				uapi.connErr <- err
				break
			}
			uapi.connNew <- conn
		}
	}, "wgo: UAPI accept loop")

	return uapi, nil
}
