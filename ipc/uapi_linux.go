/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Modifications Copyright (C) 2026 AsciiMoth
 */

package ipc

import (
	"net"
	"os"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/wgo/rwcancel"
	"golang.org/x/sys/unix"
)

type UAPIListener struct {
	listener        net.Listener // unix socket listener
	connNew         chan net.Conn
	connErr         chan error
	inotifyFd       int
	inotifyRWCancel *rwcancel.RWCancel
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
	err1 := unix.Close(l.inotifyFd)
	err2 := l.inotifyRWCancel.Cancel()
	err3 := l.listener.Close()
	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	return err3
}

func (l *UAPIListener) Addr() net.Addr {
	return l.listener.Addr()
}

// UAPIListen creates a UAPI listener from file.
//
// Long-lived listener workers are started with spawner when it is non-nil.
func UAPIListen(name string, file *os.File, spawner gonnect.Spawner) (net.Listener, error) {
	// wrap file in listener

	listener, err := net.FileListener(file)
	if err != nil {
		return nil, err
	}

	if unixListener, ok := listener.(*net.UnixListener); ok {
		unixListener.SetUnlinkOnClose(true)
	}

	uapi := &UAPIListener{
		listener: listener,
		connNew:  make(chan net.Conn, 1),
		connErr:  make(chan error, 1),
	}

	// watch for deletion of socket

	socketPath := sockPath(name)

	uapi.inotifyFd, err = unix.InotifyInit()
	if err != nil {
		return nil, err
	}

	_, err = unix.InotifyAddWatch(
		uapi.inotifyFd,
		socketPath,
		unix.IN_ATTRIB|
			unix.IN_DELETE|
			unix.IN_DELETE_SELF,
	)

	if err != nil {
		return nil, err
	}

	uapi.inotifyRWCancel, err = rwcancel.NewRWCancel(uapi.inotifyFd)
	if err != nil {
		_ = unix.Close(uapi.inotifyFd)
		return nil, err
	}

	spawnWorker(spawner, func() {
		var buf [0]byte
		for {
			defer uapi.inotifyRWCancel.Close()
			// start with lstat to avoid race condition
			if _, err := os.Lstat(socketPath); os.IsNotExist(err) {
				uapi.connErr <- err
				return
			}
			_, err := uapi.inotifyRWCancel.Read(buf[:])
			if err != nil {
				uapi.connErr <- err
				return
			}
		}
	}, "wgo: UAPI socket deletion watcher")

	// watch for new connections

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
