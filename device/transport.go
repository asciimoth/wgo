/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 AsciiMoth
 */

package device

import (
	"fmt"
	"sync"

	conn "github.com/asciimoth/batchudp"
	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/wgo/rwcancel"
)

type TransportID string

const DefaultTransportID TransportID = ""

type TransportConfig struct {
	Bind       conn.Bind
	ListenPort uint16
	Fwmark     uint32
}

type TransportInfo struct {
	ID         TransportID
	ListenPort uint16
	Fwmark     uint32
	Up         bool
	Generation uint64
}

type transportState struct {
	id         TransportID
	bind       conn.Bind
	port       uint16
	fwmark     uint32
	generation uint64
	up         bool

	netlinkCancel *rwcancel.RWCancel
	stopping      sync.WaitGroup
}

func (device *Device) initTransports(bind conn.Bind) {
	device.net.transports = make(map[TransportID]*transportState)
	if bind == nil {
		return
	}
	device.net.transports[DefaultTransportID] = &transportState{
		id:         DefaultTransportID,
		bind:       bind,
		generation: 1,
	}
}

func (device *Device) defaultTransportLocked() *transportState {
	st := device.net.transports[DefaultTransportID]
	if st == nil && device.net.bind != nil {
		st = &transportState{id: DefaultTransportID, bind: device.net.bind, port: device.net.port, fwmark: device.net.fwmark}
		device.net.transports[DefaultTransportID] = st
	}
	return st
}

func (device *Device) syncDefaultTransportAliasesLocked(st *transportState) {
	if st == nil {
		device.net.bind = nil
		device.net.port = 0
		device.net.netlinkCancel = nil
		return
	}
	device.net.bind = st.bind
	device.net.port = st.port
	device.net.fwmark = st.fwmark
	device.net.netlinkCancel = st.netlinkCancel
}

func validateTransportConfig(device *Device, id TransportID, cfg TransportConfig) error {
	if id == DefaultTransportID {
		return fmt.Errorf("%w: default transport uses bind compatibility methods", ErrTransportExists)
	}
	if cfg.Bind == nil {
		return fmt.Errorf("%w: bind is nil", ErrTransportUnavailable)
	}
	if cfg.Bind.BatchSize() > device.BatchSize() {
		return fmt.Errorf("%w: transport batch size %d exceeds device batch size %d", ErrBatchSizeTooLarge, cfg.Bind.BatchSize(), device.BatchSize())
	}
	return nil
}

func (device *Device) openTransportLocked(st *transportState) ([]conn.ReceiveFunc, error) {
	if st == nil || st.bind == nil || !device.isUp() {
		return nil, nil
	}
	if st.up {
		return nil, nil
	}

	recvFns, actualPort, err := st.bind.Open(st.port)
	if err != nil {
		st.port = 0
		return nil, err
	}
	st.port = actualPort
	if st.id == DefaultTransportID {
		st.netlinkCancel, err = device.startRouteListener(st.bind)
		if err != nil {
			_ = st.bind.Close()
			st.port = 0
			return nil, err
		}
	}
	if st.fwmark != 0 {
		if err := setBindMark(st.bind, st.fwmark); err != nil {
			_ = st.bind.Close()
			st.port = 0
			return nil, err
		}
	}
	st.up = true
	return recvFns, nil
}

func (device *Device) closeTransportLocked(st *transportState) error {
	if st == nil {
		return nil
	}
	var err error
	st.up = false
	if st.netlinkCancel != nil {
		_ = st.netlinkCancel.Cancel()
		st.netlinkCancel = nil
	}
	if st.bind != nil {
		err = gonnect.ClosedNetworkErrToNil(st.bind.Close())
	}
	return err
}

func (device *Device) startTransportReceiveRoutinesLocked(st *transportState, recvFns []conn.ReceiveFunc) {
	st.stopping.Add(len(recvFns))
	device.queue.decryption.wg.Add(len(recvFns))
	device.queue.handshake.wg.Add(len(recvFns))
	batchSize := st.bind.BatchSize()
	for _, fn := range recvFns {
		transport := st
		recv := fn
		recvName := fmt.Sprintf("%T", recv)
		device.spawnWorker(func() {
			device.routineReceiveIncoming(batchSize, recv, transport.id, &transport.stopping)
		}, "wgo: receive incoming "+recvName)
	}
}

func (device *Device) transportBindLocked(id TransportID) (conn.Bind, error) {
	st := device.net.transports[id]
	if st == nil || st.bind == nil {
		return nil, ErrTransportUnavailable
	}
	return st.bind, nil
}

func (device *Device) rebindPeerEndpointsForTransportLocked(id TransportID, st *transportState) error {
	device.peers.RLock()
	defer device.peers.RUnlock()
	for _, peer := range device.peers.keyMap {
		if err := peer.rebindEndpointForTransport(id, st.bind); err != nil {
			return err
		}
	}
	return nil
}

func (device *Device) AddTransport(id TransportID, cfg TransportConfig) error {
	if err := validateTransportConfig(device, id, cfg); err != nil {
		return err
	}

	device.state.Lock()
	defer device.state.Unlock()
	if device.isClosed() {
		return ErrDeviceClosed
	}

	device.net.Lock()
	if _, ok := device.net.transports[id]; ok {
		device.net.Unlock()
		return ErrTransportExists
	}

	st := &transportState{id: id, bind: cfg.Bind, port: cfg.ListenPort, fwmark: cfg.Fwmark, generation: 1}
	recvFns, err := device.openTransportLocked(st)
	if err != nil {
		device.net.Unlock()
		return err
	}
	if err := device.rebindPeerEndpointsForTransportLocked(id, st); err != nil {
		_ = device.closeTransportLocked(st)
		device.net.Unlock()
		st.stopping.Wait()
		return err
	}
	device.net.transports[id] = st
	device.startTransportReceiveRoutinesLocked(st, recvFns)
	device.signalRuntimeStats()
	device.net.Unlock()
	return nil
}

func (device *Device) ReplaceTransport(id TransportID, cfg TransportConfig) error {
	if id == DefaultTransportID {
		if cfg.Bind == nil {
			return device.DetachBind()
		}
		if cfg.Bind.BatchSize() > device.BatchSize() {
			return fmt.Errorf("%w: transport batch size %d exceeds device batch size %d", ErrBatchSizeTooLarge, cfg.Bind.BatchSize(), device.BatchSize())
		}
		device.net.Lock()
		device.net.port = cfg.ListenPort
		device.net.fwmark = cfg.Fwmark
		if st := device.defaultTransportLocked(); st != nil {
			st.port = cfg.ListenPort
			st.fwmark = cfg.Fwmark
		}
		device.net.Unlock()
		return device.ReplaceBind(cfg.Bind)
	}
	if err := validateTransportConfig(device, id, cfg); err != nil {
		return err
	}

	device.state.Lock()
	defer device.state.Unlock()
	if device.isClosed() {
		return ErrDeviceClosed
	}

	device.net.Lock()
	old := device.net.transports[id]
	if old == nil {
		device.net.Unlock()
		return ErrTransportNotFound
	}

	st := &transportState{
		id:         id,
		bind:       cfg.Bind,
		port:       cfg.ListenPort,
		fwmark:     cfg.Fwmark,
		generation: old.generation + 1,
	}
	recvFns, err := device.openTransportLocked(st)
	if err != nil {
		device.net.Unlock()
		return err
	}
	if err := device.rebindPeerEndpointsForTransportLocked(id, st); err != nil {
		_ = device.closeTransportLocked(st)
		device.net.Unlock()
		st.stopping.Wait()
		return err
	}
	device.net.transports[id] = st
	device.startTransportReceiveRoutinesLocked(st, recvFns)
	_ = device.closeTransportLocked(old)
	device.signalRuntimeStats()
	device.net.Unlock()
	old.stopping.Wait()
	return nil
}

func (device *Device) RemoveTransport(id TransportID) error {
	if id == DefaultTransportID {
		return device.DetachBind()
	}

	device.state.Lock()
	defer device.state.Unlock()
	if device.isClosed() {
		return ErrDeviceClosed
	}

	device.net.Lock()
	st := device.net.transports[id]
	if st == nil {
		device.net.Unlock()
		return ErrTransportNotFound
	}
	delete(device.net.transports, id)
	err := device.closeTransportLocked(st)
	device.signalRuntimeStats()
	device.net.Unlock()
	st.stopping.Wait()
	return err
}

func (device *Device) TransportInfo(id TransportID) (TransportInfo, bool) {
	device.net.RLock()
	defer device.net.RUnlock()
	st := device.net.transports[id]
	if st == nil {
		return TransportInfo{}, false
	}
	return TransportInfo{
		ID:         st.id,
		ListenPort: st.port,
		Fwmark:     st.fwmark,
		Up:         st.up,
		Generation: st.generation,
	}, true
}
