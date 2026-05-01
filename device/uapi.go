/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Modifications Copyright (C) 2026 AsciiMoth
 */

package device

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/asciimoth/wgo/ipc"
)

type IPCError struct {
	code int64 // error code
	err  error // underlying/wrapped error
}

func (s IPCError) Error() string {
	return fmt.Sprintf("IPC error %d: %v", s.code, s.err)
}

func (s IPCError) Unwrap() error {
	return s.err
}

func (s IPCError) ErrorCode() int64 {
	return s.code
}

func ipcErrorf(code int64, msg string, args ...any) *IPCError {
	return &IPCError{code: code, err: fmt.Errorf(msg, args...)}
}

var byteBufferPool = &sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

// IpcGetOperation implements the WireGuard configuration protocol "get" operation.
// See https://www.wireguard.com/xplatform/#configuration-protocol for details.
func (device *Device) IpcGetOperation(w io.Writer) error {
	buf := byteBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer byteBufferPool.Put(buf)
	sendf := func(format string, args ...any) {
		fmt.Fprintf(buf, format, args...)
		buf.WriteByte('\n')
	}
	keyf := func(prefix string, key *[32]byte) {
		buf.Grow(len(key)*2 + 2 + len(prefix))
		buf.WriteString(prefix)
		buf.WriteByte('=')
		const hex = "0123456789abcdef"
		for i := 0; i < len(key); i++ {
			buf.WriteByte(hex[key[i]>>4])
			buf.WriteByte(hex[key[i]&0xf])
		}
		buf.WriteByte('\n')
	}

	cfg := device.Config()

	if !cfg.PrivateKey.IsZero() {
		keyf("private_key", (*[32]byte)(&cfg.PrivateKey))
	}

	if cfg.ListenPort != 0 {
		sendf("listen_port=%d", cfg.ListenPort)
	}

	if cfg.Fwmark != 0 {
		sendf("fwmark=%d", cfg.Fwmark)
	}
	if cfg.AmneziaWG.JunkCount != 0 {
		sendf("jc=%d", cfg.AmneziaWG.JunkCount)
	}
	if cfg.AmneziaWG.JunkMin != 0 {
		sendf("jmin=%d", cfg.AmneziaWG.JunkMin)
	}
	if cfg.AmneziaWG.JunkMax != 0 {
		sendf("jmax=%d", cfg.AmneziaWG.JunkMax)
	}
	if cfg.AmneziaWG.InitPadding != 0 {
		sendf("s1=%d", cfg.AmneziaWG.InitPadding)
	}
	if cfg.AmneziaWG.ResponsePadding != 0 {
		sendf("s2=%d", cfg.AmneziaWG.ResponsePadding)
	}
	if cfg.AmneziaWG.CookiePadding != 0 {
		sendf("s3=%d", cfg.AmneziaWG.CookiePadding)
	}
	if cfg.AmneziaWG.TransportPadding != 0 {
		sendf("s4=%d", cfg.AmneziaWG.TransportPadding)
	}
	sendf("h1=%s", cfg.AmneziaWG.InitHeader.Spec())
	sendf("h2=%s", cfg.AmneziaWG.ResponseHeader.Spec())
	sendf("h3=%s", cfg.AmneziaWG.CookieHeader.Spec())
	sendf("h4=%s", cfg.AmneziaWG.TransportHeader.Spec())
	for i, spec := range cfg.AmneziaWG.InitiationPackets {
		if spec != "" {
			sendf("i%d=%s", i+1, spec)
		}
	}

	for _, peer := range cfg.Peers {
		keyf("public_key", (*[32]byte)(&peer.PublicKey))
		if peer.AmneziaWG != nil {
			if peer.AmneziaWG.JunkCount != 0 {
				sendf("jc=%d", peer.AmneziaWG.JunkCount)
			}
			if peer.AmneziaWG.JunkMin != 0 {
				sendf("jmin=%d", peer.AmneziaWG.JunkMin)
			}
			if peer.AmneziaWG.JunkMax != 0 {
				sendf("jmax=%d", peer.AmneziaWG.JunkMax)
			}
			if peer.AmneziaWG.InitPadding != 0 {
				sendf("s1=%d", peer.AmneziaWG.InitPadding)
			}
			if peer.AmneziaWG.ResponsePadding != 0 {
				sendf("s2=%d", peer.AmneziaWG.ResponsePadding)
			}
			if peer.AmneziaWG.CookiePadding != 0 {
				sendf("s3=%d", peer.AmneziaWG.CookiePadding)
			}
			if peer.AmneziaWG.TransportPadding != 0 {
				sendf("s4=%d", peer.AmneziaWG.TransportPadding)
			}
			sendf("h1=%s", peer.AmneziaWG.InitHeader.Spec())
			sendf("h2=%s", peer.AmneziaWG.ResponseHeader.Spec())
			sendf("h3=%s", peer.AmneziaWG.CookieHeader.Spec())
			sendf("h4=%s", peer.AmneziaWG.TransportHeader.Spec())
			for i, spec := range peer.AmneziaWG.InitiationPackets {
				if spec != "" {
					sendf("i%d=%s", i+1, spec)
				}
			}
		}
		keyf("preshared_key", (*[32]byte)(&peer.PresharedKey))
		sendf("protocol_version=%d", peer.ProtocolVersion)
		if peer.Endpoint != "" {
			sendf("endpoint=%s", peer.Endpoint)
		}

		nano := peer.LastHandshakeTime.UnixNano()
		secs := nano / time.Second.Nanoseconds()
		nano %= time.Second.Nanoseconds()

		sendf("last_handshake_time_sec=%d", secs)
		sendf("last_handshake_time_nsec=%d", nano)
		sendf("tx_bytes=%d", peer.TxBytes)
		sendf("rx_bytes=%d", peer.RxBytes)
		sendf("persistent_keepalive_interval=%d", peer.PersistentKeepaliveInterval)

		for _, prefix := range peer.AllowedIPs {
			sendf("allowed_ip=%s", prefix.String())
		}
	}

	// send lines (does not require resource locks)
	if _, err := w.Write(buf.Bytes()); err != nil {
		return ipcErrorf(ipc.IpcErrorIO, "failed to write output: %w", err)
	}

	return nil
}

// IpcSetOperation implements the WireGuard configuration protocol "set" operation.
// See https://www.wireguard.com/xplatform/#configuration-protocol for details.
func (device *Device) IpcSetOperation(r io.Reader) (err error) {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	defer func() {
		if err != nil {
			device.log.Errf("%v", err)
		}
	}()

	peer := new(ipcSetPeer)
	amnezia := new(ipcSetAmneziaWG)
	deviceConfig := true

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			// Blank line means terminate operation.
			if err := amnezia.mergeWithDevice(device); err != nil {
				return ipcErrorf(ipc.IpcErrorInvalid, "failed to apply amneziawg config: %w", err)
			}
			if err := peer.handlePostConfig(); err != nil {
				return ipcErrorf(ipc.IpcErrorInvalid, "failed to apply peer config: %w", err)
			}
			return nil
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return ipcErrorf(ipc.IpcErrorProtocol, "failed to parse line %q", line)
		}

		if key == "public_key" {
			if deviceConfig {
				deviceConfig = false
			}
			if err := peer.handlePostConfig(); err != nil {
				return ipcErrorf(ipc.IpcErrorInvalid, "failed to apply peer config: %w", err)
			}
			// Load/create the peer we are now configuring.
			err := device.handlePublicKeyLine(peer, value)
			if err != nil {
				return err
			}
			continue
		}

		var err error
		if deviceConfig {
			err = device.handleDeviceLine(key, value, amnezia)
		} else {
			err = device.handlePeerLine(peer, key, value)
		}
		if err != nil {
			return err
		}
	}
	if err := amnezia.mergeWithDevice(device); err != nil {
		return ipcErrorf(ipc.IpcErrorInvalid, "failed to apply amneziawg config: %w", err)
	}
	if err := peer.handlePostConfig(); err != nil {
		return ipcErrorf(ipc.IpcErrorInvalid, "failed to apply peer config: %w", err)
	}

	if err := scanner.Err(); err != nil {
		return ipcErrorf(ipc.IpcErrorIO, "failed to read input: %w", err)
	}
	return nil
}

func handleAmneziaLine(key, value string, amnezia *ipcSetAmneziaWG) (bool, error) {
	switch key {
	case "jc":
		jc, err := strconv.Atoi(value)
		if err != nil {
			return true, ipcErrorf(ipc.IpcErrorInvalid, "failed to parse jc: %w", err)
		}
		if jc <= 0 {
			return true, ipcErrorf(ipc.IpcErrorInvalid, "jc must be a positive value")
		}
		amnezia.junkCount = &jc
	case "jmin":
		jmin, err := strconv.Atoi(value)
		if err != nil {
			return true, ipcErrorf(ipc.IpcErrorInvalid, "failed to parse jmin: %w", err)
		}
		if jmin <= 0 {
			return true, ipcErrorf(ipc.IpcErrorInvalid, "jmin must be a positive value")
		}
		amnezia.junkMin = &jmin
	case "jmax":
		jmax, err := strconv.Atoi(value)
		if err != nil {
			return true, ipcErrorf(ipc.IpcErrorInvalid, "failed to parse jmax: %w", err)
		}
		if jmax <= 0 {
			return true, ipcErrorf(ipc.IpcErrorInvalid, "jmax must be a positive value")
		}
		amnezia.junkMax = &jmax
	case "s1":
		padding, err := strconv.Atoi(value)
		if err != nil {
			return true, ipcErrorf(ipc.IpcErrorInvalid, "failed to parse s1: %w", err)
		}
		if padding < 0 {
			return true, ipcErrorf(ipc.IpcErrorInvalid, "s1 must be non-negative")
		}
		amnezia.initPadding = &padding
	case "s2":
		padding, err := strconv.Atoi(value)
		if err != nil {
			return true, ipcErrorf(ipc.IpcErrorInvalid, "failed to parse s2: %w", err)
		}
		if padding < 0 {
			return true, ipcErrorf(ipc.IpcErrorInvalid, "s2 must be non-negative")
		}
		amnezia.responsePadding = &padding
	case "s3":
		padding, err := strconv.Atoi(value)
		if err != nil {
			return true, ipcErrorf(ipc.IpcErrorInvalid, "failed to parse s3: %w", err)
		}
		if padding < 0 {
			return true, ipcErrorf(ipc.IpcErrorInvalid, "s3 must be non-negative")
		}
		amnezia.cookiePadding = &padding
	case "s4":
		padding, err := strconv.Atoi(value)
		if err != nil {
			return true, ipcErrorf(ipc.IpcErrorInvalid, "failed to parse s4: %w", err)
		}
		if padding < 0 {
			return true, ipcErrorf(ipc.IpcErrorInvalid, "s4 must be non-negative")
		}
		amnezia.transportPadding = &padding
	case "h1":
		header, err := newMagicHeader(value)
		if err != nil {
			return true, ipcErrorf(ipc.IpcErrorInvalid, "failed to parse H1: %w", err)
		}
		amnezia.initHeader = header
	case "h2":
		header, err := newMagicHeader(value)
		if err != nil {
			return true, ipcErrorf(ipc.IpcErrorInvalid, "failed to parse H2: %w", err)
		}
		amnezia.responseHeader = header
	case "h3":
		header, err := newMagicHeader(value)
		if err != nil {
			return true, ipcErrorf(ipc.IpcErrorInvalid, "failed to parse H3: %w", err)
		}
		amnezia.cookieHeader = header
	case "h4":
		header, err := newMagicHeader(value)
		if err != nil {
			return true, ipcErrorf(ipc.IpcErrorInvalid, "failed to parse H4: %w", err)
		}
		amnezia.transportHeader = header
	case "i1", "i2", "i3", "i4", "i5":
		chain, err := newObfChain(value)
		if err != nil {
			return true, ipcErrorf(ipc.IpcErrorInvalid, "failed to parse %s: %w", strings.ToUpper(key), err)
		}
		index := int(key[1] - '1')
		amnezia.initiationPackets[index] = chain
		amnezia.packetSet[index] = true
	default:
		return false, nil
	}

	return true, nil
}

func (device *Device) handleDeviceLine(key, value string, amnezia *ipcSetAmneziaWG) error {
	if handled, err := handleAmneziaLine(key, value, amnezia); handled {
		return err
	}

	switch key {
	case "private_key":
		var sk NoisePrivateKey
		err := sk.FromMaybeZeroHex(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set private_key: %w", err)
		}
		device.log.Debugf("UAPI: Updating private key")
		if err := device.SetPrivateKey(sk); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set private_key: %w", err)
		}

	case "listen_port":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse listen_port: %w", err)
		}

		// update port and rebind
		device.log.Debugf("UAPI: Updating listen port")
		if err := device.setListenPortLocked(uint16(port)); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set listen_port: %w", err)
		}

	case "fwmark":
		mark, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid fwmark: %w", err)
		}

		device.log.Debugf("UAPI: Updating fwmark")
		if err := device.setFwmarkLocked(uint32(mark)); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to update fwmark: %w", err)
		}

	case "replace_peers":
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set replace_peers, invalid value: %v", value)
		}
		device.log.Debugf("UAPI: Removing all peers")
		device.RemoveAllPeers()

	default:
		return ipcErrorf(ipc.IpcErrorInvalid, "invalid UAPI device key: %v", key)
	}

	return nil
}

// An ipcSetPeer is the current state of an IPC set operation on a peer.
type ipcSetPeer struct {
	*Peer                   // Peer is the current peer being operated on
	dummy   bool            // dummy reports whether this peer is a temporary, placeholder peer
	created bool            // new reports whether this is a newly created peer
	pkaOn   bool            // pkaOn reports whether the peer had the persistent keepalive turn on
	amnezia ipcSetAmneziaWG // pending peer-local amnezia settings for the current operation
}

func (peer *ipcSetPeer) handlePostConfig() error {
	if peer.Peer == nil || peer.dummy {
		return nil
	}
	if peer.amnezia.hasValues() {
		if err := peer.device.setPeerAmneziaWGConfigPatchLocked(peer.Peer, peer.amnezia); err != nil {
			return err
		}
	}
	if peer.created {
		peer.endpoint.disableRoaming = peer.device.net.brokenRoaming && peer.endpoint.val != nil
	}
	if peer.device.isUp() {
		peer.Start()
		if peer.pkaOn {
			peer.SendKeepalive()
		}
		peer.SendStagedPackets()
	}
	return nil
}

func (device *Device) handlePublicKeyLine(peer *ipcSetPeer, value string) error {
	peer.pkaOn = false
	peer.amnezia = ipcSetAmneziaWG{}

	// Load/create the peer we are configuring.
	var publicKey NoisePublicKey
	err := publicKey.FromHex(value)
	if err != nil {
		return ipcErrorf(ipc.IpcErrorInvalid, "failed to get peer by public key: %w", err)
	}

	// Ignore peer with the same public key as this device.
	device.staticIdentity.RLock()
	peer.dummy = device.staticIdentity.publicKey.Equals(publicKey)
	device.staticIdentity.RUnlock()

	if peer.dummy {
		peer.Peer = &Peer{}
	} else {
		peer.Peer = device.LookupPeer(publicKey)
	}

	peer.created = peer.Peer == nil
	if peer.created {
		peer.Peer, err = device.NewPeer(publicKey)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to create new peer: %w", err)
		}
		device.log.Debugf("%v - UAPI: Created", peer.Peer)
	}
	return nil
}

func (device *Device) handlePeerLine(peer *ipcSetPeer, key, value string) error {
	if handled, err := handleAmneziaLine(key, value, &peer.amnezia); handled {
		return err
	}

	switch key {
	case "update_only":
		// allow disabling of creation
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set update only, invalid value: %v", value)
		}
		if peer.created && !peer.dummy {
			device.RemovePeer(peer.handshake.remoteStatic)
			peer.Peer = &Peer{}
			peer.dummy = true
		}

	case "remove":
		// remove currently selected peer from device
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set remove, invalid value: %v", value)
		}
		if !peer.dummy {
			device.log.Debugf("%v - UAPI: Removing", peer.Peer)
			device.RemovePeer(peer.handshake.remoteStatic)
		}
		peer.Peer = &Peer{}
		peer.dummy = true

	case "preshared_key":
		device.log.Debugf("%v - UAPI: Updating preshared key", peer.Peer)
		var presharedKey NoisePresharedKey
		err := presharedKey.FromHex(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set preshared key: %w", err)
		}
		if peer.dummy {
			return nil
		}
		if err := device.setPeerPresharedKeyLocked(peer.handshake.remoteStatic, presharedKey); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set preshared key: %w", err)
		}

	case "endpoint":
		device.log.Debugf("%v - UAPI: Updating endpoint", peer.Peer)
		if peer.dummy {
			return nil
		}
		if err := device.setPeerEndpointLocked(peer.handshake.remoteStatic, value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "%w", err)
		}

	case "persistent_keepalive_interval":
		device.log.Debugf("%v - UAPI: Updating persistent keepalive interval", peer.Peer)

		secs, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set persistent keepalive interval: %w", err)
		}

		if peer.dummy {
			return nil
		}
		old, err := device.setPeerPersistentKeepaliveIntervalLocked(peer.handshake.remoteStatic, uint16(secs), false)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set persistent keepalive interval: %w", err)
		}
		peer.pkaOn = old == 0 && secs != 0

	case "replace_allowed_ips":
		device.log.Debugf("%v - UAPI: Removing all allowedips", peer.Peer)
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to replace allowedips, invalid value: %v", value)
		}
		if peer.dummy {
			return nil
		}
		if err := device.replacePeerAllowedIPsLocked(peer.handshake.remoteStatic, nil); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to replace allowedips: %w", err)
		}

	case "allowed_ip":
		add := true
		verb := "Adding"
		if len(value) > 0 && value[0] == '-' {
			add = false
			verb = "Removing"
			value = value[1:]
		}
		device.log.Debugf("%v - UAPI: %s allowedip", peer.Peer, verb)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set allowed ip: %w", err)
		}
		if peer.dummy {
			return nil
		}
		if add {
			if err := device.addPeerAllowedIPLocked(peer.handshake.remoteStatic, prefix); err != nil {
				return ipcErrorf(ipc.IpcErrorInvalid, "failed to set allowed ip: %w", err)
			}
		} else {
			if err := device.removePeerAllowedIPLocked(peer.handshake.remoteStatic, prefix); err != nil {
				return ipcErrorf(ipc.IpcErrorInvalid, "failed to set allowed ip: %w", err)
			}
		}

	case "protocol_version":
		version, err := strconv.Atoi(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid protocol version: %v", value)
		}
		if peer.dummy {
			if version != 1 {
				return ipcErrorf(ipc.IpcErrorInvalid, "invalid protocol version: %v", value)
			}
			return nil
		}
		if err := device.setPeerProtocolVersionLocked(peer.handshake.remoteStatic, version); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "%w", err)
		}

	default:
		return ipcErrorf(ipc.IpcErrorInvalid, "invalid UAPI peer key: %v", key)
	}

	return nil
}

func (device *Device) IpcGet() (string, error) {
	buf := new(strings.Builder)
	if err := device.IpcGetOperation(buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (device *Device) IpcSet(uapiConf string) error {
	return device.IpcSetOperation(strings.NewReader(uapiConf))
}

func (device *Device) IpcHandle(socket net.Conn) {
	defer func() {
		_ = socket.Close()
	}()

	buffered := func(s io.ReadWriter) *bufio.ReadWriter {
		reader := bufio.NewReader(s)
		writer := bufio.NewWriter(s)
		return bufio.NewReadWriter(reader, writer)
	}(socket)

	for {
		op, err := buffered.ReadString('\n')
		if err != nil {
			return
		}

		// handle operation
		switch op {
		case "set=1\n":
			err = device.IpcSetOperation(buffered.Reader)
		case "get=1\n":
			var nextByte byte
			nextByte, err = buffered.ReadByte()
			if err != nil {
				return
			}
			if nextByte != '\n' {
				err = ipcErrorf(ipc.IpcErrorInvalid, "trailing character in UAPI get: %q", nextByte)
				break
			}
			err = device.IpcGetOperation(buffered.Writer)
		default:
			device.log.Errf("invalid UAPI operation: %v", op)
			return
		}

		// write status
		var status *IPCError
		if err != nil && !errors.As(err, &status) {
			// shouldn't happen
			status = ipcErrorf(ipc.IpcErrorUnknown, "other UAPI error: %w", err)
		}
		if status != nil {
			device.log.Errf("%v", status)
			if _, err = fmt.Fprintf(buffered, "errno=%d\n\n", status.ErrorCode()); err != nil {
				return
			}
		} else {
			if _, err = fmt.Fprintf(buffered, "errno=0\n\n"); err != nil {
				return
			}
		}
		if err = buffered.Flush(); err != nil {
			return
		}
	}
}
