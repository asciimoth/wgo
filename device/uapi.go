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

	conn "github.com/asciimoth/batchudp"
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
	sendAmneziaWGV3UAPI(sendf, keyf, cfg.AmneziaWG, false)

	for _, peer := range cfg.Peers {
		keyf("public_key", (*[32]byte)(&peer.PublicKey))
		if peer.AmneziaWG != nil {
			sendf("jc=%d", peer.AmneziaWG.JunkCount)
			sendf("jmin=%d", peer.AmneziaWG.JunkMin)
			sendf("jmax=%d", peer.AmneziaWG.JunkMax)
			sendf("s1=%d", peer.AmneziaWG.InitPadding)
			sendf("s2=%d", peer.AmneziaWG.ResponsePadding)
			sendf("s3=%d", peer.AmneziaWG.CookiePadding)
			sendf("s4=%d", peer.AmneziaWG.TransportPadding)
			sendf("h1=%s", peer.AmneziaWG.InitHeader.Spec())
			sendf("h2=%s", peer.AmneziaWG.ResponseHeader.Spec())
			sendf("h3=%s", peer.AmneziaWG.CookieHeader.Spec())
			sendf("h4=%s", peer.AmneziaWG.TransportHeader.Spec())
			for i, spec := range peer.AmneziaWG.InitiationPackets {
				sendf("i%d=%s", i+1, spec)
			}
			sendAmneziaWGV3UAPI(sendf, keyf, *peer.AmneziaWG, true)
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
		if peer.PersistentKeepaliveRange != nil {
			sendf("persistent_keepalive_interval=%s", peer.PersistentKeepaliveRange.String())
		} else {
			sendf("persistent_keepalive_interval=%d", peer.PersistentKeepaliveInterval)
		}

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

	peer := &ipcSetPeer{device: device}
	amnezia := new(ipcSetAmneziaWG)
	deviceConfig := true
	var committedPeers []ipcPeerUAPIRollback
	var committedDeviceAmnezia *AmneziaWGConfig
	commitDeviceAmnezia := func() error {
		if !amnezia.hasValues() {
			return nil
		}
		previous := device.amneziaWGConfigLocked()
		if err := amnezia.mergeWithDevice(device); err != nil {
			return err
		}
		committedDeviceAmnezia = &previous
		amnezia = new(ipcSetAmneziaWG)
		return nil
	}

	scanner := bufio.NewScanner(r)
	defer func() {
		if err == nil {
			return
		}
		for i := len(committedPeers) - 1; i >= 0; i-- {
			device.rollbackPeerUAPI(committedPeers[i])
		}
		if committedDeviceAmnezia != nil {
			_ = device.setAmneziaWGConfigLocked(*committedDeviceAmnezia)
		}
	}()
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			// Blank line means terminate operation.
			if err := commitDeviceAmnezia(); err != nil {
				return ipcErrorf(ipc.IpcErrorInvalid, "failed to apply amneziawg config: %w", err)
			}
			rollback, err := peer.handlePostConfig()
			if err != nil {
				return ipcErrorf(ipc.IpcErrorInvalid, "failed to apply peer config: %w", err)
			}
			if rollback != nil {
				committedPeers = append(committedPeers, *rollback)
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
			if err := commitDeviceAmnezia(); err != nil {
				return ipcErrorf(ipc.IpcErrorInvalid, "failed to apply amneziawg config: %w", err)
			}
			rollback, err := peer.handlePostConfig()
			if err != nil {
				return ipcErrorf(ipc.IpcErrorInvalid, "failed to apply peer config: %w", err)
			}
			if rollback != nil {
				committedPeers = append(committedPeers, *rollback)
			}
			// Load/create the peer we are now configuring.
			err = device.handlePublicKeyLine(peer, value)
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
	if err := commitDeviceAmnezia(); err != nil {
		return ipcErrorf(ipc.IpcErrorInvalid, "failed to apply amneziawg config: %w", err)
	}
	rollback, err := peer.handlePostConfig()
	if err != nil {
		return ipcErrorf(ipc.IpcErrorInvalid, "failed to apply peer config: %w", err)
	}
	if rollback != nil {
		committedPeers = append(committedPeers, *rollback)
	}

	if err := scanner.Err(); err != nil {
		return ipcErrorf(ipc.IpcErrorIO, "failed to read input: %w", err)
	}
	return nil
}

func handleAmneziaLine(key, value string, amnezia *ipcSetAmneziaWG) (bool, error) {
	switch key {
	case "awg_version", "amneziawg_version":
		version64, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return true, ipcErrorf(ipc.IpcErrorInvalid, "failed to parse %s: %w", key, err)
		}
		version := AmneziaWGVersion(version64)
		amnezia.version = &version
	case "jc":
		jc, err := parseNonNegativeAmneziaUAPIValue("jc", value, maxAmneziaWGJunkCount)
		if err != nil {
			return true, err
		}
		amnezia.junkCount = &jc
	case "jmin":
		jmin, err := parseNonNegativeAmneziaUAPIValue("jmin", value, maxAmneziaWGJunkSize)
		if err != nil {
			return true, err
		}
		amnezia.junkMin = &jmin
	case "jmax":
		jmax, err := parseNonNegativeAmneziaUAPIValue("jmax", value, maxAmneziaWGJunkSize)
		if err != nil {
			return true, err
		}
		amnezia.junkMax = &jmax
	case "s1":
		padding, err := parseNonNegativeAmneziaUAPIValue("s1", value, maxAmneziaWGHandshakePaddingSize)
		if err != nil {
			return true, err
		}
		amnezia.initPadding = &padding
	case "s2":
		padding, err := parseNonNegativeAmneziaUAPIValue("s2", value, MaxMessageSize-MessageResponseSize)
		if err != nil {
			return true, err
		}
		amnezia.responsePadding = &padding
	case "s3":
		padding, err := parseNonNegativeAmneziaUAPIValue("s3", value, MaxMessageSize-MessageCookieReplySize)
		if err != nil {
			return true, err
		}
		amnezia.cookiePadding = &padding
	case "s4":
		padding, err := parseNonNegativeAmneziaUAPIValue("s4", value, maxAmneziaWGTransportPaddingSize)
		if err != nil {
			return true, err
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
	case "header_protection_key":
		headerKey, err := ParseAmneziaWGHeaderProtectionKeyHex(value)
		if err != nil {
			return true, ipcErrorf(ipc.IpcErrorInvalid, "failed to parse header_protection_key: %w", err)
		}
		amnezia.headerProtectionKey = &headerKey
	case "content_padding_addition":
		rng, err := parseAmneziaRangeUAPIValue("content_padding_addition", value, uint32(MaxMessageSize))
		if err != nil {
			return true, err
		}
		amnezia.contentPadding = &rng
	case "rekey_after_time":
		rng, err := parseAmneziaRangeUAPIValue("rekey_after_time", value, maxAmneziaWGTimerRangeSeconds)
		if err != nil {
			return true, err
		}
		amnezia.rekeyAfterTime = &rng
	case "rekey_timeout":
		rng, err := parseAmneziaRangeUAPIValue("rekey_timeout", value, maxAmneziaWGTimerRangeSeconds)
		if err != nil {
			return true, err
		}
		amnezia.rekeyTimeout = &rng
	case "reject_after_time":
		rng, err := parseAmneziaRangeUAPIValue("reject_after_time", value, maxAmneziaWGTimerRangeSeconds)
		if err != nil {
			return true, err
		}
		amnezia.rejectAfterTime = &rng
	case "keepalive_timeout":
		rng, err := parseAmneziaRangeUAPIValue("keepalive_timeout", value, maxAmneziaWGTimerRangeSeconds)
		if err != nil {
			return true, err
		}
		amnezia.keepaliveTimeout = &rng
	case "max_handshake_attempts":
		rng, err := parseAmneziaRangeUAPIValue("max_handshake_attempts", value, maxAmneziaWGHandshakeAttempts)
		if err != nil {
			return true, err
		}
		amnezia.maxHandshakeAttempts = &rng
	case "random_trailers":
		v, err := parseAmneziaBoolUAPIValue("random_trailers", value)
		if err != nil {
			return true, err
		}
		amnezia.randomTrailers = &v
	case "disable_cookies":
		v, err := parseAmneziaBoolUAPIValue("disable_cookies", value)
		if err != nil {
			return true, err
		}
		amnezia.disableCookies = &v
	default:
		return false, nil
	}

	return true, nil
}

func sendAmneziaWGV3UAPI(sendf func(string, ...any), keyf func(string, *[32]byte), cfg AmneziaWGConfig, full bool) {
	if full || cfg.Version != AmneziaWGVersionAuto {
		sendf("awg_version=%d", cfg.Version)
	}
	if full || !cfg.HeaderProtectionKey.IsZero() {
		keyf("header_protection_key", (*[32]byte)(&cfg.HeaderProtectionKey))
	}
	if full || cfg.ContentPadding.Set {
		sendf("content_padding_addition=%s", cfg.ContentPadding.String())
	}
	if full || cfg.RekeyAfterTime.Set {
		sendf("rekey_after_time=%s", cfg.RekeyAfterTime.String())
	}
	if full || cfg.RekeyTimeout.Set {
		sendf("rekey_timeout=%s", cfg.RekeyTimeout.String())
	}
	if full || cfg.RejectAfterTime.Set {
		sendf("reject_after_time=%s", cfg.RejectAfterTime.String())
	}
	if full || cfg.KeepaliveTimeout.Set {
		sendf("keepalive_timeout=%s", cfg.KeepaliveTimeout.String())
	}
	if full || cfg.MaxHandshakeAttempts.Set {
		sendf("max_handshake_attempts=%s", cfg.MaxHandshakeAttempts.String())
	}
	if full || cfg.RandomTrailers {
		sendf("random_trailers=%t", cfg.RandomTrailers)
	}
	if full || cfg.DisableCookies {
		sendf("disable_cookies=%t", cfg.DisableCookies)
	}
}

func parseNonNegativeAmneziaUAPIValue(name, value string, max int) (int, error) {
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, ipcErrorf(ipc.IpcErrorInvalid, "failed to parse %s: %w", name, err)
	}
	if n < 0 {
		return 0, ipcErrorf(ipc.IpcErrorInvalid, "%s must be non-negative", name)
	}
	if n > max {
		return 0, ipcErrorf(ipc.IpcErrorInvalid, "%s must be <= %d", name, max)
	}
	return n, nil
}

func parseAmneziaRangeUAPIValue(name, value string, max uint32) (AmneziaWGRange, error) {
	if value == "off" {
		return AmneziaWGRange{}, nil
	}
	rng, err := ParseAmneziaWGRange(value)
	if err != nil {
		return AmneziaWGRange{}, ipcErrorf(ipc.IpcErrorInvalid, "failed to parse %s: %w", name, err)
	}
	if err := rng.Validate(name, max); err != nil {
		return AmneziaWGRange{}, ipcErrorf(ipc.IpcErrorInvalid, "%w", err)
	}
	return rng, nil
}

func parseAmneziaBoolUAPIValue(name, value string) (bool, error) {
	switch value {
	case "true", "1":
		return true, nil
	case "false", "0":
		return false, nil
	default:
		return false, ipcErrorf(ipc.IpcErrorInvalid, "failed to parse %s: expected true or false", name)
	}
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
	device     *Device
	*Peer      // Peer is the current peer being operated on
	publicKey  NoisePublicKey
	hasPeer    bool
	dummy      bool            // dummy reports whether this peer is a temporary, placeholder peer
	created    bool            // new reports whether this is a newly created peer
	pkaOn      bool            // pkaOn reports whether the peer had the persistent keepalive turn on
	amnezia    ipcSetAmneziaWG // pending peer-local amnezia settings for the current operation
	pka        *AmneziaWGRange // pending persistent keepalive range for the current operation
	pkaIsRange bool
	remove     bool // remove reports whether this peer should be deleted at commit time
	// stagedEndpoint is applied after parsing so a later parse or validation
	// error in the same UAPI operation does not partially change the peer.
	stagedEndpoint        *string
	stagedPresharedKey    *NoisePresharedKey
	stagedProtocolVersion *int
	allowedIPOps          []ipcSetAllowedIPOp
}

type ipcSetAllowedIPOp struct {
	replace bool
	add     bool
	prefix  netip.Prefix
}

type ipcPeerUAPIRollback struct {
	peer              *Peer
	existed           bool
	presharedKey      NoisePresharedKey
	keepalive         AmneziaWGRange
	keepalivePacked   uint64
	keepaliveIsRange  bool
	endpoint          conn.Endpoint
	endpointAddress   string
	endpointTransport TransportID
	allowedIPs        []netip.Prefix
	amnezia           ipcSetAmneziaWG
}

func (device *Device) capturePeerUAPIRollback(peer *Peer, existed bool) ipcPeerUAPIRollback {
	rollback := ipcPeerUAPIRollback{
		peer:             peer,
		existed:          existed,
		keepalivePacked:  peer.persistentKeepaliveRange.Load(),
		keepaliveIsRange: peer.persistentKeepaliveIsRange.Load(),
		amnezia:          peer.amnezia.override,
	}
	rollback.keepalive = unpackAmneziaWGRange(rollback.keepalivePacked)

	peer.handshake.mutex.RLock()
	rollback.presharedKey = peer.handshake.presharedKey
	peer.handshake.mutex.RUnlock()

	peer.endpoint.Lock()
	rollback.endpoint = peer.endpoint.val
	rollback.endpointAddress = peer.endpoint.address
	rollback.endpointTransport = peer.endpoint.transport
	peer.endpoint.Unlock()

	device.allowedips.EntriesForPeer(peer, func(prefix netip.Prefix) bool {
		rollback.allowedIPs = append(rollback.allowedIPs, prefix)
		return true
	})
	return rollback
}

func (device *Device) rollbackPeerUAPI(rollback ipcPeerUAPIRollback) {
	if !rollback.existed {
		device.RemovePeer(rollback.peer.handshake.remoteStatic)
		return
	}

	peer := rollback.peer
	device.peers.Lock()
	if _, ok := device.peers.keyMap[peer.handshake.remoteStatic]; !ok {
		device.peers.keyMap[peer.handshake.remoteStatic] = peer
		device.signalRuntimeStats()
	}
	device.peers.Unlock()

	peer.handshake.mutex.Lock()
	peer.handshake.presharedKey = rollback.presharedKey
	peer.handshake.mutex.Unlock()

	peer.persistentKeepaliveRange.Store(rollback.keepalivePacked)
	peer.persistentKeepaliveIsRange.Store(rollback.keepaliveIsRange)
	if rollback.keepalive.Set && rollback.keepalive.Min == rollback.keepalive.Max && rollback.keepalive.Max <= uint32(^uint16(0)) {
		peer.persistentKeepaliveInterval.Store(rollback.keepalive.Min)
	} else {
		peer.persistentKeepaliveInterval.Store(0)
	}

	peer.endpoint.Lock()
	peer.endpoint.val = rollback.endpoint
	peer.endpoint.address = rollback.endpointAddress
	peer.endpoint.transport = rollback.endpointTransport
	peer.endpoint.Unlock()

	device.allowedips.ReplaceForPeer(peer, rollback.allowedIPs)
	peer.amnezia.override = rollback.amnezia
	_ = device.refreshPeerAmneziaWGSnapshotLocked(peer)
	device.storeAmneziaWGReceiveClassifier()
}

func (device *Device) parseDefaultPeerEndpointLocked(endpoint string) (conn.Endpoint, error) {
	device.net.RLock()
	st := device.net.transports[DefaultTransportID]
	device.net.RUnlock()
	if st == nil || st.bind == nil {
		return nil, fmt.Errorf("failed to set endpoint %v: no bind attached", endpoint)
	}
	parsed, err := st.bind.ParseEndpoint(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to set endpoint %v: %w", endpoint, err)
	}
	return parsed, nil
}

func (peer *ipcSetPeer) handlePostConfig() (*ipcPeerUAPIRollback, error) {
	if !peer.hasPeer {
		return nil, nil
	}
	if peer.remove {
		if peer.Peer != nil && peer.Peer.device != nil {
			rollback := peer.device.capturePeerUAPIRollback(peer.Peer, true)
			peer.device.log.Debugf("%v - UAPI: Removing", peer.Peer)
			peer.device.RemovePeer(peer.publicKey)
			return &rollback, nil
		}
		return nil, nil
	}
	if peer.dummy {
		return nil, nil
	}

	var parsedEndpoint conn.Endpoint
	if peer.stagedEndpoint != nil {
		parsed, err := peer.device.parseDefaultPeerEndpointLocked(*peer.stagedEndpoint)
		if err != nil {
			return nil, err
		}
		parsedEndpoint = parsed
	}

	if peer.Peer == nil {
		var err error
		peer.Peer, err = peer.device.NewPeer(peer.publicKey)
		if err != nil {
			return nil, err
		}
		peer.created = true
		peer.device.log.Debugf("%v - UAPI: Created", peer.Peer)
	}
	rollback := peer.device.capturePeerUAPIRollback(peer.Peer, !peer.created)
	committed := false
	defer func() {
		if !committed {
			peer.device.rollbackPeerUAPI(rollback)
		}
	}()

	if peer.stagedPresharedKey != nil {
		if err := peer.device.setPeerPresharedKeyLocked(peer.publicKey, *peer.stagedPresharedKey); err != nil {
			return nil, err
		}
	}
	for _, op := range peer.allowedIPOps {
		switch {
		case op.replace:
			if err := peer.device.replacePeerAllowedIPsLocked(peer.publicKey, nil); err != nil {
				return nil, err
			}
		case op.add:
			if err := peer.device.addPeerAllowedIPLocked(peer.publicKey, op.prefix); err != nil {
				return nil, err
			}
		default:
			if err := peer.device.removePeerAllowedIPLocked(peer.publicKey, op.prefix); err != nil {
				return nil, err
			}
		}
	}
	if peer.stagedProtocolVersion != nil {
		if err := peer.device.setPeerProtocolVersionLocked(peer.publicKey, *peer.stagedProtocolVersion); err != nil {
			return nil, err
		}
	}
	if peer.amnezia.hasValues() {
		if err := peer.device.setPeerAmneziaWGConfigPatchLocked(peer.Peer, peer.amnezia); err != nil {
			return nil, err
		}
	}
	if peer.pka != nil {
		oldOn := peer.persistentKeepaliveRange.Load() != 0
		if _, err := peer.device.setPeerPersistentKeepaliveLocked(peer.handshake.remoteStatic, *peer.pka, peer.pkaIsRange, false); err != nil {
			return nil, err
		}
		peer.pkaOn = !oldOn && peer.pka.Set
	}
	if peer.stagedEndpoint != nil {
		applyPeerEndpoint(peer.Peer, parsedEndpoint, DefaultTransportID, *peer.stagedEndpoint)
	}
	if peer.created {
		peer.endpoint.disableRoaming = peer.device.net.brokenRoaming && peer.endpoint.val != nil
	}
	if peer.device.isUp() {
		keepalive := peer.persistentKeepaliveRange.Load() != 0
		if peer.activation == PeerActivationEager || keepalive {
			if err := peer.device.checkActivePeerLimitLocked(peer.Peer); err != nil {
				return nil, err
			}
			peer.device.activatePeerLocked(peer.Peer)
		}
		if peer.pkaOn && peer.isRunning.Load() {
			peer.SendKeepalive()
		}
		peer.SendStagedPackets()
	}
	committed = true
	return &rollback, nil
}

func (device *Device) handlePublicKeyLine(peer *ipcSetPeer, value string) error {
	*peer = ipcSetPeer{device: device}
	peer.hasPeer = true
	peer.pkaOn = false
	peer.amnezia = ipcSetAmneziaWG{}
	peer.pka = nil
	peer.stagedEndpoint = nil
	peer.stagedPresharedKey = nil
	peer.stagedProtocolVersion = nil
	peer.allowedIPOps = nil

	// Load/create the peer we are configuring.
	var publicKey NoisePublicKey
	err := publicKey.FromHex(value)
	if err != nil {
		return ipcErrorf(ipc.IpcErrorInvalid, "failed to get peer by public key: %w", err)
	}
	peer.publicKey = publicKey

	// Ignore peer with the same public key as this device.
	device.staticIdentity.RLock()
	peer.dummy = device.staticIdentity.publicKey.Equals(publicKey)
	device.staticIdentity.RUnlock()

	if peer.dummy {
		peer.Peer = &Peer{}
	} else {
		peer.Peer = device.LookupPeer(publicKey)
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
		if peer.Peer == nil && !peer.dummy {
			peer.dummy = true
		}

	case "remove":
		// remove currently selected peer from device
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set remove, invalid value: %v", value)
		}
		peer.remove = true
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
		peer.stagedPresharedKey = &presharedKey

	case "endpoint":
		device.log.Debugf("%v - UAPI: Updating endpoint", peer.Peer)
		if peer.dummy {
			return nil
		}
		peer.stagedEndpoint = &value

	case "persistent_keepalive_interval":
		device.log.Debugf("%v - UAPI: Updating persistent keepalive interval", peer.Peer)

		keepalive, err := parseAmneziaRangeUAPIValue("persistent_keepalive_interval", value, uint32(^uint16(0)))
		if err != nil {
			return err
		}
		if keepalive.Min == 0 && keepalive.Max == 0 {
			keepalive = AmneziaWGRange{}
		}

		if !peer.dummy {
			peer.pka = &keepalive
			peer.pkaIsRange = keepalive.Set && strings.Contains(value, "-")
		}

	case "replace_allowed_ips":
		device.log.Debugf("%v - UAPI: Removing all allowedips", peer.Peer)
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to replace allowedips, invalid value: %v", value)
		}
		if peer.dummy {
			return nil
		}
		peer.allowedIPOps = append(peer.allowedIPOps, ipcSetAllowedIPOp{replace: true})

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
		peer.allowedIPOps = append(peer.allowedIPOps, ipcSetAllowedIPOp{add: add, prefix: prefix})

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
		peer.stagedProtocolVersion = &version

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
