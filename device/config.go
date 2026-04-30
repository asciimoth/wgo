/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

type DeviceConfig struct {
	PrivateKey NoisePrivateKey
	ListenPort uint16
	Fwmark     uint32
	AmneziaWG  AmneziaWGConfig
	Peers      []PeerConfig
}

type PeerConfig struct {
	PublicKey                   NoisePublicKey
	PresharedKey                NoisePresharedKey
	ProtocolVersion             int
	Endpoint                    string
	LastHandshakeTime           time.Time
	TxBytes                     uint64
	RxBytes                     uint64
	PersistentKeepaliveInterval uint16
	AllowedIPs                  []netip.Prefix
	AmneziaWG                   *AmneziaWGConfig
}

type AmneziaWGConfigPatch struct {
	JunkCount         *int
	JunkMin           *int
	JunkMax           *int
	InitHeader        *AmneziaWGHeaderRange
	ResponseHeader    *AmneziaWGHeaderRange
	CookieHeader      *AmneziaWGHeaderRange
	TransportHeader   *AmneziaWGHeaderRange
	InitPadding       *int
	ResponsePadding   *int
	CookiePadding     *int
	TransportPadding  *int
	InitiationPackets [amneziaPacketCount]*string
}

func (device *Device) PrivateKey() NoisePrivateKey {
	device.ipcMutex.RLock()
	defer device.ipcMutex.RUnlock()

	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()
	return device.staticIdentity.privateKey
}

func (device *Device) ListenPort() uint16 {
	device.ipcMutex.RLock()
	defer device.ipcMutex.RUnlock()

	device.net.RLock()
	defer device.net.RUnlock()
	return device.net.port
}

func (device *Device) SetListenPort(port uint16) error {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()
	return device.setListenPortLocked(port)
}

func (device *Device) Fwmark() uint32 {
	device.ipcMutex.RLock()
	defer device.ipcMutex.RUnlock()

	device.net.RLock()
	defer device.net.RUnlock()
	return device.net.fwmark
}

func (device *Device) AmneziaWGConfig() AmneziaWGConfig {
	device.ipcMutex.RLock()
	defer device.ipcMutex.RUnlock()
	return device.amneziaWGConfigLocked()
}

func (device *Device) SetAmneziaWGConfig(cfg AmneziaWGConfig) error {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()
	return device.setAmneziaWGConfigLocked(cfg)
}

func (device *Device) SetAmneziaWGConfigPatch(patch AmneziaWGConfigPatch) error {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()
	override, err := patch.toIPC()
	if err != nil {
		return err
	}
	cfg := device.amneziaWGConfigLocked()
	override.merge(&cfg)
	return device.setAmneziaWGConfigLocked(cfg)
}

func (device *Device) SetFwmark(mark uint32) error {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()
	return device.setFwmarkLocked(mark)
}

func (device *Device) Config() DeviceConfig {
	device.ipcMutex.RLock()
	defer device.ipcMutex.RUnlock()

	device.net.RLock()
	defer device.net.RUnlock()

	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	device.peers.RLock()
	defer device.peers.RUnlock()

	cfg := DeviceConfig{
		PrivateKey: device.staticIdentity.privateKey,
		ListenPort: device.net.port,
		Fwmark:     device.net.fwmark,
		AmneziaWG:  device.amneziaWGConfigLocked(),
		Peers:      make([]PeerConfig, 0, len(device.peers.keyMap)),
	}
	for _, peer := range device.peers.keyMap {
		cfg.Peers = append(cfg.Peers, device.peerConfigLocked(peer))
	}
	slices.SortFunc(cfg.Peers, func(a, b PeerConfig) int {
		return bytes.Compare(a.PublicKey[:], b.PublicKey[:])
	})
	return cfg
}

func (device *Device) PeerConfig(publicKey NoisePublicKey) (PeerConfig, bool) {
	device.ipcMutex.RLock()
	defer device.ipcMutex.RUnlock()

	peer := device.lookupPeerLocked(publicKey)
	if peer == nil {
		return PeerConfig{}, false
	}
	return device.peerConfigLocked(peer), true
}

func (device *Device) SetPeerPresharedKey(publicKey NoisePublicKey, presharedKey NoisePresharedKey) error {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()
	return device.setPeerPresharedKeyLocked(publicKey, presharedKey)
}

func (device *Device) SetPeerEndpoint(publicKey NoisePublicKey, endpoint string) error {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()
	return device.setPeerEndpointLocked(publicKey, endpoint)
}

func (device *Device) SetPeerPersistentKeepaliveInterval(publicKey NoisePublicKey, seconds uint16) error {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()
	_, err := device.setPeerPersistentKeepaliveIntervalLocked(publicKey, seconds, true)
	return err
}

func (device *Device) SetPeerProtocolVersion(publicKey NoisePublicKey, version int) error {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()
	return device.setPeerProtocolVersionLocked(publicKey, version)
}

func (device *Device) SetPeerAmneziaWGConfig(publicKey NoisePublicKey, cfg AmneziaWGConfig) error {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()
	return device.setPeerAmneziaWGConfigLocked(publicKey, &cfg)
}

func (device *Device) PeerAmneziaWGConfigOverride(publicKey NoisePublicKey) (AmneziaWGConfigPatch, bool) {
	device.ipcMutex.RLock()
	defer device.ipcMutex.RUnlock()

	peer := device.lookupPeerLocked(publicKey)
	if peer == nil || !peer.amnezia.override.hasValues() {
		return AmneziaWGConfigPatch{}, false
	}
	return amneziaWGConfigPatchFromIPC(peer.amnezia.override), true
}

func (device *Device) SetPeerAmneziaWGConfigPatch(publicKey NoisePublicKey, patch AmneziaWGConfigPatch) error {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()
	override, err := patch.toIPC()
	if err != nil {
		return err
	}
	peer, err := device.requirePeerLocked(publicKey)
	if err != nil {
		return err
	}
	if peer.amnezia.override.hasValues() {
		base := peer.amnezia.override
		override.mergeIntoOverride(&base)
		override = base
	}
	return device.setPeerAmneziaWGConfigPatchLocked(peer, override)
}

func (device *Device) ClearPeerAmneziaWGConfig(publicKey NoisePublicKey) error {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()
	return device.setPeerAmneziaWGConfigLocked(publicKey, nil)
}

func (device *Device) ReplacePeerAllowedIPs(publicKey NoisePublicKey, allowedIPs []netip.Prefix) error {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()
	return device.replacePeerAllowedIPsLocked(publicKey, allowedIPs)
}

func (device *Device) AddPeerAllowedIP(publicKey NoisePublicKey, prefix netip.Prefix) error {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()
	return device.addPeerAllowedIPLocked(publicKey, prefix)
}

func (device *Device) RemovePeerAllowedIP(publicKey NoisePublicKey, prefix netip.Prefix) error {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()
	return device.removePeerAllowedIPLocked(publicKey, prefix)
}

// ActivatePeer applies the same post-configuration activation used by UAPI.
// If the device is up, it starts the peer and flushes any staged packets.
func (device *Device) ActivatePeer(publicKey NoisePublicKey) error {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	peer, err := device.requirePeerLocked(publicKey)
	if err != nil {
		return err
	}
	if !device.isUp() {
		return nil
	}
	peer.Start()
	if peer.persistentKeepaliveInterval.Load() > 0 {
		peer.SendKeepalive()
	}
	peer.SendStagedPackets()
	return nil
}

func (device *Device) setListenPortLocked(port uint16) error {
	device.net.Lock()
	device.net.port = port
	device.net.Unlock()
	return device.BindUpdate()
}

func (device *Device) setFwmarkLocked(mark uint32) error {
	return device.BindSetMark(mark)
}

func (device *Device) amneziaWGConfigLocked() AmneziaWGConfig {
	cfg := DefaultAmneziaWGConfig()
	cfg.JunkCount = device.junk.count
	cfg.JunkMin = device.junk.min
	cfg.JunkMax = device.junk.max
	cfg.InitHeader = device.headers.init.toConfig()
	cfg.ResponseHeader = device.headers.response.toConfig()
	cfg.CookieHeader = device.headers.cookie.toConfig()
	cfg.TransportHeader = device.headers.transport.toConfig()
	cfg.InitPadding = device.paddings.init
	cfg.ResponsePadding = device.paddings.response
	cfg.CookiePadding = device.paddings.cookie
	cfg.TransportPadding = device.paddings.transport
	for i, chain := range device.ipackets {
		if chain != nil {
			cfg.InitiationPackets[i] = chain.Spec
		}
	}
	return cfg
}

func (patch AmneziaWGConfigPatch) toIPC() (ipcSetAmneziaWG, error) {
	override := ipcSetAmneziaWG{
		junkCount:        patch.JunkCount,
		junkMin:          patch.JunkMin,
		junkMax:          patch.JunkMax,
		initPadding:      patch.InitPadding,
		responsePadding:  patch.ResponsePadding,
		cookiePadding:    patch.CookiePadding,
		transportPadding: patch.TransportPadding,
	}
	if patch.InitHeader != nil {
		override.initHeader = &magicHeader{start: patch.InitHeader.Start, end: patch.InitHeader.End}
	}
	if patch.ResponseHeader != nil {
		override.responseHeader = &magicHeader{start: patch.ResponseHeader.Start, end: patch.ResponseHeader.End}
	}
	if patch.CookieHeader != nil {
		override.cookieHeader = &magicHeader{start: patch.CookieHeader.Start, end: patch.CookieHeader.End}
	}
	if patch.TransportHeader != nil {
		override.transportHeader = &magicHeader{start: patch.TransportHeader.Start, end: patch.TransportHeader.End}
	}
	for i, spec := range patch.InitiationPackets {
		if spec == nil {
			continue
		}
		override.packetSet[i] = true
		if *spec == "" {
			continue
		}
		chain, err := newObfChain(*spec)
		if err != nil {
			return ipcSetAmneziaWG{}, fmt.Errorf("parse initiation packet %d: %w", i+1, err)
		}
		override.initiationPackets[i] = chain
	}
	return override, nil
}

func amneziaWGConfigPatchFromIPC(override ipcSetAmneziaWG) AmneziaWGConfigPatch {
	patch := AmneziaWGConfigPatch{
		JunkCount:        override.junkCount,
		JunkMin:          override.junkMin,
		JunkMax:          override.junkMax,
		InitPadding:      override.initPadding,
		ResponsePadding:  override.responsePadding,
		CookiePadding:    override.cookiePadding,
		TransportPadding: override.transportPadding,
	}
	if override.initHeader != nil {
		header := override.initHeader.toConfig()
		patch.InitHeader = &header
	}
	if override.responseHeader != nil {
		header := override.responseHeader.toConfig()
		patch.ResponseHeader = &header
	}
	if override.cookieHeader != nil {
		header := override.cookieHeader.toConfig()
		patch.CookieHeader = &header
	}
	if override.transportHeader != nil {
		header := override.transportHeader.toConfig()
		patch.TransportHeader = &header
	}
	for i, chain := range override.initiationPackets {
		if !override.packetSet[i] {
			continue
		}
		spec := ""
		if chain != nil {
			spec = chain.Spec
		}
		patch.InitiationPackets[i] = &spec
	}
	return patch
}

func (device *Device) setAmneziaWGConfigLocked(cfg AmneziaWGConfig) error {
	if err := validateAmneziaWGConfig(cfg); err != nil {
		return err
	}

	device.junk.count = cfg.JunkCount
	device.junk.min = cfg.JunkMin
	device.junk.max = cfg.JunkMax
	device.headers.init = &magicHeader{start: cfg.InitHeader.Start, end: cfg.InitHeader.End}
	device.headers.response = &magicHeader{start: cfg.ResponseHeader.Start, end: cfg.ResponseHeader.End}
	device.headers.cookie = &magicHeader{start: cfg.CookieHeader.Start, end: cfg.CookieHeader.End}
	device.headers.transport = &magicHeader{start: cfg.TransportHeader.Start, end: cfg.TransportHeader.End}
	device.paddings.init = cfg.InitPadding
	device.paddings.response = cfg.ResponsePadding
	device.paddings.cookie = cfg.CookiePadding
	device.paddings.transport = cfg.TransportPadding
	for i := range device.ipackets {
		device.ipackets[i] = nil
		if cfg.InitiationPackets[i] == "" {
			continue
		}
		chain, err := newObfChain(cfg.InitiationPackets[i])
		if err != nil {
			return fmt.Errorf("parse initiation packet %d: %w", i+1, err)
		}
		device.ipackets[i] = chain
	}
	device.storeAmneziaWGSnapshot()
	device.refreshPeerAmneziaWGSnapshotsLocked()
	return nil
}

func validateAmneziaWGConfig(cfg AmneziaWGConfig) error {
	if cfg.JunkCount < 0 {
		return fmt.Errorf("junk count must be non-negative")
	}
	if cfg.JunkMin < 0 {
		return fmt.Errorf("junk min must be non-negative")
	}
	if cfg.JunkMax < 0 {
		return fmt.Errorf("junk max must be non-negative")
	}
	if cfg.JunkCount > 0 && (cfg.JunkMin <= 0 || cfg.JunkMax <= 0) {
		return fmt.Errorf("junk min and max must be positive when junk is enabled")
	}
	for _, padding := range []int{cfg.InitPadding, cfg.ResponsePadding, cfg.CookiePadding, cfg.TransportPadding} {
		if padding < 0 {
			return fmt.Errorf("padding values must be non-negative")
		}
	}
	headers := []AmneziaWGHeaderRange{
		cfg.InitHeader,
		cfg.ResponseHeader,
		cfg.CookieHeader,
		cfg.TransportHeader,
	}
	for _, header := range headers {
		if header.End < header.Start {
			return fmt.Errorf("header range end must be >= start")
		}
	}
	for i := 0; i < len(headers); i++ {
		for j := i + 1; j < len(headers); j++ {
			left := headers[i]
			right := headers[j]
			if left.Start <= right.End && right.Start <= left.End {
				return fmt.Errorf("headers must not overlap")
			}
		}
	}
	for i, spec := range cfg.InitiationPackets {
		if spec == "" {
			continue
		}
		if _, err := newObfChain(spec); err != nil {
			return fmt.Errorf("parse initiation packet %d: %w", i+1, err)
		}
	}
	return nil
}

func (device *Device) setPeerPresharedKeyLocked(publicKey NoisePublicKey, presharedKey NoisePresharedKey) error {
	peer, err := device.requirePeerLocked(publicKey)
	if err != nil {
		return err
	}

	peer.handshake.mutex.Lock()
	peer.handshake.presharedKey = presharedKey
	peer.handshake.mutex.Unlock()
	return nil
}

func (device *Device) setPeerEndpointLocked(publicKey NoisePublicKey, endpoint string) error {
	peer, err := device.requirePeerLocked(publicKey)
	if err != nil {
		return err
	}

	device.net.RLock()
	bind := device.net.bind
	device.net.RUnlock()
	if bind == nil {
		return fmt.Errorf("failed to set endpoint %v: no bind attached", endpoint)
	}

	parsed, err := bind.ParseEndpoint(endpoint)
	if err != nil {
		return fmt.Errorf("failed to set endpoint %v: %w", endpoint, err)
	}

	peer.endpoint.Lock()
	peer.endpoint.val = parsed
	peer.endpoint.Unlock()
	return nil
}

func (device *Device) setPeerPersistentKeepaliveIntervalLocked(publicKey NoisePublicKey, seconds uint16, sendImmediate bool) (uint32, error) {
	peer, err := device.requirePeerLocked(publicKey)
	if err != nil {
		return 0, err
	}

	old := peer.persistentKeepaliveInterval.Swap(uint32(seconds))
	if sendImmediate && old == 0 && seconds != 0 && device.isUp() {
		peer.SendKeepalive()
	}
	return old, nil
}

func (device *Device) setPeerProtocolVersionLocked(publicKey NoisePublicKey, version int) error {
	if _, err := device.requirePeerLocked(publicKey); err != nil {
		return err
	}
	if version != 1 {
		return fmt.Errorf("invalid protocol version: %v", version)
	}
	return nil
}

func (device *Device) setPeerAmneziaWGConfigLocked(publicKey NoisePublicKey, cfg *AmneziaWGConfig) error {
	peer, err := device.requirePeerLocked(publicKey)
	if err != nil {
		return err
	}

	if cfg == nil {
		peer.amnezia.override = ipcSetAmneziaWG{}
		peer.amnezia.snapshot.Store(nil)
		return nil
	}

	if err := validateAmneziaWGConfig(*cfg); err != nil {
		return err
	}

	override := ipcSetAmneziaWG{
		junkCount:        &cfg.JunkCount,
		junkMin:          &cfg.JunkMin,
		junkMax:          &cfg.JunkMax,
		initHeader:       &magicHeader{start: cfg.InitHeader.Start, end: cfg.InitHeader.End},
		responseHeader:   &magicHeader{start: cfg.ResponseHeader.Start, end: cfg.ResponseHeader.End},
		cookieHeader:     &magicHeader{start: cfg.CookieHeader.Start, end: cfg.CookieHeader.End},
		transportHeader:  &magicHeader{start: cfg.TransportHeader.Start, end: cfg.TransportHeader.End},
		initPadding:      &cfg.InitPadding,
		responsePadding:  &cfg.ResponsePadding,
		cookiePadding:    &cfg.CookiePadding,
		transportPadding: &cfg.TransportPadding,
	}
	for i, spec := range cfg.InitiationPackets {
		override.packetSet[i] = true
		if spec == "" {
			continue
		}
		chain, err := newObfChain(spec)
		if err != nil {
			return fmt.Errorf("parse initiation packet %d: %w", i+1, err)
		}
		override.initiationPackets[i] = chain
	}
	peer.amnezia.override = override
	return device.refreshPeerAmneziaWGSnapshotLocked(peer)
}

func (device *Device) setPeerAmneziaWGConfigPatchLocked(peer *Peer, override ipcSetAmneziaWG) error {
	if !override.hasValues() {
		peer.amnezia.override = ipcSetAmneziaWG{}
		peer.amnezia.snapshot.Store(nil)
		return nil
	}

	peer.amnezia.override = override
	return device.refreshPeerAmneziaWGSnapshotLocked(peer)
}

func (device *Device) replacePeerAllowedIPsLocked(publicKey NoisePublicKey, allowedIPs []netip.Prefix) error {
	peer, err := device.requirePeerLocked(publicKey)
	if err != nil {
		return err
	}
	for _, prefix := range allowedIPs {
		if !prefix.IsValid() {
			return fmt.Errorf("invalid allowed ip: %v", prefix)
		}
	}

	device.allowedips.RemoveByPeer(peer)
	for _, prefix := range allowedIPs {
		device.allowedips.Insert(prefix, peer)
	}
	return nil
}

func (device *Device) addPeerAllowedIPLocked(publicKey NoisePublicKey, prefix netip.Prefix) error {
	peer, err := device.requirePeerLocked(publicKey)
	if err != nil {
		return err
	}
	if !prefix.IsValid() {
		return fmt.Errorf("invalid allowed ip: %v", prefix)
	}

	device.allowedips.Insert(prefix, peer)
	return nil
}

func (device *Device) removePeerAllowedIPLocked(publicKey NoisePublicKey, prefix netip.Prefix) error {
	peer, err := device.requirePeerLocked(publicKey)
	if err != nil {
		return err
	}
	if !prefix.IsValid() {
		return fmt.Errorf("invalid allowed ip: %v", prefix)
	}

	device.allowedips.Remove(prefix, peer)
	return nil
}

func (device *Device) lookupPeerLocked(publicKey NoisePublicKey) *Peer {
	device.peers.RLock()
	defer device.peers.RUnlock()
	return device.peers.keyMap[publicKey]
}

func (device *Device) requirePeerLocked(publicKey NoisePublicKey) (*Peer, error) {
	peer := device.lookupPeerLocked(publicKey)
	if peer == nil {
		return nil, fmt.Errorf("peer not found")
	}
	return peer, nil
}

func (device *Device) peerConfigLocked(peer *Peer) PeerConfig {
	var cfg PeerConfig

	peer.handshake.mutex.RLock()
	cfg.PublicKey = peer.handshake.remoteStatic
	cfg.PresharedKey = peer.handshake.presharedKey
	peer.handshake.mutex.RUnlock()

	cfg.ProtocolVersion = 1

	peer.endpoint.Lock()
	if peer.endpoint.val != nil {
		cfg.Endpoint = peer.endpoint.val.DstToString()
	}
	peer.endpoint.Unlock()

	if nano := peer.lastHandshakeNano.Load(); nano != 0 {
		cfg.LastHandshakeTime = time.Unix(0, nano)
	}
	cfg.TxBytes = peer.txBytes.Load()
	cfg.RxBytes = peer.rxBytes.Load()
	cfg.PersistentKeepaliveInterval = uint16(peer.persistentKeepaliveInterval.Load())

	device.allowedips.EntriesForPeer(peer, func(prefix netip.Prefix) bool {
		cfg.AllowedIPs = append(cfg.AllowedIPs, prefix)
		return true
	})
	slices.SortFunc(cfg.AllowedIPs, func(a, b netip.Prefix) int {
		return strings.Compare(a.String(), b.String())
	})
	if peer.amnezia.override.hasValues() {
		effective, err := device.peerAmneziaWGConfigLocked(peer)
		if err == nil {
			cfg.AmneziaWG = &effective
		}
	}
	return cfg
}

func (device *Device) peerAmneziaWGConfigLocked(peer *Peer) (AmneziaWGConfig, error) {
	cfg := device.amneziaWGConfigLocked()
	peer.amnezia.override.merge(&cfg)
	if err := validateAmneziaWGConfig(cfg); err != nil {
		return AmneziaWGConfig{}, err
	}
	return cfg, nil
}

func (device *Device) refreshPeerAmneziaWGSnapshotsLocked() {
	device.peers.RLock()
	defer device.peers.RUnlock()
	for _, peer := range device.peers.keyMap {
		_ = device.refreshPeerAmneziaWGSnapshotLocked(peer)
	}
}

func (device *Device) refreshPeerAmneziaWGSnapshotLocked(peer *Peer) error {
	if !peer.amnezia.override.hasValues() {
		peer.amnezia.snapshot.Store(nil)
		return nil
	}

	cfg, err := device.peerAmneziaWGConfigLocked(peer)
	if err != nil {
		return err
	}

	var snapshot amneziaWGSnapshot
	snapshot.junk.count = cfg.JunkCount
	snapshot.junk.min = cfg.JunkMin
	snapshot.junk.max = cfg.JunkMax
	snapshot.headers.init = &magicHeader{start: cfg.InitHeader.Start, end: cfg.InitHeader.End}
	snapshot.headers.response = &magicHeader{start: cfg.ResponseHeader.Start, end: cfg.ResponseHeader.End}
	snapshot.headers.cookie = &magicHeader{start: cfg.CookieHeader.Start, end: cfg.CookieHeader.End}
	snapshot.headers.transport = &magicHeader{start: cfg.TransportHeader.Start, end: cfg.TransportHeader.End}
	snapshot.paddings.init = cfg.InitPadding
	snapshot.paddings.response = cfg.ResponsePadding
	snapshot.paddings.cookie = cfg.CookiePadding
	snapshot.paddings.transport = cfg.TransportPadding
	for i, spec := range cfg.InitiationPackets {
		if spec == "" {
			continue
		}
		chain, err := newObfChain(spec)
		if err != nil {
			return fmt.Errorf("parse initiation packet %d: %w", i+1, err)
		}
		snapshot.ipackets[i] = chain
	}
	peer.amnezia.snapshot.Store(&snapshot)
	return nil
}
