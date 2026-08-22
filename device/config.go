/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 AsciiMoth
 */

package device

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	conn "github.com/asciimoth/batchudp"
)

// DeviceConfig is a complete device configuration snapshot.
//
// Config returns this type with current state. ApplyConfig uses the same type as
// desired state, but it ignores peer runtime fields such as byte counters and
// handshake time. Use DefaultAmneziaWGConfig when you build a config manually;
// the zero AmneziaWGConfig value is not a valid complete profile.
type DeviceConfig struct {
	PrivateKey NoisePrivateKey
	ListenPort uint16
	Fwmark     uint32
	AmneziaWG  AmneziaWGConfig
	Peers      []PeerConfig
}

// PeerConfig is a peer configuration snapshot.
//
// PublicKey identifies the peer. LastHandshakeTime, TxBytes, and RxBytes are
// runtime output fields from Config and PeerConfig. ApplyConfig does not write
// those runtime fields back to the device.
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

// ApplyConfigOptions controls how ApplyConfig reconciles peers and endpoints.
type ApplyConfigOptions struct {
	// ReplacePeers removes peers that are not present in DeviceConfig.Peers.
	ReplacePeers bool
	// ApplyEndpoints applies PeerConfig.Endpoint values. When false, existing
	// endpoints stay unchanged.
	ApplyEndpoints bool
	// ActivatePeers starts configured peers when the device is up.
	ActivatePeers bool
}

// AmneziaWGConfigPatch is a partial AmneziaWG update.
//
// Nil fields mean "leave unchanged". A nil InitiationPackets entry leaves that
// packet spec unchanged. A non-nil empty string clears that packet spec.
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

// EndpointParser validates endpoint strings using bind-specific endpoint parsing.
type EndpointParser interface {
	ParseEndpoint(string) (conn.Endpoint, error)
}

// ValidationOptions configures optional dependencies for pure config validation.
type ValidationOptions struct {
	EndpointParser EndpointParser
}

// ValidateConfig validates a full device configuration without mutating a Device.
func ValidateConfig(cfg DeviceConfig) error {
	return ValidateConfigWithOptions(cfg, ValidationOptions{})
}

// ValidateConfigWithOptions validates a full device configuration with optional parser dependencies.
func ValidateConfigWithOptions(cfg DeviceConfig, opts ValidationOptions) error {
	if err := ValidateAmneziaWGConfig(cfg.AmneziaWG); err != nil {
		return fmt.Errorf("amneziawg: %w", err)
	}
	if len(cfg.Peers) > MaxPeers {
		return fmt.Errorf("peers: too many peers")
	}

	seen := make(map[NoisePublicKey]struct{}, len(cfg.Peers))
	for _, peer := range cfg.Peers {
		if _, ok := seen[peer.PublicKey]; ok {
			return fmt.Errorf("peer %s: duplicate public key", validationPeerName(peer.PublicKey))
		}
		seen[peer.PublicKey] = struct{}{}

		if err := validatePeerConfig(peer, opts); err != nil {
			return fmt.Errorf("peer %s: %w", validationPeerName(peer.PublicKey), err)
		}
	}
	if err := validateDeviceConfigAmneziaWGReceiveProfiles(cfg); err != nil {
		return err
	}
	return nil
}

// ValidatePeerConfig validates a single peer configuration without mutating a Device.
func ValidatePeerConfig(peer PeerConfig) error {
	return validatePeerConfig(peer, ValidationOptions{})
}

// ValidateAmneziaWGConfig validates a complete AmneziaWG configuration.
func ValidateAmneziaWGConfig(cfg AmneziaWGConfig) error {
	return validateAmneziaWGConfig(cfg)
}

// ValidateAmneziaWGConfigPatch validates patch-local AmneziaWG values.
func ValidateAmneziaWGConfigPatch(patch AmneziaWGConfigPatch) error {
	override, err := patch.toIPC()
	if err != nil {
		return err
	}
	return validateAmneziaWGConfigPatch(override)
}

func validatePeerConfig(peer PeerConfig, opts ValidationOptions) error {
	if peer.ProtocolVersion != 1 {
		return fmt.Errorf("protocol version: invalid protocol version: %v", peer.ProtocolVersion)
	}
	if err := validateEndpoint(peer.Endpoint, opts.EndpointParser); err != nil {
		return fmt.Errorf("endpoint: %w", err)
	}
	for _, prefix := range peer.AllowedIPs {
		if !prefix.IsValid() {
			return fmt.Errorf("allowed IPs: invalid allowed ip: %v", prefix)
		}
	}
	if peer.AmneziaWG != nil {
		if err := ValidateAmneziaWGConfig(*peer.AmneziaWG); err != nil {
			return fmt.Errorf("amneziawg: %w", err)
		}
	}
	return nil
}

func validateEndpoint(endpoint string, parser EndpointParser) error {
	if endpoint == "" {
		return nil
	}
	if parser != nil {
		if _, err := parser.ParseEndpoint(endpoint); err != nil {
			return err
		}
		return nil
	}
	if _, err := netip.ParseAddrPort(endpoint); err != nil {
		host, port, splitErr := net.SplitHostPort(endpoint)
		if splitErr != nil {
			return splitErr
		}
		if host == "" {
			return fmt.Errorf("missing host in address")
		}
		if _, portErr := strconv.ParseUint(port, 10, 16); portErr != nil {
			return fmt.Errorf("invalid port %q: %w", port, portErr)
		}
	}
	return nil
}

func validateAmneziaWGConfigPatch(patch ipcSetAmneziaWG) error {
	for _, field := range []struct {
		name  string
		value *int
		max   int
	}{
		{"junk count", patch.junkCount, maxAmneziaWGJunkCount},
		{"junk min", patch.junkMin, maxAmneziaWGJunkSize},
		{"junk max", patch.junkMax, maxAmneziaWGJunkSize},
	} {
		if field.value != nil {
			if err := validateAmneziaWGNonNegativeField(field.name, *field.value, field.max); err != nil {
				return err
			}
		}
	}
	for _, field := range []struct {
		name  string
		value *int
		max   int
	}{
		{"init padding", patch.initPadding, maxAmneziaWGHandshakePaddingSize},
		{"response padding", patch.responsePadding, MaxMessageSize - MessageResponseSize},
		{"cookie padding", patch.cookiePadding, MaxMessageSize - MessageCookieReplySize},
		{"transport padding", patch.transportPadding, maxAmneziaWGTransportPaddingSize},
	} {
		if field.value != nil {
			if err := validateAmneziaWGNonNegativeField(field.name, *field.value, field.max); err != nil {
				return err
			}
		}
	}
	for _, field := range []struct {
		name   string
		header *magicHeader
	}{
		{"init header", patch.initHeader},
		{"response header", patch.responseHeader},
		{"cookie header", patch.cookieHeader},
		{"transport header", patch.transportHeader},
	} {
		if field.header != nil && field.header.end < field.header.start {
			return fmt.Errorf("%s range end must be >= start", field.name)
		}
	}
	headers := []*magicHeader{patch.initHeader, patch.responseHeader, patch.cookieHeader, patch.transportHeader}
	for i := 0; i < len(headers); i++ {
		if headers[i] == nil {
			continue
		}
		for j := i + 1; j < len(headers); j++ {
			if headers[j] == nil {
				continue
			}
			left := headers[i]
			right := headers[j]
			if left.start <= right.end && right.start <= left.end {
				return fmt.Errorf("headers must not overlap")
			}
		}
	}
	if patch.junkCount != nil && *patch.junkCount > 0 {
		if patch.junkMin != nil && *patch.junkMin <= 0 {
			return fmt.Errorf("junk min must be positive when junk is enabled")
		}
		if patch.junkMax != nil && *patch.junkMax <= 0 {
			return fmt.Errorf("junk max must be positive when junk is enabled")
		}
	}
	if patch.junkMin != nil && patch.junkMax != nil && *patch.junkMin > *patch.junkMax {
		return fmt.Errorf("junk min must be <= junk max")
	}
	for i, chain := range patch.initiationPackets {
		if !patch.packetSet[i] || chain == nil {
			continue
		}
		if chain.ObfuscatedLen() > maxAmneziaWGInitiationPacketSize {
			return fmt.Errorf("initiation packet %d length must be <= %d", i+1, maxAmneziaWGInitiationPacketSize)
		}
	}
	return nil
}

func validationPeerName(key NoisePublicKey) string {
	if key.IsZero() {
		return "<zero>"
	}
	return fmt.Sprintf("%x", key[:])
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

// ApplyConfig reconciles the device with cfg according to opts.
func (device *Device) ApplyConfig(cfg DeviceConfig, opts ApplyConfigOptions) error {
	validationOpts := ValidationOptions{}
	if opts.ApplyEndpoints {
		device.net.RLock()
		bind := device.net.bind
		device.net.RUnlock()
		if bind != nil {
			validationOpts.EndpointParser = bind
		}
		for _, peer := range cfg.Peers {
			if peer.Endpoint != "" && bind == nil {
				return fmt.Errorf("peer %s: endpoint: no bind attached", validationPeerName(peer.PublicKey))
			}
		}
	}
	if err := ValidateConfigWithOptions(cfg, validationOpts); err != nil {
		return err
	}
	if device.isClosed() {
		return fmt.Errorf("device is closed")
	}
	if err := device.validateApplyPeerCapacity(cfg, opts); err != nil {
		return err
	}

	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	if err := device.SetPrivateKey(cfg.PrivateKey); err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	if err := device.setListenPortLocked(cfg.ListenPort); err != nil {
		return fmt.Errorf("listen port: %w", err)
	}
	if err := device.setFwmarkLocked(cfg.Fwmark); err != nil {
		return fmt.Errorf("fwmark: %w", err)
	}
	if opts.ReplacePeers {
		device.RemoveAllPeers()
	}
	if err := device.setAmneziaWGConfigLocked(cfg.AmneziaWG); err != nil {
		return fmt.Errorf("amneziawg: %w", err)
	}

	for _, peerCfg := range cfg.Peers {
		if err := device.applyPeerConfigLocked(peerCfg, opts); err != nil {
			return fmt.Errorf("peer %s: %w", validationPeerName(peerCfg.PublicKey), err)
		}
	}
	return nil
}

func (device *Device) validateApplyPeerCapacity(cfg DeviceConfig, opts ApplyConfigOptions) error {
	if opts.ReplacePeers {
		return nil
	}

	var self NoisePublicKey
	if !cfg.PrivateKey.IsZero() {
		self = cfg.PrivateKey.PublicKey()
	}

	device.peers.RLock()
	defer device.peers.RUnlock()

	count := 0
	for key := range device.peers.keyMap {
		if !self.IsZero() && key.Equals(self) {
			continue
		}
		count++
	}
	for _, peer := range cfg.Peers {
		if !self.IsZero() && peer.PublicKey.Equals(self) {
			continue
		}
		if _, ok := device.peers.keyMap[peer.PublicKey]; ok {
			continue
		}
		count++
		if count > MaxPeers {
			return fmt.Errorf("peers: too many peers")
		}
	}
	return nil
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
	if err := device.checkActivePeerLimitLocked(peer); err != nil {
		return err
	}
	device.activatePeerLocked(peer)
	return nil
}

func (device *Device) applyPeerConfigLocked(cfg PeerConfig, opts ApplyConfigOptions) error {
	device.staticIdentity.RLock()
	self := device.staticIdentity.publicKey
	device.staticIdentity.RUnlock()
	if !self.IsZero() && cfg.PublicKey.Equals(self) {
		return nil
	}

	peer := device.lookupPeerLocked(cfg.PublicKey)
	if peer == nil {
		var err error
		peer, err = device.NewPeer(cfg.PublicKey)
		if err != nil {
			return fmt.Errorf("create: %w", err)
		}
	}

	if err := device.setPeerPresharedKeyLocked(cfg.PublicKey, cfg.PresharedKey); err != nil {
		return fmt.Errorf("preshared key: %w", err)
	}
	if err := device.setPeerProtocolVersionLocked(cfg.PublicKey, cfg.ProtocolVersion); err != nil {
		return fmt.Errorf("protocol version: %w", err)
	}
	if err := device.replacePeerAllowedIPsLocked(cfg.PublicKey, cfg.AllowedIPs); err != nil {
		return fmt.Errorf("allowed IPs: %w", err)
	}
	if _, err := device.setPeerPersistentKeepaliveIntervalLocked(cfg.PublicKey, cfg.PersistentKeepaliveInterval, false); err != nil {
		return fmt.Errorf("persistent keepalive interval: %w", err)
	}
	if err := device.setPeerAmneziaWGConfigLocked(cfg.PublicKey, cfg.AmneziaWG); err != nil {
		return fmt.Errorf("amneziawg: %w", err)
	}
	if opts.ApplyEndpoints {
		if cfg.Endpoint == "" {
			peer.endpoint.Lock()
			peer.endpoint.val = nil
			peer.endpoint.Unlock()
		} else if err := device.setPeerEndpointLocked(cfg.PublicKey, cfg.Endpoint); err != nil {
			return fmt.Errorf("endpoint: %w", err)
		}
	}
	if opts.ActivatePeers {
		if err := device.checkActivePeerLimitLocked(peer); err != nil {
			return err
		}
		device.activatePeerLocked(peer)
	}
	return nil
}

func (device *Device) activatePeerLocked(peer *Peer) {
	if !device.isUp() {
		return
	}
	peer.Start()
	if peer.persistentKeepaliveInterval.Load() > 0 {
		peer.SendKeepalive()
	}
	peer.SendStagedPackets()
}

func (device *Device) setListenPortLocked(port uint16) error {
	device.net.Lock()
	device.net.port = port
	if st := device.defaultTransportLocked(); st != nil {
		st.port = port
	}
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
	if err := device.validateAmneziaWGReceiveProfilesForBaseLocked(cfg); err != nil {
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
	device.storeAmneziaWGReceiveClassifier()
	return nil
}

func validateAmneziaWGConfig(cfg AmneziaWGConfig) error {
	if err := validateAmneziaWGNonNegativeField("junk count", cfg.JunkCount, maxAmneziaWGJunkCount); err != nil {
		return err
	}
	if err := validateAmneziaWGNonNegativeField("junk min", cfg.JunkMin, maxAmneziaWGJunkSize); err != nil {
		return err
	}
	if err := validateAmneziaWGNonNegativeField("junk max", cfg.JunkMax, maxAmneziaWGJunkSize); err != nil {
		return err
	}
	if cfg.JunkMin > cfg.JunkMax {
		return fmt.Errorf("junk min must be <= junk max")
	}
	if cfg.JunkCount > 0 && (cfg.JunkMin <= 0 || cfg.JunkMax <= 0) {
		return fmt.Errorf("junk min and max must be positive when junk is enabled")
	}
	for _, field := range []struct {
		name  string
		value int
		max   int
	}{
		{"init padding", cfg.InitPadding, maxAmneziaWGHandshakePaddingSize},
		{"response padding", cfg.ResponsePadding, MaxMessageSize - MessageResponseSize},
		{"cookie padding", cfg.CookiePadding, MaxMessageSize - MessageCookieReplySize},
		{"transport padding", cfg.TransportPadding, maxAmneziaWGTransportPaddingSize},
	} {
		if err := validateAmneziaWGNonNegativeField(field.name, field.value, field.max); err != nil {
			return err
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
		chain, err := newObfChain(spec)
		if err != nil {
			return fmt.Errorf("parse initiation packet %d: %w", i+1, err)
		}
		if chain.ObfuscatedLen() > maxAmneziaWGInitiationPacketSize {
			return fmt.Errorf("initiation packet %d length must be <= %d", i+1, maxAmneziaWGInitiationPacketSize)
		}
	}
	return nil
}

func validateAmneziaWGGeneratedLength(length int) error {
	return validateAmneziaWGNonNegativeField("generated length", length, maxAmneziaWGInitiationPacketSize)
}

func validateAmneziaWGNonNegativeField(name string, value, max int) error {
	if value < 0 {
		return fmt.Errorf("%s must be non-negative", name)
	}
	if value > max {
		return fmt.Errorf("%s must be <= %d", name, max)
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
	return device.setPeerEndpointForTransportLocked(publicKey, DefaultTransportID, endpoint)
}

func (device *Device) setPeerEndpointForTransportLocked(publicKey NoisePublicKey, transportID TransportID, endpoint string) error {
	peer, err := device.requirePeerLocked(publicKey)
	if err != nil {
		return err
	}

	device.net.RLock()
	st := device.net.transports[transportID]
	device.net.RUnlock()
	if st == nil || st.bind == nil {
		if transportID == DefaultTransportID {
			return fmt.Errorf("failed to set endpoint %v: no bind attached", endpoint)
		}
		return fmt.Errorf("%w: %q", ErrTransportNotFound, transportID)
	}

	parsed, err := st.bind.ParseEndpoint(endpoint)
	if err != nil {
		return fmt.Errorf("failed to set endpoint %v: %w", endpoint, err)
	}

	peer.endpoint.Lock()
	peer.endpoint.val = parsed
	peer.endpoint.transport = transportID
	peer.endpoint.address = endpoint
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
		device.storeAmneziaWGReceiveClassifier()
		return nil
	}

	if err := validateAmneziaWGConfig(*cfg); err != nil {
		return err
	}
	if err := device.validateAmneziaWGReceiveProfilesForPeerConfigLocked(peer, *cfg); err != nil {
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
	if err := device.refreshPeerAmneziaWGSnapshotLocked(peer); err != nil {
		return err
	}
	device.storeAmneziaWGReceiveClassifier()
	return nil
}

func (device *Device) setPeerAmneziaWGConfigPatchLocked(peer *Peer, override ipcSetAmneziaWG) error {
	if !override.hasValues() {
		peer.amnezia.override = ipcSetAmneziaWG{}
		peer.amnezia.snapshot.Store(nil)
		device.storeAmneziaWGReceiveClassifier()
		return nil
	}

	previous := peer.amnezia.override
	peer.amnezia.override = override
	if err := device.refreshPeerAmneziaWGSnapshotLocked(peer); err != nil {
		peer.amnezia.override = previous
		_ = device.refreshPeerAmneziaWGSnapshotLocked(peer)
		device.storeAmneziaWGReceiveClassifier()
		return err
	}
	if err := device.validateCurrentAmneziaWGReceiveProfilesLocked(); err != nil {
		peer.amnezia.override = previous
		_ = device.refreshPeerAmneziaWGSnapshotLocked(peer)
		device.storeAmneziaWGReceiveClassifier()
		return err
	}
	device.storeAmneziaWGReceiveClassifier()
	return nil
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

	device.allowedips.ReplaceForPeer(peer, allowedIPs)
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
		return nil, ErrPeerNotFound
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
		cfg.Endpoint = peer.endpoint.address
		if cfg.Endpoint == "" {
			cfg.Endpoint = peer.endpoint.val.DstToString()
		}
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

func validateDeviceConfigAmneziaWGReceiveProfiles(cfg DeviceConfig) error {
	profiles := []amneziaWGSnapshot{amneziaWGSnapshotFromConfig(cfg.AmneziaWG)}
	for _, peer := range cfg.Peers {
		if peer.AmneziaWG == nil {
			continue
		}
		profiles = append(profiles, amneziaWGSnapshotFromConfig(*peer.AmneziaWG))
	}
	return validateAmneziaWGReceiveProfiles(profiles)
}

func (device *Device) validateAmneziaWGReceiveProfilesForBaseLocked(cfg AmneziaWGConfig) error {
	profiles := []amneziaWGSnapshot{amneziaWGSnapshotFromConfig(cfg)}
	device.peers.RLock()
	defer device.peers.RUnlock()
	for _, peer := range device.peers.keyMap {
		if !peer.amnezia.override.hasValues() {
			continue
		}
		effective := cfg
		peer.amnezia.override.merge(&effective)
		if err := validateAmneziaWGConfig(effective); err != nil {
			return err
		}
		profiles = append(profiles, amneziaWGSnapshotFromConfig(effective))
	}
	return validateAmneziaWGReceiveProfiles(profiles)
}

func (device *Device) validateAmneziaWGReceiveProfilesForPeerConfigLocked(target *Peer, cfg AmneziaWGConfig) error {
	profiles := []amneziaWGSnapshot{device.amneziaWGSnapshot()}
	device.peers.RLock()
	defer device.peers.RUnlock()
	for _, peer := range device.peers.keyMap {
		if peer == target {
			profiles = append(profiles, amneziaWGSnapshotFromConfig(cfg))
			continue
		}
		snapshot := peer.amnezia.snapshot.Load()
		if snapshot != nil {
			profiles = append(profiles, *snapshot)
		}
	}
	return validateAmneziaWGReceiveProfiles(profiles)
}

func (device *Device) validateCurrentAmneziaWGReceiveProfilesLocked() error {
	profiles := []amneziaWGSnapshot{device.amneziaWGSnapshot()}
	device.peers.RLock()
	defer device.peers.RUnlock()
	for _, peer := range device.peers.keyMap {
		snapshot := peer.amnezia.snapshot.Load()
		if snapshot != nil {
			profiles = append(profiles, *snapshot)
		}
	}
	return validateAmneziaWGReceiveProfiles(profiles)
}

func amneziaWGSnapshotFromConfig(cfg AmneziaWGConfig) amneziaWGSnapshot {
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
		if err == nil {
			snapshot.ipackets[i] = chain
		}
	}
	return snapshot
}
