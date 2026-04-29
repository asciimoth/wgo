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
	return cfg
}
