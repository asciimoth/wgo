/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 AsciiMoth
 */

package device

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

type PeerEndpoint struct {
	Transport TransportID
	Address   string
}

type PeerActivationMode uint8

const (
	PeerActivationOnDemand PeerActivationMode = iota
	PeerActivationEager
)

type PeerSpec struct {
	PublicKey                   NoisePublicKey
	PresharedKey                NoisePresharedKey
	ProtocolVersion             int
	Endpoint                    *PeerEndpoint
	PersistentKeepaliveInterval uint16
	AllowedIPs                  []netip.Prefix
	AmneziaWG                   *AmneziaWGConfig
	Activation                  PeerActivationMode
}

type PeerSnapshot struct {
	Spec              PeerSpec
	Active            bool
	Connected         bool
	LastHandshakeTime time.Time
	TxBytes           uint64
	RxBytes           uint64
	Revision          uint64
}

func clonePeerSpec(spec PeerSpec) PeerSpec {
	out := spec
	if spec.Endpoint != nil {
		endpoint := *spec.Endpoint
		out.Endpoint = &endpoint
	}
	out.AllowedIPs = slices.Clone(spec.AllowedIPs)
	if spec.AmneziaWG != nil {
		amnezia := *spec.AmneziaWG
		out.AmneziaWG = &amnezia
	}
	return out
}

func (device *Device) validatePeerSpec(spec PeerSpec) error {
	if spec.PublicKey.IsZero() {
		return fmt.Errorf("public key: zero public key")
	}
	if spec.ProtocolVersion != 1 {
		return fmt.Errorf("protocol version: invalid protocol version: %v", spec.ProtocolVersion)
	}
	switch spec.Activation {
	case PeerActivationOnDemand, PeerActivationEager:
	default:
		return fmt.Errorf("activation: invalid activation mode %d", spec.Activation)
	}
	for _, prefix := range spec.AllowedIPs {
		if !prefix.IsValid() {
			return fmt.Errorf("allowed IPs: invalid allowed ip: %v", prefix)
		}
	}
	if spec.AmneziaWG != nil {
		if err := ValidateAmneziaWGConfig(*spec.AmneziaWG); err != nil {
			return fmt.Errorf("amneziawg: %w", err)
		}
	}
	if spec.Endpoint == nil {
		return nil
	}
	if spec.Endpoint.Address == "" {
		return fmt.Errorf("endpoint: address is empty")
	}
	device.net.RLock()
	st := device.net.transports[spec.Endpoint.Transport]
	device.net.RUnlock()
	if st == nil || st.bind == nil {
		return fmt.Errorf("%w: %q", ErrTransportNotFound, spec.Endpoint.Transport)
	}
	if _, err := st.bind.ParseEndpoint(spec.Endpoint.Address); err != nil {
		return fmt.Errorf("endpoint: %w", err)
	}
	return nil
}

func (device *Device) UpsertPeer(spec PeerSpec) error {
	spec = clonePeerSpec(spec)
	if err := device.validatePeerSpec(spec); err != nil {
		return err
	}
	if device.isClosed() {
		return ErrDeviceClosed
	}

	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	device.staticIdentity.RLock()
	self := device.staticIdentity.publicKey
	device.staticIdentity.RUnlock()
	if !self.IsZero() && spec.PublicKey.Equals(self) {
		return nil
	}

	peer := device.lookupPeerLocked(spec.PublicKey)
	created := false
	if peer == nil {
		var err error
		peer, err = device.NewPeer(spec.PublicKey)
		if err != nil {
			return fmt.Errorf("create: %w", err)
		}
		created = true
	}

	var oldSpec PeerSpec
	oldCfg := device.peerConfigLocked(peer)
	if !created {
		oldSpec = device.peerSpecLocked(peer, oldCfg)
	}
	activate := device.isUp() && (spec.Activation == PeerActivationEager || spec.PersistentKeepaliveInterval > 0)
	if activate {
		if err := device.checkActivePeerLimitLocked(peer); err != nil {
			if created {
				device.peers.Lock()
				if device.peers.keyMap[spec.PublicKey] == peer {
					removePeerLocked(device, peer, spec.PublicKey)
					device.storeAmneziaWGReceiveClassifierLocked()
				}
				device.peers.Unlock()
			}
			return err
		}
	}
	if err := device.applyPeerSpecLocked(peer, spec); err != nil {
		if created {
			device.peers.Lock()
			if device.peers.keyMap[spec.PublicKey] == peer {
				removePeerLocked(device, peer, spec.PublicKey)
				device.storeAmneziaWGReceiveClassifierLocked()
			}
			device.peers.Unlock()
		} else if restoreErr := device.applyPeerSpecLocked(peer, oldSpec); restoreErr != nil {
			device.log.Errf("%v - Failed to restore peer after upsert error: %v", peer, restoreErr)
		}
		return err
	}
	peer.revision.Add(1)
	if peerSpecExpiresSession(oldCfg, spec) {
		peer.ExpireCurrentKeypairs()
	}
	if activate {
		device.activatePeerLocked(peer)
	}
	device.signalRuntimeStats()
	return nil
}

func peerSpecExpiresSession(old PeerConfig, spec PeerSpec) bool {
	if old.PresharedKey != spec.PresharedKey {
		return true
	}
	if old.ProtocolVersion != spec.ProtocolVersion {
		return true
	}
	oldAmnezia := old.AmneziaWG
	newAmnezia := spec.AmneziaWG
	if (oldAmnezia == nil) != (newAmnezia == nil) {
		return true
	}
	if oldAmnezia != nil && *oldAmnezia != *newAmnezia {
		return true
	}
	return false
}

func (device *Device) applyPeerSpecLocked(peer *Peer, spec PeerSpec) error {
	if err := device.setPeerPresharedKeyLocked(spec.PublicKey, spec.PresharedKey); err != nil {
		return fmt.Errorf("preshared key: %w", err)
	}
	if err := device.setPeerProtocolVersionLocked(spec.PublicKey, spec.ProtocolVersion); err != nil {
		return fmt.Errorf("protocol version: %w", err)
	}
	if err := device.replacePeerAllowedIPsLocked(spec.PublicKey, spec.AllowedIPs); err != nil {
		return fmt.Errorf("allowed IPs: %w", err)
	}
	if _, err := device.setPeerPersistentKeepaliveIntervalLocked(spec.PublicKey, spec.PersistentKeepaliveInterval, false); err != nil {
		return fmt.Errorf("persistent keepalive interval: %w", err)
	}
	if err := device.setPeerAmneziaWGConfigLocked(spec.PublicKey, spec.AmneziaWG); err != nil {
		return fmt.Errorf("amneziawg: %w", err)
	}
	if spec.Endpoint == nil {
		peer.endpoint.Lock()
		peer.endpoint.val = nil
		peer.endpoint.transport = DefaultTransportID
		peer.endpoint.address = ""
		peer.endpoint.Unlock()
	} else if err := device.setPeerEndpointForTransportLocked(spec.PublicKey, spec.Endpoint.Transport, spec.Endpoint.Address); err != nil {
		return fmt.Errorf("endpoint: %w", err)
	}
	peer.activation = spec.Activation
	return nil
}

func (device *Device) DeletePeer(publicKey NoisePublicKey) (bool, error) {
	if device.isClosed() {
		return false, ErrDeviceClosed
	}
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	device.peers.Lock()
	defer device.peers.Unlock()
	peer, ok := device.peers.keyMap[publicKey]
	if !ok {
		return false, nil
	}
	removePeerLocked(device, peer, publicKey)
	device.storeAmneziaWGReceiveClassifierLocked()
	return true, nil
}

func (device *Device) PeerSpec(publicKey NoisePublicKey) (PeerSpec, bool) {
	snapshot, ok := device.PeerSnapshot(publicKey)
	if !ok {
		return PeerSpec{}, false
	}
	return snapshot.Spec, true
}

func (device *Device) PeerSnapshot(publicKey NoisePublicKey) (PeerSnapshot, bool) {
	device.ipcMutex.RLock()
	defer device.ipcMutex.RUnlock()

	peer := device.lookupPeerLocked(publicKey)
	if peer == nil {
		return PeerSnapshot{}, false
	}

	cfg := device.peerConfigLocked(peer)
	spec := device.peerSpecLocked(peer, cfg)

	now := time.Now()
	snapshot := PeerSnapshot{
		Spec:     spec,
		Active:   peer.isRunning.Load(),
		TxBytes:  cfg.TxBytes,
		RxBytes:  cfg.RxBytes,
		Revision: peer.revision.Load(),
	}
	if !cfg.LastHandshakeTime.IsZero() {
		snapshot.LastHandshakeTime = cfg.LastHandshakeTime
		snapshot.Connected = snapshot.Active && now.Sub(cfg.LastHandshakeTime) <= RejectAfterTime
	}
	return snapshot, true
}

func (device *Device) peerSpecLocked(peer *Peer, cfg PeerConfig) PeerSpec {
	spec := PeerSpec{
		PublicKey:                   cfg.PublicKey,
		PresharedKey:                cfg.PresharedKey,
		ProtocolVersion:             cfg.ProtocolVersion,
		PersistentKeepaliveInterval: cfg.PersistentKeepaliveInterval,
		AllowedIPs:                  slices.Clone(cfg.AllowedIPs),
		AmneziaWG:                   cfg.AmneziaWG,
		Activation:                  peer.activation,
	}
	peer.endpoint.Lock()
	if peer.endpoint.address != "" {
		spec.Endpoint = &PeerEndpoint{
			Transport: peer.endpoint.transport,
			Address:   peer.endpoint.address,
		}
	}
	peer.endpoint.Unlock()
	if spec.AmneziaWG != nil {
		amnezia := *spec.AmneziaWG
		spec.AmneziaWG = &amnezia
	}
	slices.SortFunc(spec.AllowedIPs, func(a, b netip.Prefix) int {
		return strings.Compare(a.String(), b.String())
	})
	return spec
}
