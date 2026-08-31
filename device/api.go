/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 AsciiMoth
 */

package device

import (
	"net/netip"

	conn "github.com/asciimoth/batchudp"
	gtun "github.com/asciimoth/gonnect/tun"
)

// DeviceAPI is the supported library control interface for a WireGuard device.
//
// Implementations must permit concurrent calls. Close is terminal and must be
// safe to call more than once. After Close, methods that change configuration
// return ErrDeviceClosed. Up and Down are no-ops after Close.
//
// Methods with "Tracked" in their name bind a resource to a middleware
// lifetime. A middleware must record successful tracked changes and release
// those resources when it closes. It must forward tracked calls as tracked
// calls so that this rule also works through middleware chains. Direct Device
// calls do not have a narrower middleware lifetime, so Device treats tracked
// methods as aliases for their untracked variants.
//
// Tracking is by peer key, transport ID, or attachment slot. It is lifecycle
// ownership, not access control. Callers must not assign the same resource to
// independent middleware instances. An untracked change does not release an
// existing assignment. Use the matching tracked remove or detach method before
// another owner reuses the key, ID, or slot.
//
// The concrete Device type also has low-level methods for its packet workers
// and compatibility with the original wireguard-go implementation. Those
// methods are implementation details and are intentionally not part of this
// interface.
type DeviceAPI interface {
	// Lifecycle.
	Up() error
	Down() error
	Close()
	Wait() chan struct{}

	// Device configuration.
	PrivateKey() NoisePrivateKey
	SetPrivateKey(NoisePrivateKey) error
	ListenPort() uint16
	SetListenPort(uint16) error
	Fwmark() uint32
	SetFwmark(uint32) error
	AmneziaWGConfig() AmneziaWGConfig
	SetAmneziaWGConfig(AmneziaWGConfig) error
	SetAmneziaWGConfigPatch(AmneziaWGConfigPatch) error
	Config() DeviceConfig
	ApplyConfig(DeviceConfig, ApplyConfigOptions) error

	// Peer configuration.
	PeerConfig(NoisePublicKey) (PeerConfig, bool)
	SetPeerPresharedKey(NoisePublicKey, NoisePresharedKey) error
	SetPeerEndpoint(NoisePublicKey, string) error
	SetPeerPersistentKeepaliveInterval(NoisePublicKey, uint16) error
	SetPeerPersistentKeepaliveRange(NoisePublicKey, AmneziaWGRange) error
	PeerPersistentKeepaliveRange(NoisePublicKey) (AmneziaWGRange, bool)
	SetAmneziaWGVersion(AmneziaWGVersion) error
	SetPeerAmneziaWGVersion(NoisePublicKey, AmneziaWGVersion) error
	SetPeerProtocolVersion(NoisePublicKey, int) error
	SetPeerAmneziaWGConfig(NoisePublicKey, AmneziaWGConfig) error
	PeerAmneziaWGConfigOverride(NoisePublicKey) (AmneziaWGConfigPatch, bool)
	SetPeerAmneziaWGConfigPatch(NoisePublicKey, AmneziaWGConfigPatch) error
	ClearPeerAmneziaWGConfig(NoisePublicKey) error
	ReplacePeerAllowedIPs(NoisePublicKey, []netip.Prefix) error
	AddPeerAllowedIP(NoisePublicKey, netip.Prefix) error
	RemovePeerAllowedIP(NoisePublicKey, netip.Prefix) error
	ActivatePeer(NoisePublicKey) error
	UpsertPeer(PeerSpec) error
	DeletePeer(NoisePublicKey) (bool, error)
	// UpsertTrackedPeer adds or replaces a peer and assigns its public key to
	// the current middleware lifetime. A failed upsert does not assign it.
	UpsertTrackedPeer(PeerSpec) error
	// DeleteTrackedPeer deletes a peer and releases its public key from the
	// current middleware lifetime. A successful call releases the key even if
	// the peer did not exist.
	DeleteTrackedPeer(NoisePublicKey) (bool, error)
	PeerSpec(NoisePublicKey) (PeerSpec, bool)
	PeerSnapshot(NoisePublicKey) (PeerSnapshot, bool)
	SendKeepalivesToPeersWithCurrentKeypair()

	// Packet transports and device attachments.
	AddTransport(TransportID, TransportConfig) error
	ReplaceTransport(TransportID, TransportConfig) error
	RemoveTransport(TransportID) error
	// AddTrackedTransport adds a batchudp transport and assigns its ID to the
	// current middleware lifetime.
	AddTrackedTransport(TransportID, TransportConfig) error
	// ReplaceTrackedTransport replaces a batchudp transport and assigns its ID
	// to the current middleware lifetime.
	ReplaceTrackedTransport(TransportID, TransportConfig) error
	// RemoveTrackedTransport removes a batchudp transport and releases its ID
	// from the current middleware lifetime.
	RemoveTrackedTransport(TransportID) error
	TransportInfo(TransportID) (TransportInfo, bool)
	ReplaceTUN(gtun.Tun) error
	AttachTUN(gtun.Tun) error
	DetachTUN() error
	// Tracked TUN methods assign or release the single TUN attachment slot.
	ReplaceTrackedTUN(gtun.Tun) error
	AttachTrackedTUN(gtun.Tun) error
	DetachTrackedTUN() error
	ReplaceBind(conn.Bind) error
	AttachBind(conn.Bind) error
	DetachBind() error
	// Tracked bind methods assign or release the default batchudp bind slot.
	ReplaceTrackedBind(conn.Bind) error
	AttachTrackedBind(conn.Bind) error
	DetachTrackedBind() error

	// Runtime information and event subscriptions.
	BatchSize() int
	IsUnderLoad() bool
	AmneziaWGReceiveCounters() AmneziaWGReceiveCounters
	SetRuntimeStatsThresholds(RuntimeStatsThresholds)
	SubscribeRuntimeStats(RuntimeStatsCallback) func()
	RuntimeStats() RuntimeStats
	SubscribeReceiveErrors(func(ReceiveError)) func()
}

var _ DeviceAPI = (*Device)(nil)
