/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 AsciiMoth
 */

package device

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	conn "github.com/asciimoth/batchudp"
	gtun "github.com/asciimoth/gonnect/tun"
)

var _ DeviceAPI = (*DetachedDevice)(nil)

// DetachedDevice is an independently closable wrapper around a DeviceAPI.
//
// Close closes only this wrapper. It does not call Close, Down, or another
// lifecycle method on the wrapped device. Multiple wrappers can use the same
// device concurrently, and closing one wrapper does not close the others.
// Wrappers can also form a chain. Closing an inner wrapper closes each outer
// wrapper, but closing an outer wrapper does not close an inner wrapper. Close
// is safe to call more than once.
//
// Tracked methods assign peers, transports, TUN attachments, and bind
// attachments to this wrapper. Close releases all assigned resources from the
// wrapped device before it closes this wrapper. The corresponding tracked
// remove or detach method releases an assignment. Untracked methods do not
// change assignments. Subscriptions are always assigned to this wrapper.
//
// Calls that started before Close can finish. Close waits for those calls.
// Calls that start after Close behave like calls on a closed Device: lifecycle
// calls are no-ops, configuration calls return ErrDeviceClosed, snapshot calls
// return the state captured at Close, and subscriptions do not register.
type DetachedDevice struct {
	wrapped DeviceAPI

	gate   sync.RWMutex
	closed atomic.Bool
	done   chan struct{}

	closedConfig       DeviceConfig
	closedStats        RuntimeStats
	closedReceiveStats AmneziaWGReceiveCounters
	batchSize          int

	transportMu     sync.Mutex
	transportIDs    map[TransportID]struct{}
	closedTransport map[TransportID]TransportInfo

	trackedResourcesMu sync.Mutex
	trackedPeers       map[NoisePublicKey]struct{}
	trackedTransports  map[TransportID]struct{}
	trackedTUN         bool
	trackedBind        bool

	subscriptionsMu sync.Mutex
	nextSubID       uint64
	subscriptions   map[uint64]*detachedDeviceSubscription
}

type detachedDeviceSubscription struct {
	once        sync.Once
	unsubscribe func()
}

func (s *detachedDeviceSubscription) stop() {
	s.once.Do(s.unsubscribe)
}

// DetachDevice creates an independently closable wrapper around dev.
//
// dev must not be nil. If dev is already closed, the returned wrapper is also
// closed before this function returns.
func DetachDevice(dev DeviceAPI) *DetachedDevice {
	if dev == nil {
		panic("device.DetachDevice: nil DeviceAPI")
	}

	detached := &DetachedDevice{
		wrapped:           dev,
		done:              make(chan struct{}),
		batchSize:         dev.BatchSize(),
		transportIDs:      map[TransportID]struct{}{DefaultTransportID: {}},
		closedTransport:   make(map[TransportID]TransportInfo),
		trackedPeers:      make(map[NoisePublicKey]struct{}),
		trackedTransports: make(map[TransportID]struct{}),
		subscriptions:     make(map[uint64]*detachedDeviceSubscription),
	}

	select {
	case <-dev.Wait():
		detached.Close()
	default:
		go detached.watchWrappedDevice()
	}
	return detached
}

// GetWrapped returns the wrapped device.
func (d *DetachedDevice) GetWrapped() DeviceAPI {
	return d.wrapped
}

func (d *DetachedDevice) watchWrappedDevice() {
	select {
	case <-d.wrapped.Wait():
		d.Close()
	case <-d.done:
	}
}

func (d *DetachedDevice) begin() (DeviceAPI, bool) {
	d.gate.RLock()
	if d.closed.Load() {
		d.gate.RUnlock()
		return nil, false
	}
	return d.wrapped, true
}

func (d *DetachedDevice) end() {
	d.gate.RUnlock()
}

// Close permanently closes this wrapper without closing the wrapped device.
func (d *DetachedDevice) Close() {
	d.gate.Lock()
	if d.closed.Swap(true) {
		d.gate.Unlock()
		return
	}

	d.releaseTrackedResources()
	d.closedConfig = d.wrapped.Config()
	d.closedConfig.Peers = make([]PeerConfig, 0)
	d.closedStats = d.wrapped.RuntimeStats()
	d.closedStats.PeerCount = 0
	d.closedStats.ActivePeerCount = 0
	d.closedStats.ConnectedPeerCount = 0
	d.closedStats.ActiveTransportCount = 0
	d.closedReceiveStats = d.wrapped.AmneziaWGReceiveCounters()
	d.captureTransports()

	d.subscriptionsMu.Lock()
	subscriptions := make([]*detachedDeviceSubscription, 0, len(d.subscriptions))
	for id, subscription := range d.subscriptions {
		delete(d.subscriptions, id)
		subscriptions = append(subscriptions, subscription)
	}
	d.subscriptionsMu.Unlock()
	d.gate.Unlock()

	for _, subscription := range subscriptions {
		subscription.stop()
	}
	close(d.done)
}

func (d *DetachedDevice) releaseTrackedResources() {
	d.trackedResourcesMu.Lock()
	defer d.trackedResourcesMu.Unlock()
	for key := range d.trackedPeers {
		_, _ = d.wrapped.DeleteTrackedPeer(key)
		delete(d.trackedPeers, key)
	}
	for id := range d.trackedTransports {
		_ = d.wrapped.RemoveTrackedTransport(id)
		delete(d.trackedTransports, id)
	}
	if d.trackedTUN {
		_ = d.wrapped.DetachTrackedTUN()
		d.trackedTUN = false
	}
	if d.trackedBind {
		_ = d.wrapped.DetachTrackedBind()
		d.trackedBind = false
	}
}

func (d *DetachedDevice) captureTransports() {
	d.transportMu.Lock()
	defer d.transportMu.Unlock()
	for id := range d.transportIDs {
		info, ok := d.wrapped.TransportInfo(id)
		if !ok {
			continue
		}
		info.Up = false
		d.closedTransport[id] = info
	}
}

// Wait returns a channel that is closed when this wrapper is closed.
func (d *DetachedDevice) Wait() chan struct{} {
	return d.done
}

// Up forwards to the wrapped device while this wrapper is open. It is a no-op
// after Close, as it is for a closed Device.
func (d *DetachedDevice) Up() error {
	dev, ok := d.begin()
	if !ok {
		return nil
	}
	defer d.end()
	return dev.Up()
}

// Down forwards to the wrapped device while this wrapper is open. It is a
// no-op after Close, as it is for a closed Device.
func (d *DetachedDevice) Down() error {
	dev, ok := d.begin()
	if !ok {
		return nil
	}
	defer d.end()
	return dev.Down()
}

func (d *DetachedDevice) PrivateKey() NoisePrivateKey {
	dev, ok := d.begin()
	if !ok {
		return d.closedConfig.PrivateKey
	}
	defer d.end()
	return dev.PrivateKey()
}

func (d *DetachedDevice) SetPrivateKey(key NoisePrivateKey) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	return dev.SetPrivateKey(key)
}

func (d *DetachedDevice) ListenPort() uint16 {
	dev, ok := d.begin()
	if !ok {
		return d.closedConfig.ListenPort
	}
	defer d.end()
	return dev.ListenPort()
}

func (d *DetachedDevice) SetListenPort(port uint16) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	return dev.SetListenPort(port)
}

func (d *DetachedDevice) Fwmark() uint32 {
	dev, ok := d.begin()
	if !ok {
		return d.closedConfig.Fwmark
	}
	defer d.end()
	return dev.Fwmark()
}

func (d *DetachedDevice) SetFwmark(mark uint32) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	return dev.SetFwmark(mark)
}

func (d *DetachedDevice) AmneziaWGConfig() AmneziaWGConfig {
	dev, ok := d.begin()
	if !ok {
		return d.closedConfig.AmneziaWG
	}
	defer d.end()
	return dev.AmneziaWGConfig()
}

func (d *DetachedDevice) SetAmneziaWGConfig(cfg AmneziaWGConfig) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	return dev.SetAmneziaWGConfig(cfg)
}

func (d *DetachedDevice) SetAmneziaWGConfigPatch(patch AmneziaWGConfigPatch) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	return dev.SetAmneziaWGConfigPatch(patch)
}

func (d *DetachedDevice) Config() DeviceConfig {
	dev, ok := d.begin()
	if !ok {
		return d.closedConfig
	}
	defer d.end()
	return dev.Config()
}

func (d *DetachedDevice) ApplyConfig(cfg DeviceConfig, opts ApplyConfigOptions) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	return dev.ApplyConfig(cfg, opts)
}

func (d *DetachedDevice) PeerConfig(key NoisePublicKey) (PeerConfig, bool) {
	dev, ok := d.begin()
	if !ok {
		return PeerConfig{}, false
	}
	defer d.end()
	return dev.PeerConfig(key)
}

func (d *DetachedDevice) SetPeerPresharedKey(key NoisePublicKey, psk NoisePresharedKey) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	return dev.SetPeerPresharedKey(key, psk)
}

func (d *DetachedDevice) SetPeerEndpoint(key NoisePublicKey, endpoint string) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	return dev.SetPeerEndpoint(key, endpoint)
}

func (d *DetachedDevice) SetPeerPersistentKeepaliveInterval(key NoisePublicKey, seconds uint16) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	return dev.SetPeerPersistentKeepaliveInterval(key, seconds)
}

func (d *DetachedDevice) SetPeerPersistentKeepaliveRange(key NoisePublicKey, keepalive AmneziaWGRange) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	return dev.SetPeerPersistentKeepaliveRange(key, keepalive)
}

func (d *DetachedDevice) PeerPersistentKeepaliveRange(key NoisePublicKey) (AmneziaWGRange, bool) {
	dev, ok := d.begin()
	if !ok {
		return AmneziaWGRange{}, false
	}
	defer d.end()
	return dev.PeerPersistentKeepaliveRange(key)
}

func (d *DetachedDevice) SetAmneziaWGVersion(version AmneziaWGVersion) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	return dev.SetAmneziaWGVersion(version)
}

func (d *DetachedDevice) SetPeerAmneziaWGVersion(key NoisePublicKey, version AmneziaWGVersion) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	return dev.SetPeerAmneziaWGVersion(key, version)
}

func (d *DetachedDevice) SetPeerProtocolVersion(key NoisePublicKey, version int) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	return dev.SetPeerProtocolVersion(key, version)
}

func (d *DetachedDevice) SetPeerAmneziaWGConfig(key NoisePublicKey, cfg AmneziaWGConfig) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	return dev.SetPeerAmneziaWGConfig(key, cfg)
}

func (d *DetachedDevice) PeerAmneziaWGConfigOverride(key NoisePublicKey) (AmneziaWGConfigPatch, bool) {
	dev, ok := d.begin()
	if !ok {
		return AmneziaWGConfigPatch{}, false
	}
	defer d.end()
	return dev.PeerAmneziaWGConfigOverride(key)
}

func (d *DetachedDevice) SetPeerAmneziaWGConfigPatch(key NoisePublicKey, patch AmneziaWGConfigPatch) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	return dev.SetPeerAmneziaWGConfigPatch(key, patch)
}

func (d *DetachedDevice) ClearPeerAmneziaWGConfig(key NoisePublicKey) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	return dev.ClearPeerAmneziaWGConfig(key)
}

func (d *DetachedDevice) ReplacePeerAllowedIPs(key NoisePublicKey, prefixes []netip.Prefix) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	return dev.ReplacePeerAllowedIPs(key, prefixes)
}

func (d *DetachedDevice) AddPeerAllowedIP(key NoisePublicKey, prefix netip.Prefix) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	return dev.AddPeerAllowedIP(key, prefix)
}

func (d *DetachedDevice) RemovePeerAllowedIP(key NoisePublicKey, prefix netip.Prefix) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	return dev.RemovePeerAllowedIP(key, prefix)
}

func (d *DetachedDevice) ActivatePeer(key NoisePublicKey) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	return dev.ActivatePeer(key)
}

func (d *DetachedDevice) UpsertPeer(spec PeerSpec) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	return dev.UpsertPeer(spec)
}

func (d *DetachedDevice) DeletePeer(key NoisePublicKey) (bool, error) {
	dev, ok := d.begin()
	if !ok {
		return false, ErrDeviceClosed
	}
	defer d.end()
	return dev.DeletePeer(key)
}

// UpsertTrackedPeer adds or replaces a peer and assigns it to this wrapper.
// Close deletes peers assigned by successful calls to this method. The tracked
// call is forwarded so that nested middleware can enforce the same lifetime.
func (d *DetachedDevice) UpsertTrackedPeer(spec PeerSpec) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()

	d.trackedResourcesMu.Lock()
	defer d.trackedResourcesMu.Unlock()
	if err := dev.UpsertTrackedPeer(spec); err != nil {
		return err
	}
	d.trackedPeers[spec.PublicKey] = struct{}{}
	return nil
}

// DeleteTrackedPeer deletes a peer and releases it from this wrapper.
// A successful call releases the public key even if no peer existed.
func (d *DetachedDevice) DeleteTrackedPeer(key NoisePublicKey) (bool, error) {
	dev, ok := d.begin()
	if !ok {
		return false, ErrDeviceClosed
	}
	defer d.end()

	d.trackedResourcesMu.Lock()
	defer d.trackedResourcesMu.Unlock()
	deleted, err := dev.DeleteTrackedPeer(key)
	if err != nil {
		return false, err
	}
	delete(d.trackedPeers, key)
	return deleted, nil
}

func (d *DetachedDevice) PeerSpec(key NoisePublicKey) (PeerSpec, bool) {
	dev, ok := d.begin()
	if !ok {
		return PeerSpec{}, false
	}
	defer d.end()
	return dev.PeerSpec(key)
}

func (d *DetachedDevice) PeerSnapshot(key NoisePublicKey) (PeerSnapshot, bool) {
	dev, ok := d.begin()
	if !ok {
		return PeerSnapshot{}, false
	}
	defer d.end()
	return dev.PeerSnapshot(key)
}

func (d *DetachedDevice) SendKeepalivesToPeersWithCurrentKeypair() {
	dev, ok := d.begin()
	if !ok {
		return
	}
	defer d.end()
	dev.SendKeepalivesToPeersWithCurrentKeypair()
}

func (d *DetachedDevice) AddTransport(id TransportID, cfg TransportConfig) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	if err := dev.AddTransport(id, cfg); err != nil {
		return err
	}
	d.rememberTransport(id)
	return nil
}

func (d *DetachedDevice) ReplaceTransport(id TransportID, cfg TransportConfig) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	if err := dev.ReplaceTransport(id, cfg); err != nil {
		return err
	}
	d.rememberTransport(id)
	return nil
}

func (d *DetachedDevice) RemoveTransport(id TransportID) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	if err := dev.RemoveTransport(id); err != nil {
		return err
	}
	d.transportMu.Lock()
	delete(d.transportIDs, id)
	d.transportMu.Unlock()
	return nil
}

// AddTrackedTransport adds a transport and assigns it to this wrapper.
func (d *DetachedDevice) AddTrackedTransport(id TransportID, cfg TransportConfig) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()

	d.trackedResourcesMu.Lock()
	defer d.trackedResourcesMu.Unlock()
	if err := dev.AddTrackedTransport(id, cfg); err != nil {
		return err
	}
	d.trackedTransports[id] = struct{}{}
	d.rememberTransport(id)
	return nil
}

// ReplaceTrackedTransport replaces a transport and assigns it to this wrapper.
func (d *DetachedDevice) ReplaceTrackedTransport(id TransportID, cfg TransportConfig) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()

	d.trackedResourcesMu.Lock()
	defer d.trackedResourcesMu.Unlock()
	if err := dev.ReplaceTrackedTransport(id, cfg); err != nil {
		return err
	}
	d.trackedTransports[id] = struct{}{}
	d.rememberTransport(id)
	return nil
}

// RemoveTrackedTransport removes a transport and releases it from this wrapper.
func (d *DetachedDevice) RemoveTrackedTransport(id TransportID) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()

	d.trackedResourcesMu.Lock()
	defer d.trackedResourcesMu.Unlock()
	if err := dev.RemoveTrackedTransport(id); err != nil {
		return err
	}
	delete(d.trackedTransports, id)
	d.transportMu.Lock()
	delete(d.transportIDs, id)
	d.transportMu.Unlock()
	return nil
}

func (d *DetachedDevice) rememberTransport(id TransportID) {
	d.transportMu.Lock()
	d.transportIDs[id] = struct{}{}
	d.transportMu.Unlock()
}

func (d *DetachedDevice) TransportInfo(id TransportID) (TransportInfo, bool) {
	dev, ok := d.begin()
	if !ok {
		d.transportMu.Lock()
		defer d.transportMu.Unlock()
		info, found := d.closedTransport[id]
		return info, found
	}
	defer d.end()
	info, found := dev.TransportInfo(id)
	if found {
		d.rememberTransport(id)
	}
	return info, found
}

func (d *DetachedDevice) ReplaceTUN(tunDevice gtun.Tun) error {
	dev, ok := d.begin()
	if !ok {
		if tunDevice != nil {
			_ = tunDevice.Close()
		}
		return ErrDeviceClosed
	}
	defer d.end()
	return dev.ReplaceTUN(tunDevice)
}

func (d *DetachedDevice) AttachTUN(tunDevice gtun.Tun) error {
	dev, ok := d.begin()
	if !ok {
		if tunDevice != nil {
			_ = tunDevice.Close()
		}
		return ErrDeviceClosed
	}
	defer d.end()
	return dev.AttachTUN(tunDevice)
}

func (d *DetachedDevice) DetachTUN() error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	return dev.DetachTUN()
}

// ReplaceTrackedTUN replaces the TUN and assigns it to this wrapper.
func (d *DetachedDevice) ReplaceTrackedTUN(tunDevice gtun.Tun) error {
	dev, ok := d.begin()
	if !ok {
		if tunDevice != nil {
			_ = tunDevice.Close()
		}
		return ErrDeviceClosed
	}
	defer d.end()

	d.trackedResourcesMu.Lock()
	defer d.trackedResourcesMu.Unlock()
	if err := dev.ReplaceTrackedTUN(tunDevice); err != nil {
		return err
	}
	d.trackedTUN = tunDevice != nil
	return nil
}

// AttachTrackedTUN attaches a TUN and assigns it to this wrapper.
func (d *DetachedDevice) AttachTrackedTUN(tunDevice gtun.Tun) error {
	dev, ok := d.begin()
	if !ok {
		if tunDevice != nil {
			_ = tunDevice.Close()
		}
		return ErrDeviceClosed
	}
	defer d.end()

	d.trackedResourcesMu.Lock()
	defer d.trackedResourcesMu.Unlock()
	if err := dev.AttachTrackedTUN(tunDevice); err != nil {
		return err
	}
	d.trackedTUN = true
	return nil
}

// DetachTrackedTUN detaches the TUN and releases it from this wrapper.
func (d *DetachedDevice) DetachTrackedTUN() error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()

	d.trackedResourcesMu.Lock()
	defer d.trackedResourcesMu.Unlock()
	if err := dev.DetachTrackedTUN(); err != nil {
		return err
	}
	d.trackedTUN = false
	return nil
}

func (d *DetachedDevice) ReplaceBind(bind conn.Bind) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	return dev.ReplaceBind(bind)
}

func (d *DetachedDevice) AttachBind(bind conn.Bind) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	return dev.AttachBind(bind)
}

func (d *DetachedDevice) DetachBind() error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()
	return dev.DetachBind()
}

// ReplaceTrackedBind replaces the bind and assigns it to this wrapper.
func (d *DetachedDevice) ReplaceTrackedBind(bind conn.Bind) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()

	d.trackedResourcesMu.Lock()
	defer d.trackedResourcesMu.Unlock()
	if err := dev.ReplaceTrackedBind(bind); err != nil {
		return err
	}
	d.trackedBind = bind != nil
	return nil
}

// AttachTrackedBind attaches a bind and assigns it to this wrapper.
func (d *DetachedDevice) AttachTrackedBind(bind conn.Bind) error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()

	d.trackedResourcesMu.Lock()
	defer d.trackedResourcesMu.Unlock()
	if err := dev.AttachTrackedBind(bind); err != nil {
		return err
	}
	d.trackedBind = true
	return nil
}

// DetachTrackedBind detaches the bind and releases it from this wrapper.
func (d *DetachedDevice) DetachTrackedBind() error {
	dev, ok := d.begin()
	if !ok {
		return ErrDeviceClosed
	}
	defer d.end()

	d.trackedResourcesMu.Lock()
	defer d.trackedResourcesMu.Unlock()
	if err := dev.DetachTrackedBind(); err != nil {
		return err
	}
	d.trackedBind = false
	return nil
}

func (d *DetachedDevice) BatchSize() int {
	return d.batchSize
}

func (d *DetachedDevice) IsUnderLoad() bool {
	dev, ok := d.begin()
	if !ok {
		return false
	}
	defer d.end()
	return dev.IsUnderLoad()
}

func (d *DetachedDevice) AmneziaWGReceiveCounters() AmneziaWGReceiveCounters {
	dev, ok := d.begin()
	if !ok {
		return d.closedReceiveStats
	}
	defer d.end()
	return dev.AmneziaWGReceiveCounters()
}

func (d *DetachedDevice) SetRuntimeStatsThresholds(thresholds RuntimeStatsThresholds) {
	dev, ok := d.begin()
	if !ok {
		return
	}
	defer d.end()
	dev.SetRuntimeStatsThresholds(thresholds)
}

func (d *DetachedDevice) SubscribeRuntimeStats(cb RuntimeStatsCallback) func() {
	if cb == nil {
		return func() {}
	}
	return d.subscribe(func() func() {
		return d.wrapped.SubscribeRuntimeStats(func(stats RuntimeStats) {
			d.runCallback(func() { cb(stats) })
		})
	})
}

func (d *DetachedDevice) RuntimeStats() RuntimeStats {
	dev, ok := d.begin()
	if !ok {
		stats := d.closedStats
		stats.Timestamp = time.Now()
		return stats
	}
	defer d.end()
	return dev.RuntimeStats()
}

func (d *DetachedDevice) SubscribeReceiveErrors(cb func(ReceiveError)) func() {
	if cb == nil {
		return func() {}
	}
	return d.subscribe(func() func() {
		return d.wrapped.SubscribeReceiveErrors(func(receiveError ReceiveError) {
			d.runCallback(func() { cb(receiveError) })
		})
	})
}

func (d *DetachedDevice) subscribe(register func() func()) func() {
	d.gate.RLock()
	if d.closed.Load() {
		d.gate.RUnlock()
		return func() {}
	}
	subscription := &detachedDeviceSubscription{unsubscribe: register()}
	d.subscriptionsMu.Lock()
	id := d.nextSubID
	d.nextSubID++
	d.subscriptions[id] = subscription
	d.subscriptionsMu.Unlock()
	d.gate.RUnlock()

	return func() {
		d.subscriptionsMu.Lock()
		delete(d.subscriptions, id)
		d.subscriptionsMu.Unlock()
		subscription.stop()
	}
}

func (d *DetachedDevice) runCallback(callback func()) {
	if d.closed.Load() {
		return
	}
	callback()
}
