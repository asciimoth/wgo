/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 AsciiMoth
 */

package device

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultRuntimeStatsByteDelta is the default traffic delta required before
	// runtime stats subscribers are notified about RX/TX byte changes.
	DefaultRuntimeStatsByteDelta uint64 = 10 << 20

	// DefaultRuntimeStatsPacketDelta is the default traffic delta required before
	// runtime stats subscribers are notified about RX/TX packet changes.
	DefaultRuntimeStatsPacketDelta uint64 = 100
)

// RuntimeStatsThresholds controls how often high-frequency traffic stats notify
// subscribers. Zero fields are replaced with the package defaults.
type RuntimeStatsThresholds struct {
	ByteDelta   uint64
	PacketDelta uint64
}

// RuntimeStats is a point-in-time device stats snapshot delivered to
// subscribers and returned by Device.RuntimeStats. Traffic counters are lifetime
// totals for the device. Connected peers are active peers with a recent
// completed handshake.
type RuntimeStats struct {
	Timestamp time.Time

	PeerCount            int
	ActivePeerCount      int
	ConnectedPeerCount   int
	TransportCount       int
	ActiveTransportCount int

	RxBytes   uint64
	TxBytes   uint64
	RxPackets uint64
	TxPackets uint64

	LastHandshakeTime time.Time
}

// Equal reports whether two runtime stats snapshots describe the same device
// state, ignoring the snapshot timestamp.
func (stats RuntimeStats) Equal(other RuntimeStats) bool {
	return stats.PeerCount == other.PeerCount &&
		stats.ActivePeerCount == other.ActivePeerCount &&
		stats.ConnectedPeerCount == other.ConnectedPeerCount &&
		stats.TransportCount == other.TransportCount &&
		stats.ActiveTransportCount == other.ActiveTransportCount &&
		stats.RxBytes == other.RxBytes &&
		stats.TxBytes == other.TxBytes &&
		stats.RxPackets == other.RxPackets &&
		stats.TxPackets == other.TxPackets &&
		stats.LastHandshakeTime.Equal(other.LastHandshakeTime)
}

// RuntimeStatsCallback receives device runtime stats snapshots. Callbacks are
// invoked from a device-owned goroutine, not from packet processing goroutines.
type RuntimeStatsCallback func(RuntimeStats)

// SetRuntimeStatsThresholds updates traffic notification thresholds. Peer
// lifecycle and handshake events still notify subscribers immediately.
func (device *Device) SetRuntimeStatsThresholds(thresholds RuntimeStatsThresholds) {
	if thresholds.ByteDelta == 0 {
		thresholds.ByteDelta = DefaultRuntimeStatsByteDelta
	}
	if thresholds.PacketDelta == 0 {
		thresholds.PacketDelta = DefaultRuntimeStatsPacketDelta
	}
	device.stats.byteDelta.Store(thresholds.ByteDelta)
	device.stats.packetDelta.Store(thresholds.PacketDelta)
}

// SubscribeRuntimeStats registers cb for runtime stats updates and returns an
// unsubscribe function. The subscriber receives an initial snapshot
// asynchronously.
func (device *Device) SubscribeRuntimeStats(cb RuntimeStatsCallback) func() {
	if cb == nil {
		return func() {}
	}

	device.stats.Lock()
	device.stats.nextSubID++
	id := device.stats.nextSubID
	device.stats.subscribers[id] = cb
	device.stats.Unlock()

	device.signalRuntimeStats()

	var once sync.Once
	return func() {
		once.Do(func() {
			device.stats.Lock()
			delete(device.stats.subscribers, id)
			device.stats.Unlock()
		})
	}
}

// RuntimeStats returns a current runtime stats snapshot.
func (device *Device) RuntimeStats() RuntimeStats {
	now := time.Now()
	stats := RuntimeStats{
		Timestamp: now,
		RxBytes:   device.stats.rxBytes.Load(),
		TxBytes:   device.stats.txBytes.Load(),
		RxPackets: device.stats.rxPackets.Load(),
		TxPackets: device.stats.txPackets.Load(),
	}

	device.peers.RLock()
	stats.PeerCount = len(device.peers.keyMap)
	for _, peer := range device.peers.keyMap {
		running := peer.isRunning.Load()
		if running {
			stats.ActivePeerCount++
		}
		nano := peer.lastHandshakeNano.Load()
		if nano == 0 {
			continue
		}
		handshakeTime := time.Unix(0, nano)
		if stats.LastHandshakeTime.IsZero() || handshakeTime.After(stats.LastHandshakeTime) {
			stats.LastHandshakeTime = handshakeTime
		}
		if running && now.Sub(handshakeTime) <= peer.rejectAfterTimeMax() {
			stats.ConnectedPeerCount++
		}
	}
	device.peers.RUnlock()

	device.net.RLock()
	stats.TransportCount = len(device.net.transports)
	for _, st := range device.net.transports {
		if st.up {
			stats.ActiveTransportCount++
		}
	}
	device.net.RUnlock()

	return stats
}

func (device *Device) routineRuntimeStatsNotifier() {
	for {
		select {
		case <-device.stats.notify:
			device.dispatchRuntimeStats()
		case <-device.closed:
			return
		}
	}
}

func (device *Device) dispatchRuntimeStats() {
	stats := device.RuntimeStats()

	device.stats.RLock()
	callbacks := make([]RuntimeStatsCallback, 0, len(device.stats.subscribers))
	for _, cb := range device.stats.subscribers {
		callbacks = append(callbacks, cb)
	}
	device.stats.RUnlock()

	for _, cb := range callbacks {
		device.callRuntimeStatsCallback(cb, stats)
	}
}

func (device *Device) callRuntimeStatsCallback(cb RuntimeStatsCallback, stats RuntimeStats) {
	defer func() {
		if recover() != nil {
			device.log.Debugf("runtime stats callback panicked")
		}
	}()
	cb(stats)
}

func (device *Device) signalRuntimeStats() {
	select {
	case device.stats.notify <- struct{}{}:
	default:
	}
}

func (device *Device) accountRuntimeStatsRx(bytes, packets uint64) {
	device.accountRuntimeStatsTraffic(bytes, packets, &device.stats.rxBytes, &device.stats.rxPackets, &device.stats.lastNotifyRxBytes, &device.stats.lastNotifyRxPackets)
}

func (device *Device) accountRuntimeStatsTx(bytes, packets uint64) {
	device.accountRuntimeStatsTraffic(bytes, packets, &device.stats.txBytes, &device.stats.txPackets, &device.stats.lastNotifyTxBytes, &device.stats.lastNotifyTxPackets)
}

func (device *Device) accountRuntimeStatsTraffic(bytes, packets uint64, byteCounter, packetCounter, lastByteNotify, lastPacketNotify *atomic.Uint64) {
	if bytes == 0 && packets == 0 {
		return
	}

	var shouldNotify bool
	if bytes > 0 {
		total := byteCounter.Add(bytes)
		shouldNotify = runtimeStatsThresholdCrossed(total, device.stats.byteDelta.Load(), lastByteNotify)
	}
	if packets > 0 {
		total := packetCounter.Add(packets)
		shouldNotify = runtimeStatsThresholdCrossed(total, device.stats.packetDelta.Load(), lastPacketNotify) || shouldNotify
	}
	if shouldNotify {
		device.signalRuntimeStats()
	}
}

func runtimeStatsThresholdCrossed(total, delta uint64, lastNotify *atomic.Uint64) bool {
	if delta == 0 {
		return false
	}
	for {
		last := lastNotify.Load()
		if total-last < delta {
			return false
		}
		if lastNotify.CompareAndSwap(last, total) {
			return true
		}
	}
}
