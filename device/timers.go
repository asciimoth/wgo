/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 *
 * This is based heavily on timers.c from the kernel implementation.
 */

package device

import (
	"sync"
	"time"
	_ "unsafe"
)

//go:linkname fastrandn runtime.fastrandn
func fastrandn(n uint32) uint32

// A Timer manages time-based aspects of the WireGuard protocol.
// Timer roughly copies the interface of the Linux kernel's struct timer_list.
type Timer struct {
	*time.Timer
	modifyingLock sync.RWMutex
	runningLock   sync.Mutex
	isPending     bool
	duration      time.Duration
}

func (peer *Peer) NewTimer(expirationFunction func(*Peer)) *Timer {
	timer := &Timer{}
	timer.Timer = time.AfterFunc(time.Hour, func() {
		timer.runningLock.Lock()
		defer timer.runningLock.Unlock()

		timer.modifyingLock.Lock()
		if !timer.isPending {
			timer.modifyingLock.Unlock()
			return
		}
		timer.isPending = false
		timer.duration = 0
		timer.modifyingLock.Unlock()

		expirationFunction(peer)
	})
	timer.Stop()
	return timer
}

func (timer *Timer) Mod(d time.Duration) {
	timer.modifyingLock.Lock()
	timer.isPending = true
	timer.duration = d
	timer.Reset(d)
	timer.modifyingLock.Unlock()
}

func (timer *Timer) Del() {
	timer.modifyingLock.Lock()
	timer.isPending = false
	timer.duration = 0
	timer.Stop()
	timer.modifyingLock.Unlock()
}

func (timer *Timer) DelSync() {
	timer.Del()
	timer.runningLock.Lock()
	timer.Del()
	timer.runningLock.Unlock()
}

func (timer *Timer) IsPending() bool {
	timer.modifyingLock.RLock()
	defer timer.modifyingLock.RUnlock()
	return timer.isPending
}

func (timer *Timer) pendingDuration() (time.Duration, bool) {
	timer.modifyingLock.RLock()
	defer timer.modifyingLock.RUnlock()
	return timer.duration, timer.isPending
}

func (peer *Peer) timersActive() bool {
	return peer.isRunning.Load() && peer.device != nil && peer.device.isUp()
}

func expiredRetransmitHandshake(peer *Peer) {
	maxAttempts := peer.timers.maxHandshakeAttempts.Load()
	if maxAttempts == 0 {
		maxAttempts = peer.sampleMaxHandshakeAttempts()
		peer.timers.maxHandshakeAttempts.Store(maxAttempts)
	}
	if peer.timers.handshakeAttempts.Load() > maxAttempts {
		peer.device.log.Debugf("%s - Handshake did not complete after %d attempts, giving up", peer, maxAttempts+2)

		if peer.timersActive() {
			peer.timers.sendKeepalive.Del()
		}

		/* We drop all packets without a keypair and don't try again,
		 * if we try unsuccessfully for too long to make a handshake.
		 */
		peer.FlushStagedPackets()

		/* We set a timer for destroying any residue that might be left
		 * of a partial exchange.
		 */
		if peer.timersActive() && !peer.timers.zeroKeyMaterial.IsPending() {
			peer.timers.zeroKeyMaterial.Mod(peer.rejectAfterTimeMax() * 3)
		}
	} else {
		peer.timers.handshakeAttempts.Add(1)
		peer.device.log.Debugf("%s - Handshake did not complete after %d seconds, retrying (try %d)", peer, int(peer.rekeyTimeout().Seconds()), peer.timers.handshakeAttempts.Load()+1)

		/* We clear the endpoint address src address, in case this is the cause of trouble. */
		peer.markEndpointSrcForClearing()

		if err := peer.SendHandshakeInitiation(true); err != nil {
			peer.device.log.Debugf("%s - Failed to retry handshake: %v", peer, err)
		}
	}
}

func expiredSendKeepalive(peer *Peer) {
	peer.SendKeepalive()
	if peer.timers.needAnotherKeepalive.Load() {
		peer.timers.needAnotherKeepalive.Store(false)
		if peer.timersActive() {
			peer.timers.sendKeepalive.Mod(peer.sendKeepaliveTimeout())
		}
	}
}

func expiredNewHandshake(peer *Peer) {
	peer.device.log.Debugf("%s - Retrying handshake because we stopped hearing back after %d seconds", peer, int(peer.newHandshakeTimeout().Seconds()))
	/* We clear the endpoint address src address, in case this is the cause of trouble. */
	peer.markEndpointSrcForClearing()
	if err := peer.SendHandshakeInitiation(false); err != nil {
		peer.device.log.Debugf("%s - Failed to send handshake retry: %v", peer, err)
	}
}

func expiredZeroKeyMaterial(peer *Peer) {
	peer.device.log.Debugf("%s - Removing all keys, since we haven't received a new one in %d seconds", peer, int((peer.rejectAfterTimeMax() * 3).Seconds()))
	peer.ZeroAndFlushAll()
}

func expiredPersistentKeepalive(peer *Peer) {
	if peer.persistentKeepaliveRange.Load() != 0 {
		peer.SendKeepalive()
	}
}

/* Should be called after an authenticated data packet is sent. */
func (peer *Peer) timersDataSent() {
	if peer.timersActive() && !peer.timers.newHandshake.IsPending() {
		peer.timers.newHandshake.Mod(peer.newHandshakeTimeout() + time.Millisecond*time.Duration(fastrandn(RekeyTimeoutJitterMaxMs)))
	}
}

/* Should be called after an authenticated data packet is received. */
func (peer *Peer) timersDataReceived() {
	if peer.timersActive() {
		if !peer.timers.sendKeepalive.IsPending() {
			peer.timers.sendKeepalive.Mod(peer.sendKeepaliveTimeout())
		} else {
			peer.timers.needAnotherKeepalive.Store(true)
		}
	}
}

/* Should be called after any type of authenticated packet is sent -- keepalive, data, or handshake. */
func (peer *Peer) timersAnyAuthenticatedPacketSent() {
	if peer.timersActive() {
		peer.timers.sendKeepalive.Del()
	}
}

/* Should be called after any type of authenticated packet is received -- keepalive, data, or handshake. */
func (peer *Peer) timersAnyAuthenticatedPacketReceived() {
	if peer.timersActive() {
		peer.timers.newHandshake.Del()
	}
}

/* Should be called after a handshake initiation message is sent. */
func (peer *Peer) timersHandshakeInitiated() {
	if peer.timersActive() {
		peer.timers.retransmitHandshake.Mod(peer.retransmitHandshakeTimeout() + time.Millisecond*time.Duration(fastrandn(RekeyTimeoutJitterMaxMs)))
	}
}

/* Should be called after a handshake response message is received and processed or when getting key confirmation via the first data message. */
func (peer *Peer) timersHandshakeComplete() {
	if peer.timersActive() {
		peer.timers.retransmitHandshake.Del()
	}
	peer.timers.handshakeAttempts.Store(0)
	peer.timers.maxHandshakeAttempts.Store(peer.sampleMaxHandshakeAttempts())
	peer.timers.sentLastMinuteHandshake.Store(false)
	peer.lastHandshakeNano.Store(time.Now().UnixNano())
	peer.device.signalRuntimeStats()
	time.AfterFunc(peer.rejectAfterTimeMax()+time.Millisecond, peer.device.signalRuntimeStats)
}

/* Should be called after an ephemeral key is created, which is before sending a handshake response or after receiving a handshake response. */
func (peer *Peer) timersSessionDerived() {
	if peer.timersActive() {
		peer.timers.zeroKeyMaterial.Mod(peer.rejectAfterTimeMax() * 3)
	}
}

/* Should be called before a packet with authentication -- keepalive, data, or handshake -- is sent, or after one is received. */
func (peer *Peer) timersAnyAuthenticatedPacketTraversal() {
	keepalive := unpackAmneziaWGRange(peer.persistentKeepaliveRange.Load())
	if keepalive.Set && peer.timersActive() {
		peer.timers.persistentKeepalive.Mod(time.Duration(amneziaWGTimerRangeValue(keepalive)) * time.Second)
	}
}

// amneziaWGTimerRangeValue follows official amneziawg-go timer semantics:
// timer ranges are sampled with runtime.fastrandn from an inclusive uint32
// range. Other AWG range users can still use AmneziaWGRange.Generate.
func amneziaWGTimerRangeValue(r AmneziaWGRange) uint32 {
	if !r.Set || r.Min == r.Max {
		return r.Min
	}
	span := amneziaWGInclusiveRangeSize(r.Min, r.Max)
	if span > uint64(^uint32(0)) {
		high := fastrandn(1 << 16)
		low := fastrandn(1 << 16)
		return high<<16 | low
	}
	return r.Min + fastrandn(uint32(span))
}

func amneziaWGRangeDuration(r AmneziaWGRange, fallback time.Duration) time.Duration {
	if !r.Set {
		return fallback
	}
	return time.Duration(amneziaWGTimerRangeValue(r)) * time.Second
}

func amneziaWGRangeDurationMax(r AmneziaWGRange, fallback time.Duration) time.Duration {
	if !r.Set {
		return fallback
	}
	return time.Duration(r.Max) * time.Second
}

func amneziaWGRangeDurationMin(r AmneziaWGRange, fallback time.Duration) time.Duration {
	if !r.Set {
		return fallback
	}
	return time.Duration(r.Min) * time.Second
}

func (peer *Peer) rekeyAfterTime() time.Duration {
	return amneziaWGRangeDuration(peer.amneziaWGSnapshot().rekeyAfterTime, RekeyAfterTime)
}

func (peer *Peer) rekeyTimeout() time.Duration {
	return amneziaWGRangeDuration(peer.amneziaWGSnapshot().rekeyTimeout, RekeyTimeout)
}

func (peer *Peer) rekeyTimeoutMin() time.Duration {
	return amneziaWGRangeDurationMin(peer.amneziaWGSnapshot().rekeyTimeout, RekeyTimeout)
}

func (peer *Peer) retransmitHandshakeTimeout() time.Duration {
	return peer.rekeyTimeout()
}

func (peer *Peer) rejectAfterTimeMax() time.Duration {
	return amneziaWGRangeDurationMax(peer.amneziaWGSnapshot().rejectAfterTime, RejectAfterTime)
}

func (peer *Peer) rejectAfterTime() time.Duration {
	return amneziaWGRangeDuration(peer.amneziaWGSnapshot().rejectAfterTime, RejectAfterTime)
}

func (peer *Peer) keepaliveTimeout() time.Duration {
	return amneziaWGRangeDuration(peer.amneziaWGSnapshot().keepaliveTimeout, KeepaliveTimeout)
}

func (peer *Peer) sendKeepaliveTimeout() time.Duration {
	return peer.keepaliveTimeout()
}

func (peer *Peer) keepaliveTimeoutMax() time.Duration {
	return amneziaWGRangeDurationMax(peer.amneziaWGSnapshot().keepaliveTimeout, KeepaliveTimeout)
}

func (peer *Peer) keepaliveTimeoutMin() time.Duration {
	return amneziaWGRangeDurationMin(peer.amneziaWGSnapshot().keepaliveTimeout, KeepaliveTimeout)
}

func (peer *Peer) newHandshakeTimeout() time.Duration {
	return peer.keepaliveTimeoutMax() + peer.rekeyTimeout()
}

func (peer *Peer) keyRefreshTimeoutReceiving() time.Duration {
	d := peer.rejectAfterTime() - peer.keepaliveTimeoutMin() - peer.rekeyTimeoutMin()
	if d < 0 {
		return 0
	}
	return d
}

func (peer *Peer) sampleMaxHandshakeAttempts() uint32 {
	r := peer.amneziaWGSnapshot().maxHandshakeAttempts
	if !r.Set {
		return MaxTimerHandshakes
	}
	return amneziaWGTimerRangeValue(r)
}

func (peer *Peer) timersInit() {
	peer.timers.retransmitHandshake = peer.NewTimer(expiredRetransmitHandshake)
	peer.timers.sendKeepalive = peer.NewTimer(expiredSendKeepalive)
	peer.timers.newHandshake = peer.NewTimer(expiredNewHandshake)
	peer.timers.zeroKeyMaterial = peer.NewTimer(expiredZeroKeyMaterial)
	peer.timers.persistentKeepalive = peer.NewTimer(expiredPersistentKeepalive)
}

func (peer *Peer) timersStart() {
	peer.timers.handshakeAttempts.Store(0)
	peer.timers.maxHandshakeAttempts.Store(peer.sampleMaxHandshakeAttempts())
	peer.timers.sentLastMinuteHandshake.Store(false)
	peer.timers.needAnotherKeepalive.Store(false)
}

func (peer *Peer) timersStop() {
	peer.timers.retransmitHandshake.DelSync()
	peer.timers.sendKeepalive.DelSync()
	peer.timers.newHandshake.DelSync()
	peer.timers.zeroKeyMaterial.DelSync()
	peer.timers.persistentKeepalive.DelSync()
}
