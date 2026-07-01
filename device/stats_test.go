/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 AsciiMoth
 */

package device

import (
	"testing"
	"time"
)

func TestRuntimeStatsPeerCounts(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil)
	t.Cleanup(dev.Close)

	privateKey := mustPrivateKey(t, 1)
	peerKey := privateKey.publicKey()
	peer, err := dev.NewPeer(peerKey)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}

	stats := dev.RuntimeStats()
	if stats.PeerCount != 1 || stats.ActivePeerCount != 0 || stats.ConnectedPeerCount != 0 {
		t.Fatalf("RuntimeStats() counts after NewPeer = %+v, want peer=1 active=0 connected=0", stats)
	}

	peer.Start()
	stats = dev.RuntimeStats()
	if stats.PeerCount != 1 || stats.ActivePeerCount != 1 || stats.ConnectedPeerCount != 0 {
		t.Fatalf("RuntimeStats() counts after Start = %+v, want peer=1 active=1 connected=0", stats)
	}

	handshakeTime := time.Now()
	peer.lastHandshakeNano.Store(handshakeTime.UnixNano())
	stats = dev.RuntimeStats()
	if stats.ConnectedPeerCount != 1 || !stats.LastHandshakeTime.Equal(handshakeTime) {
		t.Fatalf("RuntimeStats() after handshake = %+v, want connected=1 latest=%v", stats, handshakeTime)
	}

	peer.lastHandshakeNano.Store(time.Now().Add(-RejectAfterTime - time.Second).UnixNano())
	stats = dev.RuntimeStats()
	if stats.ConnectedPeerCount != 0 {
		t.Fatalf("RuntimeStats().ConnectedPeerCount with stale handshake = %d, want 0", stats.ConnectedPeerCount)
	}

	dev.RemovePeer(peer.handshake.remoteStatic)
	stats = dev.RuntimeStats()
	if stats.PeerCount != 0 || stats.ActivePeerCount != 0 || stats.ConnectedPeerCount != 0 {
		t.Fatalf("RuntimeStats() counts after RemovePeer = %+v, want all zero", stats)
	}
}

func TestRuntimeStatsSubscriptionTrafficThresholds(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil)
	t.Cleanup(dev.Close)
	dev.SetRuntimeStatsThresholds(RuntimeStatsThresholds{
		ByteDelta:   100,
		PacketDelta: 10,
	})

	updates := make(chan RuntimeStats, 8)
	unsubscribe := dev.SubscribeRuntimeStats(func(stats RuntimeStats) {
		updates <- stats
	})
	defer unsubscribe()

	waitRuntimeStatsUpdate(t, updates, func(stats RuntimeStats) bool {
		return stats.TxBytes == 0 && stats.RxPackets == 0
	})

	dev.accountRuntimeStatsTx(99, 1)
	assertNoRuntimeStatsUpdate(t, updates)

	dev.accountRuntimeStatsTx(1, 1)
	stats := waitRuntimeStatsUpdate(t, updates, func(stats RuntimeStats) bool {
		return stats.TxBytes == 100 && stats.TxPackets == 2
	})
	if stats.RxPackets != 0 {
		t.Fatalf("RuntimeStats().RxPackets after TX update = %d, want 0", stats.RxPackets)
	}

	dev.accountRuntimeStatsRx(0, 9)
	assertNoRuntimeStatsUpdate(t, updates)

	dev.accountRuntimeStatsRx(0, 1)
	waitRuntimeStatsUpdate(t, updates, func(stats RuntimeStats) bool {
		return stats.RxPackets == 10
	})
}

func waitRuntimeStatsUpdate(tb testing.TB, updates <-chan RuntimeStats, ok func(RuntimeStats) bool) RuntimeStats {
	tb.Helper()

	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		select {
		case stats := <-updates:
			if ok(stats) {
				return stats
			}
		case <-timer.C:
			tb.Fatal("timeout waiting for runtime stats update")
		}
	}
}

func assertNoRuntimeStatsUpdate(tb testing.TB, updates <-chan RuntimeStats) {
	tb.Helper()

	select {
	case stats := <-updates:
		tb.Fatalf("unexpected runtime stats update: %+v", stats)
	case <-time.After(50 * time.Millisecond):
	}
}
