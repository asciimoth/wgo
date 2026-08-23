/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 AsciiMoth
 */

package device

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	conn "github.com/asciimoth/batchudp"
	"github.com/asciimoth/wgo/tai64n"
	"golang.org/x/crypto/chacha20"
)

func TestDeviceAmneziaWGTypedConfigMethods(t *testing.T) {
	tunDev := newChannelTUN()
	bind := &fakeTransitionBind{id: "bind0", size: 1}
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	cfg := DefaultAmneziaWGConfig()
	cfg.JunkCount = 2
	cfg.JunkMin = 8
	cfg.JunkMax = 16
	cfg.InitPadding = 5
	cfg.ResponsePadding = 4
	cfg.CookiePadding = 3
	cfg.TransportPadding = 2
	cfg.InitHeader = AmneziaWGHeaderRange{Start: 1000, End: 1004}
	cfg.ResponseHeader = AmneziaWGHeaderRange{Start: 2000, End: 2000}
	cfg.CookieHeader = AmneziaWGHeaderRange{Start: 3000, End: 3001}
	cfg.TransportHeader = AmneziaWGHeaderRange{Start: 4000, End: 4007}
	cfg.InitiationPackets[1] = "<b 0xaa><rc 4><t>"
	cfg.InitiationPackets[4] = "<r 8>"

	if err := dev.SetAmneziaWGConfig(cfg); err != nil {
		t.Fatalf("SetAmneziaWGConfig: %v", err)
	}

	got := dev.AmneziaWGConfig()
	if got != cfg {
		t.Fatalf("AmneziaWGConfig() = %+v, want %+v", got, cfg)
	}

	deviceCfg := dev.Config()
	if deviceCfg.AmneziaWG != cfg {
		t.Fatalf("Config().AmneziaWG = %+v, want %+v", deviceCfg.AmneziaWG, cfg)
	}
}

func TestAmneziaWGTimerRangeParityHelpers(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)

	peerPrivateKey := mustPrivateKey(t, 201)
	peerKey := peerPrivateKey.publicKey()
	peer, err := dev.NewPeer(peerKey)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}

	cfg := DefaultAmneziaWGConfig()
	cfg.Version = AmneziaWGV3_1
	cfg.RekeyTimeout = AmneziaWGRange{Min: 7, Max: 7, Set: true}
	cfg.RejectAfterTime = AmneziaWGRange{Min: 90, Max: 90, Set: true}
	cfg.KeepaliveTimeout = AmneziaWGRange{Min: 11, Max: 13, Set: true}
	cfg.MaxHandshakeAttempts = AmneziaWGRange{Min: 3, Max: 3, Set: true}
	if err := dev.SetAmneziaWGConfig(cfg); err != nil {
		t.Fatalf("SetAmneziaWGConfig: %v", err)
	}

	if got, want := peer.newHandshakeTimeout(), 20*time.Second; got != want {
		t.Fatalf("newHandshakeTimeout() = %v, want %v", got, want)
	}
	if got, want := peer.keyRefreshTimeoutReceiving(), 72*time.Second; got != want {
		t.Fatalf("keyRefreshTimeoutReceiving() = %v, want %v", got, want)
	}
	if got, want := peer.keepaliveTimeoutMin(), 11*time.Second; got != want {
		t.Fatalf("keepaliveTimeoutMin() = %v, want %v", got, want)
	}
	if got, want := peer.keepaliveTimeoutMax(), 13*time.Second; got != want {
		t.Fatalf("keepaliveTimeoutMax() = %v, want %v", got, want)
	}

	peer.timersStart()
	if got, want := peer.timers.maxHandshakeAttempts.Load(), uint32(3); got != want {
		t.Fatalf("timersStart maxHandshakeAttempts = %d, want %d", got, want)
	}

	cfg.MaxHandshakeAttempts = AmneziaWGRange{Min: 5, Max: 5, Set: true}
	if err := dev.SetAmneziaWGConfig(cfg); err != nil {
		t.Fatalf("SetAmneziaWGConfig(updated): %v", err)
	}
	if got, want := peer.timers.maxHandshakeAttempts.Load(), uint32(3); got != want {
		t.Fatalf("config reload changed active maxHandshakeAttempts = %d, want %d", got, want)
	}
	peer.timersHandshakeComplete()
	if got, want := peer.timers.maxHandshakeAttempts.Load(), uint32(5); got != want {
		t.Fatalf("timersHandshakeComplete maxHandshakeAttempts = %d, want %d", got, want)
	}
}

func TestAmneziaWGTimerRangeSchedulesConfiguredDurations(t *testing.T) {
	tunDev := newChannelTUN()
	bind := &fakeTransitionBind{id: "bind0", size: 1}
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	peerPrivateKey := mustPrivateKey(t, 202)
	peerKey := peerPrivateKey.publicKey()
	peer, err := dev.NewPeer(peerKey)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}

	cfg := DefaultAmneziaWGConfig()
	cfg.Version = AmneziaWGV3_1
	cfg.RekeyTimeout = AmneziaWGRange{Min: 7, Max: 7, Set: true}
	cfg.RejectAfterTime = AmneziaWGRange{Min: 90, Max: 90, Set: true}
	cfg.KeepaliveTimeout = AmneziaWGRange{Min: 11, Max: 11, Set: true}
	if err := dev.SetAmneziaWGConfig(cfg); err != nil {
		t.Fatalf("SetAmneziaWGConfig: %v", err)
	}
	peer.Start()

	peer.timersDataReceived()
	assertTimerDuration(t, peer.timers.sendKeepalive, 11*time.Second, 11*time.Second)

	peer.timersDataSent()
	assertTimerDuration(t, peer.timers.newHandshake, 18*time.Second, 18*time.Second+time.Duration(RekeyTimeoutJitterMaxMs)*time.Millisecond)

	peer.timersHandshakeInitiated()
	assertTimerDuration(t, peer.timers.retransmitHandshake, 7*time.Second, 7*time.Second+time.Duration(RekeyTimeoutJitterMaxMs)*time.Millisecond)

	peer.timersSessionDerived()
	assertTimerDuration(t, peer.timers.zeroKeyMaterial, 270*time.Second, 270*time.Second)

	peer.persistentKeepaliveRange.Store(packAmneziaWGRange(AmneziaWGRange{Min: 17, Max: 17, Set: true}))
	peer.timersAnyAuthenticatedPacketTraversal()
	assertTimerDuration(t, peer.timers.persistentKeepalive, 17*time.Second, 17*time.Second)

	peer.persistentKeepaliveRange.Store(packAmneziaWGRange(AmneziaWGRange{Min: 23, Max: 23, Set: true}))
	peer.timersAnyAuthenticatedPacketTraversal()
	assertTimerDuration(t, peer.timers.persistentKeepalive, 23*time.Second, 23*time.Second)
}

func TestAmneziaWGTimerRangeSchedulesNonFixedRangesWithinBounds(t *testing.T) {
	tunDev := newChannelTUN()
	bind := &fakeTransitionBind{id: "bind0", size: 1}
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	peerPrivateKey := mustPrivateKey(t, 204)
	peerKey := peerPrivateKey.publicKey()
	peer, err := dev.NewPeer(peerKey)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}

	cfg := DefaultAmneziaWGConfig()
	cfg.Version = AmneziaWGV3_1
	cfg.RekeyTimeout = AmneziaWGRange{Min: 7, Max: 9, Set: true}
	cfg.RejectAfterTime = AmneziaWGRange{Min: 90, Max: 93, Set: true}
	cfg.KeepaliveTimeout = AmneziaWGRange{Min: 11, Max: 13, Set: true}
	if err := dev.SetAmneziaWGConfig(cfg); err != nil {
		t.Fatalf("SetAmneziaWGConfig: %v", err)
	}
	peer.Start()

	peer.timersDataReceived()
	assertTimerDuration(t, peer.timers.sendKeepalive, 11*time.Second, 13*time.Second)

	peer.timersDataSent()
	assertTimerDuration(t, peer.timers.newHandshake, 20*time.Second, 22*time.Second+time.Duration(RekeyTimeoutJitterMaxMs)*time.Millisecond)

	peer.timersHandshakeInitiated()
	assertTimerDuration(t, peer.timers.retransmitHandshake, 7*time.Second, 9*time.Second+time.Duration(RekeyTimeoutJitterMaxMs)*time.Millisecond)

	peer.timersSessionDerived()
	assertTimerDuration(t, peer.timers.zeroKeyMaterial, 279*time.Second, 279*time.Second)

	peer.persistentKeepaliveRange.Store(packAmneziaWGRange(AmneziaWGRange{Min: 17, Max: 19, Set: true}))
	peer.timersAnyAuthenticatedPacketTraversal()
	assertTimerDuration(t, peer.timers.persistentKeepalive, 17*time.Second, 19*time.Second)
}

func TestAmneziaWGTimerRangeValueMatchesUpstreamBounds(t *testing.T) {
	if got := amneziaWGTimerRangeValue(AmneziaWGRange{}); got != 0 {
		t.Fatalf("unset timer range value = %d, want 0", got)
	}
	if got := amneziaWGTimerRangeValue(AmneziaWGRange{Min: 9, Max: 9, Set: true}); got != 9 {
		t.Fatalf("fixed timer range value = %d, want 9", got)
	}

	for i := 0; i < 128; i++ {
		got := amneziaWGTimerRangeValue(AmneziaWGRange{Min: 3, Max: 7, Set: true})
		assertUint32Range(t, "sampled timer range value", got, 3, 7)
	}
}

func TestAmneziaWGFullUint32RangesDoNotPanic(t *testing.T) {
	t.Parallel()

	rng := AmneziaWGRange{Min: 0, Max: ^uint32(0), Set: true}
	for range 16 {
		_ = rng.Generate()
		_ = amneziaWGTimerRangeValue(rng)
	}

	header := AmneziaWGHeaderRange{Start: 0, End: ^uint32(0)}
	for range 16 {
		_ = header.Generate()
	}
}

func TestAmneziaWGRejectAfterRangeControlsStatusConnectivity(t *testing.T) {
	tunDev := newChannelTUN()
	bind := &fakeTransitionBind{id: "bind0", size: 1}
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	peerPrivateKey := mustPrivateKey(t, 205)
	peerKey := peerPrivateKey.publicKey()
	peer, err := dev.NewPeer(peerKey)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}

	cfg := DefaultAmneziaWGConfig()
	cfg.Version = AmneziaWGV3_1
	cfg.RekeyTimeout = AmneziaWGRange{Min: 5, Max: 5, Set: true}
	cfg.KeepaliveTimeout = AmneziaWGRange{Min: 5, Max: 5, Set: true}
	cfg.RejectAfterTime = AmneziaWGRange{Min: 20, Max: 20, Set: true}
	if err := dev.SetAmneziaWGConfig(cfg); err != nil {
		t.Fatalf("SetAmneziaWGConfig: %v", err)
	}
	peer.Start()
	peer.lastHandshakeNano.Store(time.Now().Add(-21 * time.Second).UnixNano())

	snapshot, ok := dev.PeerSnapshot(peerKey)
	if !ok {
		t.Fatal("PeerSnapshot() reported missing peer")
	}
	if snapshot.Connected {
		t.Fatal("PeerSnapshot().Connected = true, want false after AWG reject-after range")
	}
	if stats := dev.RuntimeStats(); stats.ConnectedPeerCount != 0 {
		t.Fatalf("RuntimeStats().ConnectedPeerCount = %d, want 0 after AWG reject-after range", stats.ConnectedPeerCount)
	}
}

func TestAmneziaWGRekeyAfterRangeControlsSendingRefresh(t *testing.T) {
	tunDev := newChannelTUN()
	bind := &recordingBind{id: "bind0", size: 4}
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	if err := dev.SetPrivateKey(mustPrivateKey(t, 206)); err != nil {
		t.Fatalf("SetPrivateKey: %v", err)
	}

	peerPrivateKey := mustPrivateKey(t, 207)
	peerKey := peerPrivateKey.publicKey()
	peer, err := dev.NewPeer(peerKey)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	if err := dev.SetPeerEndpoint(peerKey, "127.0.0.1:51820"); err != nil {
		t.Fatalf("SetPeerEndpoint: %v", err)
	}

	cfg := DefaultAmneziaWGConfig()
	cfg.Version = AmneziaWGV3_1
	cfg.RekeyAfterTime = AmneziaWGRange{Min: 5, Max: 5, Set: true}
	if err := dev.SetAmneziaWGConfig(cfg); err != nil {
		t.Fatalf("SetAmneziaWGConfig: %v", err)
	}
	peer.Start()

	peer.keypairs.Lock()
	peer.keypairs.current = &Keypair{isInitiator: true, created: time.Now().Add(-4 * time.Second)}
	peer.keypairs.Unlock()
	peer.keepKeyFreshSending()
	if got := len(bind.sendCalls()); got != 0 {
		t.Fatalf("send refresh calls before rekey-after threshold = %d, want 0", got)
	}

	peer.keypairs.Lock()
	peer.keypairs.current.created = time.Now().Add(-6 * time.Second)
	peer.keypairs.Unlock()
	peer.keepKeyFreshSending()
	if got := len(bind.sendCalls()); got != 1 {
		t.Fatalf("send refresh calls after rekey-after threshold = %d, want 1", got)
	}
}

func TestAmneziaWGRejectAfterRangeControlsReceivingRefresh(t *testing.T) {
	tunDev := newChannelTUN()
	bind := &recordingBind{id: "bind0", size: 4}
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	if err := dev.SetPrivateKey(mustPrivateKey(t, 208)); err != nil {
		t.Fatalf("SetPrivateKey: %v", err)
	}

	peerPrivateKey := mustPrivateKey(t, 209)
	peerKey := peerPrivateKey.publicKey()
	peer, err := dev.NewPeer(peerKey)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	if err := dev.SetPeerEndpoint(peerKey, "127.0.0.1:51820"); err != nil {
		t.Fatalf("SetPeerEndpoint: %v", err)
	}

	cfg := DefaultAmneziaWGConfig()
	cfg.Version = AmneziaWGV3_1
	cfg.RekeyTimeout = AmneziaWGRange{Min: 5, Max: 5, Set: true}
	cfg.KeepaliveTimeout = AmneziaWGRange{Min: 5, Max: 5, Set: true}
	cfg.RejectAfterTime = AmneziaWGRange{Min: 20, Max: 20, Set: true}
	if err := dev.SetAmneziaWGConfig(cfg); err != nil {
		t.Fatalf("SetAmneziaWGConfig: %v", err)
	}
	peer.Start()

	peer.keypairs.Lock()
	peer.keypairs.current = &Keypair{isInitiator: true, created: time.Now().Add(-9 * time.Second)}
	peer.keypairs.Unlock()
	peer.keepKeyFreshReceiving()
	if got := len(bind.sendCalls()); got != 0 {
		t.Fatalf("receive refresh calls before key refresh threshold = %d, want 0", got)
	}

	peer.keypairs.Lock()
	peer.keypairs.current.created = time.Now().Add(-11 * time.Second)
	peer.keypairs.Unlock()
	peer.keepKeyFreshReceiving()
	if got := len(bind.sendCalls()); got != 1 {
		t.Fatalf("receive refresh calls after key refresh threshold = %d, want 1", got)
	}
	if !peer.timers.sentLastMinuteHandshake.Load() {
		t.Fatal("sentLastMinuteHandshake was not set after receive refresh")
	}
}

func TestAmneziaWGMaxHandshakeAttemptsRangeStaysWithinBounds(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)

	peerPrivateKey := mustPrivateKey(t, 210)
	peerKey := peerPrivateKey.publicKey()
	peer, err := dev.NewPeer(peerKey)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}

	cfg := DefaultAmneziaWGConfig()
	cfg.Version = AmneziaWGV3_1
	cfg.MaxHandshakeAttempts = AmneziaWGRange{Min: 3, Max: 5, Set: true}
	if err := dev.SetAmneziaWGConfig(cfg); err != nil {
		t.Fatalf("SetAmneziaWGConfig: %v", err)
	}

	for i := 0; i < 64; i++ {
		peer.timersStart()
		assertUint32Range(t, "timersStart maxHandshakeAttempts", peer.timers.maxHandshakeAttempts.Load(), 3, 5)

		peer.timers.maxHandshakeAttempts.Store(0)
		peer.timersHandshakeComplete()
		assertUint32Range(t, "timersHandshakeComplete maxHandshakeAttempts", peer.timers.maxHandshakeAttempts.Load(), 3, 5)
	}
}

func TestAmneziaWGTimerRangeConfigReloadRace(t *testing.T) {
	tunDev := newChannelTUN()
	bind := &fakeTransitionBind{id: "bind0", size: 1}
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	peerPrivateKey := mustPrivateKey(t, 203)
	peerKey := peerPrivateKey.publicKey()
	peer, err := dev.NewPeer(peerKey)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	peer.Start()
	peer.persistentKeepaliveRange.Store(packAmneziaWGRange(AmneziaWGRange{Min: 30, Max: 30, Set: true}))

	configs := []AmneziaWGConfig{
		DefaultAmneziaWGConfig(),
		DefaultAmneziaWGConfig(),
	}
	configs[0].Version = AmneziaWGV3_1
	configs[0].RekeyTimeout = AmneziaWGRange{Min: 5, Max: 5, Set: true}
	configs[0].RejectAfterTime = AmneziaWGRange{Min: 40, Max: 40, Set: true}
	configs[0].KeepaliveTimeout = AmneziaWGRange{Min: 10, Max: 10, Set: true}
	configs[0].MaxHandshakeAttempts = AmneziaWGRange{Min: 3, Max: 3, Set: true}
	configs[1].Version = AmneziaWGV3_1
	configs[1].RekeyTimeout = AmneziaWGRange{Min: 6, Max: 6, Set: true}
	configs[1].RejectAfterTime = AmneziaWGRange{Min: 45, Max: 45, Set: true}
	configs[1].KeepaliveTimeout = AmneziaWGRange{Min: 11, Max: 11, Set: true}
	configs[1].MaxHandshakeAttempts = AmneziaWGRange{Min: 4, Max: 4, Set: true}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			if err := dev.SetAmneziaWGConfig(configs[i%len(configs)]); err != nil {
				t.Errorf("SetAmneziaWGConfig: %v", err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			peer.timersDataReceived()
			peer.timersDataSent()
			peer.timersHandshakeInitiated()
			peer.timersSessionDerived()
			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersStart()
		}
	}()
	wg.Wait()
}

func assertTimerDuration(tb testing.TB, timer *Timer, min, max time.Duration) {
	tb.Helper()

	got, ok := timer.pendingDuration()
	if !ok {
		tb.Fatal("timer is not pending")
	}
	if got < min || got > max {
		tb.Fatalf("timer duration = %v, want [%v, %v]", got, min, max)
	}
}

func assertUint32Range(tb testing.TB, name string, got, min, max uint32) {
	tb.Helper()

	if got < min || got > max {
		tb.Fatalf("%s = %d, want [%d, %d]", name, got, min, max)
	}
}

func TestDeviceAmneziaWGRejectsOverlappingHeaders(t *testing.T) {
	cfg := DefaultAmneziaWGConfig()
	cfg.InitHeader = AmneziaWGHeaderRange{Start: 10, End: 20}
	cfg.ResponseHeader = AmneziaWGHeaderRange{Start: 20, End: 30}

	if err := validateAmneziaWGConfig(cfg); err == nil {
		t.Fatal("validateAmneziaWGConfig() succeeded for overlapping headers")
	}
}

func TestAmneziaWGObfChainParsesReferenceQuirks(t *testing.T) {
	chain, err := newObfChain("ignored-prefix<b 0x0102>ignored-middle<rc 32><rd 32><t>")
	if err != nil {
		t.Fatalf("newObfChain: %v", err)
	}

	buf := make([]byte, chain.ObfuscatedLen())
	chain.Obfuscate(buf)

	if !bytes.Equal(buf[:2], []byte{0x01, 0x02}) {
		t.Fatalf("fixed prefix = %x, want 0102", buf[:2])
	}
	for _, b := range buf[2:34] {
		if !unicode.IsLetter(rune(b)) {
			t.Fatalf("random chars contained non-letter byte %q", b)
		}
	}
	for _, b := range buf[34:66] {
		if !unicode.IsDigit(rune(b)) {
			t.Fatalf("random digits contained non-digit byte %q", b)
		}
	}
	if len(buf[66:]) != 4 {
		t.Fatalf("timestamp length = %d, want 4", len(buf[66:]))
	}
}

func TestAmneziaWGSendHandshakeInitiationSendsConfiguredPreludes(t *testing.T) {
	tunDev := newChannelTUN()
	bind := &recordingBind{id: "bind0", size: 8}
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	if err := dev.SetPrivateKey(mustPrivateKey(t, 40)); err != nil {
		t.Fatalf("SetPrivateKey: %v", err)
	}

	peerPrivateKey := mustPrivateKey(t, 41)
	peerKey := peerPrivateKey.publicKey()
	peer, err := dev.NewPeer(peerKey)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	if err := dev.SetPeerEndpoint(peerKey, "127.0.0.1:51820"); err != nil {
		t.Fatalf("SetPeerEndpoint: %v", err)
	}

	cfg := DefaultAmneziaWGConfig()
	cfg.JunkCount = 1
	cfg.JunkMin = 8
	cfg.JunkMax = 8
	cfg.InitPadding = 5
	cfg.InitHeader = AmneziaWGHeaderRange{Start: 100000, End: 100000}
	cfg.InitiationPackets[1] = "<b 0xaa>"
	if err := dev.SetAmneziaWGConfig(cfg); err != nil {
		t.Fatalf("SetAmneziaWGConfig: %v", err)
	}

	if err := peer.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("SendHandshakeInitiation: %v", err)
	}

	sent := bind.packets()
	if len(sent) != 3 {
		t.Fatalf("sent packets = %d, want 3", len(sent))
	}
	if !bytes.Equal(sent[0], []byte{0xaa}) {
		t.Fatalf("sent[0] = %x, want aa", sent[0])
	}
	if len(sent[1]) != 8 {
		t.Fatalf("junk packet length = %d, want 8", len(sent[1]))
	}
	if len(sent[2]) != MessageInitiationSize+cfg.InitPadding {
		t.Fatalf("initiation length = %d, want %d", len(sent[2]), MessageInitiationSize+cfg.InitPadding)
	}
	if got := sent[2][cfg.InitPadding : cfg.InitPadding+4]; !bytes.Equal(got, []byte{0xa0, 0x86, 0x01, 0x00}) {
		t.Fatalf("handshake type bytes = %x, want a0860100", got)
	}
}

func TestAmneziaWGPerPeerOverrideUsesPeerSnapshotAndFallsBackToDeviceDefault(t *testing.T) {
	tunDev := newChannelTUN()
	bind := &recordingBind{id: "bind0", size: 8}
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	if err := dev.SetPrivateKey(mustPrivateKey(t, 50)); err != nil {
		t.Fatalf("SetPrivateKey: %v", err)
	}

	base := DefaultAmneziaWGConfig()
	base.InitPadding = 4
	base.InitHeader = AmneziaWGHeaderRange{Start: 1111, End: 1111}
	if err := dev.SetAmneziaWGConfig(base); err != nil {
		t.Fatalf("SetAmneziaWGConfig: %v", err)
	}

	override := DefaultAmneziaWGConfig()
	override.JunkCount = 1
	override.JunkMin = 9
	override.JunkMax = 9
	override.InitPadding = 7
	override.InitHeader = AmneziaWGHeaderRange{Start: 2222, End: 2222}
	override.InitiationPackets[0] = "<b 0xbb>"

	peerDefaultPrivate := mustPrivateKey(t, 51)
	peerDefaultKey := peerDefaultPrivate.publicKey()
	peerOverridePrivate := mustPrivateKey(t, 52)
	peerOverrideKey := peerOverridePrivate.publicKey()
	peerDefault, err := dev.NewPeer(peerDefaultKey)
	if err != nil {
		t.Fatalf("NewPeer(default): %v", err)
	}
	peerOverride, err := dev.NewPeer(peerOverrideKey)
	if err != nil {
		t.Fatalf("NewPeer(override): %v", err)
	}
	if err := dev.SetPeerEndpoint(peerDefaultKey, "127.0.0.1:51820"); err != nil {
		t.Fatalf("SetPeerEndpoint(default): %v", err)
	}
	if err := dev.SetPeerEndpoint(peerOverrideKey, "127.0.0.1:51821"); err != nil {
		t.Fatalf("SetPeerEndpoint(override): %v", err)
	}
	if err := dev.SetPeerAmneziaWGConfig(peerOverrideKey, override); err != nil {
		t.Fatalf("SetPeerAmneziaWGConfig: %v", err)
	}

	if err := peerDefault.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("SendHandshakeInitiation(default): %v", err)
	}
	sent := bind.packets()
	if len(sent) != 1 {
		t.Fatalf("default peer sent packets = %d, want 1", len(sent))
	}
	if len(sent[0]) != MessageInitiationSize+base.InitPadding {
		t.Fatalf("default initiation length = %d, want %d", len(sent[0]), MessageInitiationSize+base.InitPadding)
	}
	if got := sent[0][base.InitPadding : base.InitPadding+4]; !bytes.Equal(got, []byte{0x57, 0x04, 0x00, 0x00}) {
		t.Fatalf("default handshake type bytes = %x, want 57040000", got)
	}

	if err := peerOverride.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("SendHandshakeInitiation(override): %v", err)
	}
	sent = bind.packets()
	if len(sent) != 3 {
		t.Fatalf("override peer sent packets = %d, want 3", len(sent))
	}
	if !bytes.Equal(sent[0], []byte{0xbb}) {
		t.Fatalf("override sent[0] = %x, want bb", sent[0])
	}
	if len(sent[1]) != 9 {
		t.Fatalf("override junk packet length = %d, want 9", len(sent[1]))
	}
	if len(sent[2]) != MessageInitiationSize+override.InitPadding {
		t.Fatalf("override initiation length = %d, want %d", len(sent[2]), MessageInitiationSize+override.InitPadding)
	}
	if got := sent[2][override.InitPadding : override.InitPadding+4]; !bytes.Equal(got, []byte{0xae, 0x08, 0x00, 0x00}) {
		t.Fatalf("override handshake type bytes = %x, want ae080000", got)
	}
}

func TestDeterminePacketTypeAndPaddingAcceptsPeerSpecificOverrides(t *testing.T) {
	tunDev := newChannelTUN()
	bind := &fakeTransitionBind{id: "bind0", size: 1}
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	base := DefaultAmneziaWGConfig()
	base.InitPadding = 1
	base.InitHeader = AmneziaWGHeaderRange{Start: 1111, End: 1111}
	if err := dev.SetAmneziaWGConfig(base); err != nil {
		t.Fatalf("SetAmneziaWGConfig: %v", err)
	}

	peerPrivate := mustPrivateKey(t, 53)
	peerKey := peerPrivate.publicKey()
	if _, err := dev.NewPeer(peerKey); err != nil {
		t.Fatalf("NewPeer: %v", err)
	}

	override := DefaultAmneziaWGConfig()
	override.InitPadding = 6
	override.InitHeader = AmneziaWGHeaderRange{Start: 7777, End: 7777}
	if err := dev.SetPeerAmneziaWGConfig(peerKey, override); err != nil {
		t.Fatalf("SetPeerAmneziaWGConfig: %v", err)
	}

	packet := make([]byte, override.InitPadding+MessageInitiationSize)
	binary.LittleEndian.PutUint32(packet[override.InitPadding:], override.InitHeader.Start)

	msgType, padding := dev.DeterminePacketTypeAndPadding(packet, MessageUnknownType)
	if msgType != MessageInitiationType || padding != override.InitPadding {
		t.Fatalf("DeterminePacketTypeAndPadding() = (%d, %d), want (%d, %d)", msgType, padding, MessageInitiationType, override.InitPadding)
	}
}

func TestAmneziaWGReceiveClassifierCompactsPeerProfiles(t *testing.T) {
	tunDev := newChannelTUN()
	bind := &fakeTransitionBind{id: "bind0", size: 1}
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	peer1PrivateKey := mustPrivateKey(t, 54)
	peer1Key := peer1PrivateKey.publicKey()
	peer2PrivateKey := mustPrivateKey(t, 55)
	peer2Key := peer2PrivateKey.publicKey()
	if _, err := dev.NewPeer(peer1Key); err != nil {
		t.Fatalf("NewPeer(peer1): %v", err)
	}
	if _, err := dev.NewPeer(peer2Key); err != nil {
		t.Fatalf("NewPeer(peer2): %v", err)
	}

	override := DefaultAmneziaWGConfig()
	override.InitPadding = 6
	override.InitHeader = AmneziaWGHeaderRange{Start: 7777, End: 7777}
	if err := dev.SetPeerAmneziaWGConfig(peer1Key, override); err != nil {
		t.Fatalf("SetPeerAmneziaWGConfig(peer1): %v", err)
	}
	if err := dev.SetPeerAmneziaWGConfig(peer2Key, override); err != nil {
		t.Fatalf("SetPeerAmneziaWGConfig(peer2): %v", err)
	}

	classifier := dev.amneziaReceiveClassifier.Load()
	if classifier == nil {
		t.Fatal("receive classifier is nil")
	}
	if got := len(classifier.profiles); got != 2 {
		t.Fatalf("classifier profiles = %d, want 2", got)
	}

	packet := make([]byte, override.InitPadding+MessageInitiationSize)
	binary.LittleEndian.PutUint32(packet[override.InitPadding:], override.InitHeader.Start)
	msgType, padding := dev.DeterminePacketTypeAndPadding(packet, MessageUnknownType)
	if msgType != MessageInitiationType || padding != override.InitPadding {
		t.Fatalf("DeterminePacketTypeAndPadding() = (%d, %d), want (%d, %d)", msgType, padding, MessageInitiationType, override.InitPadding)
	}

	if err := dev.ClearPeerAmneziaWGConfig(peer1Key); err != nil {
		t.Fatalf("ClearPeerAmneziaWGConfig(peer1): %v", err)
	}
	if got := len(dev.amneziaReceiveClassifier.Load().profiles); got != 2 {
		t.Fatalf("classifier profiles after clearing one duplicate = %d, want 2", got)
	}

	dev.RemovePeer(peer2Key)
	if got := len(dev.amneziaReceiveClassifier.Load().profiles); got != 1 {
		t.Fatalf("classifier profiles after removing last override = %d, want 1", got)
	}
}

func TestAmneziaWGReceiveClassifierIndexesByPacketShape(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)

	base := DefaultAmneziaWGConfig()
	base.InitPadding = 8
	base.InitHeader = AmneziaWGHeaderRange{Start: 9000, End: 9000}
	if err := dev.SetAmneziaWGConfig(base); err != nil {
		t.Fatalf("SetAmneziaWGConfig: %v", err)
	}

	const exactPeerProfiles = 32
	for i := 0; i < exactPeerProfiles; i++ {
		peerKey := mustPrivateKey(t, byte(60+i)).PublicKey()
		if _, err := dev.NewPeer(peerKey); err != nil {
			t.Fatalf("NewPeer(%d): %v", i, err)
		}
		override := DefaultAmneziaWGConfig()
		override.InitPadding = base.InitPadding
		override.InitHeader = AmneziaWGHeaderRange{Start: uint32(10000 + i), End: uint32(10000 + i)}
		if err := dev.SetPeerAmneziaWGConfig(peerKey, override); err != nil {
			t.Fatalf("SetPeerAmneziaWGConfig(%d): %v", i, err)
		}
	}

	rangePeerKey := mustPrivateKey(t, 92).PublicKey()
	if _, err := dev.NewPeer(rangePeerKey); err != nil {
		t.Fatalf("NewPeer(range): %v", err)
	}
	rangeOverride := DefaultAmneziaWGConfig()
	rangeOverride.InitPadding = base.InitPadding
	rangeOverride.InitHeader = AmneziaWGHeaderRange{Start: 20000, End: 20005}
	if err := dev.SetPeerAmneziaWGConfig(rangePeerKey, rangeOverride); err != nil {
		t.Fatalf("SetPeerAmneziaWGConfig(range): %v", err)
	}

	classifier := dev.amneziaReceiveClassifier.Load()
	if classifier == nil {
		t.Fatal("receive classifier is nil")
	}
	wantProfiles := exactPeerProfiles + 2 // device profile plus exact peer profiles plus range profile.
	if got := len(classifier.profiles); got != wantProfiles {
		t.Fatalf("classifier profiles = %d, want %d", got, wantProfiles)
	}
	index := classifier.fixedBySize[MessageInitiationSize+base.InitPadding][base.InitPadding]
	if index == nil {
		t.Fatal("initiation index is missing")
	}
	if got := len(index.exact); got != exactPeerProfiles+1 {
		t.Fatalf("exact initiation headers = %d, want %d", got, exactPeerProfiles+1)
	}
	if got := len(index.ranges); got != 1 {
		t.Fatalf("range initiation headers = %d, want 1", got)
	}

	packet := make([]byte, MessageInitiationSize+base.InitPadding)
	binary.LittleEndian.PutUint32(packet[base.InitPadding:], 10017)
	msgType, padding := dev.DeterminePacketTypeAndPadding(packet, MessageUnknownType)
	if msgType != MessageInitiationType || padding != base.InitPadding {
		t.Fatalf("DeterminePacketTypeAndPadding(exact) = (%d, %d), want (%d, %d)", msgType, padding, MessageInitiationType, base.InitPadding)
	}

	binary.LittleEndian.PutUint32(packet[base.InitPadding:], 20003)
	msgType, padding = dev.DeterminePacketTypeAndPadding(packet, MessageUnknownType)
	if msgType != MessageInitiationType || padding != base.InitPadding {
		t.Fatalf("DeterminePacketTypeAndPadding(range) = (%d, %d), want (%d, %d)", msgType, padding, MessageInitiationType, base.InitPadding)
	}

	binary.LittleEndian.PutUint32(packet[base.InitPadding:], 30000)
	msgType, padding = dev.DeterminePacketTypeAndPadding(packet, MessageUnknownType)
	if msgType != MessageUnknownType || padding != 0 {
		t.Fatalf("DeterminePacketTypeAndPadding(miss) = (%d, %d), want (%d, 0)", msgType, padding, MessageUnknownType)
	}
}

func TestAmneziaWGRejectsAmbiguousPeerReceiveProfiles(t *testing.T) {
	tunDev := newChannelTUN()
	bind := &fakeTransitionBind{id: "bind0", size: 1}
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	peer1Key := mustPrivateKey(t, 93).PublicKey()
	peer2Key := mustPrivateKey(t, 94).PublicKey()
	if _, err := dev.NewPeer(peer1Key); err != nil {
		t.Fatalf("NewPeer(peer1): %v", err)
	}
	if _, err := dev.NewPeer(peer2Key); err != nil {
		t.Fatalf("NewPeer(peer2): %v", err)
	}

	peer1Profile := DefaultAmneziaWGConfig()
	peer1Profile.TransportPadding = 5
	peer1Profile.TransportHeader = AmneziaWGHeaderRange{Start: 9000, End: 9010}
	if err := dev.SetPeerAmneziaWGConfig(peer1Key, peer1Profile); err != nil {
		t.Fatalf("SetPeerAmneziaWGConfig(peer1): %v", err)
	}

	peer2Profile := DefaultAmneziaWGConfig()
	peer2Profile.TransportPadding = 6
	peer2Profile.TransportHeader = AmneziaWGHeaderRange{Start: 9010, End: 9020}
	if err := dev.SetPeerAmneziaWGConfig(peer2Key, peer2Profile); err == nil {
		t.Fatal("SetPeerAmneziaWGConfig(peer2) succeeded for ambiguous receive profiles")
	} else if !strings.Contains(err.Error(), "receive profile ambiguity") {
		t.Fatalf("SetPeerAmneziaWGConfig(peer2) = %v, want receive profile ambiguity", err)
	}
}

func TestAmneziaWGRejectsRandomTrailerReceiveProfileAmbiguity(t *testing.T) {
	tunDev := newChannelTUN()
	bind := &fakeTransitionBind{id: "bind0", size: 1}
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	peer1Key := mustPrivateKey(t, 95).PublicKey()
	peer2Key := mustPrivateKey(t, 96).PublicKey()
	if _, err := dev.NewPeer(peer1Key); err != nil {
		t.Fatalf("NewPeer(peer1): %v", err)
	}
	if _, err := dev.NewPeer(peer2Key); err != nil {
		t.Fatalf("NewPeer(peer2): %v", err)
	}

	peer1Profile := DefaultAmneziaWGConfig()
	peer1Profile.Version = AmneziaWGV3_1
	peer1Profile.InitHeader = AmneziaWGHeaderRange{Start: 9100, End: 9100}
	peer1Profile.RandomTrailers = true
	if err := dev.SetPeerAmneziaWGConfig(peer1Key, peer1Profile); err != nil {
		t.Fatalf("SetPeerAmneziaWGConfig(peer1): %v", err)
	}

	peer2Profile := DefaultAmneziaWGConfig()
	peer2Profile.ResponsePadding = MessageInitiationSize - MessageResponseSize + 8
	peer2Profile.ResponseHeader = peer1Profile.InitHeader
	if err := dev.SetPeerAmneziaWGConfig(peer2Key, peer2Profile); err == nil {
		t.Fatal("SetPeerAmneziaWGConfig(peer2) succeeded for random-trailer ambiguity")
	} else if !strings.Contains(err.Error(), "receive profile ambiguity") {
		t.Fatalf("SetPeerAmneziaWGConfig(peer2) = %v, want receive profile ambiguity", err)
	}
}

func TestDeterminePacketTypeAndPaddingAcceptsPaddedTransportAndUnpaddedKeepalive(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)

	cfg := DefaultAmneziaWGConfig()
	cfg.TransportPadding = 11
	cfg.TransportHeader = AmneziaWGHeaderRange{Start: 60000, End: 60000}
	if err := dev.SetAmneziaWGConfig(cfg); err != nil {
		t.Fatalf("SetAmneziaWGConfig: %v", err)
	}

	dataPacket := make([]byte, cfg.TransportPadding+MessageTransportHeaderSize+1)
	binary.LittleEndian.PutUint32(dataPacket[cfg.TransportPadding:], cfg.TransportHeader.Start)
	msgType, padding := dev.DeterminePacketTypeAndPadding(dataPacket, MessageUnknownType)
	if msgType != MessageTransportType || padding != cfg.TransportPadding {
		t.Fatalf("DeterminePacketTypeAndPadding(data) = (%d, %d), want (%d, %d)", msgType, padding, MessageTransportType, cfg.TransportPadding)
	}

	keepalivePacket := make([]byte, MessageKeepaliveSize)
	binary.LittleEndian.PutUint32(keepalivePacket, cfg.TransportHeader.Start)
	msgType, padding = dev.DeterminePacketTypeAndPadding(keepalivePacket, MessageUnknownType)
	if msgType != MessageTransportType || padding != 0 {
		t.Fatalf("DeterminePacketTypeAndPadding(keepalive) = (%d, %d), want (%d, 0)", msgType, padding, MessageTransportType)
	}
}

func TestDeterminePacketTypeAndPaddingAcceptsHeaderProtectedPackets(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)

	var key AmneziaWGHeaderProtectionKey
	for i := range key {
		key[i] = byte(255 - i)
	}
	cfg := DefaultAmneziaWGConfig()
	cfg.InitPadding = 12
	cfg.ResponsePadding = 12
	cfg.CookiePadding = 12
	cfg.TransportPadding = 12
	cfg.InitHeader = AmneziaWGHeaderRange{Start: 70001, End: 70001}
	cfg.TransportHeader = AmneziaWGHeaderRange{Start: 70004, End: 70004}
	cfg.HeaderProtectionKey = key
	if err := dev.SetAmneziaWGConfig(cfg); err != nil {
		t.Fatalf("SetAmneziaWGConfig: %v", err)
	}
	amnezia := dev.amneziaWGSnapshot()

	initPacket := make([]byte, cfg.InitPadding+MessageInitiationSize)
	for i := 0; i < cfg.InitPadding; i++ {
		initPacket[i] = byte(i + 1)
	}
	binary.LittleEndian.PutUint32(initPacket[cfg.InitPadding:], cfg.InitHeader.Start)
	amneziaWGProtectInPlace(amnezia, initPacket, cfg.InitPadding, MessageInitiationSize)
	if got := binary.LittleEndian.Uint32(initPacket[cfg.InitPadding:]); got == cfg.InitHeader.Start {
		t.Fatal("protected initiation header stayed plaintext")
	}
	msgType, padding := dev.DeterminePacketTypeAndPadding(initPacket, MessageUnknownType)
	if msgType != MessageInitiationType || padding != cfg.InitPadding {
		t.Fatalf("DeterminePacketTypeAndPadding(init) = (%d, %d), want (%d, %d)", msgType, padding, MessageInitiationType, cfg.InitPadding)
	}

	transportPacket := make([]byte, cfg.TransportPadding+MessageTransportHeaderSize)
	for i := 0; i < cfg.TransportPadding; i++ {
		transportPacket[i] = byte(32 + i)
	}
	binary.LittleEndian.PutUint32(transportPacket[cfg.TransportPadding:], cfg.TransportHeader.Start)
	amneziaWGProtectInPlace(amnezia, transportPacket, cfg.TransportPadding, MessageTransportHeaderSize)
	msgType, padding = dev.DeterminePacketTypeAndPadding(transportPacket, MessageUnknownType)
	if msgType != MessageTransportType || padding != cfg.TransportPadding {
		t.Fatalf("DeterminePacketTypeAndPadding(transport) = (%d, %d), want (%d, %d)", msgType, padding, MessageTransportType, cfg.TransportPadding)
	}
}

func TestAmneziaWGHeaderProtectionMatchesOfficialFixedMessageVector(t *testing.T) {
	// This vector follows amnezia-vpn/amneziawg-go commit
	// 1b86b2ae0e493e7ea93f8c1a0f0cb6735b1551f1: the first 12 S-padding
	// bytes are the ChaCha20 nonce, and only the fixed message core is masked.
	var key AmneziaWGHeaderProtectionKey
	for i := range key {
		key[i] = byte(i)
	}
	cfg := DefaultAmneziaWGConfig()
	cfg.Version = AmneziaWGV3_1
	cfg.InitPadding = 12
	cfg.ResponsePadding = 12
	cfg.CookiePadding = 12
	cfg.TransportPadding = 12
	cfg.InitHeader = AmneziaWGHeaderRange{Start: 0x44332211, End: 0x44332211}
	cfg.TransportHeader = AmneziaWGHeaderRange{Start: 0x88776655, End: 0x88776655}
	cfg.HeaderProtectionKey = key
	cfg.RandomTrailers = true
	profile := amneziaWGSnapshotFromConfig(cfg)

	initPacket := make([]byte, cfg.InitPadding+MessageInitiationSize+17)
	for i := 0; i < cfg.InitPadding; i++ {
		initPacket[i] = byte(0xf0 + i)
	}
	binary.LittleEndian.PutUint32(initPacket[cfg.InitPadding:], cfg.InitHeader.Start)
	for i := 4; i < MessageInitiationSize; i++ {
		initPacket[cfg.InitPadding+i] = byte((i*37 + 19) & 0xff)
	}
	trailer := initPacket[cfg.InitPadding+MessageInitiationSize:]
	for i := range trailer {
		trailer[i] = byte(0xa0 + i)
	}

	amneziaWGProtectInPlace(profile, initPacket, cfg.InitPadding, MessageInitiationSize)
	if got := binary.LittleEndian.Uint32(initPacket[cfg.InitPadding:]); got != 0x185b3701 {
		t.Fatalf("protected initiation header = %#x, want official vector %#x", got, uint32(0x185b3701))
	}
	if got := sha256Hex(initPacket); got != "ee74e6b356b89557d9da694cd2da30806752890bf0b5646b1d7444ee8d4830ae" {
		t.Fatalf("protected initiation packet sha256 = %s, want official vector", got)
	}
	if got := hex.EncodeToString(trailer); got != "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0" {
		t.Fatalf("protected initiation trailer = %s, want unchanged official trailer", got)
	}

	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)
	if err := dev.SetAmneziaWGConfig(cfg); err != nil {
		t.Fatalf("SetAmneziaWGConfig: %v", err)
	}
	msgType, padding := dev.DeterminePacketTypeAndPadding(initPacket, MessageUnknownType)
	if msgType != MessageInitiationType || padding != cfg.InitPadding {
		t.Fatalf("DeterminePacketTypeAndPadding(init vector) = (%d, %d), want (%d, %d)", msgType, padding, MessageInitiationType, cfg.InitPadding)
	}

	wrongKeyCfg := cfg
	wrongKeyCfg.HeaderProtectionKey[0] ^= 0xff
	if err := dev.SetAmneziaWGConfig(wrongKeyCfg); err != nil {
		t.Fatalf("SetAmneziaWGConfig(wrong key): %v", err)
	}
	msgType, padding = dev.DeterminePacketTypeAndPadding(initPacket, MessageUnknownType)
	if msgType != MessageUnknownType || padding != 0 {
		t.Fatalf("DeterminePacketTypeAndPadding(wrong key) = (%d, %d), want unknown", msgType, padding)
	}
}

func TestAmneziaWGHeaderProtectionMatchesOfficialTransportVector(t *testing.T) {
	// This vector covers the 16-byte transport header masking used by official
	// AWG 3.1 with an exact 12-byte S4 nonce prefix.
	var key AmneziaWGHeaderProtectionKey
	for i := range key {
		key[i] = byte(i)
	}
	cfg := DefaultAmneziaWGConfig()
	cfg.Version = AmneziaWGV3_1
	cfg.InitPadding = 12
	cfg.ResponsePadding = 12
	cfg.CookiePadding = 12
	cfg.TransportPadding = 12
	cfg.TransportHeader = AmneziaWGHeaderRange{Start: 0x88776655, End: 0x88776655}
	cfg.HeaderProtectionKey = key
	profile := amneziaWGSnapshotFromConfig(cfg)

	packet := make([]byte, cfg.TransportPadding+MessageTransportHeaderSize)
	for i := 0; i < cfg.TransportPadding; i++ {
		packet[i] = byte(0x30 + i)
	}
	binary.LittleEndian.PutUint32(packet[cfg.TransportPadding:], cfg.TransportHeader.Start)
	binary.LittleEndian.PutUint32(packet[cfg.TransportPadding+4:], 0x01020304)
	binary.LittleEndian.PutUint64(packet[cfg.TransportPadding+8:], 0x0908070605040302)

	amneziaWGProtectInPlace(profile, packet, cfg.TransportPadding, MessageTransportHeaderSize)
	if got := binary.LittleEndian.Uint32(packet[cfg.TransportPadding:]); got != 0x218fc80a {
		t.Fatalf("protected transport header = %#x, want official vector %#x", got, uint32(0x218fc80a))
	}
	if got := sha256Hex(packet); got != "f53dbc548265d989599239ea454112648c04acb10f383d4043bd5eeba4b250a5" {
		t.Fatalf("protected transport packet sha256 = %s, want official vector", got)
	}

	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)
	if err := dev.SetAmneziaWGConfig(cfg); err != nil {
		t.Fatalf("SetAmneziaWGConfig: %v", err)
	}
	msgType, padding := dev.DeterminePacketTypeAndPadding(packet, MessageUnknownType)
	if msgType != MessageTransportType || padding != cfg.TransportPadding {
		t.Fatalf("DeterminePacketTypeAndPadding(transport vector) = (%d, %d), want (%d, %d)", msgType, padding, MessageTransportType, cfg.TransportPadding)
	}

	truncatedNonceProfile := profile
	truncatedNonceProfile.paddings.transport = 11
	if _, ok := amneziaWGProtectedHeader(truncatedNonceProfile, packet, truncatedNonceProfile.paddings.transport); ok {
		t.Fatal("amneziaWGProtectedHeader accepted a truncated S4 nonce prefix")
	}
}

func TestAmneziaWGContentPaddingSizing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		packetSize       int
		mtu              int
		transportPadding int
		requested        int
		want             int
	}{
		{
			name:       "disabled request",
			packetSize: 100,
			mtu:        1420,
			requested:  0,
			want:       0,
		},
		{
			name:       "clips to remaining mtu",
			packetSize: 100,
			mtu:        1420,
			requested:  2000,
			want:       1320,
		},
		{
			name:       "clips near mtu",
			packetSize: 1410,
			mtu:        1420,
			requested:  20,
			want:       10,
		},
		{
			name:             "reserves transport prefix with no mtu",
			packetSize:       65400,
			transportPadding: 64,
			requested:        100,
			want:             24,
		},
		{
			name:             "reserves transport prefix near segment limit",
			packetSize:       MaxMessageSize - MessageTransportSize - maxAmneziaWGTransportPaddingSize - 3,
			transportPadding: maxAmneziaWGTransportPaddingSize,
			requested:        100,
			want:             0,
		},
		{
			name:             "reserves segment size with no mtu",
			packetSize:       65480,
			transportPadding: 0,
			requested:        100,
			want:             8,
		},
		{
			name:             "no room after transport prefix",
			packetSize:       MaxMessageSize - MessageTransportSize,
			transportPadding: 12,
			requested:        100,
			want:             0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateAmneziaWGContentPaddingSize(tt.packetSize, tt.mtu, tt.transportPadding, tt.requested)
			if got != tt.want {
				t.Fatalf("calculateAmneziaWGContentPaddingSize() = %d, want %d", got, tt.want)
			}
			finalContent := tt.packetSize + got
			finalContent += calculatePaddingSize(finalContent, tt.mtu)
			inputContent := tt.packetSize + calculatePaddingSize(tt.packetSize, tt.mtu)
			inputFits := inputContent+MessageTransportSize+tt.transportPadding <= MaxMessageSize
			if inputFits && finalContent+MessageTransportSize+tt.transportPadding > MaxMessageSize {
				t.Fatalf("final datagram length = %d, exceeds MaxMessageSize %d", finalContent+MessageTransportSize+tt.transportPadding, MaxMessageSize)
			}
			if tt.mtu > 0 && tt.packetSize+got > tt.mtu {
				t.Fatalf("content length = %d, exceeds mtu %d", tt.packetSize+got, tt.mtu)
			}
		})
	}
}

func TestAmneziaWGTransportContentPaddingSizing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		packetSize       int
		mtu              int
		transportPadding int
		want             int
	}{
		{
			name:       "plain wireguard unchanged",
			packetSize: 101,
			mtu:        1420,
			want:       11,
		},
		{
			name:             "reserves max transport prefix",
			packetSize:       MaxMessageSize - MessageTransportSize - maxAmneziaWGTransportPaddingSize - 5,
			transportPadding: maxAmneziaWGTransportPaddingSize,
			want:             5,
		},
		{
			name:             "no room after transport prefix",
			packetSize:       MaxMessageSize - MessageTransportSize - maxAmneziaWGTransportPaddingSize,
			transportPadding: maxAmneziaWGTransportPaddingSize,
			want:             0,
		},
		{
			name:             "keeps mtu clipping",
			packetSize:       1410,
			mtu:              1420,
			transportPadding: 12,
			want:             10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateAmneziaWGTransportContentPaddingSize(tt.packetSize, tt.mtu, tt.transportPadding)
			if got != tt.want {
				t.Fatalf("calculateAmneziaWGTransportContentPaddingSize() = %d, want %d", got, tt.want)
			}
			if tt.transportPadding > 0 && tt.packetSize+got+MessageTransportSize+tt.transportPadding > MaxMessageSize {
				t.Fatalf("datagram length = %d, exceeds MaxMessageSize %d", tt.packetSize+got+MessageTransportSize+tt.transportPadding, MaxMessageSize)
			}
		})
	}
}

func TestAmneziaWGRandomTrailerTransportContentPaddingSizing(t *testing.T) {
	t.Parallel()

	const (
		packetSize       = 100
		mtu              = 1420
		transportPadding = 12
	)
	maxPadding := calculateAmneziaWGContentPaddingSize(packetSize, mtu, transportPadding, MaxMessageSize)
	if maxPadding <= 0 {
		t.Fatal("test setup has no room for random trailer padding")
	}

	seenNonZero := false
	for range 256 {
		got := calculateAmneziaWGRandomTrailerContentPaddingSize(packetSize, mtu, transportPadding)
		if got < 0 || got > maxPadding {
			t.Fatalf("calculateAmneziaWGRandomTrailerContentPaddingSize() = %d, want [0, %d]", got, maxPadding)
		}
		finalContent := packetSize + got
		finalContent += calculatePaddingSize(finalContent, mtu)
		if finalContent+MessageTransportSize+transportPadding > MaxMessageSize {
			t.Fatalf("final datagram length = %d, exceeds MaxMessageSize %d", finalContent+MessageTransportSize+transportPadding, MaxMessageSize)
		}
		if packetSize+got > mtu {
			t.Fatalf("content length = %d, exceeds mtu %d", packetSize+got, mtu)
		}
		seenNonZero = seenNonZero || got > 0
	}
	if !seenNonZero {
		t.Fatal("random trailer transport padding never produced a non-zero value")
	}
}

func TestPrependAmneziaWGTransportPaddingBounds(t *testing.T) {
	t.Parallel()

	var buffer [MessageBufferSize]byte
	packet := buffer[:MaxMessageSize-12]
	for i := range packet {
		packet[i] = byte(i)
	}
	plain := append([]byte(nil), packet...)

	padded, err := prependAmneziaWGTransportPadding(&buffer, packet, 12)
	if err != nil {
		t.Fatalf("prependAmneziaWGTransportPadding rejected maximum datagram: %v", err)
	}
	if len(padded) != MaxMessageSize {
		t.Fatalf("padded length = %d, want %d", len(padded), MaxMessageSize)
	}
	if !bytes.Equal(padded[12:], plain) {
		t.Fatal("prependAmneziaWGTransportPadding corrupted shifted transport packet")
	}

	packet = buffer[:MaxMessageSize-11]
	got, err := prependAmneziaWGTransportPadding(&buffer, packet, 12)
	if err == nil {
		t.Fatal("prependAmneziaWGTransportPadding accepted oversized datagram")
	}
	if len(got) != len(packet) {
		t.Fatalf("oversized result length = %d, want original %d", len(got), len(packet))
	}
}

func TestAmneziaWGTransportPaddingHeadroomBoundary(t *testing.T) {
	t.Parallel()

	if maxAmneziaWGTransportPaddingSize > MaxTunOffsetHeadroom {
		t.Fatalf("transport padding limit = %d, exceeds buffer headroom %d", maxAmneziaWGTransportPaddingSize, MaxTunOffsetHeadroom)
	}

	cfg := DefaultAmneziaWGConfig()
	cfg.TransportPadding = maxAmneziaWGTransportPaddingSize
	if err := ValidateAmneziaWGConfig(cfg); err != nil {
		t.Fatalf("ValidateAmneziaWGConfig(max transport padding): %v", err)
	}

	cfg.TransportPadding++
	if err := ValidateAmneziaWGConfig(cfg); err == nil || !strings.Contains(err.Error(), "transport padding must be <=") {
		t.Fatalf("ValidateAmneziaWGConfig(oversized transport padding) = %v, want limit error", err)
	}
}

func TestAmneziaWGRandomTrailerMaxPacketNoGrowth(t *testing.T) {
	t.Parallel()

	amnezia := amneziaWGSnapshot{randomTrailers: true}
	packet := make([]byte, MaxMessageSize)
	got := amneziaWGAppendRandomTrailer(amnezia, packet)
	if len(got) != MaxMessageSize {
		t.Fatalf("amneziaWGAppendRandomTrailer(max packet) length = %d, want %d", len(got), MaxMessageSize)
	}
	if &got[0] != &packet[0] {
		t.Fatal("amneziaWGAppendRandomTrailer(max packet) reallocated unexpectedly")
	}
}

func TestAmneziaWGDecodedCandidateDoesNotMutateProtectedPacket(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)

	var key AmneziaWGHeaderProtectionKey
	for i := range key {
		key[i] = byte(i + 1)
	}
	cfg := DefaultAmneziaWGConfig()
	cfg.Version = AmneziaWGV3_1
	cfg.InitPadding = 12
	cfg.ResponsePadding = 12
	cfg.CookiePadding = 12
	cfg.TransportPadding = 12
	cfg.InitHeader = AmneziaWGHeaderRange{Start: 72001, End: 72001}
	cfg.HeaderProtectionKey = key
	cfg.RandomTrailers = true
	if err := dev.SetAmneziaWGConfig(cfg); err != nil {
		t.Fatalf("SetAmneziaWGConfig: %v", err)
	}
	amnezia := dev.amneziaWGSnapshot()

	packet := make([]byte, cfg.InitPadding+MessageInitiationSize+19)
	for i := 0; i < cfg.InitPadding; i++ {
		packet[i] = byte(40 + i)
	}
	binary.LittleEndian.PutUint32(packet[cfg.InitPadding:], cfg.InitHeader.Start)
	amneziaWGProtectInPlace(amnezia, packet, cfg.InitPadding, MessageInitiationSize)
	protected := append([]byte(nil), packet...)

	decoded := dev.decodeAmneziaWGPacket(packet, MessageUnknownType)
	if decoded.messageType() != MessageInitiationType || decoded.padding() != cfg.InitPadding {
		t.Fatalf("decodeAmneziaWGPacket() = (%d, %d), want (%d, %d)", decoded.messageType(), decoded.padding(), MessageInitiationType, cfg.InitPadding)
	}
	if !bytes.Equal(packet, protected) {
		t.Fatal("decodeAmneziaWGPacket mutated the receive buffer")
	}

	materialized := decoded.materialize(packet)
	if len(materialized) != MessageInitiationSize {
		t.Fatalf("materialized length = %d, want %d", len(materialized), MessageInitiationSize)
	}
	if got := binary.LittleEndian.Uint32(materialized); got != cfg.InitHeader.Start {
		t.Fatalf("materialized header = %d, want %d", got, cfg.InitHeader.Start)
	}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestAmneziaWGReceiveClassifierKeepsMultipleProtectedCandidates(t *testing.T) {
	var key1, key2 AmneziaWGHeaderProtectionKey
	for i := range key1 {
		key1[i] = byte(i + 1)
		key2[i] = byte(200 - i)
	}

	cfg1 := DefaultAmneziaWGConfig()
	cfg1.Version = AmneziaWGV3_1
	cfg1.InitPadding = 12
	cfg1.InitHeader = AmneziaWGHeaderRange{Start: 73001, End: 73001}
	cfg1.HeaderProtectionKey = key1
	profile1 := amneziaWGSnapshotFromConfig(cfg1)

	packet := make([]byte, cfg1.InitPadding+MessageInitiationSize)
	for i := 0; i < cfg1.InitPadding; i++ {
		packet[i] = byte(70 + i)
	}
	binary.LittleEndian.PutUint32(packet[cfg1.InitPadding:], cfg1.InitHeader.Start)
	amneziaWGProtectInPlace(profile1, packet, cfg1.InitPadding, MessageInitiationSize)

	cfg2 := DefaultAmneziaWGConfig()
	cfg2.Version = AmneziaWGV3_1
	cfg2.InitPadding = cfg1.InitPadding
	cfg2.HeaderProtectionKey = key2
	profile2 := amneziaWGSnapshotFromConfig(cfg2)
	header2, ok := amneziaWGProtectedHeader(profile2, packet, cfg2.InitPadding)
	if !ok {
		t.Fatal("amneziaWGProtectedHeader(profile2) failed")
	}
	cfg2.InitHeader = AmneziaWGHeaderRange{Start: header2, End: header2}
	profile2 = amneziaWGSnapshotFromConfig(cfg2)

	classifier := newAmneziaWGReceiveClassifier([]amneziaWGSnapshot{profile1, profile2})
	decoded, tried, _ := classifier.classify(packet, MessageInitiationType)
	if tried != 2 {
		t.Fatalf("classifier tried candidates = %d, want 2", tried)
	}
	if len(decoded) != 2 {
		t.Fatalf("decoded candidates = %d, want 2", len(decoded))
	}
	if got := binary.LittleEndian.Uint32(decoded[0].core[:4]); got != cfg1.InitHeader.Start {
		t.Fatalf("first decoded header = %d, want %d", got, cfg1.InitHeader.Start)
	}
	if got := binary.LittleEndian.Uint32(decoded[1].core[:4]); got != cfg2.InitHeader.Start {
		t.Fatalf("second decoded header = %d, want %d", got, cfg2.InitHeader.Start)
	}
}

func BenchmarkAmneziaWGInvalidProtectedPacketReceiveProfiles(b *testing.B) {
	for _, profileCount := range []int{1, 4, 16, MaxPeers + 1} {
		b.Run(strconv.Itoa(profileCount), func(b *testing.B) {
			profiles := make([]amneziaWGSnapshot, profileCount)
			for i := range profiles {
				cfg := DefaultAmneziaWGConfig()
				cfg.Version = AmneziaWGV3_1
				cfg.InitPadding = chacha20.NonceSize
				cfg.InitHeader = AmneziaWGHeaderRange{Start: 0xf0000000 + uint32(i), End: 0xf0000000 + uint32(i)}
				for j := range cfg.HeaderProtectionKey {
					cfg.HeaderProtectionKey[j] = byte(1 + i + j)
				}
				profiles[i] = amneziaWGSnapshotFromConfig(cfg)
			}
			classifier := newAmneziaWGReceiveClassifier(profiles)
			packet := make([]byte, chacha20.NonceSize+MessageInitiationSize)
			for i := range packet {
				packet[i] = byte(0xa5 ^ i)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				decoded, tried, headerFailures := classifier.classify(packet, MessageInitiationType)
				if len(decoded) != 0 || int(tried) != profileCount || headerFailures != 0 {
					b.Fatalf("classify() decoded=%d tried=%d headerFailures=%d, want decoded=0 tried=%d headerFailures=0", len(decoded), tried, headerFailures, profileCount)
				}
			}
		})
	}
}

func TestDeterminePacketTypeAndPaddingAcceptsRandomTrailers(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)

	cfg := DefaultAmneziaWGConfig()
	cfg.InitPadding = 4
	cfg.InitHeader = AmneziaWGHeaderRange{Start: 71001, End: 71001}
	cfg.RandomTrailers = true
	if err := dev.SetAmneziaWGConfig(cfg); err != nil {
		t.Fatalf("SetAmneziaWGConfig: %v", err)
	}

	packet := make([]byte, cfg.InitPadding+MessageInitiationSize+37)
	binary.LittleEndian.PutUint32(packet[cfg.InitPadding:], cfg.InitHeader.Start)
	msgType, padding := dev.DeterminePacketTypeAndPadding(packet, MessageUnknownType)
	if msgType != MessageInitiationType || padding != cfg.InitPadding {
		t.Fatalf("DeterminePacketTypeAndPadding(trailer) = (%d, %d), want (%d, %d)", msgType, padding, MessageInitiationType, cfg.InitPadding)
	}

	cfg.RandomTrailers = false
	if err := dev.SetAmneziaWGConfig(cfg); err != nil {
		t.Fatalf("SetAmneziaWGConfig(no trailers): %v", err)
	}
	msgType, padding = dev.DeterminePacketTypeAndPadding(packet, MessageUnknownType)
	if msgType != MessageUnknownType || padding != 0 {
		t.Fatalf("DeterminePacketTypeAndPadding(no trailer config) = (%d, %d), want unknown", msgType, padding)
	}
}

func TestDeterminePacketTypeAndPaddingRejectsOversizedRandomTrailer(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)

	cfg := DefaultAmneziaWGConfig()
	cfg.InitPadding = 12
	cfg.InitHeader = AmneziaWGHeaderRange{Start: 71101, End: 71101}
	cfg.RandomTrailers = true
	if err := dev.SetAmneziaWGConfig(cfg); err != nil {
		t.Fatalf("SetAmneziaWGConfig: %v", err)
	}

	maxPacket := make([]byte, MaxMessageSize)
	binary.LittleEndian.PutUint32(maxPacket[cfg.InitPadding:], cfg.InitHeader.Start)
	msgType, padding := dev.DeterminePacketTypeAndPadding(maxPacket, MessageUnknownType)
	if msgType != MessageInitiationType || padding != cfg.InitPadding {
		t.Fatalf("DeterminePacketTypeAndPadding(max trailer) = (%d, %d), want (%d, %d)", msgType, padding, MessageInitiationType, cfg.InitPadding)
	}

	oversizedPacket := make([]byte, MaxMessageSize+1)
	binary.LittleEndian.PutUint32(oversizedPacket[cfg.InitPadding:], cfg.InitHeader.Start)
	msgType, padding = dev.DeterminePacketTypeAndPadding(oversizedPacket, MessageUnknownType)
	if msgType != MessageUnknownType || padding != 0 {
		t.Fatalf("DeterminePacketTypeAndPadding(oversized trailer) = (%d, %d), want unknown", msgType, padding)
	}
}

func TestAmneziaWGReceiveCountersTrackClassifierWork(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)

	packet := make([]byte, MessageInitiationSize)
	msgType, _ := dev.DeterminePacketTypeAndPadding(packet, MessageUnknownType)
	if msgType != MessageUnknownType {
		t.Fatalf("DeterminePacketTypeAndPadding() type = %d, want unknown", msgType)
	}
	if counters := dev.AmneziaWGReceiveCounters(); counters.UnknownPackets == 0 {
		t.Fatalf("UnknownPackets = 0, want increment")
	}
}

func TestAmneziaWGReceiveCountersTrackProtectedHeaderFailures(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)

	var key AmneziaWGHeaderProtectionKey
	for i := range key {
		key[i] = byte(i + 11)
	}
	cfg := DefaultAmneziaWGConfig()
	cfg.Version = AmneziaWGV3_1
	cfg.InitPadding = 12
	cfg.ResponsePadding = 12
	cfg.CookiePadding = 12
	cfg.TransportPadding = 12
	cfg.HeaderProtectionKey = key
	if err := dev.SetAmneziaWGConfig(cfg); err != nil {
		t.Fatalf("SetAmneziaWGConfig: %v", err)
	}

	packet := make([]byte, MessageKeepaliveSize)
	msgType, padding := dev.DeterminePacketTypeAndPadding(packet, MessageUnknownType)
	if msgType != MessageUnknownType || padding != 0 {
		t.Fatalf("DeterminePacketTypeAndPadding(protected keepalive without nonce) = (%d, %d), want unknown", msgType, padding)
	}

	counters := dev.AmneziaWGReceiveCounters()
	if counters.CandidatesTried != 1 {
		t.Fatalf("CandidatesTried = %d, want 1", counters.CandidatesTried)
	}
	if counters.HeaderDecryptFailures != 0 {
		t.Fatalf("HeaderDecryptFailures = %d, want 0", counters.HeaderDecryptFailures)
	}
	if counters.UnknownPackets != 1 {
		t.Fatalf("UnknownPackets = %d, want 1", counters.UnknownPackets)
	}
}

func TestAmneziaWGReceiveCountersTrackProfileLimitRejections(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{
		WorkerCount:                 1,
		MaxAmneziaWGReceiveProfiles: 1,
	})
	t.Cleanup(dev.Close)

	peerKey := mustPrivateKey(t, 101).PublicKey()
	peer, err := dev.NewPeer(peerKey)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}

	override := DefaultAmneziaWGConfig()
	override.InitPadding = 6
	override.InitHeader = AmneziaWGHeaderRange{Start: 77101, End: 77101}
	snapshot := amneziaWGSnapshotFromConfig(override)
	peer.amnezia.snapshot.Store(&snapshot)
	dev.storeAmneziaWGReceiveClassifier()

	classifier := dev.amneziaReceiveClassifier.Load()
	if classifier == nil {
		t.Fatal("receive classifier is nil")
	}
	if got := len(classifier.profiles); got != 1 {
		t.Fatalf("classifier profiles = %d, want 1", got)
	}
	if counters := dev.AmneziaWGReceiveCounters(); counters.ProfileLimitRejections != 1 {
		t.Fatalf("ProfileLimitRejections = %d, want 1", counters.ProfileLimitRejections)
	}
}

func TestConsumeMessageInitiationWithProfileDoesNotCommitMismatch(t *testing.T) {
	client := randDevice(t)
	server := randDevice(t)
	defer client.Close()
	defer server.Close()

	serverPeer, err := server.NewPeer(client.staticIdentity.privateKey.publicKey())
	if err != nil {
		t.Fatalf("server NewPeer: %v", err)
	}
	clientPeer, err := client.NewPeer(server.staticIdentity.privateKey.publicKey())
	if err != nil {
		t.Fatalf("client NewPeer: %v", err)
	}
	serverPeer.Start()
	clientPeer.Start()

	msg, err := client.CreateMessageInitiation(clientPeer)
	if err != nil {
		t.Fatalf("CreateMessageInitiation: %v", err)
	}

	wrong := DefaultAmneziaWGConfig()
	wrong.InitHeader = AmneziaWGHeaderRange{Start: 76001, End: 76001}
	peer, result := server.ConsumeMessageInitiationWithProfile(msg, amneziaWGSnapshotFromConfig(wrong))
	if peer != serverPeer {
		t.Fatalf("ConsumeMessageInitiationWithProfile peer = %v, want server peer", peer)
	}
	if result != consumeInitiationProfileMismatch {
		t.Fatalf("ConsumeMessageInitiationWithProfile result = %d, want profile mismatch", result)
	}
	if serverPeer.handshake.state != handshakeZeroed {
		t.Fatalf("handshake state = %v, want %v", serverPeer.handshake.state, handshakeZeroed)
	}
	if serverPeer.handshake.lastTimestamp != (tai64n.Timestamp{}) {
		t.Fatalf("last timestamp was committed on profile mismatch")
	}
}

func TestConsumeInitiationCandidatesRetriesAfterProfileMismatch(t *testing.T) {
	client := randDevice(t)
	server := randDevice(t)
	defer client.Close()
	defer server.Close()

	serverPeer, err := server.NewPeer(client.staticIdentity.privateKey.publicKey())
	if err != nil {
		t.Fatalf("server NewPeer: %v", err)
	}
	clientPeer, err := client.NewPeer(server.staticIdentity.privateKey.publicKey())
	if err != nil {
		t.Fatalf("client NewPeer: %v", err)
	}
	serverPeer.Start()
	clientPeer.Start()

	msg, err := client.CreateMessageInitiation(clientPeer)
	if err != nil {
		t.Fatalf("CreateMessageInitiation: %v", err)
	}
	packet := make([]byte, MessageInitiationSize)
	if err := msg.marshal(packet); err != nil {
		t.Fatalf("marshal initiation: %v", err)
	}
	clientPeer.cookieGenerator.AddMacs(packet)

	rightProfile := serverPeer.amneziaWGSnapshot()
	wrongCfg := DefaultAmneziaWGConfig()
	wrongCfg.InitHeader = AmneziaWGHeaderRange{Start: 76002, End: 76002}
	wrongProfile := amneziaWGSnapshotFromConfig(wrongCfg)

	wrong := decodedAmneziaPacket{
		candidate: amneziaWGReceiveCandidate{
			msgType:    MessageInitiationType,
			coreLength: MessageInitiationSize,
			amnezia:    wrongProfile,
		},
	}
	copy(wrong.core[:], packet)
	right := decodedAmneziaPacket{
		candidate: amneziaWGReceiveCandidate{
			msgType:    MessageInitiationType,
			coreLength: MessageInitiationSize,
			amnezia:    rightProfile,
		},
	}
	copy(right.core[:], packet)

	elem := QueueHandshakeElement{
		amnezia:           wrongProfile,
		packet:            append([]byte(nil), packet...),
		decodedCandidates: []decodedAmneziaPacket{wrong, right},
		endpoint:          fakeBindEndpoint{bindID: "bind0", dst: "127.0.0.1:51820"},
	}
	peer, _, ok := server.consumeInitiationCandidates(&elem)
	if !ok {
		t.Fatal("consumeInitiationCandidates failed")
	}
	if peer != serverPeer {
		t.Fatalf("consumeInitiationCandidates peer = %v, want server peer", peer)
	}
	if serverPeer.handshake.state != handshakeInitiationConsumed {
		t.Fatalf("handshake state = %v, want %v", serverPeer.handshake.state, handshakeInitiationConsumed)
	}
	if counters := server.AmneziaWGReceiveCounters(); counters.ProfileMismatches != 1 {
		t.Fatalf("ProfileMismatches = %d, want 1", counters.ProfileMismatches)
	}
}

func TestSendHandshakeCookieUsesMatchedAmneziaWGProfile(t *testing.T) {
	tunDev := newChannelTUN()
	bind := &recordingBind{id: "bind0", size: 4}
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	if err := dev.SetPrivateKey(mustPrivateKey(t, 56)); err != nil {
		t.Fatalf("SetPrivateKey: %v", err)
	}

	peerPrivateKey := mustPrivateKey(t, 57)
	peerKey := peerPrivateKey.publicKey()
	peer, err := dev.NewPeer(peerKey)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	override := DefaultAmneziaWGConfig()
	override.CookiePadding = 9
	override.CookieHeader = AmneziaWGHeaderRange{Start: 8888, End: 8888}
	if err := dev.SetPeerAmneziaWGConfig(peerKey, override); err != nil {
		t.Fatalf("SetPeerAmneziaWGConfig: %v", err)
	}

	packet := make([]byte, MessageInitiationSize)
	binary.LittleEndian.PutUint32(packet[4:8], 1234)
	elem := QueueHandshakeElement{
		amnezia:  peer.amneziaWGSnapshot(),
		packet:   packet,
		endpoint: fakeBindEndpoint{bindID: "bind0", dst: "127.0.0.1:51820"},
	}
	if err := dev.SendHandshakeCookie(&elem); err != nil {
		t.Fatalf("SendHandshakeCookie: %v", err)
	}

	sent := bind.packets()
	if len(sent) != 1 {
		t.Fatalf("sent packets = %d, want 1", len(sent))
	}
	if len(sent[0]) != override.CookiePadding+MessageCookieReplySize {
		t.Fatalf("cookie reply length = %d, want %d", len(sent[0]), override.CookiePadding+MessageCookieReplySize)
	}
	if got := binary.LittleEndian.Uint32(sent[0][override.CookiePadding:]); got != override.CookieHeader.Start {
		t.Fatalf("cookie reply header = %d, want %d", got, override.CookieHeader.Start)
	}
}

func TestPeerSendBuffersChunksByBindBatchSize(t *testing.T) {
	tunDev := newChannelTUN()
	bind := &recordingBind{id: "bind0", size: 2}
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{BatchSize: 4, WorkerCount: 1})
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	peerPrivateKey := mustPrivateKey(t, 58)
	peerKey := peerPrivateKey.publicKey()
	peer, err := dev.NewPeer(peerKey)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	if err := dev.SetPeerEndpoint(peerKey, "127.0.0.1:51820"); err != nil {
		t.Fatalf("SetPeerEndpoint: %v", err)
	}

	buffers := [][]byte{{1}, {2, 2}, {3, 3, 3}, {4, 4, 4, 4}, {5, 5, 5, 5, 5}}
	if err := peer.SendBuffers(buffers); err != nil {
		t.Fatalf("SendBuffers: %v", err)
	}

	calls := bind.sendCalls()
	if got, want := len(calls), 3; got != want {
		t.Fatalf("send calls = %d, want %d", got, want)
	}
	for i, want := range []int{2, 2, 1} {
		if got := len(calls[i]); got != want {
			t.Fatalf("send call %d packet count = %d, want %d", i, got, want)
		}
	}
	var flattened [][]byte
	for _, call := range calls {
		flattened = append(flattened, call...)
	}
	if len(flattened) != len(buffers) {
		t.Fatalf("flattened sent packets = %d, want %d", len(flattened), len(buffers))
	}
	for i := range buffers {
		if !bytes.Equal(flattened[i], buffers[i]) {
			t.Fatalf("sent packet %d = %x, want %x", i, flattened[i], buffers[i])
		}
	}
	if got, want := peer.txBytes.Load(), uint64(15); got != want {
		t.Fatalf("peer tx bytes = %d, want %d", got, want)
	}
}

func TestPeerSendBuffersRejectsOversizedPacket(t *testing.T) {
	tunDev := newChannelTUN()
	bind := &recordingBind{id: "bind0", size: 4}
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{BatchSize: 4, WorkerCount: 1})
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	peerPrivateKey := mustPrivateKey(t, 59)
	peerKey := peerPrivateKey.publicKey()
	peer, err := dev.NewPeer(peerKey)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	if err := dev.SetPeerEndpoint(peerKey, "127.0.0.1:51820"); err != nil {
		t.Fatalf("SetPeerEndpoint: %v", err)
	}

	err = peer.SendBuffers([][]byte{
		make([]byte, MaxMessageSize),
		make([]byte, MaxMessageSize+1),
	})
	if !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("SendBuffers error = %v, want ErrPacketTooLarge", err)
	}
	if calls := bind.sendCalls(); len(calls) != 0 {
		t.Fatalf("send calls = %d, want 0 after oversized packet", len(calls))
	}
	if got := peer.txBytes.Load(); got != 0 {
		t.Fatalf("peer tx bytes = %d, want 0 after oversized packet", got)
	}
}

func TestPeerSendBuffersAcceptsMaximumPacketBatch(t *testing.T) {
	tunDev := newChannelTUN()
	bind := &recordingBind{id: "bind0", size: 2}
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{BatchSize: 2, WorkerCount: 1})
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	peerPrivateKey := mustPrivateKey(t, 60)
	peerKey := peerPrivateKey.publicKey()
	peer, err := dev.NewPeer(peerKey)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	if err := dev.SetPeerEndpoint(peerKey, "127.0.0.1:51820"); err != nil {
		t.Fatalf("SetPeerEndpoint: %v", err)
	}

	first := bytes.Repeat([]byte{0xaa}, MaxMessageSize)
	second := bytes.Repeat([]byte{0xbb}, MaxMessageSize)
	if err := peer.SendBuffers([][]byte{first, second}); err != nil {
		t.Fatalf("SendBuffers: %v", err)
	}

	calls := bind.sendCalls()
	if len(calls) != 1 {
		t.Fatalf("send calls = %d, want 1", len(calls))
	}
	if len(calls[0]) != 2 {
		t.Fatalf("batched packets = %d, want 2", len(calls[0]))
	}
	if !bytes.Equal(calls[0][0], first) || !bytes.Equal(calls[0][1], second) {
		t.Fatal("maximum packets changed during batched send")
	}
	if got, want := peer.txBytes.Load(), uint64(2*MaxMessageSize); got != want {
		t.Fatalf("peer tx bytes = %d, want %d", got, want)
	}
}

type recordingBind struct {
	id   string
	size int

	mu    sync.Mutex
	sent  [][]byte
	calls [][][]byte
}

func (b *recordingBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	return nil, port, nil
}

func (b *recordingBind) Close() error              { return nil }
func (b *recordingBind) SetMark(mark uint32) error { return nil }
func (b *recordingBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return fakeBindEndpoint{bindID: b.id, dst: s}, nil
}
func (b *recordingBind) BatchSize() int { return b.size }

func (b *recordingBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sent = b.sent[:0]
	call := make([][]byte, 0, len(bufs))
	for _, buf := range bufs {
		packet := append([]byte(nil), buf...)
		b.sent = append(b.sent, packet)
		call = append(call, packet)
	}
	b.calls = append(b.calls, call)
	return nil
}

func (b *recordingBind) packets() [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([][]byte, len(b.sent))
	for i, buf := range b.sent {
		out[i] = append([]byte(nil), buf...)
	}
	return out
}

func (b *recordingBind) sendCalls() [][][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([][][]byte, len(b.calls))
	for i, call := range b.calls {
		out[i] = make([][]byte, len(call))
		for j, buf := range call {
			out[i][j] = append([]byte(nil), buf...)
		}
	}
	return out
}
