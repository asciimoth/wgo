/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"net/netip"
	"slices"
	"testing"
	"time"
)

func TestDeviceTypedConfigMethods(t *testing.T) {
	tunDev := newChannelTUN()
	bind := &fakeTransitionBind{id: "bind0", size: 1}
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""))
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	privateKey := mustPrivateKey(t, 1)
	if err := dev.SetPrivateKey(privateKey); err != nil {
		t.Fatalf("SetPrivateKey: %v", err)
	}
	if got := dev.PrivateKey(); !got.Equals(privateKey) {
		t.Fatal("PrivateKey() did not return the configured key")
	}

	if err := dev.SetListenPort(51820); err != nil {
		t.Fatalf("SetListenPort: %v", err)
	}
	if got := dev.ListenPort(); got != 51820 {
		t.Fatalf("ListenPort() = %d, want 51820", got)
	}

	if err := dev.SetFwmark(23); err != nil {
		t.Fatalf("SetFwmark: %v", err)
	}
	if got := dev.Fwmark(); got != 23 {
		t.Fatalf("Fwmark() = %d, want 23", got)
	}

	peerPrivateKey := mustPrivateKey(t, 2)
	peerKey := peerPrivateKey.publicKey()
	peer, err := dev.NewPeer(peerKey)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}

	var presharedKey NoisePresharedKey
	for i := range presharedKey {
		presharedKey[i] = byte(0xa0 + i)
	}
	if err := dev.SetPeerPresharedKey(peerKey, presharedKey); err != nil {
		t.Fatalf("SetPeerPresharedKey: %v", err)
	}
	if err := dev.SetPeerProtocolVersion(peerKey, 1); err != nil {
		t.Fatalf("SetPeerProtocolVersion: %v", err)
	}
	if err := dev.SetPeerEndpoint(peerKey, "127.0.0.1:12345"); err != nil {
		t.Fatalf("SetPeerEndpoint: %v", err)
	}
	if err := dev.SetPeerPersistentKeepaliveInterval(peerKey, 17); err != nil {
		t.Fatalf("SetPeerPersistentKeepaliveInterval: %v", err)
	}

	baseAllowedIPs := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("fd00::/64"),
	}
	if err := dev.ReplacePeerAllowedIPs(peerKey, baseAllowedIPs); err != nil {
		t.Fatalf("ReplacePeerAllowedIPs: %v", err)
	}
	if err := dev.AddPeerAllowedIP(peerKey, netip.MustParsePrefix("10.0.1.0/24")); err != nil {
		t.Fatalf("AddPeerAllowedIP: %v", err)
	}
	if err := dev.RemovePeerAllowedIP(peerKey, netip.MustParsePrefix("10.0.0.0/24")); err != nil {
		t.Fatalf("RemovePeerAllowedIP: %v", err)
	}

	handshakeTime := time.Unix(1712345678, 123456789)
	peer.lastHandshakeNano.Store(handshakeTime.UnixNano())
	peer.txBytes.Store(99)
	peer.rxBytes.Store(123)

	peerCfg, ok := dev.PeerConfig(peerKey)
	if !ok {
		t.Fatal("PeerConfig() reported missing peer")
	}
	if !peerCfg.PublicKey.Equals(peerKey) {
		t.Fatal("PeerConfig() returned the wrong public key")
	}
	if peerCfg.PresharedKey != presharedKey {
		t.Fatal("PeerConfig() returned the wrong preshared key")
	}
	if peerCfg.ProtocolVersion != 1 {
		t.Fatalf("PeerConfig().ProtocolVersion = %d, want 1", peerCfg.ProtocolVersion)
	}
	if peerCfg.Endpoint != "127.0.0.1:12345" {
		t.Fatalf("PeerConfig().Endpoint = %q, want %q", peerCfg.Endpoint, "127.0.0.1:12345")
	}
	if !peerCfg.LastHandshakeTime.Equal(handshakeTime) {
		t.Fatalf("PeerConfig().LastHandshakeTime = %v, want %v", peerCfg.LastHandshakeTime, handshakeTime)
	}
	if peerCfg.TxBytes != 99 || peerCfg.RxBytes != 123 {
		t.Fatalf("PeerConfig() stats = (%d, %d), want (99, 123)", peerCfg.TxBytes, peerCfg.RxBytes)
	}
	if peerCfg.PersistentKeepaliveInterval != 17 {
		t.Fatalf("PeerConfig().PersistentKeepaliveInterval = %d, want 17", peerCfg.PersistentKeepaliveInterval)
	}

	wantAllowedIPs := []netip.Prefix{
		netip.MustParsePrefix("10.0.1.0/24"),
		netip.MustParsePrefix("fd00::/64"),
	}
	sortPrefixes(wantAllowedIPs)
	if !slices.Equal(peerCfg.AllowedIPs, wantAllowedIPs) {
		t.Fatalf("PeerConfig().AllowedIPs = %v, want %v", peerCfg.AllowedIPs, wantAllowedIPs)
	}

	cfg := dev.Config()
	if !cfg.PrivateKey.Equals(privateKey) {
		t.Fatal("Config().PrivateKey did not match")
	}
	if cfg.ListenPort != 51820 {
		t.Fatalf("Config().ListenPort = %d, want 51820", cfg.ListenPort)
	}
	if cfg.Fwmark != 23 {
		t.Fatalf("Config().Fwmark = %d, want 23", cfg.Fwmark)
	}
	if len(cfg.Peers) != 1 {
		t.Fatalf("len(Config().Peers) = %d, want 1", len(cfg.Peers))
	}
	if cfg.Peers[0].PublicKey != peerCfg.PublicKey ||
		cfg.Peers[0].PresharedKey != peerCfg.PresharedKey ||
		cfg.Peers[0].ProtocolVersion != peerCfg.ProtocolVersion ||
		cfg.Peers[0].Endpoint != peerCfg.Endpoint ||
		!cfg.Peers[0].LastHandshakeTime.Equal(peerCfg.LastHandshakeTime) ||
		cfg.Peers[0].TxBytes != peerCfg.TxBytes ||
		cfg.Peers[0].RxBytes != peerCfg.RxBytes ||
		cfg.Peers[0].PersistentKeepaliveInterval != peerCfg.PersistentKeepaliveInterval ||
		!slices.Equal(cfg.Peers[0].AllowedIPs, peerCfg.AllowedIPs) {
		t.Fatalf("Config().Peers[0] = %+v, want %+v", cfg.Peers[0], peerCfg)
	}
}

func TestDeviceTypedConfigMethodErrors(t *testing.T) {
	peerPrivateKey := mustPrivateKey(t, 9)
	peerKey := peerPrivateKey.publicKey()

	t.Run("missing peer", func(t *testing.T) {
		tunDev := newChannelTUN()
		bind := &fakeTransitionBind{id: "bind0", size: 1}
		dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""))
		t.Cleanup(dev.Close)
		waitForDeviceUp(t, dev)

		if _, ok := dev.PeerConfig(peerKey); ok {
			t.Fatal("PeerConfig() reported an unexpected peer")
		}
		if err := dev.SetPeerPresharedKey(peerKey, NoisePresharedKey{}); err == nil {
			t.Fatal("SetPeerPresharedKey() succeeded for a missing peer")
		}
		if err := dev.SetPeerProtocolVersion(peerKey, 1); err == nil {
			t.Fatal("SetPeerProtocolVersion() succeeded for a missing peer")
		}
		if err := dev.ReplacePeerAllowedIPs(peerKey, nil); err == nil {
			t.Fatal("ReplacePeerAllowedIPs() succeeded for a missing peer")
		}
		if err := dev.AddPeerAllowedIP(peerKey, netip.MustParsePrefix("10.0.0.0/24")); err == nil {
			t.Fatal("AddPeerAllowedIP() succeeded for a missing peer")
		}
		if err := dev.RemovePeerAllowedIP(peerKey, netip.MustParsePrefix("10.0.0.0/24")); err == nil {
			t.Fatal("RemovePeerAllowedIP() succeeded for a missing peer")
		}
	})

	t.Run("invalid protocol version", func(t *testing.T) {
		tunDev := newChannelTUN()
		bind := &fakeTransitionBind{id: "bind0", size: 1}
		dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""))
		t.Cleanup(dev.Close)
		waitForDeviceUp(t, dev)

		if _, err := dev.NewPeer(peerKey); err != nil {
			t.Fatalf("NewPeer: %v", err)
		}
		if err := dev.SetPeerProtocolVersion(peerKey, 2); err == nil {
			t.Fatal("SetPeerProtocolVersion() accepted an invalid version")
		}
	})

	t.Run("missing bind", func(t *testing.T) {
		tunDev := newChannelTUN()
		dev := NewDevice(tunDev.TUN(), nil, NewLogger(LogLevelError, ""))
		t.Cleanup(dev.Close)
		waitForDeviceUp(t, dev)

		if _, err := dev.NewPeer(peerKey); err != nil {
			t.Fatalf("NewPeer: %v", err)
		}
		if err := dev.SetPeerEndpoint(peerKey, "127.0.0.1:12345"); err == nil {
			t.Fatal("SetPeerEndpoint() succeeded without an attached bind")
		}
	})

	t.Run("invalid allowed ip", func(t *testing.T) {
		tunDev := newChannelTUN()
		bind := &fakeTransitionBind{id: "bind0", size: 1}
		dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""))
		t.Cleanup(dev.Close)
		waitForDeviceUp(t, dev)

		if _, err := dev.NewPeer(peerKey); err != nil {
			t.Fatalf("NewPeer: %v", err)
		}
		if err := dev.ReplacePeerAllowedIPs(peerKey, []netip.Prefix{{}}); err == nil {
			t.Fatal("ReplacePeerAllowedIPs() accepted an invalid prefix")
		}
		if err := dev.AddPeerAllowedIP(peerKey, netip.Prefix{}); err == nil {
			t.Fatal("AddPeerAllowedIP() accepted an invalid prefix")
		}
		if err := dev.RemovePeerAllowedIP(peerKey, netip.Prefix{}); err == nil {
			t.Fatal("RemovePeerAllowedIP() accepted an invalid prefix")
		}
	})
}

func TestActivatePeerStartsPeerWhenDeviceIsUp(t *testing.T) {
	tunDev := newChannelTUN()
	bind := &fakeTransitionBind{id: "bind0", size: 1}
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""))
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	peerPrivateKey := mustPrivateKey(t, 10)
	peerKey := peerPrivateKey.publicKey()
	peer, err := dev.NewPeer(peerKey)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	if peer.isRunning.Load() {
		t.Fatal("new peer unexpectedly started before activation")
	}

	if err := dev.ActivatePeer(peerKey); err != nil {
		t.Fatalf("ActivatePeer: %v", err)
	}
	if !peer.isRunning.Load() {
		t.Fatal("ActivatePeer() did not start the peer while device was up")
	}
}

func sortPrefixes(prefixes []netip.Prefix) {
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int {
		switch {
		case a.String() < b.String():
			return -1
		case a.String() > b.String():
			return 1
		default:
			return 0
		}
	})
}

func waitForDeviceUp(tb testing.TB, dev *Device) {
	tb.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if dev.isUp() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	tb.Fatal("device did not reach up state")
}
