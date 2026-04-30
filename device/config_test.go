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
	if peerCfg.AmneziaWG != nil {
		t.Fatalf("PeerConfig().AmneziaWG = %+v, want nil", *peerCfg.AmneziaWG)
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

	t.Run("peer amnezia override", func(t *testing.T) {
		tunDev := newChannelTUN()
		bind := &fakeTransitionBind{id: "bind0", size: 1}
		dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""))
		t.Cleanup(dev.Close)
		waitForDeviceUp(t, dev)

		if _, err := dev.NewPeer(peerKey); err != nil {
			t.Fatalf("NewPeer: %v", err)
		}

		cfg := DefaultAmneziaWGConfig()
		cfg.InitPadding = 5
		cfg.ResponsePadding = 7
		cfg.InitHeader = AmneziaWGHeaderRange{Start: 9000, End: 9001}
		cfg.InitiationPackets[0] = "<b 0xaa>"

		if err := dev.SetPeerAmneziaWGConfig(peerKey, cfg); err != nil {
			t.Fatalf("SetPeerAmneziaWGConfig: %v", err)
		}

		peerCfg, ok := dev.PeerConfig(peerKey)
		if !ok {
			t.Fatal("PeerConfig() reported missing peer")
		}
		if peerCfg.AmneziaWG == nil {
			t.Fatal("PeerConfig().AmneziaWG = nil, want override")
		}
		if *peerCfg.AmneziaWG != cfg {
			t.Fatalf("PeerConfig().AmneziaWG = %+v, want %+v", *peerCfg.AmneziaWG, cfg)
		}

		if err := dev.ClearPeerAmneziaWGConfig(peerKey); err != nil {
			t.Fatalf("ClearPeerAmneziaWGConfig: %v", err)
		}
		peerCfg, ok = dev.PeerConfig(peerKey)
		if !ok {
			t.Fatal("PeerConfig() reported missing peer after clear")
		}
		if peerCfg.AmneziaWG != nil {
			t.Fatalf("PeerConfig().AmneziaWG after clear = %+v, want nil", *peerCfg.AmneziaWG)
		}
	})

	t.Run("amnezia patch methods", func(t *testing.T) {
		tunDev := newChannelTUN()
		bind := &fakeTransitionBind{id: "bind0", size: 1}
		dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""))
		t.Cleanup(dev.Close)
		waitForDeviceUp(t, dev)

		if _, err := dev.NewPeer(peerKey); err != nil {
			t.Fatalf("NewPeer: %v", err)
		}

		base := DefaultAmneziaWGConfig()
		base.JunkCount = 1
		base.JunkMin = 10
		base.JunkMax = 20
		base.InitPadding = 5
		base.CookiePadding = 7
		base.InitiationPackets[0] = "<b 0xaa>"
		base.InitiationPackets[2] = "<b 0xcc>"
		if err := dev.SetAmneziaWGConfig(base); err != nil {
			t.Fatalf("SetAmneziaWGConfig: %v", err)
		}

		globalPatch := AmneziaWGConfigPatch{
			ResponsePadding: intPtr(9),
			InitiationPackets: [amneziaPacketCount]*string{
				nil,
				strPtr("<b 0xbb>"),
				strPtr(""),
			},
		}
		if err := dev.SetAmneziaWGConfigPatch(globalPatch); err != nil {
			t.Fatalf("SetAmneziaWGConfigPatch: %v", err)
		}

		global := dev.AmneziaWGConfig()
		if global.InitPadding != 5 || global.ResponsePadding != 9 || global.CookiePadding != 7 {
			t.Fatalf("AmneziaWGConfig() paddings = %+v, want init=5 response=9 cookie=7", global)
		}
		if global.InitiationPackets[0] != "<b 0xaa>" || global.InitiationPackets[1] != "<b 0xbb>" || global.InitiationPackets[2] != "" {
			t.Fatalf("AmneziaWGConfig() packets = %v, want [<b 0xaa> <b 0xbb> \"\" ...]", global.InitiationPackets)
		}

		peerPatch := AmneziaWGConfigPatch{
			JunkCount:        intPtr(2),
			JunkMin:          intPtr(30),
			JunkMax:          intPtr(40),
			InitHeader:       headerPtr(AmneziaWGHeaderRange{Start: 9000, End: 9001}),
			TransportPadding: intPtr(11),
			InitiationPackets: [amneziaPacketCount]*string{
				nil,
				nil,
				strPtr("<b 0xdd>"),
			},
		}
		if err := dev.SetPeerAmneziaWGConfigPatch(peerKey, peerPatch); err != nil {
			t.Fatalf("SetPeerAmneziaWGConfigPatch(first): %v", err)
		}

		peerPatch2 := AmneziaWGConfigPatch{
			InitiationPackets: [amneziaPacketCount]*string{
				strPtr(""),
			},
		}
		if err := dev.SetPeerAmneziaWGConfigPatch(peerKey, peerPatch2); err != nil {
			t.Fatalf("SetPeerAmneziaWGConfigPatch(second): %v", err)
		}

		gotPatch, ok := dev.PeerAmneziaWGConfigOverride(peerKey)
		if !ok {
			t.Fatal("PeerAmneziaWGConfigOverride() reported missing override")
		}
		if gotPatch.JunkCount == nil || *gotPatch.JunkCount != 2 ||
			gotPatch.JunkMin == nil || *gotPatch.JunkMin != 30 ||
			gotPatch.JunkMax == nil || *gotPatch.JunkMax != 40 {
			t.Fatalf("PeerAmneziaWGConfigOverride() junk = %+v, want 2/30/40", gotPatch)
		}
		if gotPatch.InitHeader == nil || *gotPatch.InitHeader != (AmneziaWGHeaderRange{Start: 9000, End: 9001}) {
			t.Fatalf("PeerAmneziaWGConfigOverride() InitHeader = %+v, want 9000-9001", gotPatch.InitHeader)
		}
		if gotPatch.TransportPadding == nil || *gotPatch.TransportPadding != 11 {
			t.Fatalf("PeerAmneziaWGConfigOverride() TransportPadding = %+v, want 11", gotPatch.TransportPadding)
		}
		if gotPatch.InitiationPackets[0] == nil || *gotPatch.InitiationPackets[0] != "" {
			t.Fatalf("PeerAmneziaWGConfigOverride() I1 = %+v, want explicit clear", gotPatch.InitiationPackets[0])
		}
		if gotPatch.InitiationPackets[2] == nil || *gotPatch.InitiationPackets[2] != "<b 0xdd>" {
			t.Fatalf("PeerAmneziaWGConfigOverride() I3 = %+v, want <b 0xdd>", gotPatch.InitiationPackets[2])
		}

		peerCfg, ok := dev.PeerConfig(peerKey)
		if !ok {
			t.Fatal("PeerConfig() reported missing peer")
		}
		if peerCfg.AmneziaWG == nil {
			t.Fatal("PeerConfig().AmneziaWG = nil, want effective config")
		}
		if peerCfg.AmneziaWG.JunkCount != 2 || peerCfg.AmneziaWG.JunkMin != 30 || peerCfg.AmneziaWG.JunkMax != 40 {
			t.Fatalf("PeerConfig().AmneziaWG junk = %+v, want 2/30/40", *peerCfg.AmneziaWG)
		}
		if peerCfg.AmneziaWG.InitPadding != 5 || peerCfg.AmneziaWG.ResponsePadding != 9 || peerCfg.AmneziaWG.CookiePadding != 7 || peerCfg.AmneziaWG.TransportPadding != 11 {
			t.Fatalf("PeerConfig().AmneziaWG paddings = %+v, want inherited 5/9/7 plus override 11", *peerCfg.AmneziaWG)
		}
		if peerCfg.AmneziaWG.InitHeader != (AmneziaWGHeaderRange{Start: 9000, End: 9001}) {
			t.Fatalf("PeerConfig().AmneziaWG.InitHeader = %+v, want 9000-9001", peerCfg.AmneziaWG.InitHeader)
		}
		if peerCfg.AmneziaWG.InitiationPackets[0] != "" || peerCfg.AmneziaWG.InitiationPackets[1] != "<b 0xbb>" || peerCfg.AmneziaWG.InitiationPackets[2] != "<b 0xdd>" {
			t.Fatalf("PeerConfig().AmneziaWG packets = %v, want [\"\" <b 0xbb> <b 0xdd> ...]", peerCfg.AmneziaWG.InitiationPackets)
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

func TestDevicePeerAmneziaWGConfigTransitions(t *testing.T) {
	tunDev := newChannelTUN()
	bind := &fakeTransitionBind{id: "bind0", size: 1}
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""))
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	peer1PrivateKey := mustPrivateKey(t, 101)
	peer1Key := peer1PrivateKey.publicKey()
	peer2PrivateKey := mustPrivateKey(t, 102)
	peer2Key := peer2PrivateKey.publicKey()

	if _, err := dev.NewPeer(peer1Key); err != nil {
		t.Fatalf("NewPeer(peer1): %v", err)
	}
	if _, err := dev.NewPeer(peer2Key); err != nil {
		t.Fatalf("NewPeer(peer2): %v", err)
	}

	global1 := DefaultAmneziaWGConfig()
	global1.JunkCount = 1
	global1.JunkMin = 10
	global1.JunkMax = 20
	global1.InitPadding = 3
	global1.ResponsePadding = 4
	global1.CookiePadding = 5
	global1.TransportPadding = 6
	global1.InitHeader = AmneziaWGHeaderRange{Start: 1001, End: 1001}
	global1.ResponseHeader = AmneziaWGHeaderRange{Start: 2001, End: 2001}
	global1.CookieHeader = AmneziaWGHeaderRange{Start: 3001, End: 3001}
	global1.TransportHeader = AmneziaWGHeaderRange{Start: 4001, End: 4001}
	global1.InitiationPackets[0] = "<b 0xaa>"
	if err := dev.SetAmneziaWGConfig(global1); err != nil {
		t.Fatalf("SetAmneziaWGConfig(global1): %v", err)
	}

	override := AmneziaWGConfigPatch{
		InitPadding: intPtr(13),
		InitHeader:  headerPtr(AmneziaWGHeaderRange{Start: 9001, End: 9001}),
		InitiationPackets: [amneziaPacketCount]*string{
			nil,
			strPtr("<b 0xbb>"),
		},
	}
	if err := dev.SetPeerAmneziaWGConfigPatch(peer1Key, override); err != nil {
		t.Fatalf("SetPeerAmneziaWGConfigPatch(peer1): %v", err)
	}

	peer1Cfg, ok := dev.PeerConfig(peer1Key)
	if !ok {
		t.Fatal("PeerConfig(peer1) reported missing peer")
	}
	if peer1Cfg.AmneziaWG == nil {
		t.Fatal("PeerConfig(peer1).AmneziaWG = nil, want effective override")
	}
	if peer1Cfg.AmneziaWG.InitPadding != 13 || peer1Cfg.AmneziaWG.InitHeader != (AmneziaWGHeaderRange{Start: 9001, End: 9001}) {
		t.Fatalf("PeerConfig(peer1).AmneziaWG override fields = %+v, want init padding/header override", *peer1Cfg.AmneziaWG)
	}
	if peer1Cfg.AmneziaWG.ResponsePadding != global1.ResponsePadding || peer1Cfg.AmneziaWG.TransportPadding != global1.TransportPadding {
		t.Fatalf("PeerConfig(peer1).AmneziaWG inherited paddings = %+v, want response=%d transport=%d", *peer1Cfg.AmneziaWG, global1.ResponsePadding, global1.TransportPadding)
	}
	if peer1Cfg.AmneziaWG.InitiationPackets[0] != "<b 0xaa>" || peer1Cfg.AmneziaWG.InitiationPackets[1] != "<b 0xbb>" {
		t.Fatalf("PeerConfig(peer1).AmneziaWG packets = %v, want inherited I1 and override I2", peer1Cfg.AmneziaWG.InitiationPackets)
	}

	peer2Cfg, ok := dev.PeerConfig(peer2Key)
	if !ok {
		t.Fatal("PeerConfig(peer2) reported missing peer")
	}
	if peer2Cfg.AmneziaWG != nil {
		t.Fatalf("PeerConfig(peer2).AmneziaWG = %+v, want nil while inheriting global config", *peer2Cfg.AmneziaWG)
	}

	global2 := global1
	global2.ResponsePadding = 14
	global2.TransportPadding = 16
	global2.ResponseHeader = AmneziaWGHeaderRange{Start: 2014, End: 2014}
	global2.InitiationPackets[0] = "<b 0xcc>"
	if err := dev.SetAmneziaWGConfig(global2); err != nil {
		t.Fatalf("SetAmneziaWGConfig(global2): %v", err)
	}

	peer1Cfg, ok = dev.PeerConfig(peer1Key)
	if !ok {
		t.Fatal("PeerConfig(peer1) reported missing peer after global change")
	}
	if peer1Cfg.AmneziaWG == nil {
		t.Fatal("PeerConfig(peer1).AmneziaWG = nil after global change, want effective override")
	}
	if peer1Cfg.AmneziaWG.InitPadding != 13 || peer1Cfg.AmneziaWG.InitHeader != (AmneziaWGHeaderRange{Start: 9001, End: 9001}) {
		t.Fatalf("PeerConfig(peer1).AmneziaWG override fields after global change = %+v, want preserved override", *peer1Cfg.AmneziaWG)
	}
	if peer1Cfg.AmneziaWG.ResponsePadding != 14 || peer1Cfg.AmneziaWG.TransportPadding != 16 {
		t.Fatalf("PeerConfig(peer1).AmneziaWG inherited paddings after global change = %+v, want response=14 transport=16", *peer1Cfg.AmneziaWG)
	}
	if peer1Cfg.AmneziaWG.ResponseHeader != (AmneziaWGHeaderRange{Start: 2014, End: 2014}) {
		t.Fatalf("PeerConfig(peer1).AmneziaWG.ResponseHeader = %+v, want inherited 2014", peer1Cfg.AmneziaWG.ResponseHeader)
	}
	if peer1Cfg.AmneziaWG.InitiationPackets[0] != "<b 0xcc>" || peer1Cfg.AmneziaWG.InitiationPackets[1] != "<b 0xbb>" {
		t.Fatalf("PeerConfig(peer1).AmneziaWG packets after global change = %v, want updated inherited I1 and preserved override I2", peer1Cfg.AmneziaWG.InitiationPackets)
	}

	packet := make([]byte, 13+MessageInitiationSize)
	packet[13] = 0x29
	packet[14] = 0x23
	msgType, padding := dev.DeterminePacketTypeAndPadding(packet, MessageUnknownType)
	if msgType != MessageInitiationType || padding != 13 {
		t.Fatalf("DeterminePacketTypeAndPadding(peer1 override packet) = (%d, %d), want (%d, %d)", msgType, padding, MessageInitiationType, 13)
	}

	if err := dev.ClearPeerAmneziaWGConfig(peer1Key); err != nil {
		t.Fatalf("ClearPeerAmneziaWGConfig(peer1): %v", err)
	}

	peer1Cfg, ok = dev.PeerConfig(peer1Key)
	if !ok {
		t.Fatal("PeerConfig(peer1) reported missing peer after clear")
	}
	if peer1Cfg.AmneziaWG != nil {
		t.Fatalf("PeerConfig(peer1).AmneziaWG after clear = %+v, want nil", *peer1Cfg.AmneziaWG)
	}

	packet = make([]byte, global2.InitPadding+MessageInitiationSize)
	packet[global2.InitPadding] = 0xe9
	packet[global2.InitPadding+1] = 0x03
	msgType, padding = dev.DeterminePacketTypeAndPadding(packet, MessageUnknownType)
	if msgType != MessageInitiationType || padding != global2.InitPadding {
		t.Fatalf("DeterminePacketTypeAndPadding(global packet after clear) = (%d, %d), want (%d, %d)", msgType, padding, MessageInitiationType, global2.InitPadding)
	}

	peer3PrivateKey := mustPrivateKey(t, 103)
	peer3Key := peer3PrivateKey.publicKey()
	if _, err := dev.NewPeer(peer3Key); err != nil {
		t.Fatalf("NewPeer(peer3): %v", err)
	}
	peer3Cfg, ok := dev.PeerConfig(peer3Key)
	if !ok {
		t.Fatal("PeerConfig(peer3) reported missing peer")
	}
	if peer3Cfg.AmneziaWG != nil {
		t.Fatalf("PeerConfig(peer3).AmneziaWG = %+v, want nil while inheriting latest global config", *peer3Cfg.AmneziaWG)
	}

	fullOverride := global2
	fullOverride.InitPadding = 21
	fullOverride.InitHeader = AmneziaWGHeaderRange{Start: 9021, End: 9021}
	if err := dev.SetPeerAmneziaWGConfig(peer2Key, fullOverride); err != nil {
		t.Fatalf("SetPeerAmneziaWGConfig(peer2): %v", err)
	}
	dev.RemovePeer(peer2Key)
	if _, err := dev.NewPeer(peer2Key); err != nil {
		t.Fatalf("NewPeer(peer2 re-add): %v", err)
	}
	peer2Cfg, ok = dev.PeerConfig(peer2Key)
	if !ok {
		t.Fatal("PeerConfig(peer2) reported missing peer after re-add")
	}
	if peer2Cfg.AmneziaWG != nil {
		t.Fatalf("PeerConfig(peer2).AmneziaWG after re-add = %+v, want nil without stale override", *peer2Cfg.AmneziaWG)
	}
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

func intPtr(v int) *int {
	return &v
}

func strPtr(v string) *string {
	return &v
}

func headerPtr(v AmneziaWGHeaderRange) *AmneziaWGHeaderRange {
	return &v
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
