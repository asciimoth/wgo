/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 AsciiMoth
 */

package device

import (
	"bytes"
	"encoding/binary"
	"strings"
	"sync"
	"testing"
	"unicode"

	conn "github.com/asciimoth/batchudp"
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
