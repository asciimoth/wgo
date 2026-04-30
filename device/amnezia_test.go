/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"sync"
	"testing"
	"unicode"

	conn "github.com/asciimoth/batchudp"
)

func TestDeviceAmneziaWGTypedConfigMethods(t *testing.T) {
	tunDev := newChannelTUN()
	bind := &fakeTransitionBind{id: "bind0", size: 1}
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""))
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
	bind := &recordingBind{id: "bind0", size: 1}
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""))
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

type recordingBind struct {
	id   string
	size int

	mu   sync.Mutex
	sent [][]byte
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
	for _, buf := range bufs {
		b.sent = append(b.sent, append([]byte(nil), buf...))
	}
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
