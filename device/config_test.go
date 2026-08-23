/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 AsciiMoth
 */

package device

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	conn "github.com/asciimoth/batchudp"
)

func TestDeviceTypedConfigMethods(t *testing.T) {
	tunDev := newChannelTUN()
	bind := &fakeTransitionBind{id: "bind0", size: 1}
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
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

func TestValidateConfig(t *testing.T) {
	privateKey := mustPrivateKey(t, 31)
	peerPrivateKey := mustPrivateKey(t, 32)
	peerKey := peerPrivateKey.publicKey()

	cfg := DeviceConfig{
		PrivateKey: privateKey,
		ListenPort: 51820,
		Fwmark:     23,
		AmneziaWG:  DefaultAmneziaWGConfig(),
		Peers: []PeerConfig{
			{
				PublicKey:                   peerKey,
				ProtocolVersion:             1,
				Endpoint:                    "127.0.0.1:51820",
				PersistentKeepaliveInterval: 25,
				AllowedIPs: []netip.Prefix{
					netip.MustParsePrefix("10.0.0.0/24"),
					netip.MustParsePrefix("fd00::/64"),
				},
			},
		},
	}

	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("ValidateConfig(valid) = %v", err)
	}

	cfg.Peers = append(cfg.Peers, cfg.Peers[0])
	err := ValidateConfig(cfg)
	if err == nil || !strings.Contains(err.Error(), "duplicate public key") {
		t.Fatalf("ValidateConfig(duplicate peer) = %v, want duplicate public key", err)
	}
}

func TestValidateConfigRejectsAmbiguousAmneziaWGPeerProfiles(t *testing.T) {
	cfg := DeviceConfig{
		AmneziaWG: DefaultAmneziaWGConfig(),
		Peers: []PeerConfig{
			{
				PublicKey:       mustPrivateKey(t, 101).PublicKey(),
				ProtocolVersion: 1,
				AmneziaWG: func() *AmneziaWGConfig {
					profile := DefaultAmneziaWGConfig()
					profile.TransportPadding = 8
					profile.TransportHeader = AmneziaWGHeaderRange{Start: 7000, End: 7010}
					return &profile
				}(),
			},
			{
				PublicKey:       mustPrivateKey(t, 102).PublicKey(),
				ProtocolVersion: 1,
				AmneziaWG: func() *AmneziaWGConfig {
					profile := DefaultAmneziaWGConfig()
					profile.TransportPadding = 12
					profile.TransportHeader = AmneziaWGHeaderRange{Start: 7010, End: 7020}
					return &profile
				}(),
			},
		},
	}

	err := ValidateConfig(cfg)
	if err == nil || !strings.Contains(err.Error(), "receive profile ambiguity") {
		t.Fatalf("ValidateConfig(ambiguous profiles) = %v, want receive profile ambiguity", err)
	}
}

func TestValidateConfigWithOptionsEndpointParser(t *testing.T) {
	peerPrivateKey := mustPrivateKey(t, 33)
	peerKey := peerPrivateKey.publicKey()
	cfg := DeviceConfig{
		AmneziaWG: DefaultAmneziaWGConfig(),
		Peers: []PeerConfig{
			{
				PublicKey:       peerKey,
				ProtocolVersion: 1,
				Endpoint:        "127.0.0.1:51820",
			},
		},
	}

	parser := &validationEndpointParser{}
	if err := ValidateConfigWithOptions(cfg, ValidationOptions{EndpointParser: parser}); err != nil {
		t.Fatalf("ValidateConfigWithOptions(valid parser) = %v", err)
	}
	if parser.got != cfg.Peers[0].Endpoint {
		t.Fatalf("endpoint parser got %q, want %q", parser.got, cfg.Peers[0].Endpoint)
	}

	parser.err = errors.New("parser rejected endpoint")
	err := ValidateConfigWithOptions(cfg, ValidationOptions{EndpointParser: parser})
	if err == nil || !strings.Contains(err.Error(), "peer ") || !strings.Contains(err.Error(), "endpoint: parser rejected endpoint") {
		t.Fatalf("ValidateConfigWithOptions(parser error) = %v, want scoped parser error", err)
	}

	cfg.Peers[0].Endpoint = "127.0.0.1"
	err = ValidateConfig(cfg)
	if err == nil || !strings.Contains(err.Error(), "endpoint") {
		t.Fatalf("ValidateConfig(malformed endpoint) = %v, want endpoint error", err)
	}
}

func TestValidatePeerConfig(t *testing.T) {
	peerPrivateKey := mustPrivateKey(t, 34)
	peer := PeerConfig{
		PublicKey:       peerPrivateKey.publicKey(),
		ProtocolVersion: 1,
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	}
	if err := ValidatePeerConfig(peer); err != nil {
		t.Fatalf("ValidatePeerConfig(valid) = %v", err)
	}

	peer.ProtocolVersion = 2
	err := ValidatePeerConfig(peer)
	if err == nil || !strings.Contains(err.Error(), "protocol version") {
		t.Fatalf("ValidatePeerConfig(protocol version) = %v, want protocol version error", err)
	}

	peer.ProtocolVersion = 1
	peer.AllowedIPs = []netip.Prefix{{}}
	err = ValidatePeerConfig(peer)
	if err == nil || !strings.Contains(err.Error(), "allowed IPs") {
		t.Fatalf("ValidatePeerConfig(allowed IP) = %v, want allowed IP error", err)
	}
}

func TestValidateAmneziaWGConfigAPI(t *testing.T) {
	cfg := DefaultAmneziaWGConfig()
	cfg.InitHeader = AmneziaWGHeaderRange{Start: 1, End: 5}
	cfg.ResponseHeader = AmneziaWGHeaderRange{Start: 4, End: 9}
	err := ValidateAmneziaWGConfig(cfg)
	if err == nil || !strings.Contains(err.Error(), "headers must not overlap") {
		t.Fatalf("ValidateAmneziaWGConfig(overlap) = %v, want overlap error", err)
	}

	patch := AmneziaWGConfigPatch{
		InitHeader:     headerPtr(AmneziaWGHeaderRange{Start: 10, End: 20}),
		ResponseHeader: headerPtr(AmneziaWGHeaderRange{Start: 15, End: 30}),
	}
	err = ValidateAmneziaWGConfigPatch(patch)
	if err == nil || !strings.Contains(err.Error(), "headers must not overlap") {
		t.Fatalf("ValidateAmneziaWGConfigPatch(overlap) = %v, want overlap error", err)
	}

	patch = AmneziaWGConfigPatch{
		InitiationPackets: [amneziaPacketCount]*string{
			strPtr("<b zz>"),
		},
	}
	err = ValidateAmneziaWGConfigPatch(patch)
	if err == nil || !strings.Contains(err.Error(), "parse initiation packet 1") {
		t.Fatalf("ValidateAmneziaWGConfigPatch(packet) = %v, want packet parse error", err)
	}
}

func TestValidateAmneziaWGConfigRejectsUnsafeNumericValues(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*AmneziaWGConfig)
		wantErr string
	}{
		{
			name: "junk min greater than max",
			mutate: func(cfg *AmneziaWGConfig) {
				cfg.JunkMin = 9
				cfg.JunkMax = 8
			},
			wantErr: "junk min must be <= junk max",
		},
		{
			name: "junk count too large",
			mutate: func(cfg *AmneziaWGConfig) {
				cfg.JunkCount = maxAmneziaWGJunkCount + 1
			},
			wantErr: "junk count must be <=",
		},
		{
			name: "junk max too large",
			mutate: func(cfg *AmneziaWGConfig) {
				cfg.JunkMax = maxAmneziaWGJunkSize + 1
			},
			wantErr: "junk max must be <=",
		},
		{
			name: "init padding too large",
			mutate: func(cfg *AmneziaWGConfig) {
				cfg.InitPadding = maxAmneziaWGHandshakePaddingSize + 1
			},
			wantErr: "init padding must be <=",
		},
		{
			name: "transport padding too large",
			mutate: func(cfg *AmneziaWGConfig) {
				cfg.TransportPadding = maxAmneziaWGTransportPaddingSize + 1
			},
			wantErr: "transport padding must be <=",
		},
		{
			name: "negative generated packet length",
			mutate: func(cfg *AmneziaWGConfig) {
				cfg.InitiationPackets[0] = "<r -1>"
			},
			wantErr: "generated length must be non-negative",
		},
		{
			name: "generated packet length too large",
			mutate: func(cfg *AmneziaWGConfig) {
				cfg.InitiationPackets[0] = "<rc " + strconv.Itoa(maxAmneziaWGInitiationPacketSize+1) + ">"
			},
			wantErr: "generated length must be <=",
		},
		{
			name: "reject after time overflows runtime timers",
			mutate: func(cfg *AmneziaWGConfig) {
				cfg.RejectAfterTime = AmneziaWGRange{Min: maxAmneziaWGRejectAfterTimeMax + 1, Max: maxAmneziaWGRejectAfterTimeMax + 1, Set: true}
			},
			wantErr: "reject after time maximum must be <=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultAmneziaWGConfig()
			tt.mutate(&cfg)

			err := ValidateAmneziaWGConfig(cfg)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ValidateAmneziaWGConfig() = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAmneziaWGConfigPatchRejectsUnsafeNumericValues(t *testing.T) {
	tests := []struct {
		name    string
		patch   AmneziaWGConfigPatch
		wantErr string
	}{
		{
			name: "junk min greater than max",
			patch: AmneziaWGConfigPatch{
				JunkMin: intPtr(9),
				JunkMax: intPtr(8),
			},
			wantErr: "junk min must be <= junk max",
		},
		{
			name: "transport padding too large",
			patch: AmneziaWGConfigPatch{
				TransportPadding: intPtr(maxAmneziaWGTransportPaddingSize + 1),
			},
			wantErr: "transport padding must be <=",
		},
		{
			name: "negative generated packet length",
			patch: AmneziaWGConfigPatch{
				InitiationPackets: [amneziaPacketCount]*string{
					strPtr("<rd -1>"),
				},
			},
			wantErr: "generated length must be non-negative",
		},
		{
			name: "reject after time overflows runtime timers",
			patch: AmneziaWGConfigPatch{
				RejectAfterTime: &AmneziaWGRange{Min: maxAmneziaWGRejectAfterTimeMax + 1, Max: maxAmneziaWGRejectAfterTimeMax + 1, Set: true},
			},
			wantErr: "reject after time maximum must be <=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAmneziaWGConfigPatch(tt.patch)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ValidateAmneziaWGConfigPatch() = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestAmneziaWG31TypedConfigAndValidation(t *testing.T) {
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
	cfg.HeaderProtectionKey = key
	cfg.ContentPadding = AmneziaWGRange{Min: 2, Max: 8, Set: true}
	cfg.RekeyAfterTime = AmneziaWGRange{Min: 90, Max: 120, Set: true}
	cfg.RandomTrailers = true
	cfg.DisableCookies = true

	if err := dev.SetAmneziaWGConfig(cfg); err != nil {
		t.Fatalf("SetAmneziaWGConfig(v3.1): %v", err)
	}
	if got := dev.AmneziaWGConfig(); got != cfg {
		t.Fatalf("AmneziaWGConfig() = %+v, want %+v", got, cfg)
	}

	cfg.InitPadding = 11
	if err := ValidateAmneziaWGConfig(cfg); err == nil || !strings.Contains(err.Error(), "header protection") {
		t.Fatalf("ValidateAmneziaWGConfig(short S1) = %v, want header protection error", err)
	}

	cfg = DefaultAmneziaWGConfig()
	cfg.Version = AmneziaWGV2
	cfg.ContentPadding = AmneziaWGRange{Min: 1, Max: 1, Set: true}
	if err := ValidateAmneziaWGConfig(cfg); err == nil || !strings.Contains(err.Error(), "3.1 fields") {
		t.Fatalf("ValidateAmneziaWGConfig(v2 with v3 field) = %v, want v3 field error", err)
	}
}

func TestAmneziaWGExplicitV2RejectsRangedPersistentKeepalive(t *testing.T) {
	peerKey := mustPrivateKey(t, 109).PublicKey()
	awg := DefaultAmneziaWGConfig()
	awg.Version = AmneziaWGV2
	keepalive := AmneziaWGRange{Min: 5, Max: 9, Set: true}

	err := ValidateConfig(DeviceConfig{
		AmneziaWG: awg,
		Peers: []PeerConfig{{
			PublicKey:                peerKey,
			ProtocolVersion:          1,
			PersistentKeepaliveRange: &keepalive,
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "persistent keepalive range") {
		t.Fatalf("ValidateConfig(v2 with ranged pka) = %v, want persistent keepalive range error", err)
	}

	keepalive = AmneziaWGRange{Min: 7, Max: 7, Set: true}
	err = ValidateConfig(DeviceConfig{
		AmneziaWG: awg,
		Peers: []PeerConfig{{
			PublicKey:                peerKey,
			ProtocolVersion:          1,
			PersistentKeepaliveRange: &keepalive,
		}},
	})
	if err != nil {
		t.Fatalf("ValidateConfig(v2 with fixed pka range): %v", err)
	}
}

func TestAmneziaWG31UAPIRoundTrip(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)

	keyHex := strings.Repeat("11", 32)
	conf := strings.Join([]string{
		"s1=12",
		"s2=12",
		"s3=12",
		"s4=12",
		"header_protection_key=" + keyHex,
		"content_padding_addition=3-7",
		"rekey_after_time=90-120",
		"random_trailers=true",
		"disable_cookies=true",
		"",
	}, "\n")
	if err := dev.IpcSet(conf); err != nil {
		t.Fatalf("IpcSet(v3.1): %v", err)
	}

	got, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	for _, want := range []string{
		"header_protection_key=" + keyHex,
		"content_padding_addition=3-7",
		"rekey_after_time=90-120",
		"random_trailers=true",
		"disable_cookies=true",
	} {
		if !strings.Contains(got, want+"\n") {
			t.Fatalf("IpcGet() missing %q in:\n%s", want, got)
		}
	}
}

func TestAmneziaWGPeerUAPIEmitsExplicitClears(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)

	var key AmneziaWGHeaderProtectionKey
	for i := range key {
		key[i] = byte(i + 1)
	}
	base := DefaultAmneziaWGConfig()
	base.Version = AmneziaWGV3_1
	base.InitPadding = 12
	base.ResponsePadding = 12
	base.CookiePadding = 12
	base.TransportPadding = 12
	base.HeaderProtectionKey = key
	base.ContentPadding = AmneziaWGRange{Min: 3, Max: 7, Set: true}
	base.RekeyAfterTime = AmneziaWGRange{Min: 90, Max: 120, Set: true}
	base.RandomTrailers = true
	base.DisableCookies = true
	if err := dev.SetAmneziaWGConfig(base); err != nil {
		t.Fatalf("SetAmneziaWGConfig: %v", err)
	}

	peerKey := mustPrivateKey(t, 130).PublicKey()
	if _, err := dev.NewPeer(peerKey); err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	zeroKey := AmneziaWGHeaderProtectionKey{}
	unsetRange := AmneziaWGRange{}
	disabled := false
	patch := AmneziaWGConfigPatch{
		HeaderProtectionKey: &zeroKey,
		ContentPadding:      &unsetRange,
		RekeyAfterTime:      &unsetRange,
		RandomTrailers:      &disabled,
		DisableCookies:      &disabled,
	}
	if err := dev.SetPeerAmneziaWGConfigPatch(peerKey, patch); err != nil {
		t.Fatalf("SetPeerAmneziaWGConfigPatch: %v", err)
	}

	got, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	for _, want := range []string{
		"header_protection_key=" + strings.Repeat("00", 32),
		"content_padding_addition=off",
		"rekey_after_time=off",
		"random_trailers=false",
		"disable_cookies=false",
	} {
		if !strings.Contains(got, want+"\n") {
			t.Fatalf("IpcGet() missing peer clear %q in:\n%s", want, got)
		}
	}

	replayed := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(replayed.Close)
	var replay strings.Builder
	for _, line := range strings.Split(got, "\n") {
		switch {
		case strings.HasPrefix(line, "last_handshake_time_"),
			strings.HasPrefix(line, "tx_bytes="),
			strings.HasPrefix(line, "rx_bytes="):
			continue
		case line == "":
			continue
		default:
			replay.WriteString(line)
			replay.WriteByte('\n')
		}
	}
	if err := replayed.IpcSet(replay.String()); err != nil {
		t.Fatalf("replay IpcSet: %v", err)
	}
	cfg, ok := replayed.PeerConfig(peerKey)
	if !ok || cfg.AmneziaWG == nil {
		t.Fatalf("replayed PeerConfig missing AWG override")
	}
	if !cfg.AmneziaWG.HeaderProtectionKey.IsZero() || cfg.AmneziaWG.ContentPadding.Set ||
		cfg.AmneziaWG.RekeyAfterTime.Set || cfg.AmneziaWG.RandomTrailers || cfg.AmneziaWG.DisableCookies {
		t.Fatalf("replayed peer AWG clears not preserved: %+v", *cfg.AmneziaWG)
	}
}

func TestPeerPersistentKeepaliveRangeAPIAndUAPI(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)

	peerKey := mustPrivateKey(t, 111).PublicKey()
	if _, err := dev.NewPeer(peerKey); err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	rng := AmneziaWGRange{Min: 5, Max: 9, Set: true}
	if err := dev.SetPeerPersistentKeepaliveRange(peerKey, rng); err != nil {
		t.Fatalf("SetPeerPersistentKeepaliveRange: %v", err)
	}
	got, ok := dev.PeerPersistentKeepaliveRange(peerKey)
	if !ok || got != rng {
		t.Fatalf("PeerPersistentKeepaliveRange() = %+v, %v; want %+v, true", got, ok, rng)
	}
	peerCfg, ok := dev.PeerConfig(peerKey)
	if !ok || peerCfg.PersistentKeepaliveRange == nil || *peerCfg.PersistentKeepaliveRange != rng {
		t.Fatalf("PeerConfig().PersistentKeepaliveRange = %+v, %v; want %+v", peerCfg.PersistentKeepaliveRange, ok, rng)
	}

	publicKeyHex := hex.EncodeToString(peerKey[:])
	if err := dev.IpcSet("public_key=" + publicKeyHex + "\npersistent_keepalive_interval=7-11\n"); err != nil {
		t.Fatalf("IpcSet(ranged pka): %v", err)
	}
	got, ok = dev.PeerPersistentKeepaliveRange(peerKey)
	if want := (AmneziaWGRange{Min: 7, Max: 11, Set: true}); !ok || got != want {
		t.Fatalf("PeerPersistentKeepaliveRange() after UAPI = %+v, %v; want %+v, true", got, ok, want)
	}
	gotUAPI, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	if !strings.Contains(gotUAPI, "persistent_keepalive_interval=7-11\n") {
		t.Fatalf("IpcGet() missing ranged persistent keepalive in:\n%s", gotUAPI)
	}
}

func TestSetPeerPersistentKeepaliveRangeRejectsExplicitV2(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)

	peerKey := mustPrivateKey(t, 113).PublicKey()
	if _, err := dev.NewPeer(peerKey); err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	awg := DefaultAmneziaWGConfig()
	awg.Version = AmneziaWGV2
	if err := dev.SetPeerAmneziaWGConfig(peerKey, awg); err != nil {
		t.Fatalf("SetPeerAmneziaWGConfig(v2): %v", err)
	}

	err := dev.SetPeerPersistentKeepaliveRange(peerKey, AmneziaWGRange{Min: 5, Max: 9, Set: true})
	if err == nil || !strings.Contains(err.Error(), "persistent keepalive range") {
		t.Fatalf("SetPeerPersistentKeepaliveRange(v2) = %v, want persistent keepalive range error", err)
	}

	if err := dev.SetPeerPersistentKeepaliveRange(peerKey, AmneziaWGRange{Min: 7, Max: 7, Set: true}); err != nil {
		t.Fatalf("SetPeerPersistentKeepaliveRange(v2 fixed): %v", err)
	}
}

func TestPeerPersistentKeepaliveFixedRangePreserved(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)

	peerKey := mustPrivateKey(t, 116).PublicKey()
	if _, err := dev.NewPeer(peerKey); err != nil {
		t.Fatalf("NewPeer: %v", err)
	}

	rng := AmneziaWGRange{Min: 5, Max: 5, Set: true}
	if err := dev.SetPeerPersistentKeepaliveRange(peerKey, rng); err != nil {
		t.Fatalf("SetPeerPersistentKeepaliveRange: %v", err)
	}
	peerCfg, ok := dev.PeerConfig(peerKey)
	if !ok {
		t.Fatal("PeerConfig() reported missing peer")
	}
	if peerCfg.PersistentKeepaliveRange == nil || *peerCfg.PersistentKeepaliveRange != rng {
		t.Fatalf("PeerConfig().PersistentKeepaliveRange = %+v, want %+v", peerCfg.PersistentKeepaliveRange, rng)
	}
	if peerCfg.PersistentKeepaliveInterval != 5 {
		t.Fatalf("PeerConfig().PersistentKeepaliveInterval = %d, want 5", peerCfg.PersistentKeepaliveInterval)
	}

	if err := dev.SetPeerPersistentKeepaliveInterval(peerKey, 5); err != nil {
		t.Fatalf("SetPeerPersistentKeepaliveInterval: %v", err)
	}
	peerCfg, ok = dev.PeerConfig(peerKey)
	if !ok {
		t.Fatal("PeerConfig() reported missing peer after interval set")
	}
	if peerCfg.PersistentKeepaliveRange != nil {
		t.Fatalf("PeerConfig().PersistentKeepaliveRange = %+v, want nil after interval set", peerCfg.PersistentKeepaliveRange)
	}
	if peerCfg.PersistentKeepaliveInterval != 5 {
		t.Fatalf("PeerConfig().PersistentKeepaliveInterval after interval set = %d, want 5", peerCfg.PersistentKeepaliveInterval)
	}
}

func TestPeerPersistentKeepaliveFixedUAPIRangePreserved(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)

	peerKey := mustPrivateKey(t, 117).PublicKey()
	if _, err := dev.NewPeer(peerKey); err != nil {
		t.Fatalf("NewPeer: %v", err)
	}

	if err := dev.IpcSet("public_key=" + hex.EncodeToString(peerKey[:]) + "\npersistent_keepalive_interval=6-6\n"); err != nil {
		t.Fatalf("IpcSet(fixed ranged pka): %v", err)
	}
	peerCfg, ok := dev.PeerConfig(peerKey)
	if !ok {
		t.Fatal("PeerConfig() reported missing peer")
	}
	if want := (AmneziaWGRange{Min: 6, Max: 6, Set: true}); peerCfg.PersistentKeepaliveRange == nil || *peerCfg.PersistentKeepaliveRange != want {
		t.Fatalf("PeerConfig().PersistentKeepaliveRange = %+v, want %+v", peerCfg.PersistentKeepaliveRange, want)
	}

	if err := dev.IpcSet("public_key=" + hex.EncodeToString(peerKey[:]) + "\npersistent_keepalive_interval=6\n"); err != nil {
		t.Fatalf("IpcSet(fixed pka): %v", err)
	}
	peerCfg, ok = dev.PeerConfig(peerKey)
	if !ok {
		t.Fatal("PeerConfig() reported missing peer after fixed pka")
	}
	if peerCfg.PersistentKeepaliveRange != nil {
		t.Fatalf("PeerConfig().PersistentKeepaliveRange = %+v, want nil after fixed pka", peerCfg.PersistentKeepaliveRange)
	}
	if peerCfg.PersistentKeepaliveInterval != 6 {
		t.Fatalf("PeerConfig().PersistentKeepaliveInterval = %d, want 6", peerCfg.PersistentKeepaliveInterval)
	}
}

func TestPeerSpecPreservesPersistentKeepaliveRange(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)

	peerKey := mustPrivateKey(t, 112).PublicKey()
	rng := AmneziaWGRange{Min: 12, Max: 18, Set: true}
	spec := PeerSpec{
		PublicKey:                peerKey,
		ProtocolVersion:          1,
		PersistentKeepaliveRange: &rng,
		Activation:               PeerActivationOnDemand,
	}
	if err := dev.UpsertPeer(spec); err != nil {
		t.Fatalf("UpsertPeer: %v", err)
	}
	got, ok := dev.PeerSpec(peerKey)
	if !ok || got.PersistentKeepaliveRange == nil || *got.PersistentKeepaliveRange != rng {
		t.Fatalf("PeerSpec().PersistentKeepaliveRange = %+v, %v; want %+v", got.PersistentKeepaliveRange, ok, rng)
	}
}

func TestAmneziaWGUAPIStagesPersistentKeepaliveRange(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)

	peerKey := mustPrivateKey(t, 113).PublicKey()
	if _, err := dev.NewPeer(peerKey); err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	if err := dev.SetPeerPersistentKeepaliveInterval(peerKey, 3); err != nil {
		t.Fatalf("SetPeerPersistentKeepaliveInterval: %v", err)
	}

	conf := "public_key=" + hex.EncodeToString(peerKey[:]) + "\n" +
		"persistent_keepalive_interval=7-11\n" +
		"s4=-1\n"
	if err := dev.IpcSet(conf); err == nil {
		t.Fatal("IpcSet(invalid after pka) succeeded")
	}

	got, ok := dev.PeerPersistentKeepaliveRange(peerKey)
	if !ok || got != (AmneziaWGRange{Min: 3, Max: 3, Set: true}) {
		t.Fatalf("PeerPersistentKeepaliveRange() after rejected UAPI = %+v, %v; want fixed 3", got, ok)
	}
}

func TestAmneziaWGUAPIRollsBackDeviceDefaultBeforeLaterPeerFailure(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)

	peerKey := mustPrivateKey(t, 120).PublicKey()
	if _, err := dev.NewPeer(peerKey); err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	oldCfg := dev.AmneziaWGConfig()
	oldCfg.TransportPadding = 4
	if err := dev.SetAmneziaWGConfig(oldCfg); err != nil {
		t.Fatalf("SetAmneziaWGConfig: %v", err)
	}

	conf := "s4=12\n" +
		"public_key=" + hex.EncodeToString(peerKey[:]) + "\n" +
		"s4=-1\n"
	if err := dev.IpcSet(conf); err == nil {
		t.Fatal("IpcSet(invalid peer after device AWG change) succeeded")
	}

	got := dev.AmneziaWGConfig()
	if got.TransportPadding != oldCfg.TransportPadding {
		t.Fatalf("AmneziaWGConfig().TransportPadding after rejected UAPI = %d, want %d", got.TransportPadding, oldCfg.TransportPadding)
	}
}

func TestUAPIStagesPeerPresharedKey(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)

	peerKey := mustPrivateKey(t, 116).PublicKey()
	if _, err := dev.NewPeer(peerKey); err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	var oldKey NoisePresharedKey
	var newKey NoisePresharedKey
	for i := range oldKey {
		oldKey[i] = byte(1 + i)
		newKey[i] = byte(101 + i)
	}
	if err := dev.SetPeerPresharedKey(peerKey, oldKey); err != nil {
		t.Fatalf("SetPeerPresharedKey: %v", err)
	}

	conf := "public_key=" + hex.EncodeToString(peerKey[:]) + "\n" +
		"preshared_key=" + hex.EncodeToString(newKey[:]) + "\n" +
		"s4=-1\n"
	if err := dev.IpcSet(conf); err == nil {
		t.Fatal("IpcSet(invalid after preshared key) succeeded")
	}

	peerCfg, ok := dev.PeerConfig(peerKey)
	if !ok {
		t.Fatal("PeerConfig() reported missing peer")
	}
	if peerCfg.PresharedKey != oldKey {
		t.Fatal("PeerConfig().PresharedKey changed after rejected UAPI")
	}
}

func TestUAPIStagesPeerAllowedIPReplacement(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)

	peerKey := mustPrivateKey(t, 117).PublicKey()
	if _, err := dev.NewPeer(peerKey); err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	oldPrefix := netip.MustParsePrefix("10.0.0.1/32")
	if err := dev.AddPeerAllowedIP(peerKey, oldPrefix); err != nil {
		t.Fatalf("AddPeerAllowedIP: %v", err)
	}

	conf := "public_key=" + hex.EncodeToString(peerKey[:]) + "\n" +
		"replace_allowed_ips=true\n" +
		"allowed_ip=192.0.2.1/32\n" +
		"s4=-1\n"
	if err := dev.IpcSet(conf); err == nil {
		t.Fatal("IpcSet(invalid after allowed IP replacement) succeeded")
	}

	peerCfg, ok := dev.PeerConfig(peerKey)
	if !ok {
		t.Fatal("PeerConfig() reported missing peer")
	}
	if !slices.Equal(peerCfg.AllowedIPs, []netip.Prefix{oldPrefix}) {
		t.Fatalf("PeerConfig().AllowedIPs after rejected UAPI = %v, want %v", peerCfg.AllowedIPs, []netip.Prefix{oldPrefix})
	}
}

func TestUAPIRollsBackCommittedPeerRemovalBeforeLaterFailure(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)

	peerKey := mustPrivateKey(t, 118).PublicKey()
	if _, err := dev.NewPeer(peerKey); err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	oldPrefix := netip.MustParsePrefix("10.0.0.2/32")
	if err := dev.AddPeerAllowedIP(peerKey, oldPrefix); err != nil {
		t.Fatalf("AddPeerAllowedIP: %v", err)
	}

	conf := "public_key=" + hex.EncodeToString(peerKey[:]) + "\n" +
		"remove=true\n" +
		"public_key=" + hex.EncodeToString(peerKey[:]) + "\n" +
		"allowed_ip=192.0.2.2/32\n" +
		"s4=-1\n"
	if err := dev.IpcSet(conf); err == nil {
		t.Fatal("IpcSet(invalid after remove/recreate) succeeded")
	}

	peerCfg, ok := dev.PeerConfig(peerKey)
	if !ok {
		t.Fatal("PeerConfig() reported missing peer after rejected remove/recreate")
	}
	if !slices.Equal(peerCfg.AllowedIPs, []netip.Prefix{oldPrefix}) {
		t.Fatalf("PeerConfig().AllowedIPs after rejected remove/recreate = %v, want %v", peerCfg.AllowedIPs, []netip.Prefix{oldPrefix})
	}
}

func TestAmneziaWGUAPIStagesEndpointWithPersistentKeepaliveRange(t *testing.T) {
	tunDev := newChannelTUN()
	bind := &fakeTransitionBind{id: "bind0", size: 1}
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	peerKey := mustPrivateKey(t, 114).PublicKey()
	if _, err := dev.NewPeer(peerKey); err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	if err := dev.SetPeerEndpoint(peerKey, "127.0.0.1:51820"); err != nil {
		t.Fatalf("SetPeerEndpoint: %v", err)
	}
	if err := dev.SetPeerPersistentKeepaliveInterval(peerKey, 3); err != nil {
		t.Fatalf("SetPeerPersistentKeepaliveInterval: %v", err)
	}

	conf := "public_key=" + hex.EncodeToString(peerKey[:]) + "\n" +
		"endpoint=127.0.0.1:51821\n" +
		"persistent_keepalive_interval=7-11\n" +
		"s4=-1\n"
	if err := dev.IpcSet(conf); err == nil {
		t.Fatal("IpcSet(invalid after endpoint and pka) succeeded")
	}

	peerCfg, ok := dev.PeerConfig(peerKey)
	if !ok {
		t.Fatal("PeerConfig() reported missing peer")
	}
	if peerCfg.Endpoint != "127.0.0.1:51820" {
		t.Fatalf("PeerConfig().Endpoint after rejected UAPI = %q, want old endpoint", peerCfg.Endpoint)
	}
	got, ok := dev.PeerPersistentKeepaliveRange(peerKey)
	if !ok || got != (AmneziaWGRange{Min: 3, Max: 3, Set: true}) {
		t.Fatalf("PeerPersistentKeepaliveRange() after rejected UAPI = %+v, %v; want fixed 3", got, ok)
	}
}

func TestAmneziaWGUAPIDoesNotApplyKeepaliveWhenStagedEndpointFails(t *testing.T) {
	tunDev := newChannelTUN()
	bind := &rejectingEndpointBind{
		fakeTransitionBind: fakeTransitionBind{id: "bind0", size: 1},
		err:                errors.New("parser rejected endpoint"),
	}
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{WorkerCount: 1})
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	peerKey := mustPrivateKey(t, 115).PublicKey()
	if _, err := dev.NewPeer(peerKey); err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	peer := dev.LookupPeer(peerKey)
	peer.endpoint.Lock()
	peer.endpoint.val = fakeBindEndpoint{bindID: "bind0", dst: "127.0.0.1:51820"}
	peer.endpoint.address = "127.0.0.1:51820"
	peer.endpoint.Unlock()
	if err := dev.SetPeerPersistentKeepaliveInterval(peerKey, 3); err != nil {
		t.Fatalf("SetPeerPersistentKeepaliveInterval: %v", err)
	}

	conf := "public_key=" + hex.EncodeToString(peerKey[:]) + "\n" +
		"endpoint=127.0.0.1:51821\n" +
		"persistent_keepalive_interval=7-11\n"
	err := dev.IpcSet(conf)
	if err == nil || !strings.Contains(err.Error(), "parser rejected endpoint") {
		t.Fatalf("IpcSet(rejecting endpoint) = %v, want parser error", err)
	}

	peerCfg, ok := dev.PeerConfig(peerKey)
	if !ok {
		t.Fatal("PeerConfig() reported missing peer")
	}
	if peerCfg.Endpoint != "127.0.0.1:51820" {
		t.Fatalf("PeerConfig().Endpoint after rejected endpoint = %q, want old endpoint", peerCfg.Endpoint)
	}
	got, ok := dev.PeerPersistentKeepaliveRange(peerKey)
	if !ok || got != (AmneziaWGRange{Min: 3, Max: 3, Set: true}) {
		t.Fatalf("PeerPersistentKeepaliveRange() after rejected endpoint = %+v, %v; want fixed 3", got, ok)
	}
}

func TestAmneziaWGUAPIRejectsUnsafeNumericValues(t *testing.T) {
	tests := []struct {
		name    string
		conf    string
		wantErr string
	}{
		{
			name:    "junk min greater than max",
			conf:    "jc=1\njmin=9\njmax=8\n",
			wantErr: "junk min must be <= junk max",
		},
		{
			name:    "negative junk count",
			conf:    "jc=-1\n",
			wantErr: "jc must be non-negative",
		},
		{
			name:    "transport padding too large",
			conf:    "s4=" + strconv.Itoa(maxAmneziaWGTransportPaddingSize+1) + "\n",
			wantErr: "s4 must be <=",
		},
		{
			name:    "negative generated packet length",
			conf:    "i1=<r -1>\n",
			wantErr: "generated length must be non-negative",
		},
		{
			name:    "generated packet length too large",
			conf:    "i1=<rc " + strconv.Itoa(maxAmneziaWGInitiationPacketSize+1) + ">\n",
			wantErr: "generated length must be <=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
			t.Cleanup(dev.Close)

			err := dev.IpcSet(tt.conf)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("IpcSet() = %v, want %q", err, tt.wantErr)
			}
			if got, want := dev.AmneziaWGConfig(), DefaultAmneziaWGConfig(); got != want {
				t.Fatalf("AmneziaWGConfig() after rejected IpcSet = %+v, want %+v", got, want)
			}
		})
	}
}

func TestAmneziaWGUAPIAcceptsZeroJunkValues(t *testing.T) {
	dev := NewDevice(nil, nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
	t.Cleanup(dev.Close)

	cfg := DefaultAmneziaWGConfig()
	cfg.JunkCount = 2
	cfg.JunkMin = 11
	cfg.JunkMax = 23
	if err := dev.SetAmneziaWGConfig(cfg); err != nil {
		t.Fatalf("SetAmneziaWGConfig: %v", err)
	}

	if err := dev.IpcSet("jc=0\njmin=0\njmax=0\n"); err != nil {
		t.Fatalf("IpcSet(clear junk): %v", err)
	}
	got := dev.AmneziaWGConfig()
	if got.JunkCount != 0 || got.JunkMin != 0 || got.JunkMax != 0 {
		t.Fatalf("AmneziaWGConfig() junk = (%d, %d, %d), want all zero", got.JunkCount, got.JunkMin, got.JunkMax)
	}

	err := dev.IpcSet("jc=1\njmin=0\njmax=0\n")
	if err == nil || !strings.Contains(err.Error(), "junk min and max must be positive") {
		t.Fatalf("IpcSet(enable junk with zero bounds) = %v, want positive bounds error", err)
	}
	got = dev.AmneziaWGConfig()
	if got.JunkCount != 0 || got.JunkMin != 0 || got.JunkMax != 0 {
		t.Fatalf("AmneziaWGConfig() after rejected IpcSet = (%d, %d, %d), want all zero", got.JunkCount, got.JunkMin, got.JunkMax)
	}
}

func TestDeviceTypedConfigMethodErrors(t *testing.T) {
	peerPrivateKey := mustPrivateKey(t, 9)
	peerKey := peerPrivateKey.publicKey()

	t.Run("missing peer", func(t *testing.T) {
		tunDev := newChannelTUN()
		bind := &fakeTransitionBind{id: "bind0", size: 1}
		dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
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
		dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
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
		dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
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
			TransportHeader:  headerPtr(AmneziaWGHeaderRange{Start: 9100, End: 9100}),
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
		if gotPatch.TransportHeader == nil || *gotPatch.TransportHeader != (AmneziaWGHeaderRange{Start: 9100, End: 9100}) {
			t.Fatalf("PeerAmneziaWGConfigOverride() TransportHeader = %+v, want 9100", gotPatch.TransportHeader)
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
		dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
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
		dev := NewDevice(tunDev.TUN(), nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
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
		dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
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
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
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
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
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

func TestDeviceApplyConfigReplaceAndActivate(t *testing.T) {
	tunDev := newChannelTUN()
	bind := &fakeTransitionBind{id: "bind0", size: 1}
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	oldPeerKey := mustPrivateKey(t, 110).PublicKey()
	if _, err := dev.NewPeer(oldPeerKey); err != nil {
		t.Fatalf("NewPeer(old): %v", err)
	}

	privateKey := mustPrivateKey(t, 111)
	peerKey := mustPrivateKey(t, 112).PublicKey()
	var presharedKey NoisePresharedKey
	for i := range presharedKey {
		presharedKey[i] = byte(i + 33)
	}
	peerAmnezia := DefaultAmneziaWGConfig()
	peerAmnezia.InitPadding = 9
	cfg := DeviceConfig{
		PrivateKey: privateKey,
		ListenPort: 51821,
		Fwmark:     44,
		AmneziaWG:  DefaultAmneziaWGConfig(),
		Peers: []PeerConfig{
			{
				PublicKey:                   peerKey,
				PresharedKey:                presharedKey,
				ProtocolVersion:             1,
				Endpoint:                    "127.0.0.1:12345",
				PersistentKeepaliveInterval: 15,
				AllowedIPs: []netip.Prefix{
					netip.MustParsePrefix("10.44.0.0/24"),
					netip.MustParsePrefix("fd44::/64"),
				},
				AmneziaWG: &peerAmnezia,
			},
		},
	}

	err := dev.ApplyConfig(cfg, ApplyConfigOptions{
		ReplacePeers:   true,
		ApplyEndpoints: true,
		ActivatePeers:  true,
	})
	if err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}
	if !dev.PrivateKey().Equals(privateKey) {
		t.Fatal("ApplyConfig did not apply the private key")
	}
	if dev.ListenPort() != 51821 {
		t.Fatalf("ListenPort() = %d, want 51821", dev.ListenPort())
	}
	if dev.Fwmark() != 44 {
		t.Fatalf("Fwmark() = %d, want 44", dev.Fwmark())
	}
	if _, ok := dev.PeerConfig(oldPeerKey); ok {
		t.Fatal("ApplyConfig with ReplacePeers left the old peer configured")
	}
	peerCfg, ok := dev.PeerConfig(peerKey)
	if !ok {
		t.Fatal("ApplyConfig did not create the configured peer")
	}
	if peerCfg.PresharedKey != presharedKey ||
		peerCfg.ProtocolVersion != 1 ||
		peerCfg.Endpoint != "127.0.0.1:12345" ||
		peerCfg.PersistentKeepaliveInterval != 15 ||
		peerCfg.AmneziaWG == nil ||
		peerCfg.AmneziaWG.InitPadding != 9 {
		t.Fatalf("PeerConfig() after ApplyConfig = %+v", peerCfg)
	}
	wantAllowedIPs := append([]netip.Prefix(nil), cfg.Peers[0].AllowedIPs...)
	sortPrefixes(wantAllowedIPs)
	if !slices.Equal(peerCfg.AllowedIPs, wantAllowedIPs) {
		t.Fatalf("PeerConfig().AllowedIPs = %v, want %v", peerCfg.AllowedIPs, wantAllowedIPs)
	}
	peer := dev.LookupPeer(peerKey)
	if peer == nil || !peer.isRunning.Load() {
		t.Fatal("ApplyConfig with ActivatePeers did not start the configured peer")
	}
}

func TestDeviceApplyConfigEndpointOptionAndValidation(t *testing.T) {
	tunDev := newChannelTUN()
	bind := &fakeTransitionBind{id: "bind0", size: 1}
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
	t.Cleanup(dev.Close)
	waitForDeviceUp(t, dev)

	privateKey := mustPrivateKey(t, 120)
	if err := dev.SetPrivateKey(privateKey); err != nil {
		t.Fatalf("SetPrivateKey: %v", err)
	}
	peerKey := mustPrivateKey(t, 121).PublicKey()
	if _, err := dev.NewPeer(peerKey); err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	if err := dev.SetPeerEndpoint(peerKey, "127.0.0.1:10000"); err != nil {
		t.Fatalf("SetPeerEndpoint: %v", err)
	}

	cfg := DeviceConfig{
		PrivateKey: mustPrivateKey(t, 122),
		AmneziaWG:  DefaultAmneziaWGConfig(),
		Peers: []PeerConfig{
			{
				PublicKey:       peerKey,
				ProtocolVersion: 1,
				Endpoint:        "127.0.0.1:20000",
			},
		},
	}
	if err := dev.ApplyConfig(cfg, ApplyConfigOptions{}); err != nil {
		t.Fatalf("ApplyConfig without endpoints: %v", err)
	}
	peerCfg, ok := dev.PeerConfig(peerKey)
	if !ok {
		t.Fatal("PeerConfig() reported missing peer")
	}
	if peerCfg.Endpoint != "127.0.0.1:10000" {
		t.Fatalf("endpoint = %q, want existing endpoint preserved", peerCfg.Endpoint)
	}

	invalid := cfg
	invalid.PrivateKey = mustPrivateKey(t, 123)
	invalid.Peers[0].ProtocolVersion = 2
	err := dev.ApplyConfig(invalid, ApplyConfigOptions{})
	if err == nil || !strings.Contains(err.Error(), "protocol version") {
		t.Fatalf("ApplyConfig(invalid protocol) = %v, want protocol error", err)
	}
	if got := dev.PrivateKey(); got.Equals(invalid.PrivateKey) {
		t.Fatal("ApplyConfig mutated private key before validation failed")
	}

	noBindDev := NewDevice(newChannelTUN().TUN(), nil, NewLogger(LogLevelError, ""), nil, DeviceOptions{})
	t.Cleanup(noBindDev.Close)
	waitForDeviceUp(t, noBindDev)
	err = noBindDev.ApplyConfig(cfg, ApplyConfigOptions{ApplyEndpoints: true})
	if err == nil || !strings.Contains(err.Error(), "no bind attached") {
		t.Fatalf("ApplyConfig(endpoint without bind) = %v, want no bind error", err)
	}
}

type validationEndpointParser struct {
	got string
	err error
}

func (p *validationEndpointParser) ParseEndpoint(s string) (conn.Endpoint, error) {
	p.got = s
	if p.err != nil {
		return nil, p.err
	}
	return fakeBindEndpoint{bindID: "validation", dst: s}, nil
}

type rejectingEndpointBind struct {
	fakeTransitionBind
	err error
}

func (b *rejectingEndpointBind) ParseEndpoint(string) (conn.Endpoint, error) {
	return nil, b.err
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
