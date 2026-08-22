// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 AsciiMoth

package main

import (
	"encoding/hex"
	"testing"

	"github.com/asciimoth/wgo/device"
)

func TestSnapshotRedactsSecretsUnlessExported(t *testing.T) {
	privateKey, err := device.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	peerPrivateKey, err := device.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey(peer): %v", err)
	}
	peerKey := peerPrivateKey.PublicKey()
	var presharedKey device.NoisePresharedKey
	for i := range presharedKey {
		presharedKey[i] = byte(i + 1)
	}

	dev := device.NewDevice(nil, nil, device.NewLogger(device.LogLevelError, ""), nil, device.DeviceOptions{})
	t.Cleanup(dev.Close)
	if err := dev.SetPrivateKey(privateKey); err != nil {
		t.Fatalf("SetPrivateKey: %v", err)
	}
	if _, err := dev.NewPeer(peerKey); err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	if err := dev.SetPeerPresharedKey(peerKey, presharedKey); err != nil {
		t.Fatalf("SetPeerPresharedKey: %v", err)
	}

	app := &adminApp{dev: dev}
	state := app.snapshot()
	if state.Device.PrivateKey != redactedSecret {
		t.Fatalf("snapshot private key = %q, want redacted", state.Device.PrivateKey)
	}
	if len(state.Device.Peers) != 1 {
		t.Fatalf("snapshot peers = %d, want 1", len(state.Device.Peers))
	}
	if state.Device.Peers[0].PresharedKey != redactedSecret {
		t.Fatalf("snapshot preshared key = %q, want redacted", state.Device.Peers[0].PresharedKey)
	}

	exported := app.secretSnapshot()
	if exported.Device.PrivateKey != hex.EncodeToString(privateKey[:]) {
		t.Fatalf("export private key = %q, want secret value", exported.Device.PrivateKey)
	}
	if exported.Device.Peers[0].PresharedKey != hex.EncodeToString(presharedKey[:]) {
		t.Fatalf("export preshared key = %q, want secret value", exported.Device.Peers[0].PresharedKey)
	}
}
