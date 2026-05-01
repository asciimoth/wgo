// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 AsciiMoth

package device

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestNoisePrivateKeyFromHexClamps(t *testing.T) {
	var key NoisePrivateKey
	if err := key.FromHex(hex.EncodeToString(make([]byte, NoisePrivateKeySize))); err != nil {
		t.Fatalf("FromHex() error = %v", err)
	}
	if key[0] != 0 || key[31] != 64 {
		t.Fatalf("clamped zero key = (%d, %d), want (0, 64)", key[0], key[31])
	}

	var allOnes NoisePrivateKey
	src := make([]byte, NoisePrivateKeySize)
	for i := range src {
		src[i] = 0xff
	}
	if err := allOnes.FromHex(hex.EncodeToString(src)); err != nil {
		t.Fatalf("FromHex() error = %v", err)
	}
	if allOnes[0] != 248 || allOnes[31] != 127 {
		t.Fatalf("clamped all-ones key = (%d, %d), want (248, 127)", allOnes[0], allOnes[31])
	}
}

func TestNoisePrivateKeyFromMaybeZeroHexPreservesZero(t *testing.T) {
	var key NoisePrivateKey
	if err := key.FromMaybeZeroHex(hex.EncodeToString(make([]byte, NoisePrivateKeySize))); err != nil {
		t.Fatalf("FromMaybeZeroHex() error = %v", err)
	}
	if !key.IsZero() {
		t.Fatal("FromMaybeZeroHex() clamped a zero key, want all zero bytes")
	}
}

func TestPeerStringMatchesBase64Abbreviation(t *testing.T) {
	var peer Peer
	for i := range peer.handshake.remoteStatic {
		peer.handshake.remoteStatic[i] = byte(i)
	}

	base64Key := base64.StdEncoding.EncodeToString(peer.handshake.remoteStatic[:])
	want := "peer(" + base64Key[:4] + "…" + base64Key[39:43] + ")"
	if got := peer.String(); got != want {
		t.Fatalf("Peer.String() = %q, want %q", got, want)
	}
}
