/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 AsciiMoth
 */

package device

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestNoiseKeyHelpers(t *testing.T) {
	privateKey := mustPrivateKey(t, 77)
	parsedPrivateKey, err := ParsePrivateKey(privateKey.Base64())
	if err != nil {
		t.Fatalf("ParsePrivateKey(base64): %v", err)
	}
	if !parsedPrivateKey.Equals(privateKey) {
		t.Fatal("ParsePrivateKey(base64) did not round-trip")
	}
	if got, want := privateKey.PublicKey(), privateKey.publicKey(); got != want {
		t.Fatalf("PublicKey() = %x, want %x", got, want)
	}

	unpadded := base64.RawStdEncoding.EncodeToString(privateKey[:])
	parsedPrivateKey, err = ParsePrivateKey(unpadded)
	if err != nil {
		t.Fatalf("ParsePrivateKey(raw base64): %v", err)
	}
	if !parsedPrivateKey.Equals(privateKey) {
		t.Fatal("ParsePrivateKey(raw base64) did not round-trip")
	}

	hexPrivateKey := hex.EncodeToString(privateKey[:])
	parsedPrivateKey, err = ParsePrivateKey(hexPrivateKey)
	if err != nil {
		t.Fatalf("ParsePrivateKey(hex): %v", err)
	}
	if !parsedPrivateKey.Equals(privateKey) {
		t.Fatal("ParsePrivateKey(hex) did not round-trip")
	}

	publicKey := privateKey.PublicKey()
	parsedPublicKey, err := ParsePublicKey(publicKey.Base64())
	if err != nil {
		t.Fatalf("ParsePublicKey(base64): %v", err)
	}
	if !parsedPublicKey.Equals(publicKey) {
		t.Fatal("ParsePublicKey(base64) did not round-trip")
	}
	if _, err := ParsePublicKey(""); err == nil {
		t.Fatal("ParsePublicKey(empty) succeeded")
	}
	if _, err := ParsePublicKey((NoisePublicKey{}).Base64()); err == nil {
		t.Fatal("ParsePublicKey(zero) succeeded")
	}

	var presharedKey NoisePresharedKey
	for i := range presharedKey {
		presharedKey[i] = byte(200 + i)
	}
	parsedPresharedKey, err := ParsePresharedKey(presharedKey.Base64())
	if err != nil {
		t.Fatalf("ParsePresharedKey(base64): %v", err)
	}
	if parsedPresharedKey != presharedKey {
		t.Fatal("ParsePresharedKey(base64) did not round-trip")
	}
	zeroPresharedKey, err := ParsePresharedKey("")
	if err != nil {
		t.Fatalf("ParsePresharedKey(empty): %v", err)
	}
	if zeroPresharedKey != (NoisePresharedKey{}) {
		t.Fatal("ParsePresharedKey(empty) returned a non-zero key")
	}
}

func TestGeneratePrivateKey(t *testing.T) {
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	if privateKey.IsZero() {
		t.Fatal("GeneratePrivateKey returned a zero key")
	}
	if privateKey[0]&7 != 0 || privateKey[31]&0x80 != 0 || privateKey[31]&0x40 == 0 {
		t.Fatalf("GeneratePrivateKey returned an unclamped key: %x", privateKey)
	}
}
