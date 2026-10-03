/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 AsciiMoth
 */

package amnezia

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// FuzzAmnesiaUntrustedInput covers the offline parsers that accept data from
// files, clipboards, QR decoders, gateways, and proxy-list storage.
func FuzzAmnesiaUntrustedInput(f *testing.F) {
	privateKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	publicKey, err := wireGuardPublicFromPrivate(privateKey)
	if err != nil {
		f.Fatal(err)
	}

	for _, seed := range [][]byte{
		nil,
		[]byte(`{"config_version":2,"api_config":{"service_type":"vpn","service_protocol":"awg"},"auth_data":{}}`),
		[]byte("vpn://not-base64"),
		[]byte("1-20"),
		[]byte("[Interface]\nPrivateKey = " + privateKey + "\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = " + publicKey + "\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n"),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Keep fuzz-generated values inside the largest supported import size.
		// The explicit size-limit behavior has deterministic unit coverage.
		if len(data) > maxVPNPayloadBytes*2+1 {
			return
		}
		text := string(data)

		if plain, err := DecodeVPNPayload(text); err == nil {
			if len(plain) > maxVPNPayloadBytes {
				t.Fatalf("DecodeVPNPayload returned %d bytes", len(plain))
			}
			if !json.Valid(plain) {
				t.Fatal("DecodeVPNPayload returned invalid JSON")
			}
		}

		_, _ = ParseActivationKey(text)
		_, _ = ParseInputBytes(data)
		_, _ = ParseSelfHostedProfile(text)
		_, _ = ParseWireGuardConfig(text)
		_, _ = ParseGatewayProfile(text, privateKey, ProfileAPI{})
		_, _ = ParseGatewayProfileWithPublicKey(text, publicKey, ProfileAPI{})

		if parsed, err := ParseUint32Range(text); err == nil {
			if err := parsed.Validate(); err != nil {
				t.Fatalf("ParseUint32Range returned an invalid range: %v", err)
			}
		}

		_, _ = parseRSAPublicKey(data)
		_, _ = decryptProxyList(data, []byte("fuzz public key"))
	})
}
