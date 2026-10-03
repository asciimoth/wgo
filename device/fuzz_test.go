/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 AsciiMoth
 */

package device

import (
	"encoding/hex"
	"testing"
)

// FuzzDeviceUntrustedInput covers configuration strings and UDP packet bytes.
func FuzzDeviceUntrustedInput(f *testing.F) {
	validKey := make([]byte, NoisePrivateKeySize)
	for i := range validKey {
		validKey[i] = byte(i + 1)
	}
	validKeyHex := hex.EncodeToString(validKey)

	for _, seed := range []struct {
		input        []byte
		expectedType uint32
	}{
		{nil, MessageUnknownType},
		{make([]byte, MessageInitiationSize), MessageInitiationType},
		{make([]byte, MessageResponseSize), MessageResponseType},
		{make([]byte, MessageCookieReplySize), MessageCookieReplyType},
		{make([]byte, MessageTransportHeaderSize), MessageTransportType},
		{[]byte("1-20"), MessageUnknownType},
		{[]byte("<b 0x0102><rc 8><t>"), MessageUnknownType},
		{[]byte("private_key=" + validKeyHex + "\nlisten_port=0\n\n"), MessageUnknownType},
	} {
		f.Add(seed.input, seed.expectedType)
	}

	packetDevice := NewDevice(nil, nil, NopLogger{}, nil, DeviceOptions{WorkerCount: 1})
	f.Cleanup(packetDevice.Close)

	f.Fuzz(func(t *testing.T, input []byte, expectedType uint32) {
		if len(input) > MaxMessageSize+1 {
			return
		}
		text := string(input)

		_, _ = ParsePrivateKey(text)
		_, _ = ParsePublicKey(text)
		_, _ = ParsePresharedKey(text)
		if parsed, err := ParseAmneziaWGRange(text); err == nil {
			if err := parsed.Validate("fuzz range", ^uint32(0)); err != nil {
				t.Fatalf("ParseAmneziaWGRange returned an invalid range: %v", err)
			}
		}
		if parsed, err := ParseAmneziaWGHeaderRange(text); err == nil {
			if reparsed, err := ParseAmneziaWGHeaderRange(parsed.Spec()); err != nil || reparsed != parsed {
				t.Fatalf("header range did not round-trip: %#v, %v", reparsed, err)
			}
		}
		_, _ = ParseAmneziaWGHeaderProtectionKeyHex(text)

		if chain, err := newObfChain(text); err == nil {
			length := chain.ObfuscatedLen()
			if length < 0 || length > maxAmneziaWGInitiationPacketSize {
				t.Fatalf("invalid obfuscation length %d", length)
			}
			chain.Obfuscate(make([]byte, length))
		}

		var initiation MessageInitiation
		if err := initiation.unmarshal(input); (err == nil) != (len(input) == MessageInitiationSize) {
			t.Fatalf("initiation unmarshal result for length %d: %v", len(input), err)
		}
		var response MessageResponse
		if err := response.unmarshal(input); (err == nil) != (len(input) == MessageResponseSize) {
			t.Fatalf("response unmarshal result for length %d: %v", len(input), err)
		}
		var cookie MessageCookieReply
		if err := cookie.unmarshal(input); (err == nil) != (len(input) == MessageCookieReplySize) {
			t.Fatalf("cookie unmarshal result for length %d: %v", len(input), err)
		}

		expectedTypes := [...]uint32{
			MessageUnknownType,
			MessageInitiationType,
			MessageResponseType,
			MessageCookieReplyType,
			MessageTransportType,
		}
		expectedType = expectedTypes[expectedType%uint32(len(expectedTypes))]
		messageType, padding := packetDevice.DeterminePacketTypeAndPadding(input, expectedType)
		if padding < 0 || padding > len(input) {
			t.Fatalf("packet classifier returned invalid padding %d for %d bytes", padding, len(input))
		}
		if messageType == MessageUnknownType && padding != 0 {
			t.Fatalf("unknown packet has padding %d", padding)
		}

		// Exercise the full UAPI transaction parser for a subset of inputs. A
		// fresh device prevents one successful input from changing later cases.
		if len(input) > 0 && input[0]&7 == 0 {
			dev := NewDevice(nil, nil, NopLogger{}, nil, DeviceOptions{WorkerCount: 1})
			_ = dev.IpcSet(text)
			dev.Close()
		}
	})
}
