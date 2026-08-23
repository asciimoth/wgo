/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 AsciiMoth
 */

package main

import (
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/chacha20"
)

func TestBuildPacketLengths(t *testing.T) {
	var key [chacha20.KeySize]byte
	tests := []struct {
		name string
		want int
	}{
		{string(caseTruncatedSPrefix), chacha20.NonceSize - 1},
		{string(caseExactSNonce), chacha20.NonceSize},
		{string(caseCorruptInitiation), chacha20.NonceSize + messageInitiationSize},
		{string(caseWrongResponseIndex), chacha20.NonceSize + messageResponseSize},
		{string(caseWrongCookieIndex), chacha20.NonceSize + messageCookieReplySize},
		{string(caseWrongReceiverIndex), chacha20.NonceSize + messageTransportHeaderSize},
		{string(caseMaximumUDPTransport), defaultMaxUDPPayloadSize},
		{string(caseOversizedFixedTrailerUDP), defaultMaxUDPPayloadSize},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet, err := buildPacket(packetCase(tt.name), key, 6444, 0xffffffff)
			if err != nil {
				t.Fatalf("buildPacket: %v", err)
			}
			if len(packet) != tt.want {
				t.Fatalf("len(packet) = %d, want %d", len(packet), tt.want)
			}
		})
	}
}

func TestFixedPacketsProtectHeader(t *testing.T) {
	var key [chacha20.KeySize]byte
	for i := range key {
		key[i] = byte(i + 3)
	}

	tests := []struct {
		name       packetCase
		header     uint32
		coreLength int
		indexOff   int
	}{
		{caseCorruptInitiation, 6111, messageInitiationSize, -1},
		{caseWrongResponseIndex, 6222, messageResponseSize, 8},
		{caseWrongCookieIndex, 6333, messageCookieReplySize, 4},
	}

	for _, tt := range tests {
		t.Run(string(tt.name), func(t *testing.T) {
			packet, err := buildPacket(tt.name, key, tt.header, 0xffffffff)
			if err != nil {
				t.Fatalf("buildPacket: %v", err)
			}
			core := unprotectCore(t, key, packet, tt.coreLength)
			if got := binary.LittleEndian.Uint32(core[0:]); got != tt.header {
				t.Fatalf("header = %d, want %d", got, tt.header)
			}
			if tt.indexOff >= 0 {
				if got := binary.LittleEndian.Uint32(core[tt.indexOff:]); got != 0xffffffff {
					t.Fatalf("receiver index = %#x, want 0xffffffff", got)
				}
			}
		})
	}
}

func TestWrongReceiverIndexPacketProtectsTransportHeader(t *testing.T) {
	var key [chacha20.KeySize]byte
	for i := range key {
		key[i] = byte(i)
	}

	const (
		header        = uint32(6444)
		receiverIndex = uint32(0xdecafbad)
	)
	packet, err := buildPacket(caseWrongReceiverIndex, key, header, receiverIndex)
	if err != nil {
		t.Fatalf("buildPacket: %v", err)
	}

	core := unprotectCore(t, key, packet, messageTransportHeaderSize)

	if got := binary.LittleEndian.Uint32(core[0:]); got != header {
		t.Fatalf("header = %d, want %d", got, header)
	}
	if got := binary.LittleEndian.Uint32(core[4:]); got != receiverIndex {
		t.Fatalf("receiver index = %#x, want %#x", got, receiverIndex)
	}
	if got := binary.LittleEndian.Uint64(core[8:]); got != 0 {
		t.Fatalf("counter = %d, want 0", got)
	}
}

func TestMaximumUDPTransportPacketProtectsOnlyTransportHeader(t *testing.T) {
	var key [chacha20.KeySize]byte
	for i := range key {
		key[i] = byte(i + 9)
	}

	const (
		header        = uint32(6444)
		receiverIndex = uint32(0xdecafbad)
	)
	packet, err := buildPacket(caseMaximumUDPTransport, key, header, receiverIndex)
	if err != nil {
		t.Fatalf("buildPacket: %v", err)
	}

	core := unprotectCore(t, key, packet, messageTransportHeaderSize)
	if got := binary.LittleEndian.Uint32(core[0:]); got != header {
		t.Fatalf("header = %d, want %d", got, header)
	}
	if got := binary.LittleEndian.Uint32(core[4:]); got != receiverIndex {
		t.Fatalf("receiver index = %#x, want %#x", got, receiverIndex)
	}
	trailerOffset := chacha20.NonceSize + messageTransportHeaderSize
	for i, got := range packet[trailerOffset : trailerOffset+16] {
		want := byte(trailerOffset + i)
		if got != want {
			t.Fatalf("trailer[%d] = %#x, want %#x", i, got, want)
		}
	}
}

func TestOversizedFixedTrailerPacketProtectsOnlyFixedCore(t *testing.T) {
	var key [chacha20.KeySize]byte
	for i := range key {
		key[i] = byte(255 - i)
	}

	const header = uint32(6111)
	packet, err := buildPacket(caseOversizedFixedTrailerUDP, key, header, 0)
	if err != nil {
		t.Fatalf("buildPacket: %v", err)
	}

	core := unprotectCore(t, key, packet, messageInitiationSize)

	if got := binary.LittleEndian.Uint32(core[0:]); got != header {
		t.Fatalf("header = %d, want %d", got, header)
	}
	trailerOffset := chacha20.NonceSize + messageInitiationSize
	for i, got := range packet[trailerOffset : trailerOffset+16] {
		want := byte(trailerOffset + i)
		if got != want {
			t.Fatalf("trailer[%d] = %#x, want %#x", i, got, want)
		}
	}
}

func unprotectCore(t *testing.T, key [chacha20.KeySize]byte, packet []byte, coreLength int) []byte {
	t.Helper()

	core := append([]byte(nil), packet[chacha20.NonceSize:chacha20.NonceSize+coreLength]...)
	cipher, err := chacha20.NewUnauthenticatedCipher(key[:], packet[:chacha20.NonceSize])
	if err != nil {
		t.Fatalf("NewUnauthenticatedCipher: %v", err)
	}
	cipher.XORKeyStream(core, core)
	return core
}
