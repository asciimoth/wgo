/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 AsciiMoth
 */

// awg-malformed-sender sends deterministic malformed AWG 3.1 datagrams for
// cross-implementation compatibility tests. It is intentionally small and only
// covers packet shapes that the compat suite needs to inject into a live UDP
// socket.
package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/chacha20"
)

const (
	messageInitiationSize      = 148
	messageResponseSize        = 92
	messageCookieReplySize     = 64
	messageTransportHeaderSize = 16
	defaultMaxUDPPayloadSize   = 65507
)

type packetCase string

const (
	caseTruncatedSPrefix         packetCase = "truncated-s-prefix"
	caseExactSNonce              packetCase = "exact-s-nonce"
	caseCorruptInitiation        packetCase = "corrupt-initiation"
	caseWrongResponseIndex       packetCase = "wrong-response-index"
	caseWrongCookieIndex         packetCase = "wrong-cookie-index"
	caseWrongReceiverIndex       packetCase = "wrong-receiver-index"
	caseMaximumUDPTransport      packetCase = "maximum-udp-transport"
	caseOversizedFixedTrailerUDP packetCase = "oversized-fixed-trailer"
)

func main() {
	target := flag.String("target", "", "UDP target address")
	caseName := flag.String("case", "", "malformed packet case")
	keyHex := flag.String("key", "", "32-byte AWG 3.1 header protection key in hex")
	header := flag.Uint("header", 6444, "AWG message header value")
	receiverIndex := flag.Uint("receiver-index", 0xffffffff, "receiver index for malformed indexed packets")
	count := flag.Int("count", 1, "number of datagrams to send")
	delay := flag.Duration("delay", 50*time.Millisecond, "delay between datagrams")
	flag.Parse()

	if *target == "" {
		exitf("missing -target")
	}
	if *count < 1 {
		exitf("-count must be >= 1")
	}

	key, err := parseHeaderKey(*keyHex)
	if err != nil {
		exitf("%v", err)
	}

	packet, err := buildPacket(packetCase(*caseName), key, uint32(*header), uint32(*receiverIndex))
	if err != nil {
		exitf("%v", err)
	}

	conn, err := net.Dial("udp", *target)
	if err != nil {
		exitf("dial %s: %v", *target, err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			exitf("close UDP connection: %v", err)
		}
	}()

	for i := 0; i < *count; i++ {
		if _, err := conn.Write(packet); err != nil {
			exitf("send %s to %s: %v", *caseName, *target, err)
		}
		if i+1 < *count {
			time.Sleep(*delay)
		}
	}
}

func parseHeaderKey(spec string) ([chacha20.KeySize]byte, error) {
	var key [chacha20.KeySize]byte
	if spec == "" {
		return key, fmt.Errorf("missing -key")
	}
	data, err := hex.DecodeString(spec)
	if err != nil {
		return key, fmt.Errorf("parse -key: %w", err)
	}
	if len(data) != len(key) {
		return key, fmt.Errorf("-key must decode to %d bytes", len(key))
	}
	copy(key[:], data)
	return key, nil
}

func buildPacket(caseName packetCase, key [chacha20.KeySize]byte, header, receiverIndex uint32) ([]byte, error) {
	switch caseName {
	case caseTruncatedSPrefix:
		return sequentialBytes(chacha20.NonceSize - 1), nil
	case caseExactSNonce:
		return sequentialBytes(chacha20.NonceSize), nil
	case caseCorruptInitiation:
		return buildProtectedFixedPacket(key, header, messageInitiationSize), nil
	case caseWrongResponseIndex:
		return buildWrongResponseIndexPacket(key, header, receiverIndex), nil
	case caseWrongCookieIndex:
		return buildWrongCookieIndexPacket(key, header, receiverIndex), nil
	case caseWrongReceiverIndex:
		return buildWrongReceiverIndexPacket(key, header, receiverIndex)
	case caseMaximumUDPTransport:
		return buildMaximumUDPTransportPacket(key, header, receiverIndex)
	case caseOversizedFixedTrailerUDP:
		return buildOversizedFixedTrailerPacket(key, header), nil
	default:
		return nil, fmt.Errorf("unknown -case %q", caseName)
	}
}

func buildProtectedFixedPacket(key [chacha20.KeySize]byte, header uint32, coreLength int) []byte {
	packet := sequentialBytes(chacha20.NonceSize + coreLength)
	core := packet[chacha20.NonceSize:]
	binary.LittleEndian.PutUint32(core[0:], header)
	protected, err := protectCore(key, packet, coreLength)
	if err != nil {
		panic(err)
	}
	return protected
}

func buildWrongResponseIndexPacket(key [chacha20.KeySize]byte, header, receiverIndex uint32) []byte {
	packet := sequentialBytes(chacha20.NonceSize + messageResponseSize)
	core := packet[chacha20.NonceSize:]
	binary.LittleEndian.PutUint32(core[0:], header)
	binary.LittleEndian.PutUint32(core[8:], receiverIndex)
	protected, err := protectCore(key, packet, messageResponseSize)
	if err != nil {
		panic(err)
	}
	return protected
}

func buildWrongCookieIndexPacket(key [chacha20.KeySize]byte, header, receiverIndex uint32) []byte {
	packet := sequentialBytes(chacha20.NonceSize + messageCookieReplySize)
	core := packet[chacha20.NonceSize:]
	binary.LittleEndian.PutUint32(core[0:], header)
	binary.LittleEndian.PutUint32(core[4:], receiverIndex)
	protected, err := protectCore(key, packet, messageCookieReplySize)
	if err != nil {
		panic(err)
	}
	return protected
}

func buildWrongReceiverIndexPacket(key [chacha20.KeySize]byte, header, receiverIndex uint32) ([]byte, error) {
	packet := sequentialBytes(chacha20.NonceSize + messageTransportHeaderSize)
	core := packet[chacha20.NonceSize:]
	binary.LittleEndian.PutUint32(core[0:], header)
	binary.LittleEndian.PutUint32(core[4:], receiverIndex)
	binary.LittleEndian.PutUint64(core[8:], 0)
	return protectCore(key, packet, messageTransportHeaderSize)
}

func buildMaximumUDPTransportPacket(key [chacha20.KeySize]byte, header, receiverIndex uint32) ([]byte, error) {
	packet := sequentialBytes(defaultMaxUDPPayloadSize)
	core := packet[chacha20.NonceSize : chacha20.NonceSize+messageTransportHeaderSize]
	binary.LittleEndian.PutUint32(core[0:], header)
	binary.LittleEndian.PutUint32(core[4:], receiverIndex)
	binary.LittleEndian.PutUint64(core[8:], 0)
	return protectCore(key, packet, messageTransportHeaderSize)
}

func buildOversizedFixedTrailerPacket(key [chacha20.KeySize]byte, header uint32) []byte {
	packet := sequentialBytes(defaultMaxUDPPayloadSize)
	core := packet[chacha20.NonceSize : chacha20.NonceSize+messageInitiationSize]
	binary.LittleEndian.PutUint32(core[0:], header)
	for i := 4; i < len(core); i++ {
		core[i] = byte((i*29 + 7) & 0xff)
	}
	protected, err := protectCore(key, packet, messageInitiationSize)
	if err != nil {
		panic(err)
	}
	return protected
}

func protectCore(key [chacha20.KeySize]byte, packet []byte, coreLength int) ([]byte, error) {
	cipher, err := chacha20.NewUnauthenticatedCipher(key[:], packet[:chacha20.NonceSize])
	if err != nil {
		return nil, err
	}
	cipher.XORKeyStream(packet[chacha20.NonceSize:chacha20.NonceSize+coreLength], packet[chacha20.NonceSize:chacha20.NonceSize+coreLength])
	return packet, nil
}

func sequentialBytes(size int) []byte {
	packet := make([]byte, size)
	for i := range packet {
		packet[i] = byte(i)
	}
	return packet
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
