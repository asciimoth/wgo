/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

const (
	amneziaPacketCount = 5
	chars52            = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits10           = "0123456789"
)

type AmneziaWGHeaderRange struct {
	Start uint32
	End   uint32
}

func DefaultAmneziaWGHeaderRange(messageType uint32) AmneziaWGHeaderRange {
	return AmneziaWGHeaderRange{Start: messageType, End: messageType}
}

func ParseAmneziaWGHeaderRange(spec string) (AmneziaWGHeaderRange, error) {
	header, err := newMagicHeader(spec)
	if err != nil {
		return AmneziaWGHeaderRange{}, err
	}
	return header.toConfig(), nil
}

func (r AmneziaWGHeaderRange) Validate(value uint32) bool {
	return r.Start <= value && value <= r.End
}

func (r AmneziaWGHeaderRange) Generate() uint32 {
	high := int64(r.End - r.Start + 1)
	n, _ := rand.Int(rand.Reader, big.NewInt(high))
	return r.Start + uint32(n.Int64())
}

func (r AmneziaWGHeaderRange) Spec() string {
	if r.Start == r.End {
		return fmt.Sprintf("%d", r.Start)
	}
	return fmt.Sprintf("%d-%d", r.Start, r.End)
}

type AmneziaWGConfig struct {
	JunkCount         int
	JunkMin           int
	JunkMax           int
	InitHeader        AmneziaWGHeaderRange
	ResponseHeader    AmneziaWGHeaderRange
	CookieHeader      AmneziaWGHeaderRange
	TransportHeader   AmneziaWGHeaderRange
	InitPadding       int
	ResponsePadding   int
	CookiePadding     int
	TransportPadding  int
	InitiationPackets [amneziaPacketCount]string
}

func DefaultAmneziaWGConfig() AmneziaWGConfig {
	return AmneziaWGConfig{
		InitHeader:      DefaultAmneziaWGHeaderRange(MessageInitiationType),
		ResponseHeader:  DefaultAmneziaWGHeaderRange(MessageResponseType),
		CookieHeader:    DefaultAmneziaWGHeaderRange(MessageCookieReplyType),
		TransportHeader: DefaultAmneziaWGHeaderRange(MessageTransportType),
	}
}

type magicHeader struct {
	start uint32
	end   uint32
}

func newMagicHeader(spec string) (*magicHeader, error) {
	parts := strings.Split(spec, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return nil, errors.New("bad format")
	}
	start, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", parts[0], err)
	}

	end := start
	if len(parts) == 2 {
		end, err = strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", parts[1], err)
		}
	}
	if end < start {
		return nil, errors.New("wrong range specified")
	}
	return &magicHeader{start: uint32(start), end: uint32(end)}, nil
}

func (h *magicHeader) toConfig() AmneziaWGHeaderRange {
	return AmneziaWGHeaderRange{Start: h.start, End: h.end}
}

func (h *magicHeader) Validate(value uint32) bool {
	return h.start <= value && value <= h.end
}

func (h *magicHeader) Generate() uint32 {
	return h.toConfig().Generate()
}

func (h *magicHeader) Spec() string {
	return h.toConfig().Spec()
}

type obfPart interface {
	Obfuscate(dst []byte)
	ObfuscatedLen() int
}

type obfChain struct {
	Spec  string
	parts []obfPart
}

func newObfChain(spec string) (*obfChain, error) {
	var (
		parts []obfPart
		errs  []error
	)

	remaining := spec
	for {
		start := strings.IndexByte(remaining, '<')
		if start == -1 {
			break
		}
		end := strings.IndexByte(remaining[start:], '>')
		if end == -1 {
			return nil, errors.New("missing enclosing >")
		}
		end += start

		tag := remaining[start+1 : end]
		fields := strings.Fields(tag)
		if len(fields) == 0 {
			errs = append(errs, errors.New("empty tag"))
			remaining = remaining[end+1:]
			continue
		}

		part, err := newObfPart(fields[0], fields[1:])
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to build <%s>: %w", fields[0], err))
		} else {
			parts = append(parts, part)
		}
		remaining = remaining[end+1:]
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return &obfChain{Spec: spec, parts: parts}, nil
}

func (c *obfChain) ObfuscatedLen() int {
	total := 0
	for _, part := range c.parts {
		total += part.ObfuscatedLen()
	}
	return total
}

func (c *obfChain) Obfuscate(dst []byte) {
	offset := 0
	for _, part := range c.parts {
		size := part.ObfuscatedLen()
		part.Obfuscate(dst[offset : offset+size])
		offset += size
	}
}

func newObfPart(kind string, args []string) (obfPart, error) {
	arg := ""
	if len(args) > 0 {
		arg = args[0]
	}

	switch kind {
	case "b":
		return newBytesObf(arg)
	case "t":
		return timestampObf{}, nil
	case "r":
		return newRandomBytesObf(arg)
	case "rc":
		return newRandomCharsetObf(arg, chars52)
	case "rd":
		return newRandomCharsetObf(arg, digits10)
	default:
		return nil, fmt.Errorf("unknown tag <%s>", kind)
	}
}

type bytesObf struct {
	data []byte
}

func newBytesObf(value string) (obfPart, error) {
	value = strings.TrimPrefix(value, "0x")
	if value == "" {
		return nil, errors.New("empty argument")
	}
	if len(value)%2 != 0 {
		return nil, errors.New("odd amount of symbols")
	}
	data, err := hex.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return bytesObf{data: data}, nil
}

func (o bytesObf) Obfuscate(dst []byte) { copy(dst, o.data) }
func (o bytesObf) ObfuscatedLen() int   { return len(o.data) }

type randomBytesObf struct {
	length int
}

func newRandomBytesObf(value string) (obfPart, error) {
	length, err := strconv.Atoi(value)
	if err != nil {
		return nil, err
	}
	return randomBytesObf{length: length}, nil
}

func (o randomBytesObf) Obfuscate(dst []byte) { _, _ = rand.Read(dst[:o.length]) }
func (o randomBytesObf) ObfuscatedLen() int   { return o.length }

type randomCharsetObf struct {
	length  int
	charset string
}

func newRandomCharsetObf(value, charset string) (obfPart, error) {
	length, err := strconv.Atoi(value)
	if err != nil {
		return nil, err
	}
	return randomCharsetObf{length: length, charset: charset}, nil
}

func (o randomCharsetObf) Obfuscate(dst []byte) {
	_, _ = rand.Read(dst[:o.length])
	for i := range dst[:o.length] {
		dst[i] = o.charset[int(dst[i])%len(o.charset)]
	}
}

func (o randomCharsetObf) ObfuscatedLen() int { return o.length }

type timestampObf struct{}

func (timestampObf) Obfuscate(dst []byte) {
	binary.BigEndian.PutUint32(dst[:4], uint32(time.Now().Unix()))
}

func (timestampObf) ObfuscatedLen() int { return 4 }

type ipcSetAmneziaWG struct {
	junkCount         *int
	junkMin           *int
	junkMax           *int
	initHeader        *magicHeader
	responseHeader    *magicHeader
	cookieHeader      *magicHeader
	transportHeader   *magicHeader
	initPadding       *int
	responsePadding   *int
	cookiePadding     *int
	transportPadding  *int
	initiationPackets [amneziaPacketCount]*obfChain
	packetSet         [amneziaPacketCount]bool
}

func (s *ipcSetAmneziaWG) mergeWithDevice(device *Device) error {
	cfg := device.amneziaWGConfigLocked()

	if s.junkCount != nil {
		cfg.JunkCount = *s.junkCount
	}
	if s.junkMin != nil {
		cfg.JunkMin = *s.junkMin
	}
	if s.junkMax != nil {
		cfg.JunkMax = *s.junkMax
	}
	if s.initHeader != nil {
		cfg.InitHeader = s.initHeader.toConfig()
	}
	if s.responseHeader != nil {
		cfg.ResponseHeader = s.responseHeader.toConfig()
	}
	if s.cookieHeader != nil {
		cfg.CookieHeader = s.cookieHeader.toConfig()
	}
	if s.transportHeader != nil {
		cfg.TransportHeader = s.transportHeader.toConfig()
	}
	if s.initPadding != nil {
		cfg.InitPadding = *s.initPadding
	}
	if s.responsePadding != nil {
		cfg.ResponsePadding = *s.responsePadding
	}
	if s.cookiePadding != nil {
		cfg.CookiePadding = *s.cookiePadding
	}
	if s.transportPadding != nil {
		cfg.TransportPadding = *s.transportPadding
	}
	for i := range s.initiationPackets {
		if !s.packetSet[i] {
			continue
		}
		if s.initiationPackets[i] == nil {
			cfg.InitiationPackets[i] = ""
			continue
		}
		cfg.InitiationPackets[i] = s.initiationPackets[i].Spec
	}

	return device.setAmneziaWGConfigLocked(cfg)
}

type amneziaWGSnapshot struct {
	junk struct {
		min   int
		max   int
		count int
	}
	headers struct {
		init      *magicHeader
		response  *magicHeader
		cookie    *magicHeader
		transport *magicHeader
	}
	paddings struct {
		init      int
		response  int
		cookie    int
		transport int
	}
	ipackets [amneziaPacketCount]*obfChain
}

func (device *Device) storeAmneziaWGSnapshot() {
	var snapshot amneziaWGSnapshot
	snapshot.junk = device.junk
	snapshot.headers = device.headers
	snapshot.paddings = device.paddings
	snapshot.ipackets = device.ipackets
	device.amneziaSnapshot.Store(&snapshot)
}

func (device *Device) amneziaWGSnapshot() amneziaWGSnapshot {
	snapshot := device.amneziaSnapshot.Load()
	if snapshot == nil {
		return amneziaWGSnapshot{}
	}
	return *snapshot
}
