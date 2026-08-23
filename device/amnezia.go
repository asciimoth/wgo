/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 AsciiMoth
 */

package device

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20"
)

const (
	amneziaPacketCount = 5
	chars52            = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits10           = "0123456789"

	maxAmneziaWGJunkCount            = 16
	maxAmneziaWGJunkSize             = MaxMessageSize
	maxAmneziaWGHandshakePaddingSize = MaxMessageSize - MessageHandshakeSize
	maxAmneziaWGTransportPaddingSize = MaxTunOffsetHeadroom
	maxAmneziaWGInitiationPacketSize = MaxMessageSize
	maxAmneziaWGTimerRangeSeconds    = ^uint32(0)
	maxAmneziaWGHandshakeAttempts    = 1024
	maxAmneziaWGRejectAfterTimeMax   = uint32((time.Duration(1<<63-1) / time.Second) / 3)
)

// AmneziaWGVersion selects the configured AmneziaWG behavior.
//
// Auto preserves source compatibility by inferring the lowest mode required by
// the configured fields. It does not negotiate a mode on the wire.
type AmneziaWGVersion uint8

const (
	AmneziaWGVersionAuto AmneziaWGVersion = iota
	AmneziaWGDisabled
	AmneziaWGV1_5
	AmneziaWGV2
	AmneziaWGV3_1
)

// AmneziaWGRange is an inclusive uint32 range. Set=false means omitted.
type AmneziaWGRange struct {
	Min uint32
	Max uint32
	Set bool
}

// ParseAmneziaWGRange parses "n" or "min-max" as an inclusive range.
func ParseAmneziaWGRange(spec string) (AmneziaWGRange, error) {
	if spec == "" {
		return AmneziaWGRange{}, errors.New("empty range")
	}
	parts := strings.Split(spec, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return AmneziaWGRange{}, errors.New("bad range format")
	}
	min, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return AmneziaWGRange{}, fmt.Errorf("failed to parse range minimum: %w", err)
	}
	max := min
	if len(parts) == 2 {
		max, err = strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return AmneziaWGRange{}, fmt.Errorf("failed to parse range maximum: %w", err)
		}
	}
	r := AmneziaWGRange{Min: uint32(min), Max: uint32(max), Set: true}
	if err := r.Validate("range", ^uint32(0)); err != nil {
		return AmneziaWGRange{}, err
	}
	return r, nil
}

// String returns "off" for an unset range, "n" for a fixed range, or "min-max".
func (r AmneziaWGRange) String() string {
	if !r.Set {
		return "off"
	}
	if r.Min == r.Max {
		return strconv.FormatUint(uint64(r.Min), 10)
	}
	return fmt.Sprintf("%d-%d", r.Min, r.Max)
}

// Validate checks range order and an inclusive upper bound.
func (r AmneziaWGRange) Validate(name string, max uint32) error {
	if !r.Set {
		return nil
	}
	if r.Min > r.Max {
		return fmt.Errorf("%s minimum must be <= maximum", name)
	}
	if r.Max > max {
		return fmt.Errorf("%s maximum must be <= %d", name, max)
	}
	return nil
}

// Generate returns a cryptographically random value from the range.
func (r AmneziaWGRange) Generate() uint32 {
	if !r.Set || r.Min == r.Max {
		return r.Min
	}
	n, err := rand.Int(rand.Reader, new(big.Int).SetUint64(amneziaWGInclusiveRangeSize(r.Min, r.Max)))
	if err != nil {
		return r.Min
	}
	return r.Min + uint32(n.Int64())
}

func amneziaWGInclusiveRangeSize(min, max uint32) uint64 {
	return uint64(max) - uint64(min) + 1
}

// AmneziaWGHeaderProtectionKey masks AWG 3.1 message headers.
type AmneziaWGHeaderProtectionKey [chacha20.KeySize]byte

// IsZero reports whether no header protection key is configured.
func (k AmneziaWGHeaderProtectionKey) IsZero() bool {
	var zero AmneziaWGHeaderProtectionKey
	return subtle.ConstantTimeCompare(k[:], zero[:]) == 1
}

// ParseAmneziaWGHeaderProtectionKeyHex parses a 32-byte lowercase or uppercase
// hexadecimal header protection key.
func ParseAmneziaWGHeaderProtectionKeyHex(spec string) (AmneziaWGHeaderProtectionKey, error) {
	var key AmneziaWGHeaderProtectionKey
	b, err := hex.DecodeString(spec)
	if err != nil {
		return key, err
	}
	if len(b) != len(key) {
		return key, fmt.Errorf("header protection key must be %d bytes", len(key))
	}
	copy(key[:], b)
	return key, nil
}

// AmneziaWGHeaderRange is an inclusive range for an AmneziaWG message header.
type AmneziaWGHeaderRange struct {
	Start uint32
	End   uint32
}

// DefaultAmneziaWGHeaderRange returns a single-value range for a WireGuard
// message type.
func DefaultAmneziaWGHeaderRange(messageType uint32) AmneziaWGHeaderRange {
	return AmneziaWGHeaderRange{Start: messageType, End: messageType}
}

// ParseAmneziaWGHeaderRange parses "n" or "start-end" as an inclusive range.
func ParseAmneziaWGHeaderRange(spec string) (AmneziaWGHeaderRange, error) {
	header, err := newMagicHeader(spec)
	if err != nil {
		return AmneziaWGHeaderRange{}, err
	}
	return header.toConfig(), nil
}

// Validate reports whether value is inside the range.
func (r AmneziaWGHeaderRange) Validate(value uint32) bool {
	return r.Start <= value && value <= r.End
}

// Generate returns a cryptographically random value from the range.
func (r AmneziaWGHeaderRange) Generate() uint32 {
	n, err := rand.Int(rand.Reader, new(big.Int).SetUint64(amneziaWGInclusiveRangeSize(r.Start, r.End)))
	if err != nil {
		return r.Start
	}
	return r.Start + uint32(n.Int64())
}

// Spec returns the UAPI string form for the range.
func (r AmneziaWGHeaderRange) Spec() string {
	if r.Start == r.End {
		return fmt.Sprintf("%d", r.Start)
	}
	return fmt.Sprintf("%d-%d", r.Start, r.End)
}

// AmneziaWGConfig is a complete AmneziaWG obfuscation profile.
//
// Use DefaultAmneziaWGConfig to get the plain WireGuard-compatible profile
// before changing fields. The zero value is not a valid complete profile,
// because all header ranges default to 0 and therefore overlap.
type AmneziaWGConfig struct {
	Version AmneziaWGVersion

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

	HeaderProtectionKey  AmneziaWGHeaderProtectionKey
	ContentPadding       AmneziaWGRange
	RekeyAfterTime       AmneziaWGRange
	RekeyTimeout         AmneziaWGRange
	RejectAfterTime      AmneziaWGRange
	KeepaliveTimeout     AmneziaWGRange
	MaxHandshakeAttempts AmneziaWGRange
	RandomTrailers       bool
	DisableCookies       bool
}

// DefaultAmneziaWGConfig returns a plain WireGuard-compatible profile.
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
		length := part.ObfuscatedLen()
		if length > maxAmneziaWGInitiationPacketSize-total {
			return maxAmneziaWGInitiationPacketSize + 1
		}
		total += length
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
	if err := validateAmneziaWGGeneratedLength(length); err != nil {
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
	if err := validateAmneziaWGGeneratedLength(length); err != nil {
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
	version           *AmneziaWGVersion
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

	headerProtectionKey  *AmneziaWGHeaderProtectionKey
	contentPadding       *AmneziaWGRange
	rekeyAfterTime       *AmneziaWGRange
	rekeyTimeout         *AmneziaWGRange
	rejectAfterTime      *AmneziaWGRange
	keepaliveTimeout     *AmneziaWGRange
	maxHandshakeAttempts *AmneziaWGRange
	randomTrailers       *bool
	disableCookies       *bool
}

func (s *ipcSetAmneziaWG) hasValues() bool {
	if s.version != nil || s.junkCount != nil || s.junkMin != nil || s.junkMax != nil ||
		s.initHeader != nil || s.responseHeader != nil || s.cookieHeader != nil || s.transportHeader != nil ||
		s.initPadding != nil || s.responsePadding != nil || s.cookiePadding != nil || s.transportPadding != nil ||
		s.headerProtectionKey != nil || s.contentPadding != nil || s.rekeyAfterTime != nil ||
		s.rekeyTimeout != nil || s.rejectAfterTime != nil || s.keepaliveTimeout != nil ||
		s.maxHandshakeAttempts != nil || s.randomTrailers != nil || s.disableCookies != nil {
		return true
	}
	for i := range s.packetSet {
		if s.packetSet[i] {
			return true
		}
	}
	return false
}

func (s *ipcSetAmneziaWG) merge(cfg *AmneziaWGConfig) {
	if s.version != nil {
		cfg.Version = *s.version
	}
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
	if s.headerProtectionKey != nil {
		cfg.HeaderProtectionKey = *s.headerProtectionKey
	}
	if s.contentPadding != nil {
		cfg.ContentPadding = *s.contentPadding
	}
	if s.rekeyAfterTime != nil {
		cfg.RekeyAfterTime = *s.rekeyAfterTime
	}
	if s.rekeyTimeout != nil {
		cfg.RekeyTimeout = *s.rekeyTimeout
	}
	if s.rejectAfterTime != nil {
		cfg.RejectAfterTime = *s.rejectAfterTime
	}
	if s.keepaliveTimeout != nil {
		cfg.KeepaliveTimeout = *s.keepaliveTimeout
	}
	if s.maxHandshakeAttempts != nil {
		cfg.MaxHandshakeAttempts = *s.maxHandshakeAttempts
	}
	if s.randomTrailers != nil {
		cfg.RandomTrailers = *s.randomTrailers
	}
	if s.disableCookies != nil {
		cfg.DisableCookies = *s.disableCookies
	}
}

func (s *ipcSetAmneziaWG) mergeIntoOverride(dst *ipcSetAmneziaWG) {
	if s.version != nil {
		dst.version = s.version
	}
	if s.junkCount != nil {
		dst.junkCount = s.junkCount
	}
	if s.junkMin != nil {
		dst.junkMin = s.junkMin
	}
	if s.junkMax != nil {
		dst.junkMax = s.junkMax
	}
	if s.initHeader != nil {
		dst.initHeader = s.initHeader
	}
	if s.responseHeader != nil {
		dst.responseHeader = s.responseHeader
	}
	if s.cookieHeader != nil {
		dst.cookieHeader = s.cookieHeader
	}
	if s.transportHeader != nil {
		dst.transportHeader = s.transportHeader
	}
	if s.initPadding != nil {
		dst.initPadding = s.initPadding
	}
	if s.responsePadding != nil {
		dst.responsePadding = s.responsePadding
	}
	if s.cookiePadding != nil {
		dst.cookiePadding = s.cookiePadding
	}
	if s.transportPadding != nil {
		dst.transportPadding = s.transportPadding
	}
	for i := range s.initiationPackets {
		if !s.packetSet[i] {
			continue
		}
		dst.packetSet[i] = true
		dst.initiationPackets[i] = s.initiationPackets[i]
	}
	if s.headerProtectionKey != nil {
		dst.headerProtectionKey = s.headerProtectionKey
	}
	if s.contentPadding != nil {
		dst.contentPadding = s.contentPadding
	}
	if s.rekeyAfterTime != nil {
		dst.rekeyAfterTime = s.rekeyAfterTime
	}
	if s.rekeyTimeout != nil {
		dst.rekeyTimeout = s.rekeyTimeout
	}
	if s.rejectAfterTime != nil {
		dst.rejectAfterTime = s.rejectAfterTime
	}
	if s.keepaliveTimeout != nil {
		dst.keepaliveTimeout = s.keepaliveTimeout
	}
	if s.maxHandshakeAttempts != nil {
		dst.maxHandshakeAttempts = s.maxHandshakeAttempts
	}
	if s.randomTrailers != nil {
		dst.randomTrailers = s.randomTrailers
	}
	if s.disableCookies != nil {
		dst.disableCookies = s.disableCookies
	}
}

func (s *ipcSetAmneziaWG) mergeWithDevice(device *Device) error {
	cfg := device.amneziaWGConfigLocked()
	s.merge(&cfg)
	return device.setAmneziaWGConfigLocked(cfg)
}

type amneziaWGSnapshot struct {
	version AmneziaWGVersion
	junk    struct {
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

	headerProtectionKey  AmneziaWGHeaderProtectionKey
	hasHeaderProtection  bool
	contentPadding       AmneziaWGRange
	rekeyAfterTime       AmneziaWGRange
	rekeyTimeout         AmneziaWGRange
	rejectAfterTime      AmneziaWGRange
	keepaliveTimeout     AmneziaWGRange
	maxHandshakeAttempts AmneziaWGRange
	randomTrailers       bool
	disableCookies       bool
}

type amneziaWGReceiveClassifier struct {
	profiles []amneziaWGSnapshot

	// Fixed-size handshake packets are keyed by datagram size first, then by
	// header offset. This avoids checking profiles that cannot match the size.
	fixedBySize map[int]map[int]*amneziaWGReceiveHeaderIndex

	// Transport packets have variable content size, so they are keyed by the
	// only bounded receive-side value: the padding/header offset.
	transportByPadding [maxAmneziaWGTransportPaddingSize + 1]amneziaWGReceiveHeaderIndex

	fixedWithTrailers []amneziaWGReceiveTrailerCandidate
}

// amneziaWGReceiveCandidate is a complete classification result for one
// message header at one padding offset.
type amneziaWGReceiveCandidate struct {
	msgType    uint32
	padding    int
	coreLength int
	order      int
	amnezia    amneziaWGSnapshot
}

// decodedAmneziaPacket stores the unmasked AWG packet core separately from the
// receive buffer. This lets receive code authenticate the selected profile
// before it commits header protection changes to the shared packet slice.
type decodedAmneziaPacket struct {
	candidate amneziaWGReceiveCandidate
	core      [MessageHandshakeSize]byte
}

func (decoded decodedAmneziaPacket) messageType() uint32 {
	return decoded.candidate.msgType
}

func (decoded decodedAmneziaPacket) padding() int {
	return decoded.candidate.padding
}

func (decoded decodedAmneziaPacket) coreLength() int {
	return decoded.candidate.coreLength
}

func (decoded decodedAmneziaPacket) amnezia() amneziaWGSnapshot {
	return decoded.candidate.amnezia
}

func (decoded decodedAmneziaPacket) receiverIndex() (uint32, bool) {
	switch decoded.messageType() {
	case MessageResponseType:
		return binary.LittleEndian.Uint32(decoded.core[8:12]), true
	case MessageCookieReplyType, MessageTransportType:
		return binary.LittleEndian.Uint32(decoded.core[4:8]), true
	default:
		return 0, false
	}
}

func (decoded decodedAmneziaPacket) materialize(packet []byte) []byte {
	padding := decoded.padding()
	coreLength := decoded.coreLength()
	copy(packet[padding:padding+coreLength], decoded.core[:coreLength])
	if padding > 0 {
		copy(packet, packet[padding:])
		packet = packet[:len(packet)-padding]
	}
	switch decoded.messageType() {
	case MessageInitiationType, MessageResponseType, MessageCookieReplyType:
		if decoded.amnezia().randomTrailers && len(packet) > coreLength {
			packet = packet[:coreLength]
		}
	}
	return packet
}

type amneziaWGReceiveTrailerCandidate struct {
	header     *magicHeader
	msgType    uint32
	padding    int
	coreLength int
	order      int
	amnezia    amneziaWGSnapshot
}

// amneziaWGReceiveRangeCandidate stores a range candidate plus the largest end
// value seen so far in its sorted bucket. The prefix maximum lets lookups stop
// once no earlier range can contain the observed header.
type amneziaWGReceiveRangeCandidate struct {
	start     uint32
	end       uint32
	maxEnd    uint32
	candidate amneziaWGReceiveCandidate
}

// amneziaWGReceiveHeaderIndex maps an observed header value to the profiles
// that can accept it at one packet offset.
type amneziaWGReceiveHeaderIndex struct {
	exact  map[uint32][]amneziaWGReceiveCandidate
	ranges []amneziaWGReceiveRangeCandidate
}

func (device *Device) storeAmneziaWGSnapshot() {
	var snapshot amneziaWGSnapshot
	snapshot.version = device.amneziaVersion
	snapshot.junk = device.junk
	snapshot.headers = device.headers
	snapshot.paddings = device.paddings
	snapshot.ipackets = device.ipackets
	snapshot.headerProtectionKey = device.amneziaV3.headerProtectionKey
	snapshot.hasHeaderProtection = !device.amneziaV3.headerProtectionKey.IsZero()
	snapshot.contentPadding = device.amneziaV3.contentPadding
	snapshot.rekeyAfterTime = device.amneziaV3.rekeyAfterTime
	snapshot.rekeyTimeout = device.amneziaV3.rekeyTimeout
	snapshot.rejectAfterTime = device.amneziaV3.rejectAfterTime
	snapshot.keepaliveTimeout = device.amneziaV3.keepaliveTimeout
	snapshot.maxHandshakeAttempts = device.amneziaV3.maxHandshakeAttempts
	snapshot.randomTrailers = device.amneziaV3.randomTrailers
	snapshot.disableCookies = device.amneziaV3.disableCookies
	device.amneziaSnapshot.Store(&snapshot)
}

func (device *Device) amneziaWGSnapshot() amneziaWGSnapshot {
	snapshot := device.amneziaSnapshot.Load()
	if snapshot == nil {
		return amneziaWGSnapshot{}
	}
	return *snapshot
}

func (device *Device) storeAmneziaWGReceiveClassifier() {
	device.peers.RLock()
	defer device.peers.RUnlock()
	device.storeAmneziaWGReceiveClassifierLocked()
}

func (device *Device) storeAmneziaWGReceiveClassifierLocked() {
	profiles := []amneziaWGSnapshot{device.amneziaWGSnapshot()}
	for _, peer := range device.peers.keyMap {
		snapshot := peer.amnezia.snapshot.Load()
		if snapshot == nil || amneziaWGReceiveProfilesContain(profiles, *snapshot) {
			continue
		}
		if device.amneziaReceiveProfileMax > 0 && len(profiles) >= device.amneziaReceiveProfileMax {
			device.amneziaReceiveCounters.profileLimitRejections.Add(1)
			break
		}
		profiles = append(profiles, *snapshot)
	}
	device.amneziaReceiveClassifier.Store(newAmneziaWGReceiveClassifier(profiles))
}

// newAmneziaWGReceiveClassifier compiles profile snapshots into immutable
// lookup tables that can be read without locks by the receive path.
func newAmneziaWGReceiveClassifier(profiles []amneziaWGSnapshot) *amneziaWGReceiveClassifier {
	classifier := &amneziaWGReceiveClassifier{
		profiles:    profiles,
		fixedBySize: make(map[int]map[int]*amneziaWGReceiveHeaderIndex),
	}
	for profileIndex, profile := range profiles {
		baseOrder := profileIndex * 4
		classifier.addFixedCandidate(profile.headers.init, MessageInitiationType, profile.paddings.init, MessageInitiationSize, baseOrder, profile)
		classifier.addFixedCandidate(profile.headers.response, MessageResponseType, profile.paddings.response, MessageResponseSize, baseOrder+1, profile)
		classifier.addFixedCandidate(profile.headers.cookie, MessageCookieReplyType, profile.paddings.cookie, MessageCookieReplySize, baseOrder+2, profile)
		classifier.addTransportCandidate(profile.headers.transport, profile.paddings.transport, baseOrder+3, profile)
	}
	classifier.finalize()
	return classifier
}

func (c *amneziaWGReceiveClassifier) addFixedCandidate(header *magicHeader, msgType uint32, padding, messageSize, order int, profile amneziaWGSnapshot) {
	if header == nil {
		return
	}
	if profile.randomTrailers {
		c.fixedWithTrailers = append(c.fixedWithTrailers, amneziaWGReceiveTrailerCandidate{
			header:     header,
			msgType:    msgType,
			padding:    padding,
			coreLength: messageSize,
			order:      order,
			amnezia:    profile,
		})
	}
	size := padding + messageSize
	byPadding := c.fixedBySize[size]
	if byPadding == nil {
		byPadding = make(map[int]*amneziaWGReceiveHeaderIndex)
		c.fixedBySize[size] = byPadding
	}
	index := byPadding[padding]
	if index == nil {
		index = new(amneziaWGReceiveHeaderIndex)
		byPadding[padding] = index
	}
	index.add(header, amneziaWGReceiveCandidate{
		msgType:    msgType,
		padding:    padding,
		coreLength: messageSize,
		order:      order,
		amnezia:    profile,
	})
}

func (c *amneziaWGReceiveClassifier) addTransportCandidate(header *magicHeader, padding, order int, profile amneziaWGSnapshot) {
	if header == nil || padding < 0 || padding > maxAmneziaWGTransportPaddingSize {
		return
	}
	c.transportByPadding[padding].add(header, amneziaWGReceiveCandidate{
		msgType:    MessageTransportType,
		padding:    padding,
		coreLength: MessageTransportHeaderSize,
		order:      order,
		amnezia:    profile,
	})
	if padding > 0 && !profile.hasHeaderProtection {
		// AmneziaWG S4 padding is not applied to keepalive transport packets.
		// Index offset 0 too so receive can accept these unpadded v2 packets.
		// AWG 3.1 header protection uses the S4 prefix as the ChaCha20 nonce,
		// so protected keepalives must keep the configured S4 padding.
		c.transportByPadding[0].add(header, amneziaWGReceiveCandidate{
			msgType:    MessageTransportType,
			padding:    0,
			coreLength: MessageTransportHeaderSize,
			order:      order,
			amnezia:    profile,
		})
	}
}

func (c *amneziaWGReceiveClassifier) finalize() {
	for _, byPadding := range c.fixedBySize {
		for _, index := range byPadding {
			index.finalize()
		}
	}
	for i := range c.transportByPadding {
		c.transportByPadding[i].finalize()
	}
}

func (index *amneziaWGReceiveHeaderIndex) add(header *magicHeader, candidate amneziaWGReceiveCandidate) {
	if header.start == header.end {
		if index.exact == nil {
			index.exact = make(map[uint32][]amneziaWGReceiveCandidate)
		}
		index.exact[header.start] = append(index.exact[header.start], candidate)
		return
	}
	index.ranges = append(index.ranges, amneziaWGReceiveRangeCandidate{
		start:     header.start,
		end:       header.end,
		candidate: candidate,
	})
}

func (index *amneziaWGReceiveHeaderIndex) finalize() {
	sort.Slice(index.ranges, func(i, j int) bool {
		if index.ranges[i].start == index.ranges[j].start {
			return index.ranges[i].end < index.ranges[j].end
		}
		return index.ranges[i].start < index.ranges[j].start
	})
	var maxEnd uint32
	for i := range index.ranges {
		if i == 0 || index.ranges[i].end > maxEnd {
			maxEnd = index.ranges[i].end
		}
		index.ranges[i].maxEnd = maxEnd
	}
}

func (index *amneziaWGReceiveHeaderIndex) empty() bool {
	return len(index.exact) == 0 && len(index.ranges) == 0
}

func (index *amneziaWGReceiveHeaderIndex) lookupAllForProfile(header uint32, expectedType uint32, profile amneziaWGSnapshot) []amneziaWGReceiveCandidate {
	var matches []amneziaWGReceiveCandidate
	for _, candidate := range index.exact[header] {
		if candidate.matches(expectedType) && amneziaWGReceiveProfileEqual(candidate.amnezia, profile) {
			matches = append(matches, candidate)
		}
	}

	limit := sort.Search(len(index.ranges), func(i int) bool {
		return index.ranges[i].start > header
	})
	for i := limit - 1; i >= 0; i-- {
		rangeCandidate := index.ranges[i]
		if rangeCandidate.maxEnd < header {
			break
		}
		candidate := rangeCandidate.candidate
		if rangeCandidate.end < header || !candidate.matches(expectedType) || !amneziaWGReceiveProfileEqual(candidate.amnezia, profile) {
			continue
		}
		matches = append(matches, candidate)
	}
	sort.SliceStable(matches, func(i, j int) bool {
		return matches[i].order < matches[j].order
	})
	return matches
}

func (index *amneziaWGReceiveHeaderIndex) profiles() []amneziaWGSnapshot {
	seen := make([]amneziaWGSnapshot, 0, len(index.exact)+len(index.ranges))
	for _, candidates := range index.exact {
		for _, candidate := range candidates {
			if !amneziaWGReceiveProfilesContain(seen, candidate.amnezia) {
				seen = append(seen, candidate.amnezia)
			}
		}
	}
	for _, rangeCandidate := range index.ranges {
		if !amneziaWGReceiveProfilesContain(seen, rangeCandidate.candidate.amnezia) {
			seen = append(seen, rangeCandidate.candidate.amnezia)
		}
	}
	return seen
}

func (candidate amneziaWGReceiveCandidate) matches(expectedType uint32) bool {
	return expectedType == MessageUnknownType || expectedType == candidate.msgType
}

func amneziaWGReceiveProfilesContain(profiles []amneziaWGSnapshot, candidate amneziaWGSnapshot) bool {
	for _, profile := range profiles {
		if amneziaWGReceiveProfileEqual(profile, candidate) {
			return true
		}
	}
	return false
}

func amneziaWGReceiveProfileEqual(a, b amneziaWGSnapshot) bool {
	return magicHeaderEqual(a.headers.init, b.headers.init) &&
		magicHeaderEqual(a.headers.response, b.headers.response) &&
		magicHeaderEqual(a.headers.cookie, b.headers.cookie) &&
		magicHeaderEqual(a.headers.transport, b.headers.transport) &&
		a.paddings == b.paddings &&
		a.headerProtectionKey == b.headerProtectionKey &&
		a.hasHeaderProtection == b.hasHeaderProtection &&
		a.randomTrailers == b.randomTrailers &&
		a.disableCookies == b.disableCookies
}

func magicHeaderEqual(a, b *magicHeader) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.start == b.start && a.end == b.end
}

type amneziaWGReceiveSignature struct {
	name    string
	minSize int
	maxSize int
	padding int
	header  *magicHeader
}

// validateAmneziaWGReceiveProfiles rejects active profile sets where one
// datagram shape can select a receive candidate with a different strip offset
// or message type. Identical per-message receive handling is allowed because it
// cannot change MAC or decrypt input.
func validateAmneziaWGReceiveProfiles(profiles []amneziaWGSnapshot) error {
	unique := make([]amneziaWGSnapshot, 0, len(profiles))
	for _, profile := range profiles {
		if amneziaWGReceiveProfilesContain(unique, profile) {
			continue
		}
		unique = append(unique, profile)
	}
	for i := 0; i < len(unique); i++ {
		for j := i + 1; j < len(unique); j++ {
			if err := validateAmneziaWGReceiveProfilePair(unique[i], unique[j]); err != nil {
				return fmt.Errorf("amneziawg receive profile ambiguity: %w", err)
			}
		}
	}
	return nil
}

// validateAmneziaWGReceiveProfilePair checks ambiguity after each profile has
// already passed single-profile header validation.
func validateAmneziaWGReceiveProfilePair(a, b amneziaWGSnapshot) error {
	if amneziaWGReceiveWireProfileEqual(a, b) && a.disableCookies != b.disableCookies {
		return fmt.Errorf("indistinguishable profiles disagree on disable cookies")
	}
	for _, left := range amneziaWGReceiveSignatures(a) {
		for _, right := range amneziaWGReceiveSignatures(b) {
			if left.isTransport() && right.isTransport() &&
				a.paddings.transport == b.paddings.transport &&
				magicHeaderEqual(a.headers.transport, b.headers.transport) {
				continue
			}
			if !amneziaWGReceiveSizesOverlap(left, right) {
				continue
			}
			if left.hasVariableSize() || right.hasVariableSize() {
				if left.padding != right.padding && magicHeadersOverlap(left.header, right.header) {
					return fmt.Errorf("%s packet overlaps %s packet length with different padding", left.name, right.name)
				}
				if left.name != right.name && magicHeadersOverlap(left.header, right.header) {
					return fmt.Errorf("%s packet overlaps %s packet at padding %d", left.name, right.name, left.padding)
				}
				continue
			}
			if left.padding != right.padding {
				return fmt.Errorf("%s packet overlaps %s packet length with different padding", left.name, right.name)
			}
			if left.name != right.name && magicHeadersOverlap(left.header, right.header) {
				return fmt.Errorf("%s packet overlaps %s packet at padding %d", left.name, right.name, left.padding)
			}
		}
	}
	return nil
}

func amneziaWGReceiveWireProfileEqual(a, b amneziaWGSnapshot) bool {
	return magicHeaderEqual(a.headers.init, b.headers.init) &&
		magicHeaderEqual(a.headers.response, b.headers.response) &&
		magicHeaderEqual(a.headers.cookie, b.headers.cookie) &&
		magicHeaderEqual(a.headers.transport, b.headers.transport) &&
		a.paddings == b.paddings &&
		a.headerProtectionKey == b.headerProtectionKey &&
		a.hasHeaderProtection == b.hasHeaderProtection &&
		a.randomTrailers == b.randomTrailers
}

func (sig amneziaWGReceiveSignature) isTransport() bool {
	return sig.name == "transport" || sig.name == "transport keepalive"
}

func (sig amneziaWGReceiveSignature) hasVariableSize() bool {
	return sig.minSize != sig.maxSize
}

func amneziaWGReceiveSizesOverlap(a, b amneziaWGReceiveSignature) bool {
	return a.minSize <= b.maxSize && b.minSize <= a.maxSize
}

func amneziaWGReceiveSignatures(profile amneziaWGSnapshot) []amneziaWGReceiveSignature {
	signatures := []amneziaWGReceiveSignature{
		amneziaWGFixedReceiveSignature("init", profile.paddings.init, MessageInitiationSize, profile.headers.init, profile.randomTrailers),
		amneziaWGFixedReceiveSignature("response", profile.paddings.response, MessageResponseSize, profile.headers.response, profile.randomTrailers),
		amneziaWGFixedReceiveSignature("cookie", profile.paddings.cookie, MessageCookieReplySize, profile.headers.cookie, profile.randomTrailers),
		{
			name:    "transport",
			minSize: profile.paddings.transport + MessageTransportHeaderSize,
			maxSize: MaxMessageSize,
			padding: profile.paddings.transport,
			header:  profile.headers.transport,
		},
	}
	if profile.paddings.transport > 0 && !profile.hasHeaderProtection {
		signatures = append(signatures, amneziaWGReceiveSignature{
			name:    "transport keepalive",
			minSize: MessageTransportHeaderSize,
			maxSize: MaxMessageSize,
			padding: 0,
			header:  profile.headers.transport,
		})
	}
	return signatures
}

func amneziaWGFixedReceiveSignature(name string, padding, messageSize int, header *magicHeader, randomTrailers bool) amneziaWGReceiveSignature {
	size := padding + messageSize
	sig := amneziaWGReceiveSignature{
		name:    name,
		minSize: size,
		maxSize: size,
		padding: padding,
		header:  header,
	}
	if randomTrailers {
		sig.maxSize = MaxMessageSize
	}
	return sig
}

func magicHeadersOverlap(a, b *magicHeader) bool {
	if a == nil || b == nil {
		return false
	}
	return a.start <= b.end && b.start <= a.end
}

func amneziaWGMaskHeaderProtection(key AmneziaWGHeaderProtectionKey, nonce, data []byte) {
	cipher, err := chacha20.NewUnauthenticatedCipher(key[:], nonce)
	if err != nil {
		return
	}
	cipher.XORKeyStream(data, data)
}

func amneziaWGProtectInPlace(amnezia amneziaWGSnapshot, packet []byte, padding, coreLength int) {
	if !amnezia.hasHeaderProtection || padding < chacha20.NonceSize || len(packet) < padding+coreLength {
		return
	}
	amneziaWGMaskHeaderProtection(amnezia.headerProtectionKey, packet[:chacha20.NonceSize], packet[padding:padding+coreLength])
}

func amneziaWGAppendRandomTrailer(amnezia amneziaWGSnapshot, packet []byte) []byte {
	if !amnezia.randomTrailers || len(packet) >= MaxMessageSize {
		return packet
	}
	maxTrailer := MaxMessageSize - len(packet)
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(maxTrailer+1)))
	if err != nil {
		return packet
	}
	n := int(nBig.Int64())
	if n == 0 {
		return packet
	}
	trailer := make([]byte, n)
	_, _ = rand.Read(trailer)
	return append(packet, trailer...)
}

func amneziaWGProtectedHeader(amnezia amneziaWGSnapshot, packet []byte, padding int) (uint32, bool) {
	if !amnezia.hasHeaderProtection {
		if len(packet) < padding+4 {
			return 0, false
		}
		return binary.LittleEndian.Uint32(packet[padding:]), true
	}
	if padding < chacha20.NonceSize || len(packet) < padding+4 {
		return 0, false
	}
	var header [4]byte
	copy(header[:], packet[padding:padding+4])
	amneziaWGMaskHeaderProtection(amnezia.headerProtectionKey, packet[:chacha20.NonceSize], header[:])
	return binary.LittleEndian.Uint32(header[:]), true
}
