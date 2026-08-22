/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 AsciiMoth
 */

package device

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"
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
)

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
	high := int64(r.End - r.Start + 1)
	n, _ := rand.Int(rand.Reader, big.NewInt(high))
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

func (s *ipcSetAmneziaWG) hasValues() bool {
	if s.junkCount != nil || s.junkMin != nil || s.junkMax != nil ||
		s.initHeader != nil || s.responseHeader != nil || s.cookieHeader != nil || s.transportHeader != nil ||
		s.initPadding != nil || s.responsePadding != nil || s.cookiePadding != nil || s.transportPadding != nil {
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
}

func (s *ipcSetAmneziaWG) mergeIntoOverride(dst *ipcSetAmneziaWG) {
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
}

func (s *ipcSetAmneziaWG) mergeWithDevice(device *Device) error {
	cfg := device.amneziaWGConfigLocked()
	s.merge(&cfg)
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

type amneziaWGReceiveClassifier struct {
	profiles []amneziaWGSnapshot

	// Fixed-size handshake packets are keyed by datagram size first, then by
	// header offset. This avoids checking profiles that cannot match the size.
	fixedBySize map[int]map[int]*amneziaWGReceiveHeaderIndex

	// Transport packets have variable content size, so they are keyed by the
	// only bounded receive-side value: the padding/header offset.
	transportByPadding [maxAmneziaWGTransportPaddingSize + 1]amneziaWGReceiveHeaderIndex
}

// amneziaWGReceiveCandidate is a complete classification result for one
// message header at one padding offset.
type amneziaWGReceiveCandidate struct {
	msgType uint32
	padding int
	order   int
	amnezia amneziaWGSnapshot
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
		msgType: msgType,
		padding: padding,
		order:   order,
		amnezia: profile,
	})
}

func (c *amneziaWGReceiveClassifier) addTransportCandidate(header *magicHeader, padding, order int, profile amneziaWGSnapshot) {
	if header == nil || padding < 0 || padding > maxAmneziaWGTransportPaddingSize {
		return
	}
	c.transportByPadding[padding].add(header, amneziaWGReceiveCandidate{
		msgType: MessageTransportType,
		padding: padding,
		order:   order,
		amnezia: profile,
	})
	if padding > 0 {
		// AmneziaWG S4 padding is not applied to keepalive transport packets.
		// Index offset 0 too so receive can accept these unpadded packets.
		c.transportByPadding[0].add(header, amneziaWGReceiveCandidate{
			msgType: MessageTransportType,
			padding: 0,
			order:   order,
			amnezia: profile,
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

func (index *amneziaWGReceiveHeaderIndex) lookup(header uint32, expectedType uint32) (amneziaWGReceiveCandidate, bool) {
	var best amneziaWGReceiveCandidate
	found := false
	for _, candidate := range index.exact[header] {
		if candidate.matches(expectedType) && (!found || candidate.order < best.order) {
			best = candidate
			found = true
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
		if rangeCandidate.end < header || !rangeCandidate.candidate.matches(expectedType) {
			continue
		}
		if !found || rangeCandidate.candidate.order < best.order {
			best = rangeCandidate.candidate
			found = true
		}
	}
	return best, found
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
		a.paddings == b.paddings
}

func magicHeaderEqual(a, b *magicHeader) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.start == b.start && a.end == b.end
}

type amneziaWGReceiveSignature struct {
	name    string
	size    int
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
	for _, left := range amneziaWGReceiveSignatures(a) {
		for _, right := range amneziaWGReceiveSignatures(b) {
			if left.isTransport() && right.isTransport() &&
				a.paddings.transport == b.paddings.transport &&
				magicHeaderEqual(a.headers.transport, b.headers.transport) {
				continue
			}
			if left.size != right.size {
				continue
			}
			if left.size == -1 {
				if left.padding != right.padding && magicHeadersOverlap(left.header, right.header) {
					return fmt.Errorf("%s packet overlaps %s packet", left.name, right.name)
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

func (sig amneziaWGReceiveSignature) isTransport() bool {
	return sig.name == "transport" || sig.name == "transport keepalive"
}

func amneziaWGReceiveSignatures(profile amneziaWGSnapshot) []amneziaWGReceiveSignature {
	signatures := []amneziaWGReceiveSignature{
		{name: "init", size: profile.paddings.init + MessageInitiationSize, padding: profile.paddings.init, header: profile.headers.init},
		{name: "response", size: profile.paddings.response + MessageResponseSize, padding: profile.paddings.response, header: profile.headers.response},
		{name: "cookie", size: profile.paddings.cookie + MessageCookieReplySize, padding: profile.paddings.cookie, header: profile.headers.cookie},
		{name: "transport", size: -1, padding: profile.paddings.transport, header: profile.headers.transport},
	}
	if profile.paddings.transport > 0 {
		signatures = append(signatures, amneziaWGReceiveSignature{
			name:    "transport keepalive",
			size:    -1,
			padding: 0,
			header:  profile.headers.transport,
		})
	}
	return signatures
}

func magicHeadersOverlap(a, b *magicHeader) bool {
	if a == nil || b == nil {
		return false
	}
	return a.start <= b.end && b.start <= a.end
}
