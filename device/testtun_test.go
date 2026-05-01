/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Modifications Copyright (C) 2026 AsciiMoth
 */

package device

import (
	"encoding/binary"
	"io"
	"net/netip"
	"os"
	"sync"

	gtun "github.com/asciimoth/gonnect/tun"
)

func pingPacket(dst, src netip.Addr) []byte {
	localPort := uint16(1337)
	seq := uint16(0)

	payload := make([]byte, 4)
	binary.BigEndian.PutUint16(payload[0:], localPort)
	binary.BigEndian.PutUint16(payload[2:], seq)

	return genICMPv4(payload, dst, src)
}

// Checksum is the "internet checksum" from https://tools.ietf.org/html/rfc1071.
func checksum(buf []byte, initial uint16) uint16 {
	v := uint32(initial)
	for i := 0; i < len(buf)-1; i += 2 {
		v += uint32(binary.BigEndian.Uint16(buf[i:]))
	}
	if len(buf)%2 == 1 {
		v += uint32(buf[len(buf)-1]) << 8
	}
	for v > 0xffff {
		v = (v >> 16) + (v & 0xffff)
	}
	return ^uint16(v)
}

func genICMPv4(payload []byte, dst, src netip.Addr) []byte {
	const (
		icmpv4ProtocolNumber = 1
		icmpv4Echo           = 8
		icmpv4ChecksumOffset = 2
		icmpv4Size           = 8
		ipv4Size             = 20
		ipv4TotalLenOffset   = 2
		ipv4ChecksumOffset   = 10
		ttl                  = 65
		headerSize           = ipv4Size + icmpv4Size
	)

	pkt := make([]byte, headerSize+len(payload))

	ip := pkt[0:ipv4Size]
	icmpv4 := pkt[ipv4Size : ipv4Size+icmpv4Size]

	icmpv4[0] = icmpv4Echo
	icmpv4[1] = 0
	chksum := ^checksum(icmpv4, checksum(payload, 0))
	binary.BigEndian.PutUint16(icmpv4[icmpv4ChecksumOffset:], chksum)

	length := uint16(len(pkt))
	ip[0] = (4 << 4) | (ipv4Size / 4)
	binary.BigEndian.PutUint16(ip[ipv4TotalLenOffset:], length)
	ip[8] = ttl
	ip[9] = icmpv4ProtocolNumber
	copy(ip[12:], src.AsSlice())
	copy(ip[16:], dst.AsSlice())
	chksum = ^checksum(ip[:], 0)
	binary.BigEndian.PutUint16(ip[ipv4ChecksumOffset:], chksum)

	copy(pkt[headerSize:], payload)
	return pkt
}

type channelTUN struct {
	Inbound  chan []byte
	Outbound chan []byte

	closed chan struct{}
	events chan gtun.Event
	tun    chTun

	mu sync.Mutex

	closeOnce sync.Once

	mwo int
	mro int
	mtu int

	lastReadOffset  int
	lastWriteOffset int
	lastWrite       []byte
}

func newChannelTUN() *channelTUN {
	return newChannelTUNWithConfig(0, 0, DefaultMTU)
}

func newChannelTUNWithOffsets(mwo, mro int) *channelTUN {
	return newChannelTUNWithConfig(mwo, mro, DefaultMTU)
}

func newChannelTUNWithMTU(mtu int) *channelTUN {
	return newChannelTUNWithConfig(0, 0, mtu)
}

func newChannelTUNWithConfig(mwo, mro, mtu int) *channelTUN {
	c := &channelTUN{
		Inbound:  make(chan []byte),
		Outbound: make(chan []byte),
		closed:   make(chan struct{}),
		events:   make(chan gtun.Event, 1),
		mwo:      mwo,
		mro:      mro,
		mtu:      mtu,
	}
	c.tun.c = c
	c.events <- gtun.EventUp
	return c
}

func (c *channelTUN) TUN() gtun.Tun {
	return &c.tun
}

type chTun struct {
	c *channelTUN
}

func (t *chTun) File() *os.File { return nil }

func (t *chTun) Read(packets [][]byte, sizes []int, offset int) (int, error) {
	t.c.mu.Lock()
	t.c.lastReadOffset = offset
	t.c.mu.Unlock()
	select {
	case <-t.c.closed:
		return 0, os.ErrClosed
	case msg := <-t.c.Outbound:
		n := copy(packets[0][offset:], msg)
		sizes[0] = n
		return 1, nil
	}
}

func (t *chTun) Write(packets [][]byte, offset int) (int, error) {
	if offset == -1 {
		t.c.closeOnce.Do(func() {
			close(t.c.closed)
			close(t.c.events)
		})
		return 0, io.EOF
	}
	for i, data := range packets {
		t.c.mu.Lock()
		t.c.lastWriteOffset = offset
		t.c.lastWrite = append(t.c.lastWrite[:0], data...)
		t.c.mu.Unlock()
		msg := make([]byte, len(data)-offset)
		copy(msg, data[offset:])
		select {
		case <-t.c.closed:
			return i, os.ErrClosed
		case t.c.Inbound <- msg:
		}
	}
	return len(packets), nil
}

func (t *chTun) BatchSize() int            { return 1 }
func (t *chTun) MWO() int                  { return t.c.mwo }
func (t *chTun) MRO() int                  { return t.c.mro }
func (t *chTun) MTU() (int, error)         { return t.c.mtu, nil }
func (t *chTun) Name() (string, error)     { return "loopbackTun1", nil }
func (t *chTun) Events() <-chan gtun.Event { return t.c.events }
func (t *chTun) Close() error {
	t.Write(nil, -1)
	return nil
}

func (c *channelTUN) lastReadCallOffset() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastReadOffset
}

func (c *channelTUN) lastWriteCallOffset() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastWriteOffset
}

func (c *channelTUN) lastWritePacket() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]byte, len(c.lastWrite))
	copy(out, c.lastWrite)
	return out
}
