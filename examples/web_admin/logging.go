package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"

	conn "github.com/asciimoth/batchudp"
	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/native"
	gtun "github.com/asciimoth/gonnect/tun"
)

type loggingTUN struct {
	gtun.Tun
	name string
}

func newLoggingTUN(name string, tun gtun.Tun) gtun.Tun {
	return &loggingTUN{Tun: tun, name: name}
}

func (t *loggingTUN) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) {
	n, err = t.Tun.Read(bufs, sizes, offset)
	if n > 0 {
		for i := 0; i < n; i++ {
			log.Printf("[web_admin tun %s] read packet[%d] bytes=%d %s", t.name, i, sizes[i], describeIPPacket(bufs[i], sizes[i], offset))
		}
	}
	if err != nil {
		log.Printf("[web_admin tun %s] read error: %v", t.name, err)
	}
	return n, err
}

func (t *loggingTUN) Write(bufs [][]byte, offset int) (n int, err error) {
	n, err = t.Tun.Write(bufs, offset)
	if n > 0 {
		for i := 0; i < n; i++ {
			log.Printf("[web_admin tun %s] write packet[%d] bytes=%d %s", t.name, i, len(bufs[i])-offset, describeIPPacket(bufs[i], len(bufs[i])-offset, offset))
		}
	}
	if err != nil {
		log.Printf("[web_admin tun %s] write error: %v", t.name, err)
	}
	return n, err
}

type loggingBind struct {
	name string
	bind conn.Bind
}

func newLoggingBind(name string, bind conn.Bind) *loggingBind {
	return &loggingBind{name: name, bind: bind}
}

func (b *loggingBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actualPort, err := b.bind.Open(port)
	if err != nil {
		log.Printf("[web_admin bind %s] open requested_port=%d error=%v", b.name, port, err)
		return nil, 0, err
	}
	log.Printf("[web_admin bind %s] open requested_port=%d actual_port=%d recv_fns=%d", b.name, port, actualPort, len(fns))

	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		index := i
		wrapped[i] = func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			n, err := fn(bufs, sizes, eps)
			if n > 0 {
				for j := 0; j < n; j++ {
					log.Printf("[web_admin bind %s] recv fn=%d packet[%d] bytes=%d %s", b.name, index, j, sizes[j], describeBindPacket(eps[j], sizes[j], bufs[j][:sizes[j]]))
				}
			}
			if err != nil {
				log.Printf("[web_admin bind %s] recv fn=%d error=%v", b.name, index, err)
			}
			return n, err
		}
	}
	return wrapped, actualPort, nil
}

func (b *loggingBind) Close() error {
	err := b.bind.Close()
	if err != nil {
		log.Printf("[web_admin bind %s] close error: %v", b.name, err)
		return err
	}
	log.Printf("[web_admin bind %s] close", b.name)
	return nil
}

func (b *loggingBind) SetMark(mark uint32) error {
	err := b.bind.SetMark(mark)
	if err != nil {
		log.Printf("[web_admin bind %s] set mark=%d error=%v", b.name, mark, err)
		return err
	}
	log.Printf("[web_admin bind %s] set mark=%d", b.name, mark)
	return nil
}

func (b *loggingBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	err := b.bind.Send(bufs, ep)
	if len(bufs) > 0 {
		for i, buf := range bufs {
			log.Printf("[web_admin bind %s] send packet[%d] bytes=%d %s err=%v", b.name, i, len(buf), describeBindPacket(ep, len(buf), buf), err)
		}
	} else {
		log.Printf("[web_admin bind %s] send empty-batch err=%v", b.name, err)
	}
	return err
}

func (b *loggingBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ep, err := b.bind.ParseEndpoint(s)
	if err != nil {
		log.Printf("[web_admin bind %s] parse endpoint=%q error=%v", b.name, s, err)
		return nil, err
	}
	log.Printf("[web_admin bind %s] parse endpoint=%q", b.name, s)
	return ep, nil
}

func (b *loggingBind) BatchSize() int {
	return b.bind.BatchSize()
}

type recordingNetwork struct {
	*native.Network

	mu         sync.Mutex
	listenAddr map[string]string
}

func newRecordingNetwork() *recordingNetwork {
	return &recordingNetwork{
		Network:    (&native.Config{}).Build(),
		listenAddr: make(map[string]string),
	}
}

func (n *recordingNetwork) ListenUDP(ctx context.Context, network, laddr string) (gonnect.UDPConn, error) {
	conn, err := n.Network.ListenUDP(ctx, network, laddr)
	n.record(network, conn, err)
	return conn, err
}

func (n *recordingNetwork) ListenUDPConfig(ctx context.Context, lc *gonnect.ListenConfig, network, laddr string) (gonnect.UDPConn, error) {
	conn, err := n.Network.ListenUDPConfig(ctx, lc, network, laddr)
	n.record(network, conn, err)
	return conn, err
}

func (n *recordingNetwork) ListenAddrs() []string {
	n.mu.Lock()
	defer n.mu.Unlock()

	keys := make([]string, 0, len(n.listenAddr))
	for key := range n.listenAddr {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	addrs := make([]string, 0, len(keys))
	for _, key := range keys {
		addrs = append(addrs, fmt.Sprintf("%s=%s", key, n.listenAddr[key]))
	}
	return addrs
}

func (n *recordingNetwork) record(network string, conn gonnect.UDPConn, err error) {
	if err != nil || conn == nil || conn.LocalAddr() == nil {
		return
	}
	addr := conn.LocalAddr().String()
	n.mu.Lock()
	n.listenAddr[network] = addr
	n.mu.Unlock()
	log.Printf("[web_admin bind network] listen %s %s", network, addr)
}

func describeIPPacket(buf []byte, size, offset int) string {
	packet := packetView(buf, size, offset)
	if len(packet) == 0 {
		return "packet=empty"
	}

	version := packet[0] >> 4
	switch version {
	case 4:
		if len(packet) < 20 {
			return fmt.Sprintf("ip=ipv4 truncated preview=%s", previewHex(packet))
		}
		src := net.IP(packet[12:16]).String()
		dst := net.IP(packet[16:20]).String()
		return fmt.Sprintf("ip=ipv4 proto=%d src=%s dst=%s preview=%s", packet[9], src, dst, previewHex(packet))
	case 6:
		if len(packet) < 40 {
			return fmt.Sprintf("ip=ipv6 truncated preview=%s", previewHex(packet))
		}
		src := net.IP(packet[8:24]).String()
		dst := net.IP(packet[24:40]).String()
		return fmt.Sprintf("ip=ipv6 next_header=%d src=%s dst=%s preview=%s", packet[6], src, dst, previewHex(packet))
	default:
		return fmt.Sprintf("ip=unknown version=%d preview=%s", version, previewHex(packet))
	}
}

func describeBindPacket(ep conn.Endpoint, size int, buf []byte) string {
	parts := []string{fmt.Sprintf("udp_size=%d", size)}
	if ep != nil {
		if src := strings.TrimSpace(ep.SrcToString()); src != "" {
			parts = append(parts, "local="+src)
		}
		if dst := strings.TrimSpace(ep.DstToString()); dst != "" {
			parts = append(parts, "remote="+dst)
		}
	}
	parts = append(parts, "wg="+describeWireGuardMessage(buf))
	return strings.Join(parts, " ")
}

func describeWireGuardMessage(buf []byte) string {
	if len(buf) == 0 {
		return "empty"
	}
	var typ string
	switch buf[0] {
	case 1:
		typ = "handshake-initiation"
	case 2:
		typ = "handshake-response"
	case 3:
		typ = "cookie-reply"
	case 4:
		typ = "transport-data"
	default:
		typ = fmt.Sprintf("unknown(%d)", buf[0])
	}
	return fmt.Sprintf("%s preview=%s", typ, previewHex(buf))
}

func packetView(buf []byte, size, offset int) []byte {
	if offset < 0 || offset > len(buf) {
		return nil
	}
	end := offset + size
	if end < offset {
		return nil
	}
	if end > len(buf) {
		end = len(buf)
	}
	return buf[offset:end]
}

func previewHex(buf []byte) string {
	const max = 16
	if len(buf) == 0 {
		return ""
	}
	if len(buf) > max {
		return hex.EncodeToString(buf[:max]) + "..."
	}
	return hex.EncodeToString(buf)
}
