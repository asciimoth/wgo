/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net/netip"
	"os"
	"runtime"
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	conn "github.com/asciimoth/batchudp"
	"github.com/asciimoth/batchudp/bindtest"
	"github.com/asciimoth/gonnect-netstack/vtun"
	"github.com/asciimoth/gonnect/native"
	gtun "github.com/asciimoth/gonnect/tun"
)

// uapiCfg returns a string that contains cfg formatted use with IpcSet.
// cfg is a series of alternating key/value strings.
// uapiCfg exists because editors and humans like to insert
// whitespace into configs, which can cause failures, some of which are silent.
// For example, a leading blank newline causes the remainder
// of the config to be silently ignored.
func uapiCfg(cfg ...string) string {
	if len(cfg)%2 != 0 {
		panic("odd number of args to uapiReader")
	}
	buf := new(bytes.Buffer)
	for i, s := range cfg {
		buf.WriteString(s)
		sep := byte('\n')
		if i%2 == 0 {
			sep = '='
		}
		buf.WriteByte(sep)
	}
	return buf.String()
}

// genConfigs generates a pair of configs that connect to each other.
// The configs use distinct, probably-usable ports.
func genConfigs(tb testing.TB) (cfgs, endpointCfgs [2]string) {
	var key1, key2 NoisePrivateKey
	_, err := rand.Read(key1[:])
	if err != nil {
		tb.Errorf("unable to generate private key random bytes: %v", err)
	}
	_, err = rand.Read(key2[:])
	if err != nil {
		tb.Errorf("unable to generate private key random bytes: %v", err)
	}
	pub1, pub2 := key1.publicKey(), key2.publicKey()

	cfgs[0] = uapiCfg(
		"private_key", hex.EncodeToString(key1[:]),
		"listen_port", "0",
		"replace_peers", "true",
		"public_key", hex.EncodeToString(pub2[:]),
		"protocol_version", "1",
		"replace_allowed_ips", "true",
		"allowed_ip", "1.0.0.2/32",
	)
	endpointCfgs[0] = uapiCfg(
		"public_key", hex.EncodeToString(pub2[:]),
		"endpoint", "127.0.0.1:%d",
	)
	cfgs[1] = uapiCfg(
		"private_key", hex.EncodeToString(key2[:]),
		"listen_port", "0",
		"replace_peers", "true",
		"public_key", hex.EncodeToString(pub1[:]),
		"protocol_version", "1",
		"replace_allowed_ips", "true",
		"allowed_ip", "1.0.0.1/32",
	)
	endpointCfgs[1] = uapiCfg(
		"public_key", hex.EncodeToString(pub1[:]),
		"endpoint", "127.0.0.1:%d",
	)
	return
}

// A testPair is a pair of testPeers.
type testPair [2]testPeer

// A testPeer is a peer used for testing.
type testPeer struct {
	tun *channelTUN
	dev *Device
	ip  netip.Addr
}

type SendDirection bool

const (
	Ping SendDirection = true
	Pong SendDirection = false
)

func (d SendDirection) String() string {
	if d == Ping {
		return "ping"
	}
	return "pong"
}

func (pair *testPair) Send(tb testing.TB, ping SendDirection, done chan struct{}) {
	tb.Helper()
	p0, p1 := pair[0], pair[1]
	if !ping {
		// pong is the new ping
		p0, p1 = p1, p0
	}
	msg := pingPacket(p0.ip, p1.ip)
	p1.tun.Outbound <- msg
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	var err error
	select {
	case msgRecv := <-p0.tun.Inbound:
		if !bytes.Equal(msg, msgRecv) {
			err = fmt.Errorf("%s did not transit correctly", ping)
		}
	case <-timer.C:
		err = fmt.Errorf("%s did not transit", ping)
	case <-done:
	}
	if err != nil {
		// The error may have occurred because the test is done.
		select {
		case <-done:
			return
		default:
		}
		// Real error.
		tb.Error(err)
	}
}

// genTestPair creates a testPair.
func genTestPair(tb testing.TB, realSocket bool) (pair testPair) {
	cfg, endpointCfg := genConfigs(tb)
	var binds [2]conn.Bind
	if realSocket {
		for i := range binds {
			network := (&native.Config{}).Build()
			tb.Cleanup(func() {
				_ = network.Down()
			})
			binds[i] = conn.NewDefaultBind(network)
		}
	} else {
		binds = bindtest.NewChannelBinds()
	}
	// Bring up a ChannelTun for each config.
	for i := range pair {
		p := &pair[i]
		p.tun = newChannelTUN()
		p.ip = netip.AddrFrom4([4]byte{1, 0, 0, byte(i + 1)})
		level := LogLevelVerbose
		if _, ok := tb.(*testing.B); ok && !testing.Verbose() {
			level = LogLevelError
		}
		p.dev = NewDevice(p.tun.TUN(), binds[i], NewLogger(level, fmt.Sprintf("dev%d: ", i)))
		if err := p.dev.IpcSet(cfg[i]); err != nil {
			tb.Errorf("failed to configure device %d: %v", i, err)
			p.dev.Close()
			continue
		}
		if err := p.dev.Up(); err != nil {
			tb.Errorf("failed to bring up device %d: %v", i, err)
			p.dev.Close()
			continue
		}
		endpointCfg[i^1] = fmt.Sprintf(endpointCfg[i^1], p.dev.net.port)
	}
	for i := range pair {
		p := &pair[i]
		if err := p.dev.IpcSet(endpointCfg[i]); err != nil {
			tb.Errorf("failed to configure device endpoint %d: %v", i, err)
			p.dev.Close()
			continue
		}
		// The device is ready. Close it when the test completes.
		tb.Cleanup(p.dev.Close)
	}
	return
}

func genTestPairWithChannelTUNOffsets(tb testing.TB, mwo, mro int) (pair testPair) {
	tb.Helper()

	tuns := [2]*channelTUN{
		newChannelTUNWithOffsets(mwo, mro),
		newChannelTUNWithOffsets(mwo, mro),
	}
	devs := newDevicePairForTUNs(tb, tuns[0].TUN(), tuns[1].TUN(), [2]netip.Addr{
		netip.AddrFrom4([4]byte{1, 0, 0, 1}),
		netip.AddrFrom4([4]byte{1, 0, 0, 2}),
	})
	for i := range pair {
		pair[i] = testPeer{
			tun: tuns[i],
			dev: devs[i],
			ip:  netip.AddrFrom4([4]byte{1, 0, 0, byte(i + 1)}),
		}
	}
	return pair
}

func newDevicePairForTUNs(tb testing.TB, tun0, tun1 gtun.Tun, ips [2]netip.Addr) [2]*Device {
	tb.Helper()

	key0 := mustPrivateKey(tb, 0)
	key1 := mustPrivateKey(tb, 1)
	pub0 := key0.publicKey()
	pub1 := key1.publicKey()

	cfgs := [2]string{
		uapiCfg(
			"private_key", hex.EncodeToString(key0[:]),
			"listen_port", "0",
			"replace_peers", "true",
			"public_key", hex.EncodeToString(pub1[:]),
			"protocol_version", "1",
			"replace_allowed_ips", "true",
			"allowed_ip", ips[1].String()+"/32",
		),
		uapiCfg(
			"private_key", hex.EncodeToString(key1[:]),
			"listen_port", "0",
			"replace_peers", "true",
			"public_key", hex.EncodeToString(pub0[:]),
			"protocol_version", "1",
			"replace_allowed_ips", "true",
			"allowed_ip", ips[0].String()+"/32",
		),
	}
	endpointCfgs := [2]string{
		uapiCfg("public_key", hex.EncodeToString(pub1[:]), "endpoint", "127.0.0.1:%d"),
		uapiCfg("public_key", hex.EncodeToString(pub0[:]), "endpoint", "127.0.0.1:%d"),
	}

	binds := bindtest.NewChannelBinds()
	devs := [2]*Device{
		NewDevice(tun0, binds[0], NewLogger(LogLevelError, "dev0: ")),
		NewDevice(tun1, binds[1], NewLogger(LogLevelError, "dev1: ")),
	}
	for i := range devs {
		if err := devs[i].IpcSet(cfgs[i]); err != nil {
			tb.Fatalf("failed to configure device %d: %v", i, err)
		}
		if err := devs[i].Up(); err != nil {
			tb.Fatalf("failed to bring up device %d: %v", i, err)
		}
		endpointCfgs[i^1] = fmt.Sprintf(endpointCfgs[i^1], devs[i].net.port)
	}
	for i := range devs {
		if err := devs[i].IpcSet(endpointCfgs[i]); err != nil {
			tb.Fatalf("failed to configure endpoint %d: %v", i, err)
		}
		tb.Cleanup(devs[i].Close)
	}
	return devs
}

func mustPrivateKey(tb testing.TB, seed byte) NoisePrivateKey {
	tb.Helper()
	var key NoisePrivateKey
	for i := range key {
		key[i] = seed + byte(i) + 1
	}
	key.clamp()
	return key
}

func TestTwoDevicePing(t *testing.T) {
	goroutineLeakCheck(t)
	pair := genTestPair(t, true)
	t.Run("ping 1.0.0.1", func(t *testing.T) {
		pair.Send(t, Ping, nil)
	})
	t.Run("ping 1.0.0.2", func(t *testing.T) {
		pair.Send(t, Pong, nil)
	})
}

func TestUpDown(t *testing.T) {
	goroutineLeakCheck(t)
	const itrials = 50
	const otrials = 10

	for n := 0; n < otrials; n++ {
		pair := genTestPair(t, false)
		for i := range pair {
			for k := range pair[i].dev.peers.keyMap {
				pair[i].dev.IpcSet(fmt.Sprintf("public_key=%s\npersistent_keepalive_interval=1\n", hex.EncodeToString(k[:])))
			}
		}
		var wg sync.WaitGroup
		wg.Add(len(pair))
		for i := range pair {
			go func(d *Device) {
				defer wg.Done()
				for i := 0; i < itrials; i++ {
					if err := d.Up(); err != nil {
						t.Errorf("failed up bring up device: %v", err)
					}
					time.Sleep(time.Duration(rand.Intn(int(time.Nanosecond * (0x10000 - 1)))))
					if err := d.Down(); err != nil {
						t.Errorf("failed to bring down device: %v", err)
					}
					time.Sleep(time.Duration(rand.Intn(int(time.Nanosecond * (0x10000 - 1)))))
				}
			}(pair[i].dev)
		}
		wg.Wait()
		for i := range pair {
			pair[i].dev.Up()
			pair[i].dev.Close()
		}
	}
}

// TestConcurrencySafety does other things concurrently with tunnel use.
// It is intended to be used with the race detector to catch data races.
func TestConcurrencySafety(t *testing.T) {
	pair := genTestPair(t, true)
	done := make(chan struct{})

	const warmupIters = 10
	var warmup sync.WaitGroup
	warmup.Add(warmupIters)
	go func() {
		// Send data continuously back and forth until we're done.
		// Note that we may continue to attempt to send data
		// even after done is closed.
		i := warmupIters
		for ping := Ping; ; ping = !ping {
			pair.Send(t, ping, done)
			select {
			case <-done:
				return
			default:
			}
			if i > 0 {
				warmup.Done()
				i--
			}
		}
	}()
	warmup.Wait()

	applyCfg := func(cfg string) {
		err := pair[0].dev.IpcSet(cfg)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Change persistent_keepalive_interval concurrently with tunnel use.
	t.Run("persistentKeepaliveInterval", func(t *testing.T) {
		var pub NoisePublicKey
		for key := range pair[0].dev.peers.keyMap {
			pub = key
			break
		}
		cfg := uapiCfg(
			"public_key", hex.EncodeToString(pub[:]),
			"persistent_keepalive_interval", "1",
		)
		for i := 0; i < 1000; i++ {
			applyCfg(cfg)
		}
	})

	// Change private keys concurrently with tunnel use.
	t.Run("privateKey", func(t *testing.T) {
		bad := uapiCfg("private_key", "7777777777777777777777777777777777777777777777777777777777777777")
		good := uapiCfg("private_key", hex.EncodeToString(pair[0].dev.staticIdentity.privateKey[:]))
		// Set iters to a large number like 1000 to flush out data races quickly.
		// Don't leave it large. That can cause logical races
		// in which the handshake is interleaved with key changes
		// such that the private key appears to be unchanging but
		// other state gets reset, which can cause handshake failures like
		// "Received packet with invalid mac1".
		const iters = 1
		for i := 0; i < iters; i++ {
			applyCfg(bad)
			applyCfg(good)
		}
	})

	// Perform bind updates and keepalive sends concurrently with tunnel use.
	t.Run("bindUpdate and keepalive", func(t *testing.T) {
		const iters = 10
		for i := 0; i < iters; i++ {
			for _, peer := range pair {
				peer.dev.BindUpdate()
				peer.dev.SendKeepalivesToPeersWithCurrentKeypair()
			}
		}
	})

	close(done)
}

func BenchmarkLatency(b *testing.B) {
	pair := genTestPair(b, true)

	// Establish a connection.
	pair.Send(b, Ping, nil)
	pair.Send(b, Pong, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pair.Send(b, Ping, nil)
		pair.Send(b, Pong, nil)
	}
}

func BenchmarkThroughput(b *testing.B) {
	pair := genTestPair(b, true)

	// Establish a connection.
	pair.Send(b, Ping, nil)
	pair.Send(b, Pong, nil)

	// Measure how long it takes to receive b.N packets,
	// starting when we receive the first packet.
	var recv atomic.Uint64
	var elapsed time.Duration
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var start time.Time
		for {
			<-pair[0].tun.Inbound
			new := recv.Add(1)
			if new == 1 {
				start = time.Now()
			}
			// Careful! Don't change this to else if; b.N can be equal to 1.
			if new == uint64(b.N) {
				elapsed = time.Since(start)
				return
			}
		}
	}()

	// Send packets as fast as we can until we've received enough.
	ping := pingPacket(pair[0].ip, pair[1].ip)
	pingc := pair[1].tun.Outbound
	var sent uint64
	for recv.Load() != uint64(b.N) {
		sent++
		pingc <- ping
	}
	wg.Wait()

	b.ReportMetric(float64(elapsed)/float64(b.N), "ns/op")
	b.ReportMetric(1-float64(b.N)/float64(sent), "packet-loss")
}

func BenchmarkUAPIGet(b *testing.B) {
	pair := genTestPair(b, true)
	pair.Send(b, Ping, nil)
	pair.Send(b, Pong, nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pair[0].dev.IpcGetOperation(io.Discard)
	}
}

func goroutineLeakCheck(t *testing.T) {
	goroutines := func() (int, []byte) {
		p := pprof.Lookup("goroutine")
		b := new(bytes.Buffer)
		p.WriteTo(b, 1)
		return p.Count(), b.Bytes()
	}

	startGoroutines, startStacks := goroutines()
	t.Cleanup(func() {
		if t.Failed() {
			return
		}
		// Give goroutines time to exit, if they need it.
		for i := 0; i < 10000; i++ {
			if runtime.NumGoroutine() <= startGoroutines {
				return
			}
			time.Sleep(1 * time.Millisecond)
		}
		endGoroutines, endStacks := goroutines()
		t.Logf("starting stacks:\n%s\n", startStacks)
		t.Logf("ending stacks:\n%s\n", endStacks)
		t.Fatalf("expected %d goroutines, got %d, leak?", startGoroutines, endGoroutines)
	})
}

type fakeBindSized struct {
	size int
}

func (b *fakeBindSized) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	return nil, 0, nil
}
func (b *fakeBindSized) Close() error                                  { return nil }
func (b *fakeBindSized) SetMark(mark uint32) error                     { return nil }
func (b *fakeBindSized) Send(bufs [][]byte, ep conn.Endpoint) error    { return nil }
func (b *fakeBindSized) ParseEndpoint(s string) (conn.Endpoint, error) { return nil, nil }
func (b *fakeBindSized) BatchSize() int                                { return b.size }

type fakeTUNDeviceSized struct {
	size int
	mwo  int
	mro  int

	events chan gtun.Event
	closed chan struct{}

	closeOnce sync.Once
}

func (t *fakeTUNDeviceSized) ensureInit() {
	if t.closed == nil {
		t.closed = make(chan struct{})
	}
	if t.events == nil {
		t.events = make(chan gtun.Event)
	}
}

func (t *fakeTUNDeviceSized) File() *os.File { return nil }
func (t *fakeTUNDeviceSized) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) {
	t.ensureInit()
	<-t.closed
	return 0, os.ErrClosed
}
func (t *fakeTUNDeviceSized) Write(bufs [][]byte, offset int) (int, error) { return 0, nil }
func (t *fakeTUNDeviceSized) MWO() int                                     { return t.mwo }
func (t *fakeTUNDeviceSized) MRO() int                                     { return t.mro }
func (t *fakeTUNDeviceSized) MTU() (int, error)                            { return 0, nil }
func (t *fakeTUNDeviceSized) Name() (string, error)                        { return "", nil }
func (t *fakeTUNDeviceSized) Events() <-chan gtun.Event {
	t.ensureInit()
	return t.events
}
func (t *fakeTUNDeviceSized) Close() error {
	t.ensureInit()
	t.closeOnce.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}
func (t *fakeTUNDeviceSized) BatchSize() int { return t.size }

func TestBatchSize(t *testing.T) {
	d := Device{}

	d.net.bind = &fakeBindSized{1}
	d.tun.device = &fakeTUNDeviceSized{size: 1}
	if want, got := 1, d.BatchSize(); got != want {
		t.Errorf("expected batch size %d, got %d", want, got)
	}

	d.net.bind = &fakeBindSized{1}
	d.tun.device = &fakeTUNDeviceSized{size: 128}
	if want, got := 128, d.BatchSize(); got != want {
		t.Errorf("expected batch size %d, got %d", want, got)
	}

	d.net.bind = &fakeBindSized{128}
	d.tun.device = &fakeTUNDeviceSized{size: 1}
	if want, got := 128, d.BatchSize(); got != want {
		t.Errorf("expected batch size %d, got %d", want, got)
	}

	d.net.bind = &fakeBindSized{128}
	d.tun.device = &fakeTUNDeviceSized{size: 128}
	if want, got := 128, d.BatchSize(); got != want {
		t.Errorf("expected batch size %d, got %d", want, got)
	}
}

func TestNewDeviceTunOffsetStrategy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		mwo             int
		mro             int
		wantReadOffset  int
		wantWriteOffset int
		wantReadCopy    bool
		wantWriteCopy   bool
		wantPanic       bool
	}{
		{name: "zero offsets", mwo: 0, mro: 0, wantReadOffset: 16, wantWriteOffset: 16},
		{name: "exact transport offsets", mwo: 16, mro: 16, wantReadOffset: 16, wantWriteOffset: 16},
		{name: "smaller offsets", mwo: 4, mro: 8, wantReadOffset: 16, wantWriteOffset: 16},
		{name: "read copy", mwo: 16, mro: 32, wantReadOffset: 32, wantWriteOffset: 16, wantReadCopy: true},
		{name: "write copy", mwo: 32, mro: 16, wantReadOffset: 16, wantWriteOffset: 32, wantWriteCopy: true},
		{name: "both copy", mwo: 48, mro: 32, wantReadOffset: 32, wantWriteOffset: 48, wantReadCopy: true, wantWriteCopy: true},
		{name: "negative write offset", mwo: -1, wantPanic: true},
		{name: "negative read offset", mro: -1, wantPanic: true},
		{name: "write offset exceeds buffer headroom", mwo: MessageBufferSize - MaxContentSize + 1, wantPanic: true},
		{name: "read offset exceeds buffer headroom", mro: MessageBufferSize - MaxContentSize + 1, wantPanic: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tunDev := &fakeTUNDeviceSized{size: 1, mwo: tt.mwo, mro: tt.mro}
			tunDev.ensureInit()
			if tt.wantPanic {
				defer func() {
					if recover() == nil {
						t.Fatal("expected panic")
					}
				}()
				NewDevice(tunDev, &fakeBindSized{1}, NewLogger(LogLevelError, ""))
				return
			}

			dev := NewDevice(tunDev, &fakeBindSized{1}, NewLogger(LogLevelError, ""))
			t.Cleanup(dev.Close)

			if got := dev.tun.readOffset; got != tt.wantReadOffset {
				t.Fatalf("readOffset = %d, want %d", got, tt.wantReadOffset)
			}
			if got := dev.tun.writeOffset; got != tt.wantWriteOffset {
				t.Fatalf("writeOffset = %d, want %d", got, tt.wantWriteOffset)
			}
			if got := dev.tun.readNeedsCopy; got != tt.wantReadCopy {
				t.Fatalf("readNeedsCopy = %v, want %v", got, tt.wantReadCopy)
			}
			if got := dev.tun.writeNeedsCopy; got != tt.wantWriteCopy {
				t.Fatalf("writeNeedsCopy = %v, want %v", got, tt.wantWriteCopy)
			}
		})
	}
}

func TestTwoDevicePingWithChannelTunOffsets(t *testing.T) {
	goroutineLeakCheck(t)

	tests := []struct {
		name      string
		mwo, mro  int
		wantRead  int
		wantWrite int
	}{
		{name: "compatible zero copy", mwo: 0, mro: 0, wantRead: 16, wantWrite: 16},
		{name: "read copy required", mwo: 0, mro: 32, wantRead: 32, wantWrite: 16},
		{name: "write copy required", mwo: 32, mro: 0, wantRead: 16, wantWrite: 32},
		{name: "both copy required", mwo: 48, mro: 32, wantRead: 32, wantWrite: 48},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pair := genTestPairWithChannelTUNOffsets(t, tt.mwo, tt.mro)
			pair.Send(t, Ping, nil)
			pair.Send(t, Pong, nil)

			for _, p := range pair {
				if got := p.tun.lastReadCallOffset(); got != tt.wantRead {
					t.Fatalf("read offset = %d, want %d", got, tt.wantRead)
				}
				if got := p.tun.lastWriteCallOffset(); got != tt.wantWrite {
					t.Fatalf("write offset = %d, want %d", got, tt.wantWrite)
				}
				raw := p.tun.lastWritePacket()
				if len(raw) == 0 {
					t.Fatal("expected write packet to be recorded")
				}
				if !bytes.Equal(raw[tt.wantWrite:], pingPacket(pair[1].ip, pair[0].ip)) && !bytes.Equal(raw[tt.wantWrite:], pingPacket(pair[0].ip, pair[1].ip)) {
					t.Fatal("recorded write packet payload mismatch")
				}
			}
		})
	}
}

func TestVTunOffsetsEndToEnd(t *testing.T) {
	goroutineLeakCheck(t)

	tests := []struct {
		name     string
		mwo, mro int
	}{
		{name: "compatible", mwo: 0, mro: 0},
		{name: "read copy", mwo: 0, mro: 32},
		{name: "write copy", mwo: 32, mro: 0},
		{name: "both copy", mwo: 48, mro: 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vt0, err := (&vtun.Opts{
				LocalAddrs:     []netip.Addr{netip.MustParseAddr("10.44.0.1")},
				NoLoopbackAddr: true,
				MWO:            tt.mwo,
				MRO:            tt.mro,
			}).Build()
			if err != nil {
				t.Fatal(err)
			}
			defer vt0.Close()

			vt1, err := (&vtun.Opts{
				LocalAddrs:     []netip.Addr{netip.MustParseAddr("10.44.0.2")},
				NoLoopbackAddr: true,
				MWO:            tt.mwo,
				MRO:            tt.mro,
			}).Build()
			if err != nil {
				t.Fatal(err)
			}
			defer vt1.Close()

			newDevicePairForTUNs(t, vt0, vt1, [2]netip.Addr{
				netip.MustParseAddr("10.44.0.1"),
				netip.MustParseAddr("10.44.0.2"),
			})

			listener, err := vt1.ListenUDPAddrPort(netip.MustParseAddrPort("10.44.0.2:9000"))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			conn, err := vt0.DialUDPAddrPort(netip.MustParseAddrPort("10.44.0.1:8000"), netip.MustParseAddrPort("10.44.0.2:9000"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			want := []byte("vtun offsets payload")
			if _, err := conn.Write(want); err != nil {
				t.Fatal(err)
			}

			_ = listener.SetReadDeadline(time.Now().Add(5 * time.Second))
			got := make([]byte, len(want))
			n, _, err := listener.ReadFrom(got)
			if err != nil {
				t.Fatal(err)
			}
			got = got[:n]
			if !bytes.Equal(got, want) {
				t.Fatalf("payload mismatch: got %q want %q", got, want)
			}
		})
	}
}
