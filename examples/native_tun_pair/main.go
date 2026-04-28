package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os/exec"
	"sync"
	"time"

	conn "github.com/asciimoth/batchudp"
	"github.com/asciimoth/gonnect/native"
	gtun "github.com/asciimoth/gonnect/tun"
	"github.com/asciimoth/tuntap"
	"github.com/asciimoth/wgo/device"
	"golang.org/x/crypto/curve25519"
)

const (
	exampleMTU          = 1420
	controlRounds       = 5
	heavyTrafficBytes   = 32 << 20
	heavyTrafficChunk   = 32 << 10
	heavyTrafficTimeout = 45 * time.Second
)

var (
	firstIP  = netip.MustParseAddr("10.66.0.1")
	secondIP = netip.MustParseAddr("10.66.0.2")
)

type nativePair struct {
	firstName  string
	secondName string
	firstDev   *device.Device
	secondDev  *device.Device
	firstNet   *native.Network
	secondNet  *native.Network
	cleanup    []func() error
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	log.Printf("creating native TUN pair; this example requires root/administrator privileges")

	pair, err := newNativePair()
	if err != nil {
		return err
	}
	defer func() {
		if err := pair.Close(); err != nil {
			log.Printf("cleanup error: %v", err)
		}
	}()

	if err := pair.runTraffic(); err != nil {
		return err
	}

	log.Printf("native TUN example completed successfully")
	return nil
}

func newNativePair() (*nativePair, error) {
	firstTun, firstName, firstCleanup, err := createConfiguredTUN("wgoex0", firstIP, secondIP)
	if err != nil {
		return nil, fmt.Errorf("create first native tun: %w", err)
	}

	secondTun, secondName, secondCleanup, err := createConfiguredTUN("wgoex1", secondIP, firstIP)
	if err != nil {
		_ = firstTun.Close()
		if firstCleanup != nil {
			_ = firstCleanup()
		}
		return nil, fmt.Errorf("create second native tun: %w", err)
	}

	firstNet := (&native.Config{}).Build()
	secondNet := (&native.Config{}).Build()

	pair := &nativePair{
		firstName:  firstName,
		secondName: secondName,
		firstDev:   device.NewDevice(firstTun, conn.NewDefaultBind(firstNet), device.NewLogger(device.LogLevelDebug, "example/first: ")),
		secondDev:  device.NewDevice(secondTun, conn.NewDefaultBind(secondNet), device.NewLogger(device.LogLevelDebug, "example/second: ")),
		firstNet:   firstNet,
		secondNet:  secondNet,
		cleanup:    []func() error{secondCleanup, firstCleanup},
	}

	if err := pair.configureWireGuard(); err != nil {
		_ = pair.Close()
		return nil, err
	}

	return pair, nil
}

func (p *nativePair) configureWireGuard() error {
	firstPrivate, firstPublic, err := deterministicKeyPair(1)
	if err != nil {
		return fmt.Errorf("generate first keypair: %w", err)
	}
	secondPrivate, secondPublic, err := deterministicKeyPair(2)
	if err != nil {
		return fmt.Errorf("generate second keypair: %w", err)
	}

	configs := []struct {
		dev        *device.Device
		privateKey device.NoisePrivateKey
		peerPubKey device.NoisePublicKey
		allowedIP  netip.Prefix
	}{
		{
			dev:        p.firstDev,
			privateKey: firstPrivate,
			peerPubKey: secondPublic,
			allowedIP:  netip.PrefixFrom(secondIP, secondIP.BitLen()),
		},
		{
			dev:        p.secondDev,
			privateKey: secondPrivate,
			peerPubKey: firstPublic,
			allowedIP:  netip.PrefixFrom(firstIP, firstIP.BitLen()),
		},
	}

	for _, cfg := range configs {
		if err := cfg.dev.SetPrivateKey(cfg.privateKey); err != nil {
			return fmt.Errorf("set private key: %w", err)
		}
		if err := cfg.dev.SetListenPort(0); err != nil {
			return fmt.Errorf("set listen port: %w", err)
		}
		cfg.dev.RemoveAllPeers()
		if _, err := cfg.dev.NewPeer(cfg.peerPubKey); err != nil {
			return fmt.Errorf("create peer: %w", err)
		}
		if err := cfg.dev.SetPeerProtocolVersion(cfg.peerPubKey, 1); err != nil {
			return fmt.Errorf("set peer protocol version: %w", err)
		}
		if err := cfg.dev.ReplacePeerAllowedIPs(cfg.peerPubKey, []netip.Prefix{cfg.allowedIP}); err != nil {
			return fmt.Errorf("set peer allowed ips: %w", err)
		}
	}

	if err := p.firstDev.Up(); err != nil {
		return fmt.Errorf("bring first device up: %w", err)
	}
	if err := p.secondDev.Up(); err != nil {
		return fmt.Errorf("bring second device up: %w", err)
	}

	firstPort := p.firstDev.ListenPort()
	secondPort := p.secondDev.ListenPort()

	log.Printf("wireguard endpoints: %s=%d %s=%d", p.firstName, firstPort, p.secondName, secondPort)

	if err := p.firstDev.SetPeerEndpoint(secondPublic, fmt.Sprintf("127.0.0.1:%d", secondPort)); err != nil {
		return fmt.Errorf("configure first endpoint: %w", err)
	}
	if err := p.secondDev.SetPeerEndpoint(firstPublic, fmt.Sprintf("127.0.0.1:%d", firstPort)); err != nil {
		return fmt.Errorf("configure second endpoint: %w", err)
	}

	return nil
}

func (p *nativePair) runTraffic() error {
	listener, err := net.Listen("tcp4", net.JoinHostPort(firstIP.String(), "0"))
	if err != nil {
		return fmt.Errorf("listen on first tunnel address: %w", err)
	}
	defer listener.Close()

	log.Printf("listening on %s", listener.Addr())

	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		log.Printf("server accepted connection from %s", conn.RemoteAddr())

		buf := make([]byte, 256)
		for i := 0; i < controlRounds; i++ {
			if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				serverDone <- err
				return
			}
			n, err := conn.Read(buf)
			if err != nil {
				serverDone <- err
				return
			}
			want := fmt.Sprintf("ping %d over native tun", i)
			if got := string(buf[:n]); got != want {
				serverDone <- fmt.Errorf("server got %q, want %q", got, want)
				return
			}

			reply := fmt.Sprintf("pong %d over native tun", i)
			if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				serverDone <- err
				return
			}
			if _, err := io.WriteString(conn, reply); err != nil {
				serverDone <- err
				return
			}
		}

		if err := exerciseHeavyTraffic(conn, 0x11, 0x22, "server"); err != nil {
			serverDone <- err
			return
		}

		serverDone <- nil
	}()

	dialer := net.Dialer{
		LocalAddr: &net.TCPAddr{IP: net.IP(secondIP.AsSlice())},
		Timeout:   10 * time.Second,
	}
	conn, err := dialer.DialContext(context.Background(), "tcp4", listener.Addr().String())
	if err != nil {
		return fmt.Errorf("dial through second tunnel address: %w", err)
	}
	defer conn.Close()

	log.Printf("client connected local=%s remote=%s", conn.LocalAddr(), conn.RemoteAddr())

	buf := make([]byte, 256)
	for i := 0; i < controlRounds; i++ {
		msg := fmt.Sprintf("ping %d over native tun", i)
		if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return err
		}
		if _, err := io.WriteString(conn, msg); err != nil {
			return err
		}
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return err
		}
		n, err := conn.Read(buf)
		if err != nil {
			return err
		}
		log.Printf("round=%d reply=%q", i, string(buf[:n]))
	}

	if err := exerciseHeavyTraffic(conn, 0x22, 0x11, "client"); err != nil {
		return err
	}

	if err := <-serverDone; err != nil {
		return err
	}

	return nil
}

func (p *nativePair) Close() error {
	if p.firstDev != nil {
		p.firstDev.Close()
	}
	if p.secondDev != nil {
		p.secondDev.Close()
	}
	if p.firstNet != nil {
		_ = p.firstNet.Down()
	}
	if p.secondNet != nil {
		_ = p.secondNet.Down()
	}

	var firstErr error
	for _, cleanup := range p.cleanup {
		if cleanup == nil {
			continue
		}
		if err := cleanup(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func createConfiguredTUN(name string, localIP, peerIP netip.Addr) (tun gtun.Tun, ifName string, cleanup func() error, err error) {
	tun, err = tuntap.CreateTUN(name, exampleMTU)
	if err != nil {
		return nil, "", nil, err
	}

	ifName, err = tun.Name()
	if err != nil {
		_ = tun.Close()
		return nil, "", nil, fmt.Errorf("load tun name: %w", err)
	}

	log.Printf("configuring native tun %s local=%s peer=%s", ifName, localIP, peerIP)
	cleanup, err = configurePlatformTUN(ifName, localIP, peerIP, exampleMTU)
	if err != nil {
		_ = tun.Close()
		return nil, "", nil, err
	}

	return tun, ifName, cleanup, nil
}

func deterministicKeyPair(seed byte) (privateKey device.NoisePrivateKey, publicKey device.NoisePublicKey, err error) {
	for i := range privateKey {
		privateKey[i] = seed + byte(i) + 1
	}
	privateKey[0] &= 248
	privateKey[31] = (privateKey[31] & 127) | 64

	publicBytes, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		return device.NoisePrivateKey{}, device.NoisePublicKey{}, err
	}
	copy(publicKey[:], publicBytes)

	return privateKey, publicKey, nil
}

func exerciseHeavyTraffic(conn net.Conn, sendSeed, recvSeed byte, side string) error {
	if err := conn.SetDeadline(time.Now().Add(heavyTrafficTimeout)); err != nil {
		return fmt.Errorf("%s set heavy-traffic deadline: %w", side, err)
	}
	defer func() {
		_ = conn.SetDeadline(time.Time{})
	}()

	start := time.Now()
	log.Printf("%s starting full-duplex transfer: %d bytes each direction", side, heavyTrafficBytes)

	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := writePattern(conn, sendSeed, heavyTrafficBytes); err != nil {
			errCh <- fmt.Errorf("%s write traffic: %w", side, err)
			return
		}
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			if err := tcpConn.CloseWrite(); err != nil {
				errCh <- fmt.Errorf("%s close write: %w", side, err)
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := readAndVerifyPattern(conn, recvSeed, heavyTrafficBytes); err != nil {
			errCh <- fmt.Errorf("%s read traffic: %w", side, err)
		}
	}()

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			return err
		}
	}

	elapsed := time.Since(start)
	mbps := (float64(heavyTrafficBytes*2) / (1024 * 1024)) / elapsed.Seconds()
	log.Printf("%s heavy transfer completed in %s total_throughput=%.2f MiB/s", side, elapsed.Round(time.Millisecond), mbps)
	return nil
}

func writePattern(w io.Writer, seed byte, total int) error {
	buf := make([]byte, heavyTrafficChunk)
	offset := 0
	for offset < total {
		n := len(buf)
		if remaining := total - offset; remaining < n {
			n = remaining
		}
		fillPattern(buf[:n], seed, offset)
		written, err := w.Write(buf[:n])
		offset += written
		if err != nil {
			return err
		}
		if written != n {
			return io.ErrShortWrite
		}
	}
	return nil
}

func readAndVerifyPattern(r io.Reader, seed byte, total int) error {
	buf := make([]byte, heavyTrafficChunk)
	want := make([]byte, heavyTrafficChunk)
	offset := 0
	for offset < total {
		n := len(buf)
		if remaining := total - offset; remaining < n {
			n = remaining
		}
		if _, err := io.ReadFull(r, buf[:n]); err != nil {
			return err
		}
		fillPattern(want[:n], seed, offset)
		for i := 0; i < n; i++ {
			if buf[i] != want[i] {
				return fmt.Errorf("payload mismatch at byte %d: got=%d want=%d", offset+i, buf[i], want[i])
			}
		}
		offset += n
	}
	return nil
}

func fillPattern(buf []byte, seed byte, offset int) {
	for i := range buf {
		buf[i] = byte((offset + i) % 251)
		buf[i] ^= seed
	}
}

func runCommand(timeout time.Duration, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, string(output))
	}
	return nil
}
