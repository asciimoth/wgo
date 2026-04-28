package e2e

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	conn "github.com/asciimoth/batchudp"
	"github.com/asciimoth/gonnect-netstack/vtun"
	"github.com/asciimoth/gonnect/loopback"
	"github.com/asciimoth/wgo/device"
	"golang.org/x/crypto/curve25519"
)

var (
	firstIP  = netip.MustParseAddr("10.44.0.1")
	secondIP = netip.MustParseAddr("10.44.0.2")
)

type Pair struct {
	FirstNet  *vtun.VTun
	SecondNet *vtun.VTun
	FirstIP   netip.Addr
	SecondIP  netip.Addr

	firstDev  *device.Device
	secondDev *device.Device
	network   *loopback.LoopbackNetwork
}

func New() (*Pair, error) {
	network := loopback.NewLoopbackNetwok()

	firstTun, err := buildVTun(firstIP)
	if err != nil {
		_ = network.Down()
		return nil, fmt.Errorf("build first vtun: %w", err)
	}
	secondTun, err := buildVTun(secondIP)
	if err != nil {
		_ = firstTun.Close()
		_ = network.Down()
		return nil, fmt.Errorf("build second vtun: %w", err)
	}

	firstBind := conn.NewDefaultBind(network)
	secondBind := conn.NewDefaultBind(network)

	pair := &Pair{
		FirstNet:  firstTun,
		SecondNet: secondTun,
		FirstIP:   firstIP,
		SecondIP:  secondIP,
		firstDev:  device.NewDevice(firstTun, firstBind, device.NewLogger(device.LogLevelError, "example/first: ")),
		secondDev: device.NewDevice(secondTun, secondBind, device.NewLogger(device.LogLevelError, "example/second: ")),
		network:   network,
	}

	if err := pair.configure(); err != nil {
		_ = pair.Close()
		return nil, err
	}
	return pair, nil
}

func (p *Pair) Close() error {
	if p.firstDev != nil {
		p.firstDev.Close()
	}
	if p.secondDev != nil {
		p.secondDev.Close()
	}
	if p.network != nil {
		return p.network.Down()
	}
	return nil
}

func (p *Pair) configure() error {
	firstPrivate, firstPublic, err := deterministicKeyPair(1)
	if err != nil {
		return fmt.Errorf("generate first keypair: %w", err)
	}
	secondPrivate, secondPublic, err := deterministicKeyPair(2)
	if err != nil {
		return fmt.Errorf("generate second keypair: %w", err)
	}

	configs := []struct {
		dev         *device.Device
		privateKey  string
		peerPubKey  string
		allowedCIDR string
	}{
		{
			dev:         p.firstDev,
			privateKey:  firstPrivate,
			peerPubKey:  secondPublic,
			allowedCIDR: p.SecondIP.String() + "/32",
		},
		{
			dev:         p.secondDev,
			privateKey:  secondPrivate,
			peerPubKey:  firstPublic,
			allowedCIDR: p.FirstIP.String() + "/32",
		},
	}

	for _, cfg := range configs {
		err := cfg.dev.IpcSet(uapiConfig(
			"private_key", cfg.privateKey,
			"listen_port", "0",
			"replace_peers", "true",
			"public_key", cfg.peerPubKey,
			"protocol_version", "1",
			"replace_allowed_ips", "true",
			"allowed_ip", cfg.allowedCIDR,
		))
		if err != nil {
			return fmt.Errorf("apply device config: %w", err)
		}
	}

	for _, dev := range []*device.Device{p.firstDev, p.secondDev} {
		if err := dev.Up(); err != nil {
			return fmt.Errorf("bring device up: %w", err)
		}
	}

	firstPort, err := listenPort(p.firstDev)
	if err != nil {
		return fmt.Errorf("read first listen port: %w", err)
	}
	secondPort, err := listenPort(p.secondDev)
	if err != nil {
		return fmt.Errorf("read second listen port: %w", err)
	}

	if err := p.firstDev.IpcSet(uapiConfig("public_key", secondPublic, "endpoint", fmt.Sprintf("127.0.0.1:%d", secondPort))); err != nil {
		return fmt.Errorf("configure first endpoint: %w", err)
	}
	if err := p.secondDev.IpcSet(uapiConfig("public_key", firstPublic, "endpoint", fmt.Sprintf("127.0.0.1:%d", firstPort))); err != nil {
		return fmt.Errorf("configure second endpoint: %w", err)
	}

	return nil
}

func buildVTun(addr netip.Addr) (*vtun.VTun, error) {
	tunDev, err := (&vtun.Opts{
		LocalAddrs:     []netip.Addr{addr},
		NoLoopbackAddr: true,
	}).Build()
	if err != nil {
		return nil, err
	}

	select {
	case <-tunDev.Events():
		return tunDev, nil
	case <-time.After(5 * time.Second):
		_ = tunDev.Close()
		return nil, errors.New("timed out waiting for vtun event")
	}
}

func deterministicKeyPair(seed byte) (privateHex, publicHex string, err error) {
	privateKey := make([]byte, 32)
	for i := range privateKey {
		privateKey[i] = seed + byte(i) + 1
	}
	privateKey[0] &= 248
	privateKey[31] = (privateKey[31] & 127) | 64

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}

	return hex.EncodeToString(privateKey), hex.EncodeToString(publicKey), nil
}

func uapiConfig(fields ...string) string {
	var b strings.Builder
	for i := 0; i+1 < len(fields); i += 2 {
		b.WriteString(fields[i])
		b.WriteByte('=')
		b.WriteString(fields[i+1])
		b.WriteByte('\n')
	}
	return b.String()
}

func listenPort(dev *device.Device) (uint16, error) {
	state, err := dev.IpcGet()
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(state, "\n") {
		if !strings.HasPrefix(line, "listen_port=") {
			continue
		}
		port, err := strconv.ParseUint(strings.TrimPrefix(line, "listen_port="), 10, 16)
		if err != nil {
			return 0, err
		}
		return uint16(port), nil
	}
	return 0, errors.New("listen_port not found in UAPI state")
}
