// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 AsciiMoth

package e2e

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	conn "github.com/asciimoth/batchudp"
	"github.com/asciimoth/gonnect-netstack/vtun"
	"github.com/asciimoth/gonnect/loopback"
	"github.com/asciimoth/gonnect/native"
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

	firstDev        *device.Device
	secondDev       *device.Device
	firstPublicKey  device.NoisePublicKey
	secondPublicKey device.NoisePublicKey
	networks        []networkDowner
}

type networkDowner interface {
	Down() error
}

func New() (*Pair, error) {
	network := loopback.NewLoopbackNetwok()

	firstTun, err := buildVTun(firstIP, 0, 0)
	if err != nil {
		_ = network.Down()
		return nil, fmt.Errorf("build first vtun: %w", err)
	}
	secondTun, err := buildVTun(secondIP, 0, 0)
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
		networks:  []networkDowner{network},
	}

	if err := pair.configure(); err != nil {
		_ = pair.Close()
		return nil, err
	}
	return pair, nil
}

func (p *Pair) SwapSecondVTun(mwo, mro int) error {
	nextTun, err := buildVTun(p.SecondIP, mwo, mro)
	if err != nil {
		return fmt.Errorf("build replacement second vtun: %w", err)
	}
	if err := p.secondDev.ReplaceTUN(nextTun); err != nil {
		_ = nextTun.Close()
		return fmt.Errorf("replace second vtun: %w", err)
	}
	p.SecondNet = nextTun
	return nil
}

func (p *Pair) SwapBindsToNative() error {
	network := (&native.Config{}).Build()
	firstBind := conn.NewDefaultBind(network)
	secondBind := conn.NewDefaultBind(network)

	if err := p.firstDev.ReplaceBind(firstBind); err != nil {
		_ = network.Down()
		return fmt.Errorf("replace first bind: %w", err)
	}
	if err := p.secondDev.ReplaceBind(secondBind); err != nil {
		_ = network.Down()
		return fmt.Errorf("replace second bind: %w", err)
	}
	p.networks = append(p.networks, network)
	if err := p.configureEndpoints(); err != nil {
		return fmt.Errorf("reconfigure endpoints after native bind swap: %w", err)
	}

	return nil
}

func (p *Pair) Close() error {
	if p.firstDev != nil {
		p.firstDev.Close()
	}
	if p.secondDev != nil {
		p.secondDev.Close()
	}
	var firstErr error
	for _, network := range p.networks {
		if network == nil {
			continue
		}
		if err := network.Down(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
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
	p.firstPublicKey = firstPublic
	p.secondPublicKey = secondPublic

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
			allowedIP:  netip.PrefixFrom(p.SecondIP, p.SecondIP.BitLen()),
		},
		{
			dev:        p.secondDev,
			privateKey: secondPrivate,
			peerPubKey: firstPublic,
			allowedIP:  netip.PrefixFrom(p.FirstIP, p.FirstIP.BitLen()),
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

	for _, dev := range []*device.Device{p.firstDev, p.secondDev} {
		if err := dev.Up(); err != nil {
			return fmt.Errorf("bring device up: %w", err)
		}
	}

	if err := p.configureEndpoints(); err != nil {
		return err
	}

	return nil
}

func (p *Pair) configureEndpoints() error {
	firstPort := p.firstDev.ListenPort()
	secondPort := p.secondDev.ListenPort()

	if err := p.firstDev.SetPeerEndpoint(p.secondPublicKey, fmt.Sprintf("127.0.0.1:%d", secondPort)); err != nil {
		return fmt.Errorf("configure first endpoint: %w", err)
	}
	if err := p.secondDev.SetPeerEndpoint(p.firstPublicKey, fmt.Sprintf("127.0.0.1:%d", firstPort)); err != nil {
		return fmt.Errorf("configure second endpoint: %w", err)
	}

	return nil
}

func buildVTun(addr netip.Addr, mwo, mro int) (*vtun.VTun, error) {
	tunDev, err := (&vtun.Opts{
		LocalAddrs:     []netip.Addr{addr},
		NoLoopbackAddr: true,
		MWO:            mwo,
		MRO:            mro,
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
