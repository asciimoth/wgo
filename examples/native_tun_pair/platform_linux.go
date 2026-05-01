//go:build linux

// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 AsciiMoth

package main

import (
	"fmt"
	"net/netip"
	"time"
)

func configurePlatformTUN(ifName string, localIP, peerIP netip.Addr, mtu int) (func() error, error) {
	if err := runCommand(5*time.Second, "ip", "addr", "replace", localIP.String()+"/32", "dev", ifName); err != nil {
		return nil, fmt.Errorf("assign %s to %s: %w", localIP, ifName, err)
	}
	if err := runCommand(5*time.Second, "ip", "link", "set", "dev", ifName, "mtu", fmt.Sprintf("%d", mtu), "up"); err != nil {
		return nil, fmt.Errorf("bring %s up: %w", ifName, err)
	}
	if err := runCommand(5*time.Second, "ip", "route", "replace", peerIP.String()+"/32", "dev", ifName); err != nil {
		return nil, fmt.Errorf("route %s via %s: %w", peerIP, ifName, err)
	}
	return nil, nil
}
