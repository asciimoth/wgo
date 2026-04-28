//go:build linux

package main

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
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

func runCommand(timeout time.Duration, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return fmt.Errorf("%s %v: %w", name, args, ctx.Err())
	}
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, string(out))
	}
	return nil
}
