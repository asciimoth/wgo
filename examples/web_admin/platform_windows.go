//go:build windows

package main

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"time"
)

func configurePlatformTUN(ifName string, localIP, peerIP netip.Addr, mtu int) (func() error, error) {
	if err := runPowerShell(fmt.Sprintf(`
$name = %q
$addr = %q
$peer = %q
$mtu = %d

Set-NetIPInterface -InterfaceAlias $name -NlMtuBytes $mtu -ErrorAction Stop
Get-NetIPAddress -InterfaceAlias $name -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
Get-NetRoute -InterfaceAlias $name -DestinationPrefix ($peer + "/32") -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
New-NetIPAddress -InterfaceAlias $name -IPAddress $addr -PrefixLength 32 -Type Unicast -ErrorAction Stop | Out-Null
New-NetRoute -InterfaceAlias $name -DestinationPrefix ($peer + "/32") -NextHop "0.0.0.0" -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
`, ifName, localIP.String(), peerIP.String(), mtu)); err != nil {
		return nil, fmt.Errorf("configure %s: %w", ifName, err)
	}

	cleanup := func() error {
		return runPowerShell(fmt.Sprintf(`
$name = %q
$addr = %q
$peer = %q

Get-NetRoute -InterfaceAlias $name -DestinationPrefix ($peer + "/32") -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
Get-NetIPAddress -InterfaceAlias $name -IPAddress $addr -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
exit 0
`, ifName, localIP.String(), peerIP.String()))
	}

	return cleanup, nil
}

func runPowerShell(script string) error {
	return runCommand(20*time.Second, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
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
