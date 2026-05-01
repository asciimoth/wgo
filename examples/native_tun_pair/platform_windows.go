//go:build windows

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

$deadline = (Get-Date).AddSeconds(10)
do {
	$ip = Get-NetIPAddress -InterfaceAlias $name -IPAddress $addr -ErrorAction SilentlyContinue
	if ($null -ne $ip -and $ip.AddressState -eq "Preferred") {
		break
	}
	Start-Sleep -Milliseconds 200
} while ((Get-Date) -lt $deadline)

if ($null -eq $ip) {
	throw "address $addr was not present on interface $name after configuration"
}
if ($ip.AddressState -ne "Preferred") {
	throw "address $addr on interface $name stayed in state $($ip.AddressState)"
}
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
	return runCommand(15*time.Second, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
}
