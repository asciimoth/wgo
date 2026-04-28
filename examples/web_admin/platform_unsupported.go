//go:build !linux && !windows

package main

import (
	"fmt"
	"net/netip"
)

func configurePlatformTUN(_ string, _, _ netip.Addr, _ int) (func() error, error) {
	return nil, fmt.Errorf("this example currently supports only linux and windows")
}
