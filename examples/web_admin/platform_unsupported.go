//go:build !linux && !windows

// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 AsciiMoth

package main

import (
	"fmt"
	"net/netip"
)

func configurePlatformTUN(_ string, _, _ netip.Addr, _ int) (func() error, error) {
	return nil, fmt.Errorf("this example currently supports only linux and windows")
}
