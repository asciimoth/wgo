//go:build !linux

// SPDX-License-Identifier: MIT
//
// Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
// Modifications Copyright (C) 2026 AsciiMoth

package device

import (
	conn "github.com/asciimoth/batchudp"
	"github.com/asciimoth/wgo/rwcancel"
)

func (device *Device) startRouteListener(_ conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
