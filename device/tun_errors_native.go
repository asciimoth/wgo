//go:build !wasm

// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 AsciiMoth

package device

import (
	"errors"

	"github.com/asciimoth/tuntap"
)

func isPlatformTooManySegmentsError(err error) bool {
	return errors.Is(err, tuntap.ErrTooManySegments)
}
