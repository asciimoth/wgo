//go:build wasm

// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 AsciiMoth

package device

func isPlatformTooManySegmentsError(error) bool {
	return false
}
