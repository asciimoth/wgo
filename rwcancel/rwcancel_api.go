// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 AsciiMoth

package rwcancel

type canceler interface {
	Cancel() error
}

var _ canceler = (*RWCancel)(nil)
