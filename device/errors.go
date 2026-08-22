/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 AsciiMoth
 */

package device

import "errors"

var (
	ErrPeerNotFound         = errors.New("peer not found")
	ErrTransportNotFound    = errors.New("transport not found")
	ErrTransportExists      = errors.New("transport exists")
	ErrTransportUnavailable = errors.New("transport unavailable")
	ErrActivePeerLimit      = errors.New("active peer limit reached")
	ErrDeviceClosed         = errors.New("device closed")
	ErrBatchSizeTooLarge    = errors.New("batch size too large")
)
