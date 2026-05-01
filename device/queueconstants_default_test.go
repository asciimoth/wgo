//go:build !android && !ios && !windows

// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 AsciiMoth

package device

import (
	"testing"

	conn "github.com/asciimoth/batchudp"
)

func TestDefaultQueueConstants(t *testing.T) {
	if QueueStagedSize != conn.IdealBatchSize {
		t.Fatalf("QueueStagedSize = %d, want %d", QueueStagedSize, conn.IdealBatchSize)
	}
	if QueueOutboundSize != 1024 || QueueInboundSize != 1024 || QueueHandshakeSize != 1024 {
		t.Fatalf("queue sizes = (%d, %d, %d), want all 1024", QueueOutboundSize, QueueInboundSize, QueueHandshakeSize)
	}
	if MaxSegmentSize != (1<<16)-1 {
		t.Fatalf("MaxSegmentSize = %d, want %d", MaxSegmentSize, (1<<16)-1)
	}
	if PreallocatedBuffersPerPool != 0 {
		t.Fatalf("PreallocatedBuffersPerPool = %d, want 0", PreallocatedBuffersPerPool)
	}
}
