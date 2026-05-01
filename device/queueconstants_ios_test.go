//go:build ios

// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 AsciiMoth

package device

import "testing"

func TestIOSQueueConstants(t *testing.T) {
	if QueueStagedSize != 128 {
		t.Fatalf("QueueStagedSize = %d, want 128", QueueStagedSize)
	}
	if QueueOutboundSize != 1024 || QueueInboundSize != 1024 || QueueHandshakeSize != 1024 {
		t.Fatalf("queue sizes = (%d, %d, %d), want all 1024", QueueOutboundSize, QueueInboundSize, QueueHandshakeSize)
	}
	if MaxSegmentSize != 1700 {
		t.Fatalf("MaxSegmentSize = %d, want 1700", MaxSegmentSize)
	}
	if PreallocatedBuffersPerPool != 1024 {
		t.Fatalf("PreallocatedBuffersPerPool = %d, want 1024", PreallocatedBuffersPerPool)
	}
}
