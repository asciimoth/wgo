/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 AsciiMoth
 */

package device

import (
	"bytes"
	"sync"
	"testing"
)

type recordingWriteTUN struct {
	fakeTUNDeviceSized

	maxWrite int

	mu      sync.Mutex
	writes  [][][]byte
	offsets []int
}

func (t *recordingWriteTUN) Write(bufs [][]byte, offset int) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	limit := t.maxWrite
	if limit < 1 || limit > len(bufs) {
		limit = len(bufs)
	}
	call := make([][]byte, 0, limit)
	for _, buf := range bufs[:limit] {
		call = append(call, append([]byte(nil), buf...))
	}
	t.writes = append(t.writes, call)
	t.offsets = append(t.offsets, offset)
	return limit, nil
}

func (t *recordingWriteTUN) writeCalls() ([][][]byte, []int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	writes := make([][][]byte, len(t.writes))
	for i, call := range t.writes {
		writes[i] = make([][]byte, len(call))
		for j, buf := range call {
			writes[i][j] = append([]byte(nil), buf...)
		}
	}
	offsets := append([]int(nil), t.offsets...)
	return writes, offsets
}

func TestWriteTUNBuffersChunksAndAdvancesPartialWrites(t *testing.T) {
	tunDev := &recordingWriteTUN{
		fakeTUNDeviceSized: fakeTUNDeviceSized{size: 2},
		maxWrite:           1,
	}
	tunDev.ensureInit()
	tun := &tunState{device: tunDev, writeOffset: 1}

	bufs := [][]byte{
		{0, 1},
		{0, 2},
		{0, 3},
		{0, 4},
		{0, 5},
	}
	if err := writeTUNBuffers(tun, bufs); err != nil {
		t.Fatalf("writeTUNBuffers: %v", err)
	}

	writes, offsets := tunDev.writeCalls()
	var flattened [][]byte
	for i, call := range writes {
		if len(call) > tunDev.BatchSize() {
			t.Fatalf("write call %d packet count = %d, want <= %d", i, len(call), tunDev.BatchSize())
		}
		flattened = append(flattened, call...)
	}
	if len(flattened) != len(bufs) {
		t.Fatalf("written packets = %d, want %d", len(flattened), len(bufs))
	}
	for i := range bufs {
		if !bytes.Equal(flattened[i], bufs[i]) {
			t.Fatalf("written packet %d = %x, want %x", i, flattened[i], bufs[i])
		}
	}
	for i, offset := range offsets {
		if offset != tun.writeOffset {
			t.Fatalf("write call %d offset = %d, want %d", i, offset, tun.writeOffset)
		}
	}
}
