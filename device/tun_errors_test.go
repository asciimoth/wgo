// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 AsciiMoth

package device

import (
	"errors"
	"fmt"
	"testing"

	"github.com/asciimoth/tuntap"
)

func TestIsTooManySegmentsError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "native sentinel",
			err:  tuntap.ErrTooManySegments,
			want: true,
		},
		{
			name: "wrapped native sentinel",
			err:  fmt.Errorf("read failed: %w", tuntap.ErrTooManySegments),
			want: true,
		},
		{
			name: "message fallback",
			err:  fmt.Errorf("read failed: %w", errors.New(tooManySegmentsErrorMessage)),
			want: true,
		},
		{
			name: "different error",
			err:  errors.New("boom"),
			want: false,
		},
		{
			name: "nil",
			err:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTooManySegmentsError(tt.err); got != tt.want {
				t.Fatalf("isTooManySegmentsError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
