// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 AsciiMoth

package wgo_test

import (
	"os"
	"os/exec"
	"testing"
)

func TestDeviceBuildsForWasm(t *testing.T) {
	cmd := exec.Command("go", "build", "./device")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("GOOS=js GOARCH=wasm go build ./device failed: %v\n%s", err, output)
	}
}
