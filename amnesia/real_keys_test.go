package amnezia

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const privateTestDirectory = "testdata/private"

func TestPrivateVPNKeyParsing(t *testing.T) {
	file, err := os.Open(filepath.Join(privateTestDirectory, "activation_keys.txt"))
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("private activation_keys.txt is not present")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("close private activation keys: %v", err)
		}
	}()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), maxVPNPayloadBytes*2)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		count++
		if _, err := ParseInput(line); err != nil {
			t.Errorf("private key line %d: %v", count, err)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Skip("private activation_keys.txt contains no keys")
	}
}

func TestPrivateInputFiles(t *testing.T) {
	directory := filepath.Join(privateTestDirectory, "inputs")
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("private input fixture directory is not present")
	}
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		count++
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Errorf("read private input fixture %q: %v", entry.Name(), err)
			continue
		}
		if _, err := ParseInputBytes(data); err != nil {
			t.Errorf("parse private input fixture %q: %v", entry.Name(), err)
		}
	}
	if count == 0 {
		t.Skip("private input fixture directory contains no inputs")
	}
}
