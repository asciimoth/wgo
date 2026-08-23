package amnezia

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestPrivateLiveGateway(t *testing.T) {
	type liveConfig struct {
		Enabled                   bool           `json:"enabled"`
		ActivationKeyFile         string         `json:"activation_key_file"`
		GatewayURL                string         `json:"gateway_url"`
		GatewayPublicKeyPEMFile   string         `json:"gateway_public_key_pem_file"`
		PrimaryS3URLs             []string       `json:"primary_s3_urls"`
		FallbackS3URLs            []string       `json:"fallback_s3_urls"`
		StaticProxyURLs           []string       `json:"static_proxy_urls"`
		DisableS3Discovery        bool           `json:"disable_s3_discovery"`
		AcceptInteractionRequired bool           `json:"accept_interaction_required"`
		Metadata                  ClientMetadata `json:"metadata"`
	}
	configBytes, err := os.ReadFile(filepath.Join(privateTestDirectory, "live_api.json"))
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("private live_api.json is not present")
	}
	if err != nil {
		t.Fatal(err)
	}
	var config liveConfig
	if err := json.Unmarshal(configBytes, &config); err != nil {
		t.Fatal(err)
	}
	if !config.Enabled {
		t.Skip("private live API test is not enabled")
	}
	keyPath := config.ActivationKeyFile
	if keyPath == "" {
		keyPath = "live_activation_key.txt"
	}
	keyBytes, err := os.ReadFile(filepath.Join(privateTestDirectory, filepath.Base(keyPath)))
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("private live activation key file is not present")
	}
	if err != nil {
		t.Fatal(err)
	}
	options := ClientOptions{
		HTTPClient:         explicitTestHTTPClient(),
		GatewayURL:         config.GatewayURL,
		PrimaryS3URLs:      config.PrimaryS3URLs,
		FallbackS3URLs:     config.FallbackS3URLs,
		StaticProxyURLs:    config.StaticProxyURLs,
		DisableS3Discovery: config.DisableS3Discovery,
		Metadata:           config.Metadata,
	}
	if config.GatewayPublicKeyPEMFile != "" {
		options.GatewayPublicKeyPEM, err = os.ReadFile(filepath.Join(privateTestDirectory, filepath.Base(config.GatewayPublicKeyPEMFile)))
		if err != nil {
			t.Fatal(err)
		}
	}
	client, err := NewClient(options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	profile, err := client.AcquireNonInteractive(ctx, strings.TrimSpace(string(keyBytes)), NegotiationOptions{})
	if errors.Is(err, ErrInteractionRequired) && config.AcceptInteractionRequired {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if profile == nil || profile.Peer.Endpoint == "" {
		t.Fatal("live gateway returned an incomplete profile")
	}
}
