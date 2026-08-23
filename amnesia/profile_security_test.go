package amnezia

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestForceNativeInterfacePrivateKey(t *testing.T) {
	local := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	foreign := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))
	native := "[Interface]\nPrivateKey = " + foreign + "\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = " + foreign + "\n"

	got, err := forceNativeInterfacePrivateKey(native, local)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "PrivateKey = "+foreign) || !strings.Contains(got, "PrivateKey = "+local) {
		t.Fatalf("native interface key was not replaced:\n%s", got)
	}
	if !strings.Contains(got, "PublicKey = "+foreign) {
		t.Fatal("peer public key was modified while sanitizing interface key")
	}
}

func TestParseGatewayProfileRejectsMismatchedClientPublicKey(t *testing.T) {
	privateKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, 32))
	reportedClientPublic := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, 32))
	serverPublic := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 32))
	lastConfig, err := json.Marshal(map[string]any{
		"hostName":        "vpn.example.test",
		"port":            443,
		"client_ip":       "10.0.0.2",
		"client_pub_key":  reportedClientPublic,
		"server_pub_key":  serverPublic,
		"allowed_ips":     []string{"0.0.0.0/0"},
		"client_priv_key": "$WIREGUARD_CLIENT_PRIVATE_KEY",
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeVPNPayload(map[string]any{
		"config_version": 2,
		"containers": []any{map[string]any{
			"awg": map[string]any{"last_config": string(lastConfig)},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseGatewayProfile(encoded, privateKey, ProfileAPI{}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched client public key error = %v", err)
	}
}

func TestParseGatewayProfileWithPublicKeyLeavesPrivateKeyExternal(t *testing.T) {
	_, publicKey := testWireGuardKeypair(t, 0x45)
	profile, err := ParseGatewayProfileWithPublicKey(testGatewayConfig(t, publicKey), publicKey, ProfileAPI{})
	if err != nil {
		t.Fatal(err)
	}
	if profile.Interface.PublicKey != publicKey || profile.Interface.PrivateKey != "" {
		t.Fatalf("public-only identity = %#v", profile.Interface)
	}
	if _, err := profile.RenderConfig(); !errors.Is(err, ErrWireGuardPrivateKeyRequired) {
		t.Fatalf("RenderConfig error = %v, want ErrWireGuardPrivateKeyRequired", err)
	}
}

func TestProfileStringRedactsEndpoint(t *testing.T) {
	text := (Profile{Name: "test", Peer: WireGuardPeer{Endpoint: "private.example:1234"}}).String()
	if strings.Contains(text, "private.example") {
		t.Fatal("Profile.String leaked endpoint")
	}
}

func TestConfigTextDoesNotReturnUnknownNativeDirectives(t *testing.T) {
	privateKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x66}, 32))
	clientPublic, err := wireGuardPublicFromPrivate(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	serverPublic := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x77}, 32))
	profile := Profile{
		Interface: WireGuardInterface{
			PrivateKey: privateKey,
			PublicKey:  clientPublic,
			Addresses:  []string{"10.0.0.2/32"},
		},
		Peer: WireGuardPeer{
			PublicKey:  serverPublic,
			Endpoint:   "vpn.example.test:443",
			AllowedIPs: []string{"0.0.0.0/0"},
		},
		NativeConfig: "[Interface]\nPrivateKey = " + privateKey + "\nPostUp = do-not-execute\n",
	}
	text, err := profile.ConfigText()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, "PostUp") || strings.Contains(text, "do-not-execute") {
		t.Fatalf("ConfigText returned an unknown native directive:\n%s", text)
	}
}

func TestCanonicalAWGKeyAcceptsUAPIHex(t *testing.T) {
	raw := bytes.Repeat([]byte{0x88}, 32)
	got, err := canonicalAWGKey(hex.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got != base64.StdEncoding.EncodeToString(raw) {
		t.Fatalf("canonical AWG key = %q", got)
	}
}
