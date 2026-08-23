package amnezia

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestActivationKeyRoundTripAndRedaction(t *testing.T) {
	original := ActivationKey{
		Name:          "Example",
		Description:   "Unit test",
		ConfigVersion: 2,
		APIConfig: ActivationAPIConfig{
			ServiceType:     "amnezia-free",
			ServiceProtocol: "awg",
			UserCountryCode: "xx",
		},
		AuthData: json.RawMessage(`{"api_key":"super-secret-test-value"}`),
		Extra: map[string]json.RawMessage{
			"future_field": json.RawMessage(`{"enabled":true}`),
		},
	}
	encoded, err := EncodeActivationKey(original)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, "vpn://") {
		t.Fatalf("encoded key has wrong scheme: %q", encoded)
	}
	parsed, err := ParseActivationKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.APIConfig != original.APIConfig || parsed.ConfigVersion != 2 {
		t.Fatalf("parsed key mismatch: %#v", parsed)
	}
	if string(parsed.AuthData) != string(original.AuthData) {
		t.Fatalf("auth_data mismatch: %s", parsed.AuthData)
	}
	if strings.Contains(parsed.String(), "super-secret") {
		t.Fatal("ActivationKey.String leaked auth_data")
	}
	if _, ok := parsed.Extra["future_field"]; !ok {
		t.Fatal("unknown field was not preserved")
	}
}

func TestEncodeActivationKeyRejectsInvalidV2Document(t *testing.T) {
	_, err := EncodeActivationKey(ActivationKey{
		ConfigVersion: 3,
		APIConfig:     ActivationAPIConfig{ServiceType: "service", ServiceProtocol: "awg"},
		AuthData:      json.RawMessage(`{"api_key":"secret"}`),
	})
	if err == nil {
		t.Fatal("non-v2 activation key was encoded")
	}
}

func TestParseUint32Range(t *testing.T) {
	for input, expected := range map[string]string{
		"25":    "25",
		"25-35": "25-35",
		"off":   "",
		"(off)": "",
	} {
		got, err := ParseUint32Range(input)
		if err != nil {
			t.Fatalf("ParseUint32Range(%q): %v", input, err)
		}
		if got.String() != expected {
			t.Fatalf("ParseUint32Range(%q).String() = %q, want %q", input, got.String(), expected)
		}
	}
	if _, err := ParseUint32Range("35-25"); err == nil {
		t.Fatal("backwards range was accepted")
	}
}
