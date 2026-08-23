package amnezia

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	vpnScheme          = "vpn://"
	maxVPNPayloadBytes = 4 << 20
)

var activationKeySignature = []byte{0x00, 0x00, 0x00, 0xff}

// ActivationAPIConfig describes which public service/profile the key selects.
type ActivationAPIConfig struct {
	ServiceType     string `json:"service_type"`
	ServiceProtocol string `json:"service_protocol"`
	UserCountryCode string `json:"user_country_code"`
}

// ActivationKey is the decoded API-v2 vpn:// key. AuthData is secret even
// though the official gateway RSA key and endpoint are public.
type ActivationKey struct {
	Name          string                     `json:"name,omitempty"`
	Description   string                     `json:"description,omitempty"`
	ConfigVersion int                        `json:"config_version"`
	APIConfig     ActivationAPIConfig        `json:"api_config"`
	AuthData      json.RawMessage            `json:"auth_data"`
	Extra         map[string]json.RawMessage `json:"-"`
}

// String is deliberately redacted.
func (k ActivationKey) String() string {
	return fmt.Sprintf("ActivationKey{name:%q, config_version:%d, service_type:%q, service_protocol:%q, auth_data:<redacted>}",
		k.Name, k.ConfigVersion, k.APIConfig.ServiceType, k.APIConfig.ServiceProtocol)
}

// ParseActivationKey decodes and validates a vpn:// activation key without
// performing network access.
func ParseActivationKey(text string) (*ActivationKey, error) {
	payload, err := DecodeVPNPayload(text)
	if err != nil {
		return nil, &ProtocolError{Op: "decode activation key", Err: err}
	}

	var all map[string]json.RawMessage
	if err := json.Unmarshal(payload, &all); err != nil {
		return nil, &ProtocolError{Op: "parse activation key JSON", Err: err}
	}
	var key ActivationKey
	if err := json.Unmarshal(payload, &key); err != nil {
		return nil, &ProtocolError{Op: "parse activation key fields", Err: err}
	}
	for _, field := range []string{"name", "description", "config_version", "api_config", "auth_data"} {
		delete(all, field)
	}
	key.Extra = all
	if key.ConfigVersion == 0 {
		return nil, &ProtocolError{Op: "validate activation key", Err: errors.New("missing config_version")}
	}
	if len(key.AuthData) == 0 || !json.Valid(key.AuthData) || firstNonSpace(key.AuthData) != '{' {
		return nil, &ProtocolError{Op: "validate activation key", Err: errors.New("auth_data must be a JSON object")}
	}
	if key.APIConfig.ServiceType == "" {
		return nil, &ProtocolError{Op: "validate activation key", Err: errors.New("missing api_config.service_type")}
	}
	return &key, nil
}

func firstNonSpace(data []byte) byte {
	for _, b := range data {
		if b != ' ' && b != '\t' && b != '\r' && b != '\n' {
			return b
		}
	}
	return 0
}

// EncodeActivationKey creates an API-v2-compatible vpn:// key using the same
// four-byte marker and zlib framing as the official app. The returned string is
// a secret whenever AuthData contains a credential.
func EncodeActivationKey(key ActivationKey) (string, error) {
	if key.ConfigVersion != 2 {
		return "", fmt.Errorf("amnezia: config_version must be 2, got %d", key.ConfigVersion)
	}
	if strings.TrimSpace(key.APIConfig.ServiceType) == "" || strings.TrimSpace(key.APIConfig.ServiceProtocol) == "" {
		return "", errors.New("amnezia: api_config service_type and service_protocol are required")
	}
	if len(key.AuthData) == 0 || !json.Valid(key.AuthData) || firstNonSpace(key.AuthData) != '{' {
		return "", errors.New("amnezia: auth_data must be a JSON object")
	}
	doc := make(map[string]any, len(key.Extra)+5)
	for field, raw := range key.Extra {
		if !json.Valid(raw) {
			return "", fmt.Errorf("amnezia: invalid JSON in extra field %q", field)
		}
		doc[field] = raw
	}
	doc["name"] = key.Name
	doc["description"] = key.Description
	doc["config_version"] = key.ConfigVersion
	doc["api_config"] = key.APIConfig
	doc["auth_data"] = key.AuthData
	return EncodeVPNPayload(doc)
}

// DecodeVPNPayload decodes raw JSON or the base64url/qCompress-compatible
// vpn:// representation used for activation keys, self-hosted exports, and
// gateway configs.
func DecodeVPNPayload(text string) ([]byte, error) {
	text = strings.TrimSpace(text)
	text = strings.TrimPrefix(text, vpnScheme)
	if text == "" {
		return nil, errors.New("empty payload")
	}
	if len(text) > maxVPNPayloadBytes*2 {
		return nil, errors.New("payload text exceeds size limit")
	}

	encoded := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, text)
	data, err := decodeFlexibleBase64(encoded)
	if err != nil {
		if json.Valid([]byte(text)) {
			if len(text) > maxVPNPayloadBytes {
				return nil, errors.New("JSON payload exceeds size limit")
			}
			return []byte(text), nil
		}
		return nil, fmt.Errorf("base64url: %w", err)
	}
	if len(data) > maxVPNPayloadBytes {
		return nil, errors.New("encoded payload exceeds size limit")
	}
	if json.Valid(data) {
		return data, nil
	}

	var compressed []byte
	if len(data) > 6 && looksLikeZlib(data[4:]) {
		compressed = data[4:]
	} else if looksLikeZlib(data) {
		compressed = data
	} else {
		return nil, errors.New("payload is neither JSON nor qCompress/zlib data")
	}
	plain, err := inflateLimited(compressed, maxVPNPayloadBytes)
	if err != nil {
		return nil, fmt.Errorf("zlib: %w", err)
	}
	if !json.Valid(plain) {
		return nil, errors.New("decompressed payload is not JSON")
	}
	return plain, nil
}

// EncodeVPNPayload serializes v as JSON, zlib-compresses it at the official
// level, prefixes the API-key marker, and returns vpn:// plus unpadded base64url.
func EncodeVPNPayload(v any) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	if len(plain) > maxVPNPayloadBytes {
		return "", errors.New("amnezia: JSON payload exceeds size limit")
	}
	var compressed bytes.Buffer
	w, err := zlib.NewWriterLevel(&compressed, 6)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(plain); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	framed := append(append([]byte(nil), activationKeySignature...), compressed.Bytes()...)
	return vpnScheme + base64.RawURLEncoding.EncodeToString(framed), nil
}

func decodeFlexibleBase64(text string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}
	var last error
	for _, encoding := range encodings {
		data, err := encoding.DecodeString(text)
		if err == nil {
			return data, nil
		}
		last = err
	}
	return nil, last
}

func looksLikeZlib(data []byte) bool {
	if len(data) < 2 || data[0] != 0x78 {
		return false
	}
	return (uint16(data[0])<<8|uint16(data[1]))%31 == 0
}

func inflateLimited(data []byte, max int64) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	limited := &io.LimitedReader{R: r, N: max + 1}
	plain, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(plain)) > max {
		return nil, errors.New("decompressed payload exceeds size limit")
	}
	return plain, nil
}
