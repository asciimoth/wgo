package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestEnsureInstallationUUIDWritesMissingMetadata(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "live_api.json")
	configBytes := []byte(`{"enabled":true}`)
	if err := os.WriteFile(configPath, configBytes, 0600); err != nil {
		t.Fatal(err)
	}
	config := liveConfig{Enabled: true}

	saved, err := ensureInstallationUUID(newTerminalOutput(io.Discard), configPath, configBytes, &config)
	if err != nil {
		t.Fatal(err)
	}
	if !saved {
		t.Fatal("expected generated UUID to be saved")
	}
	if config.Metadata.InstallationUUID == "" {
		t.Fatal("config metadata UUID was not set")
	}

	var updated struct {
		Metadata struct {
			InstallationUUID string `json:"installation_uuid"`
		} `json:"metadata"`
	}
	if err := readJSON(configPath, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Metadata.InstallationUUID != config.Metadata.InstallationUUID {
		t.Fatalf("saved UUID = %q, want %q", updated.Metadata.InstallationUUID, config.Metadata.InstallationUUID)
	}
}

func TestEnsureInstallationUUIDWritesNullMetadata(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "live_api.json")
	configBytes := []byte(`{"enabled":true,"metadata":null}`)
	if err := os.WriteFile(configPath, configBytes, 0600); err != nil {
		t.Fatal(err)
	}
	config := liveConfig{Enabled: true}

	saved, err := ensureInstallationUUID(newTerminalOutput(io.Discard), configPath, configBytes, &config)
	if err != nil {
		t.Fatal(err)
	}
	if !saved {
		t.Fatal("expected generated UUID to be saved")
	}

	var updated struct {
		Metadata struct {
			InstallationUUID string `json:"installation_uuid"`
		} `json:"metadata"`
	}
	if err := readJSON(configPath, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Metadata.InstallationUUID == "" {
		t.Fatal("saved metadata UUID is empty")
	}
}

func TestEnsureInstallationUUIDKeepsExistingUUID(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "live_api.json")
	configBytes := []byte(`{"enabled":true,"metadata":{"installation_uuid":"00000000-0000-4000-8000-000000000001"}}`)
	if err := os.WriteFile(configPath, configBytes, 0600); err != nil {
		t.Fatal(err)
	}
	config := liveConfig{Enabled: true}
	if err := json.Unmarshal(configBytes, &config); err != nil {
		t.Fatal(err)
	}

	saved, err := ensureInstallationUUID(newTerminalOutput(io.Discard), configPath, configBytes, &config)
	if err != nil {
		t.Fatal(err)
	}
	if saved {
		t.Fatal("existing UUID should not be replaced")
	}

	got, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(configBytes) {
		t.Fatal("config file changed even though UUID already existed")
	}
}

func TestParseListFlag(t *testing.T) {
	got := parseListFlag(" https://one.example/ip, ,https://two.example/ip ")
	want := []string{"https://one.example/ip", "https://two.example/ip"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseListFlag() = %#v, want %#v", got, want)
	}
}

func TestParseVisibleIP(t *testing.T) {
	tests := []struct {
		name string
		body string
		want netip.Addr
		geo  string
	}{
		{
			name: "plain IPv4",
			body: "203.0.113.10\n",
			want: netip.MustParseAddr("203.0.113.10"),
		},
		{
			name: "plain IPv6",
			body: "2001:db8::1\n",
			want: netip.MustParseAddr("2001:db8::1"),
		},
		{
			name: "JSON",
			body: `{"ip":"203.0.113.20","country":"Georgia","country_iso":"GE","region_name":"Tbilisi","city":"Tbilisi","time_zone":"Asia/Tbilisi","asn":"AS16010","asn_org":"Magticom Ltd.","latitude":41.6959,"longitude":44.832}`,
			want: netip.MustParseAddr("203.0.113.20"),
			geo:  "city=Tbilisi region=Tbilisi country=Georgia country_code=GE timezone=Asia/Tbilisi asn=AS16010 org=Magticom Ltd. loc=41.6959,44.8320",
		},
		{
			name: "mapped IPv4",
			body: "::ffff:203.0.113.30",
			want: netip.MustParseAddr("203.0.113.30"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseVisibleIPReport([]byte(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			if got.IP != tt.want {
				t.Fatalf("parseVisibleIPReport() IP = %s, want %s", got.IP, tt.want)
			}
			if got.Geo.LogValue() != tt.geo {
				t.Fatalf("parseVisibleIPReport() geo = %q, want %q", got.Geo.LogValue(), tt.geo)
			}
		})
	}
}

func TestParseVisibleIPRejectsInvalidBody(t *testing.T) {
	for _, body := range []string{"", "not an ip", `{"ip":""}`, `{"ip":123}`} {
		if _, err := parseVisibleIPReport([]byte(body)); err == nil {
			t.Fatalf("parseVisibleIPReport(%q) succeeded, want error", body)
		}
	}
}

func TestTerminalOutputUsesANSIColors(t *testing.T) {
	var buffer bytes.Buffer
	output := newTerminalOutput(&buffer)

	output.Tracef("minor")
	output.Printf("regular")
	output.Highlightf("important")
	output.Successf("passed")
	output.Errorf("failed")

	want := "\x1b[90mminor\x1b[0m\nregular\n\x1b[36mimportant\x1b[0m\n\x1b[32mpassed\x1b[0m\n\x1b[31mfailed\x1b[0m\n"
	if buffer.String() != want {
		t.Fatalf("terminal output = %q, want %q", buffer.String(), want)
	}
}

func TestDeviceOutputLoggerUsesMinorTraceOutput(t *testing.T) {
	var buffer bytes.Buffer
	logger := newDeviceOutputLogger(newTerminalOutput(&buffer))

	logger.Debug("debug")
	logger.Infof("info %d", 1)
	logger.Warn("warn")
	logger.Errf("err %s", "x")

	want := "\x1b[90mwgo device: debug\x1b[0m\n" +
		"\x1b[90mwgo device: info 1\x1b[0m\n" +
		"\x1b[90mwgo device: warn\x1b[0m\n" +
		"\x1b[90mwgo device: err x\x1b[0m\n"
	if buffer.String() != want {
		t.Fatalf("device logger output = %q, want %q", buffer.String(), want)
	}
}

func readJSON(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}
