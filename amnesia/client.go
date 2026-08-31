package amnezia

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"runtime"
	"strings"
	"sync"

	"github.com/asciimoth/wgo/device"
)

const defaultMaxResponseBytes int64 = 8 << 20

// ClientMetadata is added to each gateway request. InstallationUUID should be
// generated once and persisted by long-lived applications; otherwise NewClient
// creates a random UUID for the lifetime of that Client.
type ClientMetadata struct {
	OSVersion        string `json:"os_version,omitempty"`
	AppVersion       string `json:"app_version,omitempty"`
	CLIName          string `json:"cli_name,omitempty"`
	Distribution     string `json:"distribution,omitempty"`
	Language         string `json:"app_language,omitempty"`
	InstallationUUID string `json:"installation_uuid,omitempty"`
}

// ClientOptions configures public official defaults or a compatible custom
// deployment. HTTPClient is mandatory and must have an explicit, non-default
// Transport. Every gateway, proxy-health, and S3-compatible request uses that
// client. Nil endpoint-list fields use the official defaults; a non-nil empty
// slice explicitly disables that list.
//
// GatewayPublicKeyPEM is public encryption material. Activation keys, custom
// auth_data, WireGuard private keys, and any private deployment credentials are
// secrets and must be injected at runtime rather than committed to source.
type ClientOptions struct {
	HTTPClient *http.Client
	// Device is an optional WireGuard control implementation. The client does
	// not close it. It can be detached or replaced after construction.
	Device              device.DeviceAPI
	GatewayURL          string
	GatewayPublicKeyPEM []byte
	PrimaryS3URLs       []string
	FallbackS3URLs      []string
	StaticProxyURLs     []string
	DisableS3Discovery  bool
	ProxyCache          ProxyCache
	Metadata            ClientMetadata
	Random              io.Reader
	MaxResponseBytes    int64
}

// Client is safe for concurrent use. Individual Negotiations are state
// machines and allow only one operation in flight at a time.
type Client struct {
	httpClient       *http.Client
	gatewayURL       string
	publicKeyPEM     []byte
	publicKey        *rsa.PublicKey
	primaryS3        []string
	fallbackS3       []string
	staticProxies    []string
	disableS3        bool
	proxyCache       ProxyCache
	metadata         ClientMetadata
	random           io.Reader
	randomMu         sync.Mutex
	maxResponseBytes int64

	deviceMu  sync.RWMutex
	deviceAPI device.DeviceAPI

	preferredMu    sync.RWMutex
	preferredProxy string
}

// NewClient validates configuration and applies the official public defaults.
// It never creates an HTTP client or uses http.DefaultClient/DefaultTransport.
func NewClient(options ClientOptions) (*Client, error) {
	if options.HTTPClient == nil {
		return nil, ErrHTTPClientRequired
	}
	if nilRoundTripper(options.HTTPClient.Transport) {
		return nil, ErrHTTPTransportRequired
	}
	if nilDeviceAPI(options.Device) {
		options.Device = nil
	} else if err := validateDeviceAPI(options.Device); err != nil {
		return nil, err
	}
	if transport, ok := options.HTTPClient.Transport.(*http.Transport); ok {
		if defaultTransport, defaultOK := http.DefaultTransport.(*http.Transport); defaultOK && transport == defaultTransport {
			return nil, ErrHTTPTransportRequired
		}
	}
	// Pin the selected RoundTripper and client policy. Mutating the caller's
	// http.Client fields after construction cannot make this Client fall back to
	// the process-wide default transport. The RoundTripper itself remains shared
	// and must be safe for concurrent use, as required by net/http.
	httpClient := *options.HTTPClient
	if options.GatewayURL == "" {
		options.GatewayURL = DefaultGatewayURL
	}
	gateway, err := normalizeBaseURL(options.GatewayURL)
	if err != nil {
		return nil, fmt.Errorf("amnezia: invalid gateway URL: %w", err)
	}
	if len(options.GatewayPublicKeyPEM) == 0 {
		options.GatewayPublicKeyPEM = []byte(DefaultGatewayPublicKeyPEM)
	}
	publicKey, err := parseRSAPublicKey(options.GatewayPublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("amnezia: invalid gateway public key: %w", err)
	}
	if options.PrimaryS3URLs == nil && !options.DisableS3Discovery {
		options.PrimaryS3URLs = DefaultPrimaryS3URLs()
	}
	if options.FallbackS3URLs == nil && !options.DisableS3Discovery {
		options.FallbackS3URLs = DefaultFallbackS3URLs()
	}
	if options.StaticProxyURLs == nil {
		options.StaticProxyURLs = DefaultStaticProxyURLs()
	}
	primary, err := normalizeURLList(options.PrimaryS3URLs)
	if err != nil {
		return nil, fmt.Errorf("amnezia: invalid primary S3 URL: %w", err)
	}
	fallback, err := normalizeURLList(options.FallbackS3URLs)
	if err != nil {
		return nil, fmt.Errorf("amnezia: invalid fallback S3 URL: %w", err)
	}
	proxies, err := normalizeURLList(options.StaticProxyURLs)
	if err != nil {
		return nil, fmt.Errorf("amnezia: invalid static proxy URL: %w", err)
	}
	if options.ProxyCache == nil {
		options.ProxyCache = NewMemoryProxyCache()
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.MaxResponseBytes <= 0 {
		options.MaxResponseBytes = defaultMaxResponseBytes
	}
	metadata, err := fillMetadata(options.Metadata, options.Random)
	if err != nil {
		return nil, err
	}
	return &Client{
		httpClient:       &httpClient,
		gatewayURL:       gateway,
		publicKeyPEM:     append([]byte(nil), options.GatewayPublicKeyPEM...),
		publicKey:        publicKey,
		primaryS3:        primary,
		fallbackS3:       fallback,
		staticProxies:    proxies,
		disableS3:        options.DisableS3Discovery,
		proxyCache:       options.ProxyCache,
		metadata:         metadata,
		random:           options.Random,
		maxResponseBytes: options.MaxResponseBytes,
		deviceAPI:        options.Device,
	}, nil
}

func nilRoundTripper(transport http.RoundTripper) bool {
	if transport == nil {
		return true
	}
	value := reflect.ValueOf(transport)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func fillMetadata(metadata ClientMetadata, random io.Reader) (ClientMetadata, error) {
	if metadata.OSVersion == "" {
		metadata.OSVersion = runtime.GOOS
	}
	if metadata.AppVersion == "" {
		metadata.AppVersion = DefaultOfficialAppVersion
	}
	if metadata.CLIName == "" {
		metadata.CLIName = DefaultOfficialCLIName
	}
	if metadata.Distribution == "" {
		metadata.Distribution = "github"
	}
	if metadata.Language == "" {
		metadata.Language = "en"
	}
	if metadata.InstallationUUID == "" {
		var raw [16]byte
		if _, err := io.ReadFull(random, raw[:]); err != nil {
			return ClientMetadata{}, fmt.Errorf("amnezia: generate installation UUID: %w", err)
		}
		raw[6] = raw[6]&0x0f | 0x40
		raw[8] = raw[8]&0x3f | 0x80
		metadata.InstallationUUID = formatUUID(raw)
	}
	return metadata, nil
}

func formatUUID(raw [16]byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
}

func normalizeBaseURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", errors.New("URL must have an http(s) scheme and host")
	}
	u.RawQuery = ""
	u.Fragment = ""
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	return u.String(), nil
}

func normalizeURLList(list []string) ([]string, error) {
	result := make([]string, 0, len(list))
	seen := make(map[string]struct{}, len(list))
	for _, raw := range list {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		normalized, err := normalizeBaseURL(raw)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", raw, err)
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	return result, nil
}

func endpointURL(base, endpoint string) (string, error) {
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	baseURL.Path = strings.TrimSuffix(baseURL.Path, "/") + "/" + strings.TrimPrefix(endpoint, "/")
	baseURL.RawPath = ""
	baseURL.RawQuery = ""
	baseURL.Fragment = ""
	return baseURL.String(), nil
}

func (c *Client) withRandom(fn func(io.Reader) error) error {
	c.randomMu.Lock()
	defer c.randomMu.Unlock()
	return fn(c.random)
}
