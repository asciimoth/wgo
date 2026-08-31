// nolint
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	conn "github.com/asciimoth/batchudp"
	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect-netstack/helpers"
	"github.com/asciimoth/gonnect-netstack/vtun"
	amnezia "github.com/asciimoth/wgo/amnesia"
	"github.com/asciimoth/wgo/device"
)

const defaultTrafficTimeout = 10 * time.Second

var defaultIPCheckURLs = []string{
	"https://ifconfig.co/json",
	"https://api.ipify.org",
	"https://icanhazip.com",
}

type liveConfig struct {
	Enabled                   bool                   `json:"enabled"`
	ActivationKeyFile         string                 `json:"activation_key_file"`
	GatewayURL                string                 `json:"gateway_url"`
	GatewayPublicKeyPEMFile   string                 `json:"gateway_public_key_pem_file"`
	PrimaryS3URLs             []string               `json:"primary_s3_urls"`
	FallbackS3URLs            []string               `json:"fallback_s3_urls"`
	StaticProxyURLs           []string               `json:"static_proxy_urls"`
	DisableS3Discovery        bool                   `json:"disable_s3_discovery"`
	AcceptInteractionRequired bool                   `json:"accept_interaction_required"`
	Metadata                  amnezia.ClientMetadata `json:"metadata"`
}

type trafficConfig struct {
	Skip        bool
	Host        string
	HTTPURL     string
	IPCheckURLs []string
	PingCount   int
	HTTPCount   int
	StepTimeout time.Duration
}

type visibleIPReport struct {
	IP  netip.Addr
	Geo visibleIPGeo
}

type visibleIPGeo struct {
	City        string
	Region      string
	Country     string
	CountryCode string
	Timezone    string
	ASN         string
	Org         string
	Location    string
}

type loggingTransport struct {
	base   http.RoundTripper
	output *terminalOutput
}

func (transport loggingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	start := time.Now()
	transport.output.Tracef("HTTP request: %s %s%s", request.Method, request.URL.Host, request.URL.EscapedPath())
	response, err := transport.base.RoundTrip(request)
	if err != nil {
		transport.output.Tracef("HTTP error: host=%s duration=%s error=%v", request.URL.Host, time.Since(start).Round(time.Millisecond), err)
		return nil, err
	}
	transport.output.Tracef("HTTP response: host=%s status=%s duration=%s", request.URL.Host, response.Status, time.Since(start).Round(time.Millisecond))
	return response, nil
}

type terminalOutput struct {
	w io.Writer
}

const (
	ansiReset = "\x1b[0m"
	ansiGrey  = "\x1b[90m"
	ansiCyan  = "\x1b[36m"
	ansiGreen = "\x1b[32m"
	ansiRed   = "\x1b[31m"
)

func newTerminalOutput(w io.Writer) *terminalOutput {
	return &terminalOutput{w: w}
}

func (output *terminalOutput) Print(args ...any) {
	output.write("", fmt.Sprint(args...))
}

func (output *terminalOutput) Printf(format string, args ...any) {
	output.write("", fmt.Sprintf(format, args...))
}

func (output *terminalOutput) Tracef(format string, args ...any) {
	output.write(ansiGrey, fmt.Sprintf(format, args...))
}

func (output *terminalOutput) Highlightf(format string, args ...any) {
	output.write(ansiCyan, fmt.Sprintf(format, args...))
}

func (output *terminalOutput) Successf(format string, args ...any) {
	output.write(ansiGreen, fmt.Sprintf(format, args...))
}

func (output *terminalOutput) Errorf(format string, args ...any) {
	output.write(ansiRed, fmt.Sprintf(format, args...))
}

func (output *terminalOutput) write(color, message string) {
	if color == "" {
		fmt.Fprintln(output.w, message)
		return
	}
	fmt.Fprintf(output.w, "%s%s%s\n", color, message, ansiReset)
}

type deviceOutputLogger struct {
	output *terminalOutput
}

func newDeviceOutputLogger(output *terminalOutput) device.Logger {
	return deviceOutputLogger{output: output}
}

func (logger deviceOutputLogger) Debug(args ...any) {
	logger.output.Tracef("wgo device: %s", fmt.Sprint(args...))
}

func (logger deviceOutputLogger) Debugf(format string, args ...any) {
	logger.output.Tracef("wgo device: "+format, args...)
}

func (logger deviceOutputLogger) Info(args ...any) {
	logger.output.Tracef("wgo device: %s", fmt.Sprint(args...))
}

func (logger deviceOutputLogger) Infof(format string, args ...any) {
	logger.output.Tracef("wgo device: "+format, args...)
}

func (logger deviceOutputLogger) Warn(args ...any) {
	logger.output.Tracef("wgo device: %s", fmt.Sprint(args...))
}

func (logger deviceOutputLogger) Warnf(format string, args ...any) {
	logger.output.Tracef("wgo device: "+format, args...)
}

func (logger deviceOutputLogger) Err(args ...any) {
	logger.output.Tracef("wgo device: %s", fmt.Sprint(args...))
}

func (logger deviceOutputLogger) Errf(format string, args ...any) {
	logger.output.Tracef("wgo device: "+format, args...)
}

func (logger deviceOutputLogger) Fatal(args ...any) {
	logger.Err(args...)
	os.Exit(1)
}

func (logger deviceOutputLogger) Fatalf(format string, args ...any) {
	logger.Errf(format, args...)
	os.Exit(1)
}

func main() {
	defaultPrivateDir := filepath.Join("amnesia", "testdata", "private")
	privateDir := flag.String("private-dir", defaultPrivateDir, "directory with private Amnezia live fixtures")
	configPath := flag.String("config", "", "path to live_api.json; default is PRIVATE_DIR/live_api.json")
	timeout := flag.Duration("timeout", 2*time.Minute, "maximum time for the live gateway request")
	skipTraffic := flag.Bool("skip-traffic", false, "only request and validate the profile; do not create a VTun or send traffic")
	trafficHost := flag.String("traffic-host", "example.com", "host to resolve and ping over the WireGuard VTun")
	trafficHTTPURL := flag.String("traffic-http-url", "http://example.com/", "HTTP URL to request over the WireGuard VTun")
	ipCheckURLs := flag.String("ip-check-urls", strings.Join(defaultIPCheckURLs, ","), "comma-separated external visible-IP URLs to request outside and over the WireGuard VTun; empty disables the IP check")
	pingCount := flag.Int("ping-count", 3, "number of ICMP echo attempts to send over the WireGuard VTun")
	httpCount := flag.Int("http-count", 2, "number of HTTP requests to send over the WireGuard VTun")
	trafficTimeout := flag.Duration("traffic-timeout", defaultTrafficTimeout, "timeout for each traffic check over the WireGuard VTun")
	flag.Parse()

	output := newTerminalOutput(os.Stderr)
	traffic := trafficConfig{
		Skip:        *skipTraffic,
		Host:        *trafficHost,
		HTTPURL:     *trafficHTTPURL,
		IPCheckURLs: parseListFlag(*ipCheckURLs),
		PingCount:   *pingCount,
		HTTPCount:   *httpCount,
		StepTimeout: *trafficTimeout,
	}
	if err := run(output, *privateDir, *configPath, *timeout, traffic); err != nil {
		output.Errorf("Failed: %v", err)
		os.Exit(1)
	}
	output.Successf("Passed")
}

func run(output *terminalOutput, privateDir, configPath string, timeout time.Duration, traffic trafficConfig) error {
	if configPath == "" {
		configPath = filepath.Join(privateDir, "live_api.json")
	}
	output.Tracef("Read config: %s", configPath)
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read live config: %w", err)
	}

	var config liveConfig
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return fmt.Errorf("parse live config: %w", err)
	}
	if !config.Enabled {
		return errors.New("live config is disabled")
	}
	output.Printf("Live config is enabled")
	if saved, err := ensureInstallationUUID(output, configPath, configBytes, &config); err != nil {
		return err
	} else if saved {
		output.Tracef("Saved generated installation UUID: %s", configPath)
	}

	keyPath := config.ActivationKeyFile
	if keyPath == "" {
		keyPath = "live_activation_key.txt"
	}
	if !filepath.IsAbs(keyPath) {
		keyPath = filepath.Join(privateDir, filepath.Base(keyPath))
	}
	output.Tracef("Read activation key: %s", keyPath)
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read activation key: %w", err)
	}
	activationKey := strings.TrimSpace(string(keyBytes))
	if activationKey == "" {
		return errors.New("activation key file is empty")
	}
	key, err := amnezia.ParseActivationKey(activationKey)
	if err != nil {
		return fmt.Errorf("parse activation key: %w", err)
	}
	output.Highlightf("Activation key: name=%q config_version=%d service_type=%q service_protocol=%q user_country=%q",
		key.Name, key.ConfigVersion, key.APIConfig.ServiceType, key.APIConfig.ServiceProtocol, key.APIConfig.UserCountryCode)

	metadata, err := effectiveMetadata(config.Metadata)
	if err != nil {
		return err
	}
	output.Printf("Client metadata: installation_uuid=%q cli_name=%q app_version=%q os_version=%q distribution=%q language=%q",
		metadata.InstallationUUID, metadata.CLIName, metadata.AppVersion, metadata.OSVersion, metadata.Distribution, metadata.Language)

	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	options := amnezia.ClientOptions{
		HTTPClient: &http.Client{
			Transport: loggingTransport{base: baseTransport, output: output},
		},
		GatewayURL:         config.GatewayURL,
		PrimaryS3URLs:      config.PrimaryS3URLs,
		FallbackS3URLs:     config.FallbackS3URLs,
		StaticProxyURLs:    config.StaticProxyURLs,
		DisableS3Discovery: config.DisableS3Discovery,
		Metadata:           metadata,
	}
	if config.GatewayPublicKeyPEMFile != "" {
		publicKeyPath := config.GatewayPublicKeyPEMFile
		if !filepath.IsAbs(publicKeyPath) {
			publicKeyPath = filepath.Join(privateDir, filepath.Base(publicKeyPath))
		}
		output.Tracef("Read gateway public key: %s", publicKeyPath)
		options.GatewayPublicKeyPEM, err = os.ReadFile(publicKeyPath)
		if err != nil {
			return fmt.Errorf("read gateway public key: %w", err)
		}
	}

	output.Tracef("Build client: gateway_set=%v primary_s3=%d fallback_s3=%d static_proxies=%d s3_disabled=%v",
		config.GatewayURL != "", len(config.PrimaryS3URLs), len(config.FallbackS3URLs), len(config.StaticProxyURLs), config.DisableS3Discovery)
	client, err := amnezia.NewClient(options)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	output.Printf("Request profile: timeout=%s accept_interaction_required=%v", timeout, config.AcceptInteractionRequired)
	profile, err := client.AcquireNonInteractive(ctx, activationKey, amnezia.NegotiationOptions{})
	if errors.Is(err, amnezia.ErrInteractionRequired) && config.AcceptInteractionRequired {
		output.Highlightf("Gateway requested interaction; accepted by config")
		return nil
	}
	if err != nil {
		return fmt.Errorf("acquire profile: %w", err)
	}
	if err := validateProfile(profile); err != nil {
		return err
	}
	logProfileSummary(output, profile)
	if traffic.Skip {
		output.Highlightf("Skip VTun traffic checks")
		return nil
	}
	if err := exerciseTunnelTraffic(ctx, output, profile, traffic); err != nil {
		return fmt.Errorf("exercise tunnel traffic: %w", err)
	}
	return nil
}

func validateProfile(profile *amnezia.Profile) error {
	if profile == nil {
		return errors.New("gateway returned nil profile")
	}
	if strings.TrimSpace(profile.Peer.Endpoint) == "" {
		return errors.New("gateway returned profile without peer endpoint")
	}
	if len(profile.Interface.Addresses) == 0 {
		return errors.New("gateway returned profile without interface addresses")
	}
	if strings.TrimSpace(profile.Peer.PublicKey) == "" {
		return errors.New("gateway returned profile without peer public key")
	}
	return nil
}

func exerciseTunnelTraffic(ctx context.Context, output *terminalOutput, profile *amnezia.Profile, traffic trafficConfig) error {
	if traffic.PingCount < 0 {
		return errors.New("ping count must not be negative")
	}
	if traffic.HTTPCount < 0 {
		return errors.New("HTTP count must not be negative")
	}
	if traffic.StepTimeout <= 0 {
		traffic.StepTimeout = defaultTrafficTimeout
	}

	tunDev, err := buildProfileVTun(profile)
	if err != nil {
		return err
	}
	network := gonnect.DetachNetwork((&gonnect.NativeConfig{}).Build(), nil, nil)
	bind := conn.NewDefaultBind(network)
	dev := device.NewDevice(tunDev, bind, newDeviceOutputLogger(output), nil, device.DeviceOptions{})
	defer func() {
		dev.Close()
		if err := network.Down(); err != nil {
			output.Tracef("Native network cleanup error: %v", err)
		}
	}()

	output.Printf("Configure VTun: addrs=%d dns=%d mtu=%d", len(tunDev.LocalAddrs()), len(profile.Interface.DNS), profile.Interface.MTU)
	if err := applyProfileToDevice(dev, profile); err != nil {
		return err
	}
	output.Tracef("Execute pre-connect actions: count=%d", len(profile.PreConnect))
	if err := executePreConnectActions(ctx, output, profile.PreConnect); err != nil {
		return err
	}
	output.Printf("Bring WireGuard device up")
	if err := dev.Up(); err != nil {
		return fmt.Errorf("bring WireGuard device up: %w", err)
	}

	if len(traffic.IPCheckURLs) > 0 {
		if err := runVisibleIPCheck(ctx, output, tunDev, traffic.IPCheckURLs, traffic.StepTimeout); err != nil {
			return err
		}
	}
	if traffic.PingCount > 0 {
		if err := runPings(ctx, output, tunDev, traffic.Host, traffic.PingCount, traffic.StepTimeout); err != nil {
			return err
		}
	}
	if traffic.HTTPCount > 0 {
		if err := runHTTPRequests(ctx, output, tunDev, traffic.HTTPURL, traffic.HTTPCount, traffic.StepTimeout); err != nil {
			return err
		}
	}
	return nil
}

func parseListFlag(value string) []string {
	var values []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			values = append(values, item)
		}
	}
	return values
}

func buildProfileVTun(profile *amnezia.Profile) (*vtun.VTun, error) {
	localAddrs, err := parseProfileAddrs(profile.Interface.Addresses)
	if err != nil {
		return nil, err
	}
	dnsServers, err := parseDNSAddrs(profile.Interface.DNS)
	if err != nil {
		return nil, err
	}
	opts := &vtun.Opts{
		Name:           "amnesia-live-e2e",
		LocalAddrs:     localAddrs,
		DnsServers:     dnsServers,
		NoLoopbackAddr: true,
	}
	if profile.Interface.MTU > 0 {
		opts.NetStackOpts = &helpers.Opts{MTU: profile.Interface.MTU}
	}
	tunDev, err := opts.Build()
	if err != nil {
		return nil, fmt.Errorf("build VTun: %w", err)
	}
	select {
	case <-tunDev.Events():
		return tunDev, nil
	case <-time.After(5 * time.Second):
		_ = tunDev.Close()
		return nil, errors.New("timed out waiting for VTun event")
	}
}

func parseProfileAddrs(values []string) ([]netip.Addr, error) {
	addrs := make([]netip.Addr, 0, len(values))
	seen := make(map[netip.Addr]struct{}, len(values))
	for _, value := range values {
		addr, err := parseAddrOrPrefix(value)
		if err != nil {
			return nil, fmt.Errorf("parse interface address %q: %w", value, err)
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		addrs = append(addrs, addr)
	}
	if len(addrs) == 0 {
		return nil, errors.New("profile has no interface addresses for VTun")
	}
	return addrs, nil
}

func parseDNSAddrs(values []string) ([]netip.Addr, error) {
	addrs := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return nil, fmt.Errorf("parse DNS address %q: %w", value, err)
		}
		addrs = append(addrs, addr)
	}
	return addrs, nil
}

func parseAddrOrPrefix(value string) (netip.Addr, error) {
	value = strings.TrimSpace(value)
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Addr(), nil
	}
	return netip.ParseAddr(value)
}

func applyProfileToDevice(dev device.DeviceAPI, profile *amnezia.Profile) error {
	return amnezia.ApplyProfile(dev, profile)
}

func executePreConnectActions(ctx context.Context, output *terminalOutput, actions []amnezia.PreConnectAction) error {
	var firstErr error
	for index, action := range actions {
		if err := executePreConnectAction(ctx, output, index+1, action); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func executePreConnectAction(ctx context.Context, output *terminalOutput, index int, action amnezia.PreConnectAction) error {
	timeout := action.Timeout
	if timeout <= 0 {
		timeout = defaultTrafficTimeout
	}
	payload, err := amnezia.BuildTaggedPayload(action.PayloadSpec, nil)
	if err != nil {
		return fmt.Errorf("pre-connect action %d payload: %w", index, err)
	}
	expected, err := amnezia.BuildTaggedPayload(action.ExpectedResponseSpec, nil)
	if err != nil {
		return fmt.Errorf("pre-connect action %d expected response: %w", index, err)
	}
	protocol := strings.ToLower(strings.TrimSpace(action.Protocol))
	output.Tracef("Pre-connect action %d: protocol=%s endpoint=%s timeout=%s payload_bytes=%d expected_response_bytes=%d",
		index, protocol, action.Endpoint, timeout, len(payload), len(expected))
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var network string
	switch protocol {
	case "tcp":
		network = "tcp"
	case "udp":
		network = "udp"
	default:
		return fmt.Errorf("pre-connect action %d: unsupported protocol %q", index, action.Protocol)
	}
	dialer := net.Dialer{}
	socket, err := dialer.DialContext(actionCtx, network, action.Endpoint)
	if err != nil {
		return fmt.Errorf("pre-connect action %d dial: %w", index, err)
	}
	defer func() { _ = socket.Close() }()
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := actionCtx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := socket.SetDeadline(deadline); err != nil {
		return fmt.Errorf("pre-connect action %d deadline: %w", index, err)
	}
	if _, err := socket.Write(payload); err != nil {
		return fmt.Errorf("pre-connect action %d write: %w", index, err)
	}
	if len(expected) > 0 {
		reply := make([]byte, len(expected))
		if _, err := io.ReadFull(socket, reply); err != nil {
			return fmt.Errorf("pre-connect action %d read expected response: %w", index, err)
		}
		if !bytes.Equal(reply, expected) {
			return fmt.Errorf("pre-connect action %d expected response mismatch", index)
		}
	}
	output.Tracef("Pre-connect action %d complete", index)
	return nil
}

func runPings(ctx context.Context, output *terminalOutput, tunDev *vtun.VTun, host string, count int, timeout time.Duration) error {
	if strings.TrimSpace(host) == "" {
		return errors.New("traffic host is empty")
	}
	resolveCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	target, network, err := resolvePingTarget(resolveCtx, tunDev, host)
	if err != nil {
		return err
	}
	output.Printf("Ping target: host=%s ip=%s network=%s attempts=%d timeout=%s", host, target, network, count, timeout)
	successes := 0
	var lastErr error
	for i := 1; i <= count; i++ {
		start := time.Now()
		if err := pingOnce(tunDev, target, timeout); err != nil {
			lastErr = err
			output.Tracef("Ping attempt %d failed: duration=%s error=%v", i, time.Since(start).Round(time.Millisecond), err)
			continue
		}
		successes++
		output.Tracef("Ping attempt %d passed: duration=%s", i, time.Since(start).Round(time.Millisecond))
	}
	if successes == 0 {
		return fmt.Errorf("all ping attempts failed: %w", lastErr)
	}
	output.Successf("Ping summary: passed=%d failed=%d", successes, count-successes)
	return nil
}

func resolvePingTarget(ctx context.Context, tunDev *vtun.VTun, host string) (netip.Addr, string, error) {
	network := "ip4"
	if !hasLocalFamily(tunDev, true) && hasLocalFamily(tunDev, false) {
		network = "ip6"
	}
	addrs, err := tunDev.LookupNetIP(ctx, network, host)
	if err != nil {
		return netip.Addr{}, network, fmt.Errorf("resolve ping target %s over VTun: %w", host, err)
	}
	for _, addr := range addrs {
		if addr.IsValid() {
			return addr, network, nil
		}
	}
	return netip.Addr{}, network, fmt.Errorf("resolve ping target %s over VTun: no addresses", host)
}

func hasLocalFamily(tunDev *vtun.VTun, v4 bool) bool {
	for _, addr := range tunDev.LocalAddrs() {
		if addr.Is4() == v4 {
			return true
		}
	}
	return false
}

func pingOnce(tunDev *vtun.VTun, target netip.Addr, timeout time.Duration) error {
	pingConn, err := tunDev.DialPingAddr(netip.Addr{}, target)
	if err != nil {
		return err
	}
	defer func() { _ = pingConn.Close() }()
	if err := pingConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	payload := []byte("wgo amnesia live e2e ping")
	if _, err := pingConn.Write(payload); err != nil {
		return err
	}
	reply := make([]byte, len(payload))
	n, err := pingConn.Read(reply)
	if err != nil {
		return err
	}
	if !bytes.Equal(reply[:n], payload) {
		return errors.New("unexpected ping reply payload")
	}
	return nil
}

func runVisibleIPCheck(ctx context.Context, output *terminalOutput, tunDev *vtun.VTun, urls []string, timeout time.Duration) error {
	outsideTransport := http.DefaultTransport.(*http.Transport).Clone()
	tunnelTransport := http.DefaultTransport.(*http.Transport).Clone()
	outsideTransport.DisableKeepAlives = true
	tunnelTransport.DisableKeepAlives = true
	tunnelTransport.DialContext = tunDev.Dial

	outsideClient := http.Client{
		Transport: outsideTransport,
		Timeout:   timeout,
	}
	tunnelClient := http.Client{
		Transport: tunnelTransport,
		Timeout:   timeout,
	}

	output.Printf("Check visible public IP: services=%d timeout=%s", len(urls), timeout)
	outsideReport, outsideURL, err := firstVisibleIP(ctx, output, &outsideClient, urls, "outside")
	if err != nil {
		return fmt.Errorf("outside visible IP check: %w", err)
	}
	tunnelReport, tunnelURL, err := firstVisibleIP(ctx, output, &tunnelClient, urls, "tunnel")
	if err != nil {
		return fmt.Errorf("tunnel visible IP check: %w", err)
	}
	if outsideReport.IP == tunnelReport.IP {
		return fmt.Errorf("visible IP did not change through tunnel: outside=%s via=%s", outsideReport.IP, tunnelReport.IP)
	}
	output.Highlightf("Visible public IP changed: outside=%s outside_service=%s outside_geo=%q tunnel=%s tunnel_service=%s tunnel_geo=%q",
		outsideReport.IP, outsideURL, outsideReport.Geo.LogValue(), tunnelReport.IP, tunnelURL, tunnelReport.Geo.LogValue())
	return nil
}

func firstVisibleIP(ctx context.Context, output *terminalOutput, client *http.Client, urls []string, label string) (visibleIPReport, string, error) {
	var errs []error
	for _, url := range urls {
		report, err := fetchVisibleIP(ctx, client, url)
		if err != nil {
			output.Tracef("Visible IP service failed: route=%s url=%s error=%v", label, url, err)
			errs = append(errs, fmt.Errorf("%s: %w", url, err))
			continue
		}
		output.Printf("Visible IP via %s: ip=%s service=%s geo=%q", label, report.IP, url, report.Geo.LogValue())
		return report, url, nil
	}
	return visibleIPReport{}, "", errors.Join(errs...)
}

func fetchVisibleIP(ctx context.Context, client *http.Client, url string) (visibleIPReport, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return visibleIPReport{}, fmt.Errorf("build request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return visibleIPReport{}, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return visibleIPReport{}, fmt.Errorf("status = %s", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err != nil {
		return visibleIPReport{}, fmt.Errorf("read body: %w", err)
	}
	report, err := parseVisibleIPReport(body)
	if err != nil {
		return visibleIPReport{}, err
	}
	return report, nil
}

func parseVisibleIPReport(body []byte) (visibleIPReport, error) {
	value := strings.TrimSpace(string(body))
	var geo visibleIPGeo
	if strings.HasPrefix(value, "{") {
		var payload struct {
			IP          string  `json:"ip"`
			City        string  `json:"city"`
			Region      string  `json:"region"`
			RegionName  string  `json:"region_name"`
			Country     string  `json:"country"`
			CountryName string  `json:"country_name"`
			CountryCode string  `json:"country_code"`
			CountryISO  string  `json:"country_iso"`
			Timezone    string  `json:"timezone"`
			TimeZone    string  `json:"time_zone"`
			ASN         string  `json:"asn"`
			ASNOrg      string  `json:"asn_org"`
			Org         string  `json:"org"`
			Location    string  `json:"loc"`
			Latitude    float64 `json:"latitude"`
			Longitude   float64 `json:"longitude"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return visibleIPReport{}, fmt.Errorf("parse visible IP JSON: %w", err)
		}
		value = strings.TrimSpace(payload.IP)
		geo = visibleIPGeo{
			City:        strings.TrimSpace(payload.City),
			Region:      firstNonEmpty(payload.RegionName, payload.Region),
			Country:     countryName(payload.Country, payload.CountryName, payload.CountryCode, payload.CountryISO),
			CountryCode: firstNonEmpty(payload.CountryISO, payload.CountryCode, countryCode(payload.Country)),
			Timezone:    firstNonEmpty(payload.TimeZone, payload.Timezone),
			ASN:         strings.TrimSpace(payload.ASN),
			Org:         firstNonEmpty(payload.ASNOrg, payload.Org),
			Location:    locationValue(payload.Location, payload.Latitude, payload.Longitude),
		}
	}
	ip, err := netip.ParseAddr(value)
	if err != nil {
		return visibleIPReport{}, fmt.Errorf("parse visible IP %q: %w", value, err)
	}
	return visibleIPReport{IP: ip.Unmap(), Geo: geo}, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func countryName(country, countryNameValue, countryCodeValue, countryISO string) string {
	country = strings.TrimSpace(country)
	if country != "" && countryCode(country) == "" {
		return country
	}
	if countryNameValue = strings.TrimSpace(countryNameValue); countryNameValue != "" {
		return countryNameValue
	}
	if countryCodeValue = strings.TrimSpace(countryCodeValue); countryCodeValue != "" {
		return countryCodeValue
	}
	return strings.TrimSpace(countryISO)
}

func countryCode(country string) string {
	country = strings.TrimSpace(country)
	if len(country) == 2 {
		return strings.ToUpper(country)
	}
	return ""
}

func locationValue(location string, latitude, longitude float64) string {
	if location = strings.TrimSpace(location); location != "" {
		return location
	}
	if latitude != 0 || longitude != 0 {
		return fmt.Sprintf("%.4f,%.4f", latitude, longitude)
	}
	return ""
}

func (geo visibleIPGeo) LogValue() string {
	parts := make([]string, 0, 8)
	appendPart := func(name, value string) {
		if value = strings.TrimSpace(value); value != "" {
			parts = append(parts, name+"="+value)
		}
	}
	appendPart("city", geo.City)
	appendPart("region", geo.Region)
	appendPart("country", geo.Country)
	appendPart("country_code", geo.CountryCode)
	appendPart("timezone", geo.Timezone)
	appendPart("asn", geo.ASN)
	appendPart("org", geo.Org)
	appendPart("loc", geo.Location)
	return strings.Join(parts, " ")
}

func runHTTPRequests(ctx context.Context, output *terminalOutput, tunDev *vtun.VTun, url string, count int, timeout time.Duration) error {
	if strings.TrimSpace(url) == "" {
		return errors.New("traffic HTTP URL is empty")
	}
	client := http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext:       tunDev.Dial,
		},
		Timeout: timeout,
	}
	output.Printf("HTTP target: url=%s requests=%d timeout=%s", url, count, timeout)
	for i := 1; i <= count; i++ {
		start := time.Now()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("build HTTP request: %w", err)
		}
		response, err := client.Do(request)
		if err != nil {
			return fmt.Errorf("HTTP request %d over VTun: %w", i, err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 512))
		closeErr := response.Body.Close()
		if readErr != nil {
			return fmt.Errorf("HTTP request %d read body: %w", i, readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("HTTP request %d close body: %w", i, closeErr)
		}
		if response.StatusCode < 200 || response.StatusCode >= 400 {
			return fmt.Errorf("HTTP request %d status = %s", i, response.Status)
		}
		output.Tracef("HTTP request %d passed: status=%s duration=%s body_prefix=%q",
			i, response.Status, time.Since(start).Round(time.Millisecond), string(body))
	}
	return nil
}

func effectiveMetadata(metadata amnezia.ClientMetadata) (amnezia.ClientMetadata, error) {
	if metadata.OSVersion == "" {
		metadata.OSVersion = defaultOSVersion()
	}
	if metadata.AppVersion == "" {
		metadata.AppVersion = amnezia.DefaultOfficialAppVersion
	}
	if metadata.CLIName == "" {
		metadata.CLIName = amnezia.DefaultOfficialCLIName
	}
	if metadata.Distribution == "" {
		metadata.Distribution = "github"
	}
	if metadata.Language == "" {
		metadata.Language = "en"
	}
	if metadata.InstallationUUID == "" {
		uuid, err := newUUID()
		if err != nil {
			return amnezia.ClientMetadata{}, err
		}
		metadata.InstallationUUID = uuid
	}
	return metadata, nil
}

func ensureInstallationUUID(output *terminalOutput, configPath string, configBytes []byte, config *liveConfig) (bool, error) {
	if strings.TrimSpace(config.Metadata.InstallationUUID) != "" {
		return false, nil
	}
	uuid, err := newUUID()
	if err != nil {
		return false, err
	}
	config.Metadata.InstallationUUID = uuid
	output.Highlightf("Generated installation UUID: %q", uuid)

	var root map[string]json.RawMessage
	if err := json.Unmarshal(configBytes, &root); err != nil {
		return false, fmt.Errorf("parse live config object: %w", err)
	}
	metadata := make(map[string]json.RawMessage)
	if rawMetadata, ok := root["metadata"]; ok && strings.TrimSpace(string(rawMetadata)) != "null" {
		if err := json.Unmarshal(rawMetadata, &metadata); err != nil {
			return false, fmt.Errorf("parse live config metadata object: %w", err)
		}
	}
	uuidBytes, err := json.Marshal(uuid)
	if err != nil {
		return false, fmt.Errorf("marshal installation UUID: %w", err)
	}
	metadata["installation_uuid"] = uuidBytes
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return false, fmt.Errorf("marshal live config metadata: %w", err)
	}
	root["metadata"] = metadataBytes

	updated, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return false, fmt.Errorf("marshal live config: %w", err)
	}
	updated = append(updated, '\n')
	if err := os.WriteFile(configPath, updated, 0600); err != nil {
		return false, fmt.Errorf("save live config: %w", err)
	}
	return true, nil
}

func defaultOSVersion() string {
	fallback := runtime.GOOS + "/" + runtime.GOARCH
	if runtime.GOOS != "linux" {
		return fallback
	}
	prettyName, err := linuxPrettyName("/etc/os-release")
	if err != nil || prettyName == "" {
		return fallback
	}
	return fmt.Sprintf("%s (%s)", prettyName, fallback)
}

func linuxPrettyName(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key != "PRETTY_NAME" {
			continue
		}
		value = strings.TrimSpace(value)
		if unquoted, err := strconv.Unquote(value); err == nil {
			value = unquoted
		}
		return strings.TrimSpace(value), nil
	}
	return "", nil
}

func newUUID() (string, error) {
	var raw [16]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return "", fmt.Errorf("generate installation UUID: %w", err)
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16]), nil
}

func logProfileSummary(output *terminalOutput, profile *amnezia.Profile) {
	host, _, err := net.SplitHostPort(profile.Peer.Endpoint)
	if err != nil {
		host = profile.Peer.Endpoint
	}
	output.Highlightf("Profile received: name=%q host_name=%q endpoint_host=%q country=%q protocol=%q",
		profile.Name, profile.HostName, host, profile.API.ServerCountryCode, profile.AmneziaWG.ProtocolVersion)
	output.Printf("Profile details: addresses=%d dns=%d allowed_ips=%d mtu=%d pre_connect_actions=%d",
		len(profile.Interface.Addresses), len(profile.Interface.DNS), len(profile.Peer.AllowedIPs), profile.Interface.MTU, len(profile.PreConnect))
}
