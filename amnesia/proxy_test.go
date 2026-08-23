package amnezia

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Frozen from the verified 5.0.1.5 production endpoints.json on 2026-08-22.
const officialEncryptedProxyFixture = "sDrVtp2CSkbN3zJ3x/gKO2Ufe5WIOTWvnFVXy3wHwy8TxXzd4RUmaNIrgMF2r5LkCmaugR3wpbUBTlOgI5C4aknLwkhH1yTzFV9snEHNsUiUEjDqZLem43FEfR7vVtiKNocS1q2OqRoAP8vhJ6lNImkaSktnAEeF7wVnyGnrWZr2T8AW7FnfqB3uP0sc7U6cbp7BanAn2b/bCMmN3Rtv5bGKbqbgqa1pLnq5M5wDzDvU2xn32lWXJR9FhjiA1n9E"

func encryptedProxyFixture(t *testing.T, publicPEM []byte, urls []string) []byte {
	t.Helper()
	plain, err := json.Marshal(urls)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum512(publicPEM)
	encrypted, err := encryptAES256CBC(plain, digest[:32], digest[32:48])
	if err != nil {
		t.Fatal(err)
	}
	return []byte(base64.StdEncoding.EncodeToString(encrypted))
}

func TestOfficialProxyListFixture(t *testing.T) {
	// This proves that the exact PEM bytes and SHA-512/AES split match the
	// official binary.
	if _, err := base64.StdEncoding.DecodeString(officialEncryptedProxyFixture); err != nil {
		t.Fatalf("bad frozen fixture: %v", err)
	}
	got, err := decryptProxyList([]byte(officialEncryptedProxyFixture), []byte(DefaultGatewayPublicKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"https://gw-px-le-15436-3w5hsuiikq-ey.a.run.app/",
		"https://sxg5kzkftu.eu-central-1.awsapprunner.com/",
		"https://gw-px-le-4352.kindstone-1374c603.germanywestcentral.azurecontainerapps.io/",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("proxy list = %#v, want %#v", got, want)
	}
	if got := proxyStorageNames("amnezia-free", "xx")[0]; got != "ZW5kcG9pbnRzLWFtbmV6aWEtZnJlZS14eA.json" {
		t.Fatalf("service-specific S3 object name = %q", got)
	}
}

func TestS3CompatibleDiscoveryAndEncryptedCache(t *testing.T) {
	expectedPath := "/" + proxyStorageNames("amnezia-free", "xx")[0]
	var requestedPath string
	storage := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestedPath = request.URL.Path
		if request.URL.Path != expectedPath {
			http.NotFound(writer, request)
			return
		}
		_, _ = writer.Write([]byte(officialEncryptedProxyFixture))
	}))
	t.Cleanup(storage.Close)
	cache := NewMemoryProxyCache()
	client, err := NewClient(ClientOptions{
		HTTPClient:          storage.Client(),
		GatewayURL:          storage.URL,
		GatewayPublicKeyPEM: []byte(DefaultGatewayPublicKeyPEM),
		PrimaryS3URLs:       []string{storage.URL},
		FallbackS3URLs:      []string{},
		StaticProxyURLs:     []string{},
		ProxyCache:          cache,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := client.discoverProxyURLs(context.Background(), "amnezia-free", "xx")
	if requestedPath != expectedPath || !reflect.DeepEqual(got, DefaultStaticProxyURLs()) {
		t.Fatalf("S3 discovery path=%q URLs=%#v", requestedPath, got)
	}
	cachedClient, err := NewClient(ClientOptions{
		HTTPClient:          explicitTestHTTPClient(),
		GatewayURL:          "https://gateway.example.test/",
		GatewayPublicKeyPEM: []byte(DefaultGatewayPublicKeyPEM),
		PrimaryS3URLs:       []string{},
		FallbackS3URLs:      []string{},
		StaticProxyURLs:     []string{},
		DisableS3Discovery:  true,
		ProxyCache:          cache,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := cachedClient.discoverProxyURLs(context.Background(), "amnezia-free", "xx"); !reflect.DeepEqual(got, DefaultStaticProxyURLs()) {
		t.Fatalf("cached proxy URLs = %#v", got)
	}
}

func TestHTTPSProxyListUsesTrustedLocalCA(t *testing.T) {
	_, publicPEM := newTestRSA(t)
	expectedPath := "/" + proxyStorageNames("amnezia-free", "xx")[0]
	wantURLs := []string{"https://proxy-secure.example.test/"}
	var requestedPath string
	var sawTLS bool
	storage := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestedPath = request.URL.Path
		sawTLS = request.TLS != nil
		if request.URL.Path != expectedPath {
			http.NotFound(writer, request)
			return
		}
		_, _ = writer.Write(encryptedProxyFixture(t, publicPEM, wantURLs))
	}))
	t.Cleanup(storage.Close)

	transport, ok := storage.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("test HTTPS client transport = %T, want *http.Transport", storage.Client().Transport)
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("test HTTPS client has no TLS config")
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("test HTTPS client must trust the local CA, not disable verification")
	}

	client, err := NewClient(ClientOptions{
		HTTPClient:          storage.Client(),
		GatewayURL:          "https://gateway.example.test/",
		GatewayPublicKeyPEM: publicPEM,
		PrimaryS3URLs:       []string{storage.URL},
		FallbackS3URLs:      []string{},
		StaticProxyURLs:     []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := client.discoverProxyURLs(context.Background(), "amnezia-free", "xx")
	if requestedPath != expectedPath || !sawTLS || !reflect.DeepEqual(got, wantURLs) {
		t.Fatalf("HTTPS discovery path=%q sawTLS=%v URLs=%#v, want path=%q URLs=%#v",
			requestedPath, sawTLS, got, expectedPath, wantURLs)
	}
}

func TestS3DiscoveryGenericFallbackAndCacheAfterCorruption(t *testing.T) {
	_, publicPEM := newTestRSA(t)
	goodURLs := []string{"https://proxy-one.example.test/", "https://proxy-two.example.test/"}
	goodObject := encryptedProxyFixture(t, publicPEM, goodURLs)
	requested := make(map[string]int)
	corrupt := false
	storage := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requested[request.URL.Path]++
		switch request.URL.Path {
		case "/" + proxyStorageNames("amnezia-free", "xx")[0]:
			http.NotFound(writer, request)
		case "/endpoints.json":
			if corrupt {
				_, _ = writer.Write([]byte("not encrypted"))
				return
			}
			_, _ = writer.Write(goodObject)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer storage.Close()

	cache := NewMemoryProxyCache()
	client, err := NewClient(ClientOptions{
		HTTPClient:          storage.Client(),
		GatewayURL:          storage.URL,
		GatewayPublicKeyPEM: publicPEM,
		PrimaryS3URLs:       []string{storage.URL},
		FallbackS3URLs:      []string{},
		StaticProxyURLs:     []string{},
		ProxyCache:          cache,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := client.discoverProxyURLs(context.Background(), "amnezia-free", "xx"); !reflect.DeepEqual(got, goodURLs) {
		t.Fatalf("generic fallback URLs = %#v, want %#v", got, goodURLs)
	}
	if requested["/"+proxyStorageNames("amnezia-free", "xx")[0]] != 1 || requested["/endpoints.json"] != 1 {
		t.Fatalf("storage requests = %#v", requested)
	}

	corrupt = true
	if got := client.discoverProxyURLs(context.Background(), "amnezia-free", "xx"); !reflect.DeepEqual(got, goodURLs) {
		t.Fatalf("cached fallback URLs = %#v, want %#v", got, goodURLs)
	}
}

func TestCustomEmptyDiscoveryListsDoNotContactOfficialInfrastructure(t *testing.T) {
	calls := 0
	_, publicPEM := newTestRSA(t)
	client, err := NewClient(ClientOptions{
		HTTPClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls++
			t.Fatalf("unexpected request to %s", request.URL)
			return nil, nil
		})},
		GatewayURL:          "https://gateway.example.test",
		GatewayPublicKeyPEM: publicPEM,
		PrimaryS3URLs:       []string{},
		FallbackS3URLs:      []string{},
		StaticProxyURLs:     []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := client.discoverProxyURLs(context.Background(), "amnezia-free", "xx"); len(got) != 0 {
		t.Fatalf("proxy URLs = %#v, want none", got)
	}
	if calls != 0 {
		t.Fatalf("transport calls = %d, want 0", calls)
	}
}

func TestMinIOS3PathStyleProxyDiscovery(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
		t.Skip("docker daemon is not available")
	}

	_, publicPEM := newTestRSA(t)
	objectName := proxyStorageNames("amnezia-free", "xx")[0]
	wantURLs := []string{"https://proxy-minio.example.test/"}
	fixtureDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(fixtureDir, objectName), encryptedProxyFixture(t, publicPEM, wantURLs), 0600); err != nil {
		t.Fatal(err)
	}

	name := fmt.Sprintf("wgo-amnesia-minio-%d", time.Now().UnixNano())
	rootUser := "minioadmin"
	rootPassword := "minioadmin123"
	runDocker(t, ctx, "run", "-d", "--rm",
		"--name", name,
		"-e", "MINIO_ROOT_USER="+rootUser,
		"-e", "MINIO_ROOT_PASSWORD="+rootPassword,
		"-p", "127.0.0.1::9000",
		"minio/minio:latest",
		"server", "/data", "--console-address", ":9001")
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer stopCancel()
		_ = exec.CommandContext(stopCtx, "docker", "rm", "-f", name).Run()
	})

	hostURL := waitForMinIO(t, ctx, name)
	runDocker(t, ctx, "run", "--rm",
		"--network", "container:"+name,
		"-v", fixtureDir+":/fixture:ro",
		"-e", "MINIO_ROOT_USER="+rootUser,
		"-e", "MINIO_ROOT_PASSWORD="+rootPassword,
		"-e", "OBJECT_NAME="+objectName,
		"--entrypoint", "sh",
		"minio/mc:latest",
		"-ceu",
		"mc alias set local http://127.0.0.1:9000 \"$MINIO_ROOT_USER\" \"$MINIO_ROOT_PASSWORD\" >/dev/null && "+
			"mc mb --ignore-existing local/amnezia >/dev/null && "+
			"mc anonymous set download local/amnezia >/dev/null && "+
			"mc cp \"/fixture/$OBJECT_NAME\" \"local/amnezia/$OBJECT_NAME\" >/dev/null",
	)

	client, err := NewClient(ClientOptions{
		HTTPClient:          &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()},
		GatewayURL:          "https://gateway.example.test/",
		GatewayPublicKeyPEM: publicPEM,
		PrimaryS3URLs:       []string{hostURL + "/amnezia/"},
		FallbackS3URLs:      []string{},
		StaticProxyURLs:     []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := client.discoverProxyURLs(context.Background(), "amnezia-free", "xx"); !reflect.DeepEqual(got, wantURLs) {
		t.Fatalf("MinIO path-style URLs = %#v, want %#v", got, wantURLs)
	}
}

func runDocker(t *testing.T, ctx context.Context, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Env = append(os.Environ(),
		"MINIO_ROOT_USER=minioadmin",
		"MINIO_ROOT_PASSWORD=minioadmin123",
		"OBJECT_NAME="+proxyStorageNames("amnezia-free", "xx")[0],
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, output)
	}
}

func waitForMinIO(t *testing.T, ctx context.Context, name string) string {
	t.Helper()
	var hostURL string
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		default:
		}
		portOutput, err := exec.CommandContext(ctx, "docker", "port", name, "9000/tcp").Output()
		if err == nil {
			mapping := strings.TrimSpace(string(portOutput))
			if host, port, ok := strings.Cut(mapping, ":"); ok && port != "" {
				if host == "0.0.0.0" || host == "::" {
					host = "127.0.0.1"
				}
				hostURL = "http://" + host + ":" + port
				if minIOReady(ctx, hostURL) {
					return hostURL
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("MinIO did not become ready at %s", hostURL)
	return ""
}

func minIOReady(ctx context.Context, hostURL string) bool {
	requestCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, hostURL+"/minio/health/ready", nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode == http.StatusOK
}
