package amnezia

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func explicitTestHTTPClient() *http.Client {
	return &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()}
}

func TestNewClientRequiresExplicitHTTPClientAndTransport(t *testing.T) {
	if _, err := NewClient(ClientOptions{}); !errors.Is(err, ErrHTTPClientRequired) {
		t.Fatalf("nil HTTP client error = %v, want ErrHTTPClientRequired", err)
	}
	if _, err := NewClient(ClientOptions{HTTPClient: &http.Client{}}); !errors.Is(err, ErrHTTPTransportRequired) {
		t.Fatalf("implicit HTTP transport error = %v, want ErrHTTPTransportRequired", err)
	}
	var nilTransport *http.Transport
	if _, err := NewClient(ClientOptions{HTTPClient: &http.Client{Transport: nilTransport}}); !errors.Is(err, ErrHTTPTransportRequired) {
		t.Fatalf("typed nil HTTP transport error = %v, want ErrHTTPTransportRequired", err)
	}
	if _, err := NewClient(ClientOptions{HTTPClient: &http.Client{Transport: http.DefaultTransport}}); !errors.Is(err, ErrHTTPTransportRequired) {
		t.Fatalf("shared default HTTP transport error = %v, want ErrHTTPTransportRequired", err)
	}
}

func TestClientPinsAndUsesInjectedTransport(t *testing.T) {
	requestErr := errors.New("injected transport reached")
	firstCalls := 0
	secondCalls := 0
	callerHTTPClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		firstCalls++
		if request.URL.Host != "gateway.example.test" {
			t.Errorf("unexpected request host %q", request.URL.Host)
		}
		return nil, requestErr
	})}
	client, err := NewClient(ClientOptions{
		HTTPClient:         callerHTTPClient,
		GatewayURL:         "https://gateway.example.test",
		PrimaryS3URLs:      []string{},
		FallbackS3URLs:     []string{},
		StaticProxyURLs:    []string{},
		DisableS3Discovery: true,
		Metadata: ClientMetadata{
			OSVersion: "test", AppVersion: "test", CLIName: "test",
			Distribution: "test", Language: "en", InstallationUUID: "00000000-0000-4000-8000-000000000001",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Mutating the caller's http.Client after NewClient must not switch the
	// library onto another transport or an implicit default transport.
	callerHTTPClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		secondCalls++
		return nil, errors.New("replacement transport reached")
	})
	_, err = client.AcquireNonInteractive(context.Background(), testActivationKey(t), NegotiationOptions{})
	if !errors.Is(err, requestErr) {
		t.Fatalf("request error = %v, want injected transport error", err)
	}
	if firstCalls != 1 || secondCalls != 0 {
		t.Fatalf("transport calls: pinned=%d replacement=%d", firstCalls, secondCalls)
	}
}

func TestAllOutboundHTTPPathsUseInjectedTransport(t *testing.T) {
	requestErr := errors.New("injected transport reached")
	hosts := make(map[string]int)
	client, err := NewClient(ClientOptions{
		HTTPClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			hosts[request.URL.Host]++
			return nil, requestErr
		})},
		GatewayURL:         "https://gateway.example.test",
		PrimaryS3URLs:      []string{},
		FallbackS3URLs:     []string{},
		StaticProxyURLs:    []string{},
		DisableS3Discovery: true,
		Metadata: ClientMetadata{
			OSVersion: "test", AppVersion: "test", CLIName: "test",
			Distribution: "test", Language: "en", InstallationUUID: "00000000-0000-4000-8000-000000000001",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	attempt := client.doGatewayPost(context.Background(), "https://gateway.example.test", "v1/config", &encryptedEnvelope{
		body: []byte("{}"), requestID: "test-request",
	})
	if !errors.Is(attempt.err, requestErr) {
		t.Fatalf("gateway transport error = %v", attempt.err)
	}
	if _, err := client.fetchProxyObject(context.Background(), "https://storage.example.test/endpoints.json"); !errors.Is(err, requestErr) {
		t.Fatalf("storage transport error = %v", err)
	}
	if err := client.checkProxyHealth(context.Background(), "https://proxy.example.test"); !errors.Is(err, requestErr) {
		t.Fatalf("proxy health transport error = %v", err)
	}
	for _, host := range []string{"gateway.example.test", "storage.example.test", "proxy.example.test"} {
		if hosts[host] != 1 {
			t.Fatalf("injected transport calls for %s = %d, want 1", host, hosts[host])
		}
	}
}
