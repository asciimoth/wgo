package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"time"

	"github.com/asciimoth/gonnect-netstack/vtun"
	"github.com/asciimoth/wgo/examples/internal/e2e"
)

const (
	swappedClientMWO = 48
	swappedClientMRO = 32
)

func main() {
	pair, err := e2e.New()
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := pair.Close(); err != nil {
			log.Printf("cleanup error: %v", err)
		}
	}()

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("server received %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
			_, _ = io.WriteString(w, "hello over wireguard")
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}

	listener, err := pair.FirstNet.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(pair.FirstIP, 8080).String())
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- server.Serve(listener)
	}()

	time.Sleep(250 * time.Millisecond)

	url := fmt.Sprintf("http://%s/", netip.AddrPortFrom(pair.FirstIP, 8080))
	if err := doRequest("initial", pair.SecondNet, url); err != nil {
		log.Fatal(err)
	}

	log.Printf("swapping client vtun to MWO=%d MRO=%d", swappedClientMWO, swappedClientMRO)
	if err := pair.SwapSecondVTun(swappedClientMWO, swappedClientMRO); err != nil {
		log.Fatal(err)
	}

	if err := doRequest("after swap", pair.SecondNet, url); err != nil {
		log.Fatal(err)
	}

	if err := server.Shutdown(context.Background()); err != nil {
		log.Fatal(err)
	}
	if err := <-serverDone; err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func doRequest(label string, clientNet *vtun.VTun, url string) error {
	client := http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext:       clientNet.Dial,
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("%s request: %w", label, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%s read body: %w", label, err)
	}

	log.Printf("%s client status=%s body=%q", label, resp.Status, string(body))
	return nil
}
