package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"time"

	"github.com/asciimoth/wgo/examples/internal/e2e"
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

	client := http.Client{
		Transport: &http.Transport{
			DialContext: pair.SecondNet.Dial,
		},
		Timeout: 10 * time.Second,
	}

	url := fmt.Sprintf("http://%s/", netip.AddrPortFrom(pair.FirstIP, 8080))
	resp, err := client.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("client status=%s body=%q", resp.Status, string(body))

	if err := server.Shutdown(context.Background()); err != nil {
		log.Fatal(err)
	}
	if err := <-serverDone; err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
