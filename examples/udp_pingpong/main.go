// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 AsciiMoth

package main

import (
	"context"
	"fmt"
	"log"
	"net"
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

	ctx := context.Background()
	serverConn, err := pair.SecondNet.ListenUDP(ctx, "udp4", net.JoinHostPort(pair.SecondIP.String(), "0"))
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		_ = serverConn.Close()
	}()

	clientConn, err := pair.FirstNet.DialUDP(ctx, "udp4", "", serverConn.LocalAddr().String())
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		_ = clientConn.Close()
	}()

	serverDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 256)
		for i := 0; i < 5; i++ {
			for {
				if err := serverConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					serverDone <- err
					return
				}
				n, addr, err := serverConn.ReadFrom(buf)
				if err != nil {
					serverDone <- err
					return
				}
				want := fmt.Sprintf("ping %d over udp", i)
				if got := string(buf[:n]); got != want {
					continue
				}
				reply := fmt.Sprintf("pong %d over udp", i)
				if err := serverConn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
					serverDone <- err
					return
				}
				if _, err := serverConn.WriteTo([]byte(reply), addr); err != nil {
					serverDone <- err
					return
				}
				break
			}
		}
		serverDone <- nil
	}()

	buf := make([]byte, 256)
	for i := 0; i < 5; i++ {
		msg := []byte(fmt.Sprintf("ping %d over udp", i))
		wantReply := fmt.Sprintf("pong %d over udp", i)

		received := false
		for attempt := 0; attempt < 8; attempt++ {
			if err := clientConn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
				log.Fatal(err)
			}
			if _, err := clientConn.Write(msg); err != nil {
				log.Fatal(err)
			}
			if err := clientConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
				log.Fatal(err)
			}
			n, _, err := clientConn.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				log.Fatal(err)
			}
			if got := string(buf[:n]); got == wantReply {
				log.Printf("round=%d reply=%q", i, got)
				received = true
				break
			}
		}

		if !received {
			log.Fatalf("did not receive %q", wantReply)
		}
	}

	if err := <-serverDone; err != nil {
		log.Fatal(err)
	}
}
