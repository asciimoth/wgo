package main

import (
	"context"
	"fmt"
	"io"
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
	listener, err := pair.SecondNet.ListenTCP(ctx, "tcp4", net.JoinHostPort(pair.SecondIP.String(), "0"))
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		buf := make([]byte, 256)
		for i := 0; i < 5; i++ {
			if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				serverDone <- err
				return
			}
			n, err := conn.Read(buf)
			if err != nil {
				serverDone <- err
				return
			}
			want := fmt.Sprintf("ping %d over tcp", i)
			if got := string(buf[:n]); got != want {
				serverDone <- fmt.Errorf("server got %q, want %q", got, want)
				return
			}
			reply := fmt.Sprintf("pong %d over tcp", i)
			if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				serverDone <- err
				return
			}
			if _, err := io.WriteString(conn, reply); err != nil {
				serverDone <- err
				return
			}
		}

		serverDone <- nil
	}()

	conn, err := pair.FirstNet.DialTCP(ctx, "tcp4", "", listener.Addr().String())
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	buf := make([]byte, 256)
	for i := 0; i < 5; i++ {
		msg := fmt.Sprintf("ping %d over tcp", i)
		if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			log.Fatal(err)
		}
		if _, err := io.WriteString(conn, msg); err != nil {
			log.Fatal(err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			log.Fatal(err)
		}
		n, err := conn.Read(buf)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("round=%d reply=%q", i, string(buf[:n]))
	}

	if err := <-serverDone; err != nil {
		log.Fatal(err)
	}
}
