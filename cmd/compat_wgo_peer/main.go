//go:build linux

package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	conn "github.com/asciimoth/batchudp"
	"github.com/asciimoth/gonnect/native"
	"github.com/asciimoth/tuntap"
	"github.com/asciimoth/wgo/device"
	"github.com/asciimoth/wgo/ipc"
)

type config struct {
	iface      string
	tunLocal   string
	peerRoute  string
	listenPort int
	mtu        int
	logLevel   string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "compat-wgo-peer: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := parseFlags()

	tunDev, err := tuntap.CreateTUN(cfg.iface, cfg.mtu)
	if err != nil {
		return fmt.Errorf("create tun: %w", err)
	}
	ifName, err := tunDev.Name()
	if err != nil {
		_ = tunDev.Close()
		return fmt.Errorf("load tun name: %w", err)
	}
	if err := configureTUN(ifName, cfg.tunLocal, cfg.peerRoute, cfg.mtu); err != nil {
		_ = tunDev.Close()
		return err
	}

	network := (&native.Config{}).Build()
	bind := conn.NewDefaultBind(network)
	logger, err := parseLogLevel(cfg.logLevel)
	if err != nil {
		_ = tunDev.Close()
		_ = network.Down()
		return err
	}
	dev := device.NewDevice(tunDev, bind, device.NewLogger(logger, "compat/wgo: "))

	if err := dev.SetListenPort(uint16(cfg.listenPort)); err != nil {
		dev.Close()
		_ = network.Down()
		return fmt.Errorf("set listen port: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		_ = network.Down()
		return fmt.Errorf("bring device up: %w", err)
	}

	socketFile, err := ipc.UAPIOpen(ifName)
	if err != nil {
		dev.Close()
		_ = network.Down()
		return fmt.Errorf("open uapi socket: %w", err)
	}
	defer socketFile.Close()

	listener, err := ipc.UAPIListen(ifName, socketFile)
	if err != nil {
		dev.Close()
		_ = network.Down()
		return fmt.Errorf("listen on uapi socket: %w", err)
	}

	errCh := make(chan error, 1)
	go serveUAPI(listener, dev, errCh)

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	select {
	case sig := <-sigCh:
		err = fmt.Errorf("received signal %s", sig)
	case err = <-errCh:
	}

	_ = listener.Close()
	dev.Close()
	if downErr := network.Down(); downErr != nil && err == nil {
		err = downErr
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
		return nil
	}
	return err
}

func serveUAPI(listener net.Listener, dev *device.Device, errCh chan<- error) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		go dev.IpcHandle(conn)
	}
}

func parseFlags() config {
	cfg := config{}
	flag.StringVar(&cfg.iface, "iface", "wg0", "wireguard interface name")
	flag.StringVar(&cfg.tunLocal, "tun-local", "10.66.0.2/32", "local tunnel address in CIDR notation")
	flag.StringVar(&cfg.peerRoute, "peer-route", "10.66.0.1/32", "peer route in CIDR notation")
	flag.IntVar(&cfg.listenPort, "listen-port", 51820, "udp listen port")
	flag.IntVar(&cfg.mtu, "mtu", 1420, "interface MTU")
	flag.StringVar(&cfg.logLevel, "log-level", "info", "log level: silent,error,warn,info,debug")
	flag.Parse()
	return cfg
}

func parseLogLevel(level string) (device.LogLevel, error) {
	switch level {
	case "silent":
		return device.LogLevelSilent, nil
	case "error":
		return device.LogLevelError, nil
	case "warn":
		return device.LogLevelWarn, nil
	case "info":
		return device.LogLevelInfo, nil
	case "debug", "verbose":
		return device.LogLevelDebug, nil
	default:
		return 0, fmt.Errorf("unsupported log level %q", level)
	}
}

func configureTUN(ifName, tunLocal, peerRoute string, mtu int) error {
	if err := runCommand(5*time.Second, "ip", "addr", "replace", tunLocal, "dev", ifName); err != nil {
		return fmt.Errorf("assign %s to %s: %w", tunLocal, ifName, err)
	}
	if err := runCommand(5*time.Second, "ip", "link", "set", "dev", ifName, "mtu", fmt.Sprintf("%d", mtu), "up"); err != nil {
		return fmt.Errorf("bring %s up: %w", ifName, err)
	}
	if err := runCommand(5*time.Second, "ip", "route", "replace", peerRoute, "dev", ifName); err != nil {
		return fmt.Errorf("route %s via %s: %w", peerRoute, ifName, err)
	}
	return nil
}

func runCommand(timeout time.Duration, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	timer := time.AfterFunc(timeout, func() {
		_ = cmd.Process.Kill()
	})
	defer timer.Stop()
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %v: %w", name, args, err)
	}
	return nil
}
