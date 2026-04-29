package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

type iperfResult struct {
	Error string `json:"error"`
	Start struct {
		TestStart struct {
			Protocol string  `json:"protocol"`
			Duration float64 `json:"duration"`
		} `json:"test_start"`
	} `json:"start"`
	End struct {
		SumSent     *iperfSum `json:"sum_sent"`
		SumReceived *iperfSum `json:"sum_received"`
		Sum         *iperfSum `json:"sum"`
	} `json:"end"`
}

type iperfSum struct {
	Seconds       float64 `json:"seconds"`
	Bytes         int64   `json:"bytes"`
	BitsPerSecond float64 `json:"bits_per_second"`
	Retransmits   int     `json:"retransmits"`
	JitterMs      float64 `json:"jitter_ms"`
	LostPackets   int64   `json:"lost_packets"`
	Packets       int64   `json:"packets"`
	LostPercent   float64 `json:"lost_percent"`
}

func main() {
	var (
		subject   = flag.String("subject", "", "benchmark subject")
		protocol  = flag.String("protocol", "", "protocol name")
		direction = flag.String("direction", "", "traffic direction")
		file      = flag.String("file", "", "path to iperf3 json output")
	)
	flag.Parse()

	if *subject == "" || *protocol == "" || *direction == "" || *file == "" {
		fmt.Fprintln(os.Stderr, "all flags are required")
		os.Exit(2)
	}

	raw, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", *file, err)
		os.Exit(1)
	}

	var result iperfResult
	if err := json.Unmarshal(raw, &result); err != nil {
		fmt.Fprintf(os.Stderr, "parse %s: %v\n", *file, err)
		os.Exit(1)
	}
	if result.Error != "" {
		fmt.Fprintf(os.Stderr, "iperf error in %s: %s\n", *file, result.Error)
		os.Exit(1)
	}

	switch *protocol {
	case "tcp":
		printTCPSummary(*subject, *direction, *file, &result)
	case "udp":
		printUDPSummary(*subject, *direction, *file, &result)
	default:
		fmt.Fprintf(os.Stderr, "unsupported protocol %q\n", *protocol)
		os.Exit(1)
	}
}

func printTCPSummary(subject, direction, file string, result *iperfResult) {
	if result.End.SumSent == nil || result.End.SumReceived == nil {
		fmt.Fprintf(os.Stderr, "missing tcp summary fields in %s\n", file)
		os.Exit(1)
	}

	fmt.Printf(
		"| %s | %.2f | %.2f | %.2f | %d | %d | %d |\n",
		direction,
		duration(result.End.SumReceived.Seconds, result.Start.TestStart.Duration),
		mbps(result.End.SumSent.BitsPerSecond),
		mbps(result.End.SumReceived.BitsPerSecond),
		result.End.SumSent.Retransmits,
		result.End.SumSent.Bytes,
		result.End.SumReceived.Bytes,
	)
}

func printUDPSummary(subject, direction, file string, result *iperfResult) {
	sum := result.End.Sum
	if sum == nil {
		if result.End.SumReceived != nil {
			sum = result.End.SumReceived
		} else if result.End.SumSent != nil {
			sum = result.End.SumSent
		}
	}
	if sum == nil {
		fmt.Fprintf(os.Stderr, "missing udp summary fields in %s\n", file)
		os.Exit(1)
	}

	fmt.Printf(
		"| %s | %.2f | %.2f | %.3f | %.3f | %d | %d | %d |\n",
		direction,
		duration(sum.Seconds, result.Start.TestStart.Duration),
		mbps(sum.BitsPerSecond),
		sum.JitterMs,
		sum.LostPercent,
		sum.Bytes,
		sum.Packets,
		sum.LostPackets,
	)
}

func duration(summarySeconds, fallback float64) float64 {
	if summarySeconds > 0 {
		return summarySeconds
	}
	return fallback
}

func mbps(bitsPerSecond float64) float64 {
	return bitsPerSecond / 1_000_000
}
