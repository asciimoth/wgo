set shell := ["bash", "-euo", "pipefail", "-c"]

test:
	go test -race ./...

test-stress:
  go test ./... --race -count=100 > test.log 2>&1

vet:
	go vet ./...

tidy:
	go mod tidy

# Compatibility tests against kernel WireGuard and upstream amneziawg-go. Using sudo.
test-compat:
	sudo ./tests/compat/run.sh

test-obfuscation:
	sudo ./tests/obfuscation/run.sh

test-performance:
	sudo ./tests/perf/run.sh

# Stress tests + compat tests.
test-total: test-stress test-compat test-obfuscation
