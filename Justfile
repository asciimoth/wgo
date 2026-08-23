set shell := ["bash", "-euo", "pipefail", "-c"]

typos:
  typos

check: tidy typos vet test-total

test:
	go test -race ./...

test-stress:
  go test ./... --race -count=20 -timeout=30m > test.log 2>&1

vet:
	go vet ./...

tidy:
	go mod tidy

# Compatibility tests against kernel WireGuard and upstream amneziawg-go. Using sudo.
test-compat:
	sudo ./tests/compat/run.sh

test-obfuscation:
	sudo ./tests/obfuscation/run.sh

test-amnesia-e2e:
	sudo ./tests/amnesia/run.sh

test-performance:
	sudo ./tests/perf/run.sh

# Stress tests + compat tests.
test-total: test-stress test-compat test-obfuscation test-amnesia-e2e
