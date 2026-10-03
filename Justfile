set shell := ["bash", "-euo", "pipefail", "-c"]

typos:
  typos

check: tidy typos vet test-total fuzz

test:
	go test -race ./...

# Do not run fuzzing in GitHub Actions.
fuzz:
	if [[ "${GITHUB_ACTIONS:-false}" == "true" ]]; then \
		echo "Skipping fuzzing in GitHub Actions"; \
	else \
		fuzz_time="${FUZZ_TIME:-1m}"; status=0; \
		go test -race ./amnesia -run='^$' -fuzz='^FuzzAmnesiaUntrustedInput$' -fuzztime="$fuzz_time" & amnesia_pid=$!; \
		go test -race ./device -run='^$' -fuzz='^FuzzDeviceUntrustedInput$' -fuzztime="$fuzz_time" & device_pid=$!; \
		wait "$amnesia_pid" || status=$?; wait "$device_pid" || status=$?; exit "$status"; \
	fi

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

test-amnesia-live:
	go run ./cmd/amnesia_live_e2e

test-performance:
	sudo ./tests/perf/run.sh

# Stress tests + compat tests.
test-total: test-stress test-compat test-obfuscation test-amnesia-e2e
