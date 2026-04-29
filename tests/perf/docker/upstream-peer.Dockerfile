FROM golang:1.25.5-bookworm AS build

WORKDIR /src

RUN apt-get update \
	&& apt-get install -y --no-install-recommends git \
	&& rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/WireGuard/wireguard-go.git /src/upstream

WORKDIR /src/upstream

RUN CGO_ENABLED=1 GOOS=linux go build -o /out/wireguard-go .
RUN git rev-parse HEAD >/out/wireguard-go.commit

ARG DEBIAN_FRONTEND=noninteractive

FROM debian:bookworm-slim

RUN apt-get update \
	&& DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		ca-certificates \
		iperf3 \
		iproute2 \
		iputils-ping \
		wireguard-tools \
	&& rm -rf /var/lib/apt/lists/*

COPY --from=build /out/wireguard-go /usr/local/bin/wireguard-go
COPY --from=build /out/wireguard-go.commit /usr/local/share/wireguard-go.commit
COPY tests/perf/docker/upstream-peer-entrypoint.sh /usr/local/bin/upstream-peer-entrypoint

RUN chmod +x /usr/local/bin/upstream-peer-entrypoint

ENTRYPOINT ["/usr/local/bin/upstream-peer-entrypoint"]
