FROM golang:1.25.5-bookworm AS build

WORKDIR /src

RUN apt-get update \
	&& apt-get install -y --no-install-recommends git \
	&& rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-go.git /src/upstream

WORKDIR /src/upstream

RUN CGO_ENABLED=1 GOOS=linux go build -o /out/amneziawg-go .
RUN git rev-parse HEAD >/out/amneziawg-go.commit

ARG DEBIAN_FRONTEND=noninteractive

FROM debian:bookworm-slim

RUN apt-get update \
	&& DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		ca-certificates \
		iperf3 \
		iproute2 \
		iputils-ping \
		socat \
		wireguard-tools \
	&& rm -rf /var/lib/apt/lists/*

COPY --from=build /out/amneziawg-go /usr/local/bin/amneziawg-go
COPY --from=build /out/amneziawg-go.commit /usr/local/share/amneziawg-go.commit
COPY tests/perf/docker/amnezia-peer-entrypoint.sh /usr/local/bin/amnezia-peer-entrypoint

RUN chmod +x /usr/local/bin/amnezia-peer-entrypoint

ENTRYPOINT ["/usr/local/bin/amnezia-peer-entrypoint"]
