FROM golang:1.25.5-bookworm AS build

WORKDIR /src

RUN apt-get update \
	&& apt-get install -y --no-install-recommends git \
	&& rm -rf /var/lib/apt/lists/*

ARG AMNEZIAWG_GO_COMMIT=1b86b2ae0e493e7ea93f8c1a0f0cb6735b1551f1

RUN git init /src/upstream \
	&& cd /src/upstream \
	&& git remote add origin https://github.com/amnezia-vpn/amneziawg-go.git \
	&& git fetch --depth 1 origin "${AMNEZIAWG_GO_COMMIT}" \
	&& git checkout FETCH_HEAD

WORKDIR /src/upstream

RUN CGO_ENABLED=1 GOOS=linux go build -o /out/amneziawg-go .
RUN git rev-parse HEAD >/out/amneziawg-go.commit

FROM debian:bookworm-slim

RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
		ca-certificates \
		iproute2 \
		iputils-ping \
		socat \
		wireguard-tools \
	&& rm -rf /var/lib/apt/lists/*

COPY --from=build /out/amneziawg-go /usr/local/bin/amneziawg-go
COPY --from=build /out/amneziawg-go.commit /usr/local/share/amneziawg-go.commit
COPY tests/compat/docker/amnezia-peer-entrypoint.sh /usr/local/bin/amnezia-peer-entrypoint

RUN chmod +x /usr/local/bin/amnezia-peer-entrypoint

ENTRYPOINT ["/usr/local/bin/amnezia-peer-entrypoint"]
