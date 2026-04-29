FROM golang:1.25.5-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o /out/compat-wgo-peer ./cmd/compat_wgo_peer

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

COPY --from=build /out/compat-wgo-peer /usr/local/bin/compat-wgo-peer

ENTRYPOINT ["/usr/local/bin/compat-wgo-peer"]
