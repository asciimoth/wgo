FROM golang:1.25.5-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o /out/compat-wgo-peer ./cmd/compat_wgo_peer
RUN CGO_ENABLED=1 GOOS=linux go build -tags e2e -o /out/amnesia-e2e-tool ./tests/amnesia/cmd/amnesia_e2e_tool

FROM debian:bookworm-slim

RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
		ca-certificates \
		curl \
		iproute2 \
		iputils-ping \
		socat \
		wireguard-tools \
	&& rm -rf /var/lib/apt/lists/*

COPY --from=build /out/compat-wgo-peer /usr/local/bin/compat-wgo-peer
COPY --from=build /out/amnesia-e2e-tool /usr/local/bin/amnesia-e2e-tool

ENTRYPOINT ["/usr/local/bin/compat-wgo-peer"]
