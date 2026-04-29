ARG DEBIAN_FRONTEND=noninteractive

FROM debian:bookworm-slim

RUN apt-get update \
	&& DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		ca-certificates \
		iperf3 \
		iproute2 \
		iputils-ping \
		kmod \
		procps \
		wireguard-tools \
	&& rm -rf /var/lib/apt/lists/*

CMD ["sh", "-ceu", "modprobe wireguard || true; mkdir -p /var/run/wireguard; sleep infinity"]
