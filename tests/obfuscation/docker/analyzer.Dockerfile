FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
		ca-certificates \
		tshark \
		tcpdump \
	&& rm -rf /var/lib/apt/lists/*

CMD ["sh", "-ceu", "sleep infinity"]
