#!/bin/sh
set -eu

iface="${1:-wg0}"
export WG_PROCESS_FOREGROUND=1
mkdir -p /var/run/wireguard

exec /usr/local/bin/wireguard-go -f "${iface}"
