#!/bin/sh
set -eu

iface="${1:-wg0}"
export WG_PROCESS_FOREGROUND=1
mkdir -p /var/run/amneziawg

exec /usr/local/bin/amneziawg-go -f "${iface}"
