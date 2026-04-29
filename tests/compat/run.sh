#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN_ID="wgo-compat-$$"
TMP_DIR="${ROOT_DIR}/.tmp/compat/${RUN_ID}"
NETWORK_NAME="${RUN_ID}-net"
KERNEL_IMAGE="wgo-compat-kernel:${RUN_ID}"
WGO_IMAGE="wgo-compat-wgo:${RUN_ID}"
KERNEL_CONT="${RUN_ID}-kernel"
WGO_CONT="${RUN_ID}-wgo"
KERNEL_TUN_IP="10.88.0.1/32"
WGO_TUN_IP="10.88.0.2/32"
KERNEL_TUN_HOST="10.88.0.1"
WGO_TUN_HOST="10.88.0.2"
WG_PORT_A="51820"
WG_PORT_B="51821"
MTU="1420"

mkdir -p "${TMP_DIR}"

log() {
	printf '==> %s\n' "$*" >&2
}

run() {
	log "$*"
	"$@"
}

docker_shell() {
	local cont="$1"
	local cmd="$2"
	docker exec "${cont}" sh -ceu "${cmd}"
}

capture_state() {
	set +e
	docker logs "${WGO_CONT}" >"${TMP_DIR}/wgo.log" 2>&1 || true
	docker logs "${KERNEL_CONT}" >"${TMP_DIR}/kernel.log" 2>&1 || true
	docker_shell "${WGO_CONT}" "ip addr show; ip route show; wg show || true" >"${TMP_DIR}/wgo-state.txt" 2>&1 || true
	docker_shell "${KERNEL_CONT}" "ip addr show; ip route show; wg show || true" >"${TMP_DIR}/kernel-state.txt" 2>&1 || true
	set -e
}

cleanup() {
	set +e
	capture_state
	docker rm -f "${WGO_CONT}" "${KERNEL_CONT}" >/dev/null 2>&1 || true
	docker network rm "${NETWORK_NAME}" >/dev/null 2>&1 || true
	docker image rm -f "${WGO_IMAGE}" "${KERNEL_IMAGE}" >/dev/null 2>&1 || true
	set -e
}

trap cleanup EXIT

require_cmd() {
	command -v "$1" >/dev/null 2>&1 || {
		echo "missing required command: $1" >&2
		exit 1
	}
}

wait_for_cmd() {
	local cont="$1"
	local cmd="$2"
	local attempts="${3:-30}"
	local i
	for ((i = 0; i < attempts; i++)); do
		if docker_shell "${cont}" "${cmd}" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	return 1
}

b64_to_hex() {
	printf '%s' "$1" | base64 -d | od -An -tx1 -v | tr -d ' \n'
}

uapi_set_wgo() {
	local payload="$1"
	local reply
	reply="$(
		printf '%s\n\n' "${payload}" \
			| docker exec -i "${WGO_CONT}" sh -ceu 'exec socat - UNIX-CONNECT:/var/run/wireguard/wg0.sock'
	)"
	printf '%s\n%s\n\n' "REQUEST" "${payload}" >>"${TMP_DIR}/uapi.log"
	printf '%s\n\n' "${reply}" >>"${TMP_DIR}/uapi.log"
	if ! grep -q '^errno=0$' <<<"${reply}"; then
		echo "uapi request failed" >&2
		echo "${reply}" >&2
		exit 1
	fi
}

expect_ping_success() {
	local cont="$1"
	local addr="$2"
	local attempts="${3:-10}"
	local i
	for ((i = 0; i < attempts; i++)); do
		if docker_shell "${cont}" "ping -c 1 -W 1 ${addr}" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	echo "expected ping from ${cont} to ${addr} to succeed" >&2
	return 1
}

expect_ping_failure() {
	local cont="$1"
	local addr="$2"
	local attempts="${3:-3}"
	local i
	for ((i = 0; i < attempts; i++)); do
		if docker_shell "${cont}" "ping -c 1 -W 1 ${addr}" >/dev/null 2>&1; then
			echo "expected ping from ${cont} to ${addr} to fail" >&2
			return 1
		fi
		sleep 1
	done
}

setup_kernel_interface() {
	log "configuring kernel-space wireguard interface"
	docker_shell "${KERNEL_CONT}" "ip link add wg0 type wireguard"
	docker_shell "${KERNEL_CONT}" "ip addr replace ${KERNEL_TUN_IP} dev wg0"
	docker_shell "${KERNEL_CONT}" "ip link set dev wg0 mtu ${MTU} up"
	docker_shell "${KERNEL_CONT}" "ip route replace ${WGO_TUN_HOST}/32 dev wg0"
}

configure_basic_case() {
	log "basic case: configuring kernel peer"
	printf '%s' "${KERNEL_PRIV_B64}" \
		| docker exec -i -e WGO_PUB_B64="${WGO_PUB_B64}" -e WGO_OUTER_IP="${WGO_OUTER_IP}" "${KERNEL_CONT}" \
			sh -ceu '
				umask 077
				cat >/tmp/kernel.key
				wg set wg0 \
					private-key /tmp/kernel.key \
					listen-port '"${WG_PORT_A}"' \
					peer "${WGO_PUB_B64}" \
						allowed-ips '"${WGO_TUN_HOST}"'/32 \
						endpoint "${WGO_OUTER_IP}:'"${WG_PORT_A}"'"
			'

	log "basic case: configuring wgo peer through UAPI"
	uapi_set_wgo "$(cat <<EOF
set=1
private_key=${WGO_PRIV_HEX}
listen_port=${WG_PORT_A}
replace_peers=true
public_key=${KERNEL_PUB_HEX}
protocol_version=1
replace_allowed_ips=true
allowed_ip=${KERNEL_TUN_HOST}/32
endpoint=${KERNEL_OUTER_IP}:${WG_PORT_A}
EOF
)"

	expect_ping_success "${KERNEL_CONT}" "${WGO_TUN_HOST}"
	expect_ping_success "${WGO_CONT}" "${KERNEL_TUN_HOST}"
}

configure_psk_case() {
	log "psk case: rotating both peers to a shared preshared key"
	printf '%s' "${KERNEL_PSK_B64}" \
		| docker exec -i -e WGO_PUB_B64="${WGO_PUB_B64}" -e WGO_OUTER_IP="${WGO_OUTER_IP}" "${KERNEL_CONT}" \
			sh -ceu '
				umask 077
				cat >/tmp/psk.key
				wg set wg0 peer "${WGO_PUB_B64}" remove
				wg set wg0 \
					listen-port '"${WG_PORT_A}"' \
					peer "${WGO_PUB_B64}" \
						preshared-key /tmp/psk.key \
						allowed-ips '"${WGO_TUN_HOST}"'/32 \
						endpoint "${WGO_OUTER_IP}:'"${WG_PORT_A}"'"
			'

	uapi_set_wgo "$(cat <<EOF
set=1
public_key=${KERNEL_PUB_HEX}
remove=true
EOF
)"

	uapi_set_wgo "$(cat <<EOF
set=1
public_key=${KERNEL_PUB_HEX}
protocol_version=1
preshared_key=${PSK_HEX}
replace_allowed_ips=true
allowed_ip=${KERNEL_TUN_HOST}/32
endpoint=${KERNEL_OUTER_IP}:${WG_PORT_A}
EOF
)"

	expect_ping_success "${KERNEL_CONT}" "${WGO_TUN_HOST}"
	expect_ping_success "${WGO_CONT}" "${KERNEL_TUN_HOST}"
}

configure_dynamic_case() {
	log "dynamic case: remove peer via UAPI and confirm traffic stops"
	uapi_set_wgo "$(cat <<EOF
set=1
public_key=${KERNEL_PUB_HEX}
remove=true
EOF
)"

	expect_ping_failure "${WGO_CONT}" "${KERNEL_TUN_HOST}"

	log "dynamic case: add peer back via UAPI and confirm traffic resumes"
	uapi_set_wgo "$(cat <<EOF
set=1
public_key=${KERNEL_PUB_HEX}
protocol_version=1
preshared_key=${PSK_HEX}
replace_allowed_ips=true
allowed_ip=${KERNEL_TUN_HOST}/32
endpoint=${KERNEL_OUTER_IP}:${WG_PORT_A}
EOF
)"

	expect_ping_success "${WGO_CONT}" "${KERNEL_TUN_HOST}"

	log "dynamic case: edit endpoint after kernel listen-port change"
	docker exec -e WGO_PUB_B64="${WGO_PUB_B64}" "${KERNEL_CONT}" \
		sh -ceu 'wg set wg0 listen-port '"${WG_PORT_B}"' peer "${WGO_PUB_B64}" endpoint "'"${WGO_OUTER_IP}:${WG_PORT_A}"'"'

	expect_ping_failure "${WGO_CONT}" "${KERNEL_TUN_HOST}"

	uapi_set_wgo "$(cat <<EOF
set=1
public_key=${KERNEL_PUB_HEX}
endpoint=${KERNEL_OUTER_IP}:${WG_PORT_B}
EOF
)"

	expect_ping_success "${WGO_CONT}" "${KERNEL_TUN_HOST}"
	expect_ping_success "${KERNEL_CONT}" "${WGO_TUN_HOST}"
}

main() {
	require_cmd docker
	require_cmd base64
	require_cmd od

	run docker build -f tests/compat/docker/kernel-peer.Dockerfile -t "${KERNEL_IMAGE}" "${ROOT_DIR}"
	run docker build -f tests/compat/docker/wgo-peer.Dockerfile -t "${WGO_IMAGE}" "${ROOT_DIR}"
	run docker network create "${NETWORK_NAME}"

	run docker run -d \
		--name "${KERNEL_CONT}" \
		--hostname kernel-peer \
		--network "${NETWORK_NAME}" \
		--network-alias kernel-peer \
		--privileged \
		-v /lib/modules:/lib/modules:ro \
		"${KERNEL_IMAGE}"

	run docker run -d \
		--name "${WGO_CONT}" \
		--hostname wgo-peer \
		--network "${NETWORK_NAME}" \
		--network-alias wgo-peer \
		--privileged \
		"${WGO_IMAGE}" \
		-iface wg0 \
		-tun-local "${WGO_TUN_IP}" \
		-peer-route "${KERNEL_TUN_IP}" \
		-listen-port "${WG_PORT_A}" \
		-mtu "${MTU}" \
		-log-level debug

	wait_for_cmd "${WGO_CONT}" "test -S /var/run/wireguard/wg0.sock"
	wait_for_cmd "${WGO_CONT}" "ip link show dev wg0"

	KERNEL_OUTER_IP="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${KERNEL_CONT}")"
	WGO_OUTER_IP="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${WGO_CONT}")"

	KERNEL_PRIV_B64="$(docker_shell "${KERNEL_CONT}" "wg genkey" | tr -d '\r\n')"
	WGO_PRIV_B64="$(docker_shell "${KERNEL_CONT}" "wg genkey" | tr -d '\r\n')"
	KERNEL_PUB_B64="$(printf '%s' "${KERNEL_PRIV_B64}" | docker exec -i "${KERNEL_CONT}" sh -ceu 'wg pubkey' | tr -d '\r\n')"
	WGO_PUB_B64="$(printf '%s' "${WGO_PRIV_B64}" | docker exec -i "${KERNEL_CONT}" sh -ceu 'wg pubkey' | tr -d '\r\n')"
	KERNEL_PSK_B64="$(docker_shell "${KERNEL_CONT}" "wg genpsk" | tr -d '\r\n')"

	KERNEL_PUB_HEX="$(b64_to_hex "${KERNEL_PUB_B64}")"
	WGO_PRIV_HEX="$(b64_to_hex "${WGO_PRIV_B64}")"
	PSK_HEX="$(b64_to_hex "${KERNEL_PSK_B64}")"

	setup_kernel_interface
	configure_basic_case
	configure_psk_case
	configure_dynamic_case

	log "compatibility suite passed"
	log "artifacts: ${TMP_DIR}"
}

main "$@"
