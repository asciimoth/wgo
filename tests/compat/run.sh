#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN_ID="wgo-compat-$$"
TMP_DIR="${ROOT_DIR}/.tmp/compat/${RUN_ID}"
MTU="${MTU:-1420}"
WG_PORT_A="${WG_PORT_A:-51820}"
WG_PORT_B="${WG_PORT_B:-51821}"

VANILLA_DIR="${TMP_DIR}/vanilla"
AMNEZIA_DIR="${TMP_DIR}/amnezia"

VANILLA_NETWORK="${RUN_ID}-vanilla-net"
AMNEZIA_NETWORK="${RUN_ID}-amnezia-net"

KERNEL_IMAGE="wgo-compat-kernel:${RUN_ID}"
WGO_IMAGE="wgo-compat-wgo:${RUN_ID}"
AMNEZIA_IMAGE="wgo-compat-amnezia:${RUN_ID}"

KERNEL_CONT="${RUN_ID}-kernel"
VANILLA_WGO_CONT="${RUN_ID}-wgo"
AMNEZIA_CONT="${RUN_ID}-amnezia"
AMNEZIA_WGO_CONT="${RUN_ID}-amnezia-wgo"

VANILLA_KERNEL_TUN_IP="10.88.0.1/32"
VANILLA_WGO_TUN_IP="10.88.0.2/32"
VANILLA_KERNEL_TUN_HOST="10.88.0.1"
VANILLA_WGO_TUN_HOST="10.88.0.2"

AMNEZIA_PEER_TUN_IP="10.89.0.1/32"
AMNEZIA_WGO_TUN_IP="10.89.0.2/32"
AMNEZIA_PEER_TUN_HOST="10.89.0.1"
AMNEZIA_WGO_TUN_HOST="10.89.0.2"

mkdir -p "${VANILLA_DIR}" "${AMNEZIA_DIR}"

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
	local cont="$1"
	local dir="$2"
	local prefix="$3"

	set +e
	docker logs "${cont}" >"${dir}/${prefix}.log" 2>&1 || true
	docker_shell "${cont}" "ip addr show; ip route show; wg show || true" >"${dir}/${prefix}-state.txt" 2>&1 || true
	set -e
}

cleanup() {
	set +e
	capture_state "${VANILLA_WGO_CONT}" "${VANILLA_DIR}" "wgo" || true
	capture_state "${KERNEL_CONT}" "${VANILLA_DIR}" "kernel" || true
	capture_state "${AMNEZIA_WGO_CONT}" "${AMNEZIA_DIR}" "wgo" || true
	capture_state "${AMNEZIA_CONT}" "${AMNEZIA_DIR}" "amnezia" || true

	docker rm -f "${VANILLA_WGO_CONT}" "${KERNEL_CONT}" "${AMNEZIA_WGO_CONT}" "${AMNEZIA_CONT}" >/dev/null 2>&1 || true
	docker network rm "${VANILLA_NETWORK}" "${AMNEZIA_NETWORK}" >/dev/null 2>&1 || true
	docker image rm -f "${WGO_IMAGE}" "${KERNEL_IMAGE}" "${AMNEZIA_IMAGE}" >/dev/null 2>&1 || true
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

new_key_pair() {
	local cont="$1"
	local priv pub
	priv="$(docker_shell "${cont}" "wg genkey" | tr -d '\r\n')"
	pub="$(printf '%s' "${priv}" | docker exec -i "${cont}" sh -ceu 'wg pubkey' | tr -d '\r\n')"
	printf '%s %s\n' "${priv}" "${pub}"
}

new_psk() {
	local cont="$1"
	docker_shell "${cont}" "wg genpsk" | tr -d '\r\n'
}

uapi_set() {
	local cont="$1"
	local payload="$2"
	local log_file="$3"
	local reply
	reply="$(
		printf '%s\n\n' "${payload}" \
			| docker exec -i "${cont}" sh -ceu '
				socket=/var/run/wireguard/wg0.sock
				if [ ! -S "${socket}" ] && [ -S /var/run/amneziawg/wg0.sock ]; then
					socket=/var/run/amneziawg/wg0.sock
				fi
				exec socat - UNIX-CONNECT:"${socket}"
			'
	)"
	printf '%s\n%s\n\n' "REQUEST" "${payload}" >>"${log_file}"
	printf '%s\n\n' "${reply}" >>"${log_file}"
	if ! grep -q '^errno=0$' <<<"${reply}"; then
		echo "uapi request failed in ${cont}" >&2
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

configure_kernel_interface() {
	local cont="$1"
	local tun_ip="$2"
	local peer_host="$3"
	log "configuring kernel-space wireguard interface in ${cont}"
	docker_shell "${cont}" "ip link add wg0 type wireguard"
	docker_shell "${cont}" "ip addr replace ${tun_ip} dev wg0"
	docker_shell "${cont}" "ip link set dev wg0 mtu ${MTU} up"
	docker_shell "${cont}" "ip route replace ${peer_host}/32 dev wg0"
}

configure_userspace_interface() {
	local cont="$1"
	local tun_ip="$2"
	local peer_host="$3"
	log "configuring userspace wireguard interface in ${cont}"
	docker_shell "${cont}" "ip addr replace ${tun_ip} dev wg0"
	docker_shell "${cont}" "ip link set dev wg0 mtu ${MTU} up"
	docker_shell "${cont}" "ip route replace ${peer_host}/32 dev wg0"
}

configure_kernel_peer() {
	local cont="$1"
	local private_key_b64="$2"
	local listen_port="$3"
	local peer_pub_b64="$4"
	local peer_outer_ip="$5"
	local peer_port="$6"
	local peer_tun_host="$7"

	printf '%s' "${private_key_b64}" \
		| docker exec -i \
			-e PEER_PUB_B64="${peer_pub_b64}" \
			-e PEER_OUTER_IP="${peer_outer_ip}" \
			-e PEER_PORT="${peer_port}" \
			-e PEER_TUN_HOST="${peer_tun_host}" \
			-e LISTEN_PORT="${listen_port}" \
			"${cont}" \
			sh -ceu '
				umask 077
				cat >/tmp/private.key
				wg set wg0 \
					private-key /tmp/private.key \
					listen-port "${LISTEN_PORT}" \
					peer "${PEER_PUB_B64}" \
						allowed-ips "${PEER_TUN_HOST}/32" \
						endpoint "${PEER_OUTER_IP}:${PEER_PORT}"
			'
}

amnezia_device_config_payload() {
	cat <<'EOF'
jc=2
jmin=11
jmax=23
s1=13
s2=17
s3=19
s4=29
h1=1111-1113
h2=2222-2225
h3=3333-3333
h4=4444-4449
i1=<b 0xaa55><rc 3><rd 2><t>
i2=<r 5>
i3=<rd 4>
i4=<rc 6>
i5=<b 0x01020304>
EOF
}

configure_wgo_peer() {
	local cont="$1"
	local log_file="$2"
	local private_key_hex="$3"
	local listen_port="$4"
	local peer_pub_hex="$5"
	local peer_outer_ip="$6"
	local peer_port="$7"
	local peer_tun_host="$8"
	local extra_device_lines="${9:-}"

	uapi_set "${cont}" "$(cat <<EOF
set=1
private_key=${private_key_hex}
listen_port=${listen_port}
${extra_device_lines}replace_peers=true
public_key=${peer_pub_hex}
protocol_version=1
replace_allowed_ips=true
allowed_ip=${peer_tun_host}/32
endpoint=${peer_outer_ip}:${peer_port}
EOF
)" "${log_file}"
}

configure_peer_preshared_key() {
	local cont="$1"
	local log_file="$2"
	local peer_pub_hex="$3"
	local psk_hex="$4"
	local peer_outer_ip="$5"
	local peer_port="$6"
	local peer_tun_host="$7"

	uapi_set "${cont}" "$(cat <<EOF
set=1
public_key=${peer_pub_hex}
protocol_version=1
preshared_key=${psk_hex}
replace_allowed_ips=true
allowed_ip=${peer_tun_host}/32
endpoint=${peer_outer_ip}:${peer_port}
EOF
)" "${log_file}"
}

remove_peer() {
	local cont="$1"
	local log_file="$2"
	local peer_pub_hex="$3"

	uapi_set "${cont}" "$(cat <<EOF
set=1
public_key=${peer_pub_hex}
remove=true
EOF
)" "${log_file}"
}

update_peer_endpoint() {
	local cont="$1"
	local log_file="$2"
	local peer_pub_hex="$3"
	local endpoint="$4"

	uapi_set "${cont}" "$(cat <<EOF
set=1
public_key=${peer_pub_hex}
endpoint=${endpoint}
EOF
)" "${log_file}"
}

run_vanilla_suite() {
	local kernel_outer_ip wgo_outer_ip
	local kernel_priv_b64 kernel_pub_b64 wgo_priv_b64 wgo_pub_b64 kernel_psk_b64
	local kernel_pub_hex wgo_priv_hex psk_hex

	log "starting vanilla wireguard compatibility suite"
	run docker network create "${VANILLA_NETWORK}"

	run docker run -d \
		--name "${KERNEL_CONT}" \
		--hostname kernel-peer \
		--network "${VANILLA_NETWORK}" \
		--network-alias kernel-peer \
		--privileged \
		-v /lib/modules:/lib/modules:ro \
		"${KERNEL_IMAGE}"

	run docker run -d \
		--name "${VANILLA_WGO_CONT}" \
		--hostname wgo-peer \
		--network "${VANILLA_NETWORK}" \
		--network-alias wgo-peer \
		--privileged \
		"${WGO_IMAGE}" \
		-iface wg0 \
		-tun-local "${VANILLA_WGO_TUN_IP}" \
		-peer-route "${VANILLA_KERNEL_TUN_IP}" \
		-listen-port "${WG_PORT_A}" \
		-mtu "${MTU}" \
		-log-level debug

	wait_for_cmd "${VANILLA_WGO_CONT}" "test -S /var/run/wireguard/wg0.sock"
	wait_for_cmd "${VANILLA_WGO_CONT}" "ip link show dev wg0"

	kernel_outer_ip="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${KERNEL_CONT}")"
	wgo_outer_ip="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${VANILLA_WGO_CONT}")"

	read -r kernel_priv_b64 kernel_pub_b64 <<<"$(new_key_pair "${KERNEL_CONT}")"
	read -r wgo_priv_b64 wgo_pub_b64 <<<"$(new_key_pair "${KERNEL_CONT}")"
	kernel_psk_b64="$(new_psk "${KERNEL_CONT}")"

	kernel_pub_hex="$(b64_to_hex "${kernel_pub_b64}")"
	wgo_priv_hex="$(b64_to_hex "${wgo_priv_b64}")"
	psk_hex="$(b64_to_hex "${kernel_psk_b64}")"

	configure_kernel_interface "${KERNEL_CONT}" "${VANILLA_KERNEL_TUN_IP}" "${VANILLA_WGO_TUN_HOST}"

	log "vanilla basic case: configuring kernel peer"
	configure_kernel_peer "${KERNEL_CONT}" "${kernel_priv_b64}" "${WG_PORT_A}" "${wgo_pub_b64}" "${wgo_outer_ip}" "${WG_PORT_A}" "${VANILLA_WGO_TUN_HOST}"

	log "vanilla basic case: configuring wgo peer through UAPI"
	configure_wgo_peer "${VANILLA_WGO_CONT}" "${VANILLA_DIR}/uapi.log" "${wgo_priv_hex}" "${WG_PORT_A}" "${kernel_pub_hex}" "${kernel_outer_ip}" "${WG_PORT_A}" "${VANILLA_KERNEL_TUN_HOST}"

	expect_ping_success "${KERNEL_CONT}" "${VANILLA_WGO_TUN_HOST}"
	expect_ping_success "${VANILLA_WGO_CONT}" "${VANILLA_KERNEL_TUN_HOST}"

	log "vanilla psk case: rotating both peers to a shared preshared key"
	printf '%s' "${kernel_psk_b64}" \
		| docker exec -i -e PEER_PUB_B64="${wgo_pub_b64}" -e PEER_OUTER_IP="${wgo_outer_ip}" "${KERNEL_CONT}" \
			sh -ceu '
				umask 077
				cat >/tmp/psk.key
				wg set wg0 peer "${PEER_PUB_B64}" remove
				wg set wg0 \
					listen-port '"${WG_PORT_A}"' \
					peer "${PEER_PUB_B64}" \
						preshared-key /tmp/psk.key \
						allowed-ips '"${VANILLA_WGO_TUN_HOST}"'/32 \
						endpoint "${PEER_OUTER_IP}:'"${WG_PORT_A}"'"
			'

	remove_peer "${VANILLA_WGO_CONT}" "${VANILLA_DIR}/uapi.log" "${kernel_pub_hex}"
	configure_peer_preshared_key "${VANILLA_WGO_CONT}" "${VANILLA_DIR}/uapi.log" "${kernel_pub_hex}" "${psk_hex}" "${kernel_outer_ip}" "${WG_PORT_A}" "${VANILLA_KERNEL_TUN_HOST}"

	expect_ping_success "${KERNEL_CONT}" "${VANILLA_WGO_TUN_HOST}"
	expect_ping_success "${VANILLA_WGO_CONT}" "${VANILLA_KERNEL_TUN_HOST}"

	log "vanilla dynamic case: remove peer via UAPI and confirm traffic stops"
	remove_peer "${VANILLA_WGO_CONT}" "${VANILLA_DIR}/uapi.log" "${kernel_pub_hex}"
	expect_ping_failure "${VANILLA_WGO_CONT}" "${VANILLA_KERNEL_TUN_HOST}"

	log "vanilla dynamic case: add peer back via UAPI and confirm traffic resumes"
	configure_peer_preshared_key "${VANILLA_WGO_CONT}" "${VANILLA_DIR}/uapi.log" "${kernel_pub_hex}" "${psk_hex}" "${kernel_outer_ip}" "${WG_PORT_A}" "${VANILLA_KERNEL_TUN_HOST}"
	expect_ping_success "${VANILLA_WGO_CONT}" "${VANILLA_KERNEL_TUN_HOST}"

	log "vanilla dynamic case: edit endpoint after kernel listen-port change"
	docker exec -e PEER_PUB_B64="${wgo_pub_b64}" "${KERNEL_CONT}" \
		sh -ceu 'wg set wg0 listen-port '"${WG_PORT_B}"' peer "${PEER_PUB_B64}" endpoint "'"${wgo_outer_ip}:${WG_PORT_A}"'"'

	expect_ping_failure "${VANILLA_WGO_CONT}" "${VANILLA_KERNEL_TUN_HOST}"
	update_peer_endpoint "${VANILLA_WGO_CONT}" "${VANILLA_DIR}/uapi.log" "${kernel_pub_hex}" "${kernel_outer_ip}:${WG_PORT_B}"

	expect_ping_success "${VANILLA_WGO_CONT}" "${VANILLA_KERNEL_TUN_HOST}"
	expect_ping_success "${KERNEL_CONT}" "${VANILLA_WGO_TUN_HOST}"
}

run_amnezia_suite() {
	local amnezia_outer_ip wgo_outer_ip
	local amnezia_priv_b64 amnezia_pub_b64 wgo_priv_b64 wgo_pub_b64 psk_b64
	local amnezia_priv_hex amnezia_pub_hex wgo_priv_hex psk_hex amnezia_device_lines

	log "starting amneziawg compatibility suite"
	run docker network create "${AMNEZIA_NETWORK}"

	run docker run -d \
		--name "${AMNEZIA_CONT}" \
		--hostname amnezia-peer \
		--network "${AMNEZIA_NETWORK}" \
		--network-alias amnezia-peer \
		--privileged \
		"${AMNEZIA_IMAGE}" \
		wg0

	run docker run -d \
		--name "${AMNEZIA_WGO_CONT}" \
		--hostname wgo-peer \
		--network "${AMNEZIA_NETWORK}" \
		--network-alias wgo-peer \
		--privileged \
		"${WGO_IMAGE}" \
		-iface wg0 \
		-tun-local "${AMNEZIA_WGO_TUN_IP}" \
		-peer-route "${AMNEZIA_PEER_TUN_IP}" \
		-listen-port "${WG_PORT_A}" \
		-mtu "${MTU}" \
		-log-level debug

	wait_for_cmd "${AMNEZIA_CONT}" "test -S /var/run/amneziawg/wg0.sock"
	wait_for_cmd "${AMNEZIA_CONT}" "ip link show dev wg0"
	wait_for_cmd "${AMNEZIA_WGO_CONT}" "test -S /var/run/wireguard/wg0.sock"
	wait_for_cmd "${AMNEZIA_WGO_CONT}" "ip link show dev wg0"

	amnezia_outer_ip="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${AMNEZIA_CONT}")"
	wgo_outer_ip="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${AMNEZIA_WGO_CONT}")"

	read -r amnezia_priv_b64 amnezia_pub_b64 <<<"$(new_key_pair "${AMNEZIA_CONT}")"
	read -r wgo_priv_b64 wgo_pub_b64 <<<"$(new_key_pair "${AMNEZIA_CONT}")"
	psk_b64="$(new_psk "${AMNEZIA_CONT}")"

	amnezia_priv_hex="$(b64_to_hex "${amnezia_priv_b64}")"
	amnezia_pub_hex="$(b64_to_hex "${amnezia_pub_b64}")"
	wgo_priv_hex="$(b64_to_hex "${wgo_priv_b64}")"
	psk_hex="$(b64_to_hex "${psk_b64}")"
	amnezia_device_lines="$(amnezia_device_config_payload)"

	configure_userspace_interface "${AMNEZIA_CONT}" "${AMNEZIA_PEER_TUN_IP}" "${AMNEZIA_WGO_TUN_HOST}"

	log "amnezia basic case: configuring both peers with non-default amnezia params"
	configure_wgo_peer "${AMNEZIA_CONT}" "${AMNEZIA_DIR}/amnezia-uapi.log" "${amnezia_priv_hex}" "${WG_PORT_A}" "$(b64_to_hex "${wgo_pub_b64}")" "${wgo_outer_ip}" "${WG_PORT_A}" "${AMNEZIA_WGO_TUN_HOST}" "${amnezia_device_lines}"$'\n'
	configure_wgo_peer "${AMNEZIA_WGO_CONT}" "${AMNEZIA_DIR}/wgo-uapi.log" "${wgo_priv_hex}" "${WG_PORT_A}" "${amnezia_pub_hex}" "${amnezia_outer_ip}" "${WG_PORT_A}" "${AMNEZIA_PEER_TUN_HOST}" "${amnezia_device_lines}"$'\n'

	expect_ping_success "${AMNEZIA_CONT}" "${AMNEZIA_WGO_TUN_HOST}"
	expect_ping_success "${AMNEZIA_WGO_CONT}" "${AMNEZIA_PEER_TUN_HOST}"

	log "amnezia psk case: rotating both peers while preserving non-default amnezia params"
	remove_peer "${AMNEZIA_CONT}" "${AMNEZIA_DIR}/amnezia-uapi.log" "$(b64_to_hex "${wgo_pub_b64}")"
	configure_peer_preshared_key "${AMNEZIA_CONT}" "${AMNEZIA_DIR}/amnezia-uapi.log" "$(b64_to_hex "${wgo_pub_b64}")" "${psk_hex}" "${wgo_outer_ip}" "${WG_PORT_A}" "${AMNEZIA_WGO_TUN_HOST}"

	remove_peer "${AMNEZIA_WGO_CONT}" "${AMNEZIA_DIR}/wgo-uapi.log" "${amnezia_pub_hex}"
	configure_peer_preshared_key "${AMNEZIA_WGO_CONT}" "${AMNEZIA_DIR}/wgo-uapi.log" "${amnezia_pub_hex}" "${psk_hex}" "${amnezia_outer_ip}" "${WG_PORT_A}" "${AMNEZIA_PEER_TUN_HOST}"

	expect_ping_success "${AMNEZIA_CONT}" "${AMNEZIA_WGO_TUN_HOST}"
	expect_ping_success "${AMNEZIA_WGO_CONT}" "${AMNEZIA_PEER_TUN_HOST}"

	log "amnezia dynamic case: remove peer via UAPI and confirm traffic stops"
	remove_peer "${AMNEZIA_WGO_CONT}" "${AMNEZIA_DIR}/wgo-uapi.log" "${amnezia_pub_hex}"
	expect_ping_failure "${AMNEZIA_WGO_CONT}" "${AMNEZIA_PEER_TUN_HOST}"

	log "amnezia dynamic case: add peer back via UAPI and confirm traffic resumes"
	configure_peer_preshared_key "${AMNEZIA_WGO_CONT}" "${AMNEZIA_DIR}/wgo-uapi.log" "${amnezia_pub_hex}" "${psk_hex}" "${amnezia_outer_ip}" "${WG_PORT_A}" "${AMNEZIA_PEER_TUN_HOST}"
	expect_ping_success "${AMNEZIA_WGO_CONT}" "${AMNEZIA_PEER_TUN_HOST}"

	log "amnezia dynamic case: edit endpoint after amnezia peer listen-port change"
	uapi_set "${AMNEZIA_CONT}" "$(cat <<EOF
set=1
listen_port=${WG_PORT_B}
EOF
)" "${AMNEZIA_DIR}/amnezia-uapi.log"

	expect_ping_failure "${AMNEZIA_WGO_CONT}" "${AMNEZIA_PEER_TUN_HOST}"
	update_peer_endpoint "${AMNEZIA_WGO_CONT}" "${AMNEZIA_DIR}/wgo-uapi.log" "${amnezia_pub_hex}" "${amnezia_outer_ip}:${WG_PORT_B}"

	expect_ping_success "${AMNEZIA_WGO_CONT}" "${AMNEZIA_PEER_TUN_HOST}"
	expect_ping_success "${AMNEZIA_CONT}" "${AMNEZIA_WGO_TUN_HOST}"
}

main() {
	require_cmd docker
	require_cmd base64
	require_cmd od

	run docker build -f tests/compat/docker/kernel-peer.Dockerfile -t "${KERNEL_IMAGE}" "${ROOT_DIR}"
	run docker build -f tests/compat/docker/wgo-peer.Dockerfile -t "${WGO_IMAGE}" "${ROOT_DIR}"
	run docker build -f tests/compat/docker/amnezia-peer.Dockerfile -t "${AMNEZIA_IMAGE}" "${ROOT_DIR}"

	run_vanilla_suite
	run_amnezia_suite

	log "compatibility suite passed"
	log "artifacts: ${TMP_DIR}"
}

main "$@"
