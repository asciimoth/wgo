#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN_ID="wgo-amnesia-e2e-$$"
TMP_DIR="${ROOT_DIR}/.tmp/amnesia-e2e/${RUN_ID}"
MTU="${MTU:-1420}"
SERVER_PORT="${SERVER_PORT:-51820}"
CLIENT_PORT="${CLIENT_PORT:-51821}"
SELFHOST_HTTP_PORT="${SELFHOST_HTTP_PORT:-8080}"
CLIENT_HTTP_PORT="${CLIENT_HTTP_PORT:-8081}"
GATEWAY_HTTP_PORT="${GATEWAY_HTTP_PORT:-18080}"
AMNEZIA_HEADER_KEY="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

WGO_IMAGE="wgo-amnesia-e2e-client:${RUN_ID}"
SELFHOST_IMAGE="wgo-amnesia-e2e-selfhost:${RUN_ID}"

CONTAINERS=()
NETWORKS=()
IMAGES=("${WGO_IMAGE}" "${SELFHOST_IMAGE}")

mkdir -p "${TMP_DIR}"

log() {
	printf '==> %s\n' "$*" >&2
}

skip() {
	printf 'SKIP: %s\n' "$*" >&2
	exit 0
}

run() {
	log "$*"
	"$@"
}

remember_container() {
	CONTAINERS+=("$1")
}

remember_network() {
	NETWORKS+=("$1")
}

require_cmd() {
	command -v "$1" >/dev/null 2>&1 || {
		skip "missing required command: $1"
	}
}

require_tun() {
	[ -c /dev/net/tun ] || skip "missing /dev/net/tun"
}

require_docker_ready() {
	if ! docker info >/dev/null 2>&1; then
		skip "Docker daemon is unavailable or current user lacks Docker permission"
	fi
}

require_privileged_containers() {
	local probe="${RUN_ID}-capability-probe"
	local image="${WGO_IMAGE}"

	set +e
	docker run --rm --name "${probe}" --privileged --entrypoint sh "${image}" -ceu '
		test -c /dev/net/tun
		ip tuntap add dev wgo-probe mode tun
		ip link del dev wgo-probe
	' >/dev/null 2>&1
	local status=$?
	set -e
	if [ "${status}" -ne 0 ]; then
		skip "Docker cannot create privileged TUN interfaces; require /dev/net/tun and CAP_NET_ADMIN"
	fi
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
	local cont
	local network
	local image

	set +e
	for cont in "${CONTAINERS[@]}"; do
		case_dir="${TMP_DIR}/${cont#${RUN_ID}-}"
		mkdir -p "${case_dir}"
		capture_state "${cont}" "${case_dir}" "${cont}" || true
		docker rm -f "${cont}" >/dev/null 2>&1 || true
	done
	for network in "${NETWORKS[@]}"; do
		docker network rm "${network}" >/dev/null 2>&1 || true
	done
	for image in "${IMAGES[@]}"; do
		docker image rm -f "${image}" >/dev/null 2>&1 || true
	done
	set -e
}

trap cleanup EXIT

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
	local cont="${1:-}"
	local priv
	local pub
	if [ -n "${cont}" ]; then
		priv="$(docker_shell "${cont}" "wg genkey" | tr -d '\r\n')"
		pub="$(
			printf '%s' "${priv}" \
				| docker exec -i "${cont}" sh -ceu 'wg pubkey' \
				| tr -d '\r\n'
		)"
	else
		priv="$(
			docker run --rm --entrypoint sh "${WGO_IMAGE}" -ceu 'wg genkey' \
				| tr -d '\r\n'
		)"
		pub="$(
			printf '%s' "${priv}" \
				| docker run --rm -i --entrypoint sh "${WGO_IMAGE}" -ceu 'wg pubkey' \
				| tr -d '\r\n'
		)"
	fi
	printf '%s %s\n' "${priv}" "${pub}"
}

uapi_set_file() {
	local cont="$1"
	local payload_file="$2"
	local log_file="$3"
	local reply
	reply="$(
		cat "${payload_file}" \
			| docker exec -i "${cont}" sh -ceu '
				socket=/var/run/wireguard/wg0.sock
				if [ ! -S "${socket}" ] && [ -S /var/run/amneziawg/wg0.sock ]; then
					socket=/var/run/amneziawg/wg0.sock
				fi
				exec socat - UNIX-CONNECT:"${socket}"
			'
	)"
	printf '%s\n' "REQUEST" >>"${log_file}"
	cat "${payload_file}" >>"${log_file}"
	printf '\n%s\n\n' "${reply}" >>"${log_file}"
	if ! grep -q '^errno=0$' <<<"${reply}"; then
		echo "uapi request failed in ${cont}" >&2
		echo "${reply}" >&2
		exit 1
	fi
}

uapi_set_text() {
	local cont="$1"
	local payload="$2"
	local log_file="$3"
	local payload_file
	payload_file="$(mktemp "${TMP_DIR}/uapi.XXXXXX")"
	printf '%s\n\n' "${payload}" >"${payload_file}"
	uapi_set_file "${cont}" "${payload_file}" "${log_file}"
	rm -f "${payload_file}"
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

expect_http_text() {
	local cont="$1"
	local url="$2"
	local want="$3"
	local attempts="${4:-10}"
	local reply
	local i
	for ((i = 0; i < attempts; i++)); do
		if reply="$(docker_shell "${cont}" "curl -fsS --max-time 2 ${url}" 2>/dev/null)" && [ "${reply}" = "${want}" ]; then
			return 0
		fi
		sleep 1
	done
	echo "expected HTTP GET from ${cont} to ${url} to return ${want}" >&2
	if [ -n "${reply:-}" ]; then
		echo "last reply: ${reply}" >&2
	fi
	return 1
}

configure_userspace_interface() {
	local cont="$1"
	local tun_ip="$2"
	local peer_host="$3"
	log "configuring ${cont} tunnel address ${tun_ip}"
	docker_shell "${cont}" "ip addr replace ${tun_ip} dev wg0"
	docker_shell "${cont}" "ip link set dev wg0 mtu ${MTU} up"
	docker_shell "${cont}" "ip route replace ${peer_host}/32 dev wg0"
}

configure_kernel_interface() {
	local cont="$1"
	local tun_ip="$2"
	local peer_host="$3"
	log "configuring ${cont} kernel tunnel address ${tun_ip}"
	docker_shell "${cont}" "ip link add wg0 type wireguard"
	docker_shell "${cont}" "ip addr replace ${tun_ip} dev wg0"
	docker_shell "${cont}" "ip link set dev wg0 mtu ${MTU} up"
	docker_shell "${cont}" "ip route replace ${peer_host}/32 dev wg0"
}

configure_kernel_peer() {
	local cont="$1"
	local private_key_b64="$2"
	local peer_pub_b64="$3"
	local peer_outer_ip="$4"
	local peer_tun_host="$5"

	printf '%s' "${private_key_b64}" \
		| docker exec -i \
			-e PEER_PUB_B64="${peer_pub_b64}" \
			-e PEER_OUTER_IP="${peer_outer_ip}" \
			-e PEER_TUN_HOST="${peer_tun_host}" \
			-e SERVER_PORT="${SERVER_PORT}" \
			-e CLIENT_PORT="${CLIENT_PORT}" \
			"${cont}" \
			sh -ceu '
				umask 077
				cat >/tmp/private.key
				wg set wg0 \
					private-key /tmp/private.key \
					listen-port "${SERVER_PORT}" \
					peer "${PEER_PUB_B64}" \
						allowed-ips "${PEER_TUN_HOST}/32" \
						endpoint "${PEER_OUTER_IP}:${CLIENT_PORT}"
			'
}

amnezia_device_config_payload() {
	cat <<EOF
jc=2
jmin=11
jmax=23
s1=12
s2=12
s3=12
s4=12
h1=6111
h2=6222
h3=6333
h4=6444
i1=<b 0xaa55><rc 3><rd 2><t>
i2=<r 5>
i3=<rd 4>
i4=<rc 6>
i5=<b 0x01020304>
header_protection_key=${AMNEZIA_HEADER_KEY}
content_padding_addition=4-16
rekey_after_time=90-120
rekey_timeout=5-8
reject_after_time=180-220
keepalive_timeout=10-15
max_handshake_attempts=3-5
random_trailers=true
disable_cookies=true
EOF
}

configure_server_peer() {
	local cont="$1"
	local log_file="$2"
	local protocol="$3"
	local private_key_hex="$4"
	local peer_pub_hex="$5"
	local peer_outer_ip="$6"
	local peer_tun_host="$7"
	local extra_device_lines=""

	if [ "${protocol}" = "awg" ]; then
		extra_device_lines="$(amnezia_device_config_payload)"
	fi

	uapi_set_text "${cont}" "$(cat <<EOF
set=1
private_key=${private_key_hex}
listen_port=${SERVER_PORT}
${extra_device_lines}
replace_peers=true
public_key=${peer_pub_hex}
protocol_version=1
replace_allowed_ips=true
allowed_ip=${peer_tun_host}/32
endpoint=${peer_outer_ip}:${CLIENT_PORT}
EOF
)" "${log_file}"
}

make_server_guest_input() {
	local cont="$1"
	local protocol="$2"
	local format="$3"
	local endpoint="$4"
	local client_private="$5"
	local client_public="$6"
	local server_public="$7"
	local client_tun_ip="$8"
	local server_tun_host="$9"
	local output_file="${10}"

	docker exec \
		-e FORMAT="${format}" \
		-e PROTOCOL="${protocol}" \
		-e ENDPOINT="${endpoint}" \
		-e CLIENT_PRIVATE="${client_private}" \
		-e CLIENT_PUBLIC="${client_public}" \
		-e SERVER_PUBLIC="${server_public}" \
		-e CLIENT_ADDRESS="${client_tun_ip}" \
		-e ALLOWED_IP="${server_tun_host}/32" \
		-e HEADER_PROTECTION_KEY="${AMNEZIA_HEADER_KEY}" \
		-e MTU="${MTU}" \
		-e OUTPUT_FILE="${output_file}" \
		"${cont}" \
		sh -ceu '
			/usr/local/bin/amnesia-e2e-tool make-key \
				-format "${FORMAT}" \
				-protocol "${PROTOCOL}" \
				-endpoint "${ENDPOINT}" \
				-client-private-key "${CLIENT_PRIVATE}" \
				-client-public-key "${CLIENT_PUBLIC}" \
				-server-public-key "${SERVER_PUBLIC}" \
				-client-address "${CLIENT_ADDRESS}" \
				-allowed-ip "${ALLOWED_IP}" \
				-header-protection-key "${HEADER_PROTECTION_KEY}" \
				-mtu "${MTU}" \
				-keepalive 2 >"${OUTPUT_FILE}"
		'
}

start_selfhost_http() {
	local cont="$1"
	local guest_file="$2"
	local text="$3"

	docker exec -d "${cont}" \
		/usr/local/bin/amnesia-e2e-tool serve-selfhost \
			-listen "0.0.0.0:${SELFHOST_HTTP_PORT}" \
			-guest-file "${guest_file}" \
			-text "${text}"
}

start_probe_http() {
	local cont="$1"
	local port="$2"
	local text="$3"

	docker exec -d "${cont}" \
		/usr/local/bin/amnesia-e2e-tool serve-http \
			-listen "0.0.0.0:${port}" \
			-text "${text}"
}

start_gateway_http() {
	local cont="$1"

	docker exec -d "${cont}" \
		/usr/local/bin/amnesia-e2e-tool serve-gateway \
			-listen "0.0.0.0:${GATEWAY_HTTP_PORT}" \
			-private-key /tmp/gateway-private.pem \
			-config-file /tmp/gateway-profile.vpn
}

render_client_uapi() {
	local input_file="$1"
	local output_file="$2"

	docker run --rm \
		--entrypoint /usr/local/bin/amnesia-e2e-tool \
		-v "$(dirname "${input_file}"):/case:ro" \
		"${WGO_IMAGE}" render-uapi \
			-input "/case/$(basename "${input_file}")" >"${output_file}"
	printf '\n' >>"${output_file}"
}

make_gateway_profile() {
	local cont="$1"
	local endpoint="$2"
	local client_public="$3"
	local server_public="$4"
	local client_tun_ip="$5"
	local server_tun_host="$6"

	docker exec \
		-e ENDPOINT="${endpoint}" \
		-e CLIENT_PUBLIC="${client_public}" \
		-e SERVER_PUBLIC="${server_public}" \
		-e CLIENT_ADDRESS="${client_tun_ip}" \
		-e ALLOWED_IP="${server_tun_host}/32" \
		-e HEADER_PROTECTION_KEY="${AMNEZIA_HEADER_KEY}" \
		-e MTU="${MTU}" \
		"${cont}" \
		sh -ceu '
			/usr/local/bin/amnesia-e2e-tool make-gateway-profile \
				-endpoint "${ENDPOINT}" \
				-client-public-key "${CLIENT_PUBLIC}" \
				-server-public-key "${SERVER_PUBLIC}" \
				-client-address "${CLIENT_ADDRESS}" \
				-allowed-ip "${ALLOWED_IP}" \
				-header-protection-key "${HEADER_PROTECTION_KEY}" \
				-mtu "${MTU}" \
				-keepalive 2 >/tmp/gateway-profile.vpn
		'
}

render_negotiated_client_uapi() {
	local cont="$1"
	local client_private="$2"
	local output_file="$3"

	docker exec \
		-e GATEWAY_URL="http://amnesia-server:${GATEWAY_HTTP_PORT}/" \
		-e CLIENT_PRIVATE="${client_private}" \
		"${cont}" \
		sh -ceu '
			/usr/local/bin/amnesia-e2e-tool make-activation-key >/tmp/activation.vpn
			/usr/local/bin/amnesia-e2e-tool render-negotiated-uapi \
				-input /tmp/activation.vpn \
				-gateway-url "${GATEWAY_URL}" \
				-gateway-public-key /tmp/gateway-public.pem \
				-client-private-key "${CLIENT_PRIVATE}" >/tmp/client.uapi
		'
	docker cp "${cont}:/tmp/client.uapi" "${output_file}"
	printf '\n' >>"${output_file}"
}

exercise_gateway_edge_cases() {
	local cont="$1"
	local client_private="$2"

	docker exec \
		-e GATEWAY_URL="http://amnesia-server:${GATEWAY_HTTP_PORT}/" \
		-e CLIENT_PRIVATE="${client_private}" \
		"${cont}" \
		sh -ceu '
			/usr/local/bin/amnesia-e2e-tool exercise-gateway-edge-cases \
				-gateway-url "${GATEWAY_URL}" \
				-gateway-public-key /tmp/gateway-public.pem \
				-client-private-key "${CLIENT_PRIVATE}"
		'
}

run_case() {
	local protocol="$1"
	local format="$2"
	local index="$3"
	local case_name="${protocol}-${format}"
	local case_dir="${TMP_DIR}/${case_name}"
	local network="${RUN_ID}-${case_name}-net"
	local server_cont="${RUN_ID}-${case_name}-server"
	local client_cont="${RUN_ID}-${case_name}-client"
	local base=$((130 + index))
	local server_tun_ip="10.${base}.0.1/32"
	local client_tun_ip="10.${base}.0.2/32"
	local server_tun_host="10.${base}.0.1"
	local client_tun_host="10.${base}.0.2"
	local server_outer_ip
	local client_outer_ip
	local server_private_b64 server_public_b64 client_private_b64 client_public_b64
	local server_private_hex client_public_hex
	local key_file
	local server_guest_file="/tmp/profile.${format}"

	log "starting ${case_name} self-hosted import case"
	mkdir -p "${case_dir}"
	run docker network create "${network}"
	remember_network "${network}"

	if [ "${protocol}" = "wireguard" ]; then
		run docker run -d \
			--name "${server_cont}" \
			--hostname "${case_name}-server" \
			--network "${network}" \
			--network-alias amnesia-server \
			--privileged \
			-v /lib/modules:/lib/modules:ro \
			--entrypoint sleep \
			"${SELFHOST_IMAGE}" \
			infinity
	else
		run docker run -d \
			--name "${server_cont}" \
			--hostname "${case_name}-server" \
			--network "${network}" \
			--network-alias amnesia-server \
			--privileged \
			"${SELFHOST_IMAGE}" \
			wg0
	fi
	remember_container "${server_cont}"

	run docker run -d \
		--name "${client_cont}" \
		--hostname "${case_name}-client" \
		--network "${network}" \
		--network-alias wgo-client \
		--privileged \
		"${WGO_IMAGE}" \
		-iface wg0 \
		-tun-local "${client_tun_ip}" \
		-peer-route "${server_tun_ip}" \
		-listen-port "${CLIENT_PORT}" \
		-mtu "${MTU}" \
		-log-level debug
	remember_container "${client_cont}"

	if [ "${protocol}" = "awg" ]; then
		wait_for_cmd "${server_cont}" "test -S /var/run/amneziawg/wg0.sock"
		wait_for_cmd "${server_cont}" "ip link show dev wg0"
	else
		wait_for_cmd "${server_cont}" "true"
	fi
	wait_for_cmd "${client_cont}" "test -S /var/run/wireguard/wg0.sock"
	wait_for_cmd "${client_cont}" "ip link show dev wg0"

	server_outer_ip="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${server_cont}")"
	client_outer_ip="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${client_cont}")"

	read -r server_private_b64 server_public_b64 <<<"$(new_key_pair "${server_cont}")"
	read -r client_private_b64 client_public_b64 <<<"$(new_key_pair "${server_cont}")"
	server_private_hex="$(b64_to_hex "${server_private_b64}")"
	client_public_hex="$(b64_to_hex "${client_public_b64}")"

	if [ "${protocol}" = "wireguard" ]; then
		configure_kernel_interface "${server_cont}" "${server_tun_ip}" "${client_tun_host}"
		configure_kernel_peer "${server_cont}" "${server_private_b64}" "${client_public_b64}" "${client_outer_ip}" "${client_tun_host}"
	else
		configure_userspace_interface "${server_cont}" "${server_tun_ip}" "${client_tun_host}"
		configure_server_peer "${server_cont}" "${case_dir}/server-uapi.log" "${protocol}" "${server_private_hex}" "${client_public_hex}" "${client_outer_ip}" "${client_tun_host}"
	fi

	key_file="${case_dir}/profile.${format}"
	make_server_guest_input "${server_cont}" "${protocol}" "${format}" "${server_outer_ip}:${SERVER_PORT}" "${client_private_b64}" "${client_public_b64}" "${server_public_b64}" "${client_tun_ip}" "${server_tun_host}" "${server_guest_file}"
	start_selfhost_http "${server_cont}" "${server_guest_file}" "${case_name}-server-ok"
	wait_for_cmd "${client_cont}" "curl -fsS http://amnesia-server:${SELFHOST_HTTP_PORT}/health"
	if [ "${format}" = "vpn" ]; then
		docker_shell "${client_cont}" "curl -fsS http://amnesia-server:${SELFHOST_HTTP_PORT}/guest.vpn" >"${key_file}"
		if ! grep -q '^vpn://' "${key_file}"; then
			echo "server did not return a vpn:// guest key" >&2
			exit 1
		fi
	else
		docker cp "${server_cont}:${server_guest_file}" "${key_file}"
	fi
	render_client_uapi "${key_file}" "${case_dir}/client.uapi"
	uapi_set_file "${client_cont}" "${case_dir}/client.uapi" "${case_dir}/client-uapi.log"

	expect_ping_success "${client_cont}" "${server_tun_host}"
	expect_ping_success "${server_cont}" "${client_tun_host}"
	expect_http_text "${client_cont}" "http://${server_tun_host}:${SELFHOST_HTTP_PORT}/" "${case_name}-server-ok"
	start_probe_http "${client_cont}" "${CLIENT_HTTP_PORT}" "${case_name}-client-ok"
	wait_for_cmd "${client_cont}" "curl -fsS http://127.0.0.1:${CLIENT_HTTP_PORT}/health"
	expect_http_text "${server_cont}" "http://${client_tun_host}:${CLIENT_HTTP_PORT}/" "${case_name}-client-ok"
	log "${case_name} self-hosted import case passed"
}

run_gateway_case() {
	local case_name="awg-gateway"
	local case_dir="${TMP_DIR}/${case_name}"
	local network="${RUN_ID}-${case_name}-net"
	local server_cont="${RUN_ID}-${case_name}-server"
	local client_cont="${RUN_ID}-${case_name}-client"
	local base=136
	local server_tun_ip="10.${base}.0.1/32"
	local client_tun_ip="10.${base}.0.2/32"
	local server_tun_host="10.${base}.0.1"
	local client_tun_host="10.${base}.0.2"
	local server_outer_ip
	local client_outer_ip
	local server_private_b64 server_public_b64 client_private_b64 client_public_b64
	local server_private_hex client_public_hex

	log "starting ${case_name} negotiated import case"
	mkdir -p "${case_dir}"
	run docker network create "${network}"
	remember_network "${network}"

	run docker run -d \
		--name "${server_cont}" \
		--hostname "${case_name}-server" \
		--network "${network}" \
		--network-alias amnesia-server \
		--privileged \
		"${SELFHOST_IMAGE}" \
		wg0
	remember_container "${server_cont}"

	run docker run -d \
		--name "${client_cont}" \
		--hostname "${case_name}-client" \
		--network "${network}" \
		--network-alias wgo-client \
		--privileged \
		"${WGO_IMAGE}" \
		-iface wg0 \
		-tun-local "${client_tun_ip}" \
		-peer-route "${server_tun_ip}" \
		-listen-port "${CLIENT_PORT}" \
		-mtu "${MTU}" \
		-log-level debug
	remember_container "${client_cont}"

	wait_for_cmd "${server_cont}" "test -S /var/run/amneziawg/wg0.sock"
	wait_for_cmd "${server_cont}" "ip link show dev wg0"
	wait_for_cmd "${client_cont}" "test -S /var/run/wireguard/wg0.sock"
	wait_for_cmd "${client_cont}" "ip link show dev wg0"

	server_outer_ip="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${server_cont}")"
	client_outer_ip="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${client_cont}")"

	read -r server_private_b64 server_public_b64 <<<"$(new_key_pair "${server_cont}")"
	read -r client_private_b64 client_public_b64 <<<"$(new_key_pair "${server_cont}")"
	server_private_hex="$(b64_to_hex "${server_private_b64}")"
	client_public_hex="$(b64_to_hex "${client_public_b64}")"

	configure_userspace_interface "${server_cont}" "${server_tun_ip}" "${client_tun_host}"
	configure_server_peer "${server_cont}" "${case_dir}/server-uapi.log" awg "${server_private_hex}" "${client_public_hex}" "${client_outer_ip}" "${client_tun_host}"

	docker_shell "${server_cont}" "/usr/local/bin/amnesia-e2e-tool make-gateway-rsa -private-file /tmp/gateway-private.pem -public-file /tmp/gateway-public.pem >/dev/null"
	make_gateway_profile "${server_cont}" "${server_outer_ip}:${SERVER_PORT}" "${client_public_b64}" "${server_public_b64}" "${client_tun_ip}" "${server_tun_host}"
	start_gateway_http "${server_cont}"
	wait_for_cmd "${client_cont}" "curl -fsS http://amnesia-server:${GATEWAY_HTTP_PORT}/health"
	docker cp "${server_cont}:/tmp/gateway-public.pem" "${case_dir}/gateway-public.pem"
	docker cp "${case_dir}/gateway-public.pem" "${client_cont}:/tmp/gateway-public.pem"

	exercise_gateway_edge_cases "${client_cont}" "${client_private_b64}"
	render_negotiated_client_uapi "${client_cont}" "${client_private_b64}" "${case_dir}/client.uapi"
	uapi_set_file "${client_cont}" "${case_dir}/client.uapi" "${case_dir}/client-uapi.log"

	expect_ping_success "${client_cont}" "${server_tun_host}"
	expect_ping_success "${server_cont}" "${client_tun_host}"
	start_selfhost_http "${server_cont}" /tmp/gateway-profile.vpn "${case_name}-server-ok"
	expect_http_text "${client_cont}" "http://${server_tun_host}:${SELFHOST_HTTP_PORT}/" "${case_name}-server-ok"
	start_probe_http "${client_cont}" "${CLIENT_HTTP_PORT}" "${case_name}-client-ok"
	wait_for_cmd "${client_cont}" "curl -fsS http://127.0.0.1:${CLIENT_HTTP_PORT}/health"
	expect_http_text "${server_cont}" "http://${client_tun_host}:${CLIENT_HTTP_PORT}/" "${case_name}-client-ok"
	log "${case_name} negotiated import case passed"
}

main() {
	require_cmd docker
	require_cmd base64
	require_cmd od
	require_tun
	require_docker_ready

	run docker build -f tests/amnesia/docker/wgo-client.Dockerfile -t "${WGO_IMAGE}" "${ROOT_DIR}"
	run docker build -f tests/amnesia/docker/selfhost-server.Dockerfile -t "${SELFHOST_IMAGE}" "${ROOT_DIR}"
	require_privileged_containers

	run_case wireguard vpn 1
	run_case wireguard conf 2
	run_case awg vpn 3
	run_case awg conf 4
	run_gateway_case

	log "amnesia self-hosted e2e suite passed"
	log "artifacts: ${TMP_DIR}"
}

main "$@"
