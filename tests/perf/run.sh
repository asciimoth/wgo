#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN_ID="wgo-perf-$$"
TMP_DIR="${ROOT_DIR}/.tmp/perf/${RUN_ID}"
PERF_LOG="${ROOT_DIR}/performance-log.md"
SUMMARY_BIN="${TMP_DIR}/iperf-summary"

KERNEL_IMAGE="wgo-perf-kernel:${RUN_ID}"
WGO_IMAGE="wgo-perf-wgo:${RUN_ID}"
UPSTREAM_IMAGE="wgo-perf-upstream:${RUN_ID}"
AMNEZIA_IMAGE="wgo-perf-amnezia:${RUN_ID}"

MTU="${MTU:-1420}"
IPERF_SECONDS="${IPERF_SECONDS:-10}"
IPERF_OMIT_SECONDS="${IPERF_OMIT_SECONDS:-1}"
IPERF_PORT="${IPERF_PORT:-5201}"
WG_PORT_A="${WG_PORT_A:-51820}"
WG_PORT_B="${WG_PORT_B:-51821}"

SUBJECTS=(wgo wgo-amnezia wireguard-go amneziawg-go kernel)
NETWORKS=()
CONTAINERS=()
IMAGES=("${KERNEL_IMAGE}" "${WGO_IMAGE}" "${UPSTREAM_IMAGE}" "${AMNEZIA_IMAGE}")

mkdir -p "${TMP_DIR}"

log() {
	printf '==> %s\n' "$*" >&2
}

run() {
	log "$*"
	"$@"
}

append_log() {
	printf '%s\n' "$*" >>"${PERF_LOG}"
}

direction_label() {
	case "$1" in
		a-to-b) printf 'peer-a -> peer-b\n' ;;
		b-to-a) printf 'peer-b -> peer-a\n' ;;
		*) printf '%s\n' "$1" ;;
	esac
}

docker_shell() {
	local cont="$1"
	local cmd="$2"
	docker exec "${cont}" sh -ceu "${cmd}"
}

subject_dir() {
	printf '%s/%s\n' "${TMP_DIR}" "$1"
}

capture_state_for_container() {
	local subject="$1"
	local cont="$2"
	local prefix="$3"
	local dir
	dir="$(subject_dir "${subject}")"
	mkdir -p "${dir}"

	set +e
	docker logs "${cont}" >"${dir}/${prefix}.log" 2>&1 || true
	docker_shell "${cont}" "ip addr show; ip route show; wg show || true" >"${dir}/${prefix}-state.txt" 2>&1 || true
	set -e
}

cleanup() {
	local item subject cont prefix network image

	set +e
	for item in "${CONTAINERS[@]}"; do
		subject="${item%%:*}"
		cont="${item#*:}"
		prefix="${cont##*-}"
		capture_state_for_container "${subject}" "${cont}" "${prefix}"
	done
	for item in "${CONTAINERS[@]}"; do
		cont="${item#*:}"
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
	echo "timed out waiting for ${cmd} in ${cont}" >&2
	return 1
}

wait_for_iperf_server() {
	local cont="$1"
	wait_for_cmd "${cont}" "ss -lntup | grep -q ':${IPERF_PORT} '"
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

uapi_set() {
	local cont="$1"
	local payload="$2"
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
	if ! grep -q '^errno=0$' <<<"${reply}"; then
		echo "uapi request failed in ${cont}" >&2
		echo "${reply}" >&2
		exit 1
	fi
}

configure_kernel_iface() {
	local cont="$1"
	local local_ip="$2"
	local peer_host="$3"
	docker_shell "${cont}" "ip link add wg0 type wireguard"
	docker_shell "${cont}" "ip addr replace ${local_ip} dev wg0"
	docker_shell "${cont}" "ip link set dev wg0 mtu ${MTU} up"
	docker_shell "${cont}" "ip route replace ${peer_host}/32 dev wg0"
}

configure_userspace_iface() {
	local cont="$1"
	local local_ip="$2"
	local peer_host="$3"
	docker_shell "${cont}" "ip addr replace ${local_ip} dev wg0"
	docker_shell "${cont}" "ip link set dev wg0 mtu ${MTU} up"
	docker_shell "${cont}" "ip route replace ${peer_host}/32 dev wg0"
}

set_peer_with_wg() {
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

set_peer_with_uapi() {
	local cont="$1"
	local private_key_hex="$2"
	local listen_port="$3"
	local peer_pub_hex="$4"
	local peer_outer_ip="$5"
	local peer_port="$6"
	local peer_tun_host="$7"
	local extra_device_lines="${8:-}"
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
)"
}

amnezia_perf_device_config_payload() {
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

run_iperf() {
	local subject="$1"
	local protocol="$2"
	local direction="$3"
	local client_cont="$4"
	local server_cont="$5"
	local server_tun_ip="$6"
	local output_file="$7"
	local client_args=()

	client_args+=("-c" "${server_tun_ip}" "-p" "${IPERF_PORT}" "-t" "${IPERF_SECONDS}" "-O" "${IPERF_OMIT_SECONDS}" "-J")
	if [[ "${protocol}" == "udp" ]]; then
		client_args+=("-u" "-b" "0")
	fi

	docker exec -d "${server_cont}" sh -ceu "exec iperf3 -s -1 -B ${server_tun_ip} -p ${IPERF_PORT}" >/dev/null
	wait_for_iperf_server "${server_cont}"
	docker exec "${client_cont}" iperf3 "${client_args[@]}" >"${output_file}"
	"${SUMMARY_BIN}" \
		-subject "${subject}" \
		-protocol "${protocol}" \
		-direction "$(direction_label "${direction}")" \
		-file "${output_file}" >>"${PERF_LOG}"
}

benchmark_subject() {
	local subject="$1"
	local cont_a="$2"
	local cont_b="$3"
	local tun_host_a="$4"
	local tun_host_b="$5"
	local dir

	dir="$(subject_dir "${subject}")"
	mkdir -p "${dir}"

	expect_ping_success "${cont_a}" "${tun_host_b}"
	expect_ping_success "${cont_b}" "${tun_host_a}"

	append_log "### TCP"
	append_log ""
	append_log "| Direction | Duration (s) | Sender (Mbps) | Receiver (Mbps) | Retransmits | Bytes Sent | Bytes Received |"
	append_log "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"
	run_iperf "${subject}" tcp "a-to-b" "${cont_a}" "${cont_b}" "${tun_host_b}" "${dir}/tcp-a-to-b.json"
	run_iperf "${subject}" tcp "b-to-a" "${cont_b}" "${cont_a}" "${tun_host_a}" "${dir}/tcp-b-to-a.json"
	append_log ""
	append_log "### UDP"
	append_log ""
	append_log "| Direction | Duration (s) | Throughput (Mbps) | Jitter (ms) | Lost (%) | Bytes | Packets | Lost Packets |"
	append_log "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
	run_iperf "${subject}" udp "a-to-b" "${cont_a}" "${cont_b}" "${tun_host_b}" "${dir}/udp-a-to-b.json"
	run_iperf "${subject}" udp "b-to-a" "${cont_b}" "${cont_a}" "${tun_host_a}" "${dir}/udp-b-to-a.json"
	append_log ""
}

start_subject_containers() {
	local subject="$1"
	local network="$2"
	local cont_a="$3"
	local cont_b="$4"
	local tun_ip_a="$5"
	local tun_ip_b="$6"

	case "${subject}" in
		wgo | wgo-amnezia)
			run docker run -d \
				--name "${cont_a}" \
				--hostname "${cont_a}" \
				--network "${network}" \
				--privileged \
				"${WGO_IMAGE}" \
				-iface wg0 \
				-tun-local "${tun_ip_a}" \
				-peer-route "${tun_ip_b}" \
				-listen-port "${WG_PORT_A}" \
				-mtu "${MTU}" \
				-log-level error
			run docker run -d \
				--name "${cont_b}" \
				--hostname "${cont_b}" \
				--network "${network}" \
				--privileged \
				"${WGO_IMAGE}" \
				-iface wg0 \
				-tun-local "${tun_ip_b}" \
				-peer-route "${tun_ip_a}" \
				-listen-port "${WG_PORT_B}" \
				-mtu "${MTU}" \
				-log-level error
			CONTAINERS+=("${subject}:${cont_a}" "${subject}:${cont_b}")
			wait_for_cmd "${cont_a}" "test -S /var/run/wireguard/wg0.sock"
			wait_for_cmd "${cont_b}" "test -S /var/run/wireguard/wg0.sock"
			wait_for_cmd "${cont_a}" "ip link show dev wg0"
			wait_for_cmd "${cont_b}" "ip link show dev wg0"
			;;
		wireguard-go)
			run docker run -d \
				--name "${cont_a}" \
				--hostname "${cont_a}" \
				--network "${network}" \
				--privileged \
				"${UPSTREAM_IMAGE}" \
				wg0
			run docker run -d \
				--name "${cont_b}" \
				--hostname "${cont_b}" \
				--network "${network}" \
				--privileged \
				"${UPSTREAM_IMAGE}" \
				wg0
			CONTAINERS+=("${subject}:${cont_a}" "${subject}:${cont_b}")
			wait_for_cmd "${cont_a}" "test -S /var/run/wireguard/wg0.sock"
			wait_for_cmd "${cont_b}" "test -S /var/run/wireguard/wg0.sock"
			wait_for_cmd "${cont_a}" "ip link show dev wg0"
			wait_for_cmd "${cont_b}" "ip link show dev wg0"
			;;
		amneziawg-go)
			run docker run -d \
				--name "${cont_a}" \
				--hostname "${cont_a}" \
				--network "${network}" \
				--privileged \
				"${AMNEZIA_IMAGE}" \
				wg0
			run docker run -d \
				--name "${cont_b}" \
				--hostname "${cont_b}" \
				--network "${network}" \
				--privileged \
				"${AMNEZIA_IMAGE}" \
				wg0
			CONTAINERS+=("${subject}:${cont_a}" "${subject}:${cont_b}")
			wait_for_cmd "${cont_a}" "test -S /var/run/amneziawg/wg0.sock"
			wait_for_cmd "${cont_b}" "test -S /var/run/amneziawg/wg0.sock"
			wait_for_cmd "${cont_a}" "ip link show dev wg0"
			wait_for_cmd "${cont_b}" "ip link show dev wg0"
			;;
		kernel)
			run docker run -d \
				--name "${cont_a}" \
				--hostname "${cont_a}" \
				--network "${network}" \
				--privileged \
				-v /lib/modules:/lib/modules:ro \
				"${KERNEL_IMAGE}"
			run docker run -d \
				--name "${cont_b}" \
				--hostname "${cont_b}" \
				--network "${network}" \
				--privileged \
				-v /lib/modules:/lib/modules:ro \
				"${KERNEL_IMAGE}"
			CONTAINERS+=("${subject}:${cont_a}" "${subject}:${cont_b}")
			;;
		*)
			echo "unsupported subject: ${subject}" >&2
			exit 1
			;;
	esac
}

configure_subject() {
	local subject="$1"
	local cont_a="$2"
	local cont_b="$3"
	local tun_ip_a="$4"
	local tun_ip_b="$5"
	local tun_host_a="$6"
	local tun_host_b="$7"
	local outer_ip_a="$8"
	local outer_ip_b="$9"
	local key_a key_b priv_a pub_a priv_b pub_b amnezia_device_lines

	key_a="$(new_key_pair "${cont_a}")"
	key_b="$(new_key_pair "${cont_b}")"
	read -r priv_a pub_a <<<"${key_a}"
	read -r priv_b pub_b <<<"${key_b}"
	amnezia_device_lines="$(amnezia_perf_device_config_payload)"$'\n'

	case "${subject}" in
		wgo)
			set_peer_with_uapi "${cont_a}" "$(b64_to_hex "${priv_a}")" "${WG_PORT_A}" "$(b64_to_hex "${pub_b}")" "${outer_ip_b}" "${WG_PORT_B}" "${tun_host_b}"
			set_peer_with_uapi "${cont_b}" "$(b64_to_hex "${priv_b}")" "${WG_PORT_B}" "$(b64_to_hex "${pub_a}")" "${outer_ip_a}" "${WG_PORT_A}" "${tun_host_a}"
			;;
		wgo-amnezia)
			set_peer_with_uapi "${cont_a}" "$(b64_to_hex "${priv_a}")" "${WG_PORT_A}" "$(b64_to_hex "${pub_b}")" "${outer_ip_b}" "${WG_PORT_B}" "${tun_host_b}" "${amnezia_device_lines}"
			set_peer_with_uapi "${cont_b}" "$(b64_to_hex "${priv_b}")" "${WG_PORT_B}" "$(b64_to_hex "${pub_a}")" "${outer_ip_a}" "${WG_PORT_A}" "${tun_host_a}" "${amnezia_device_lines}"
			;;
		wireguard-go)
			configure_userspace_iface "${cont_a}" "${tun_ip_a}" "${tun_host_b}"
			configure_userspace_iface "${cont_b}" "${tun_ip_b}" "${tun_host_a}"
			set_peer_with_wg "${cont_a}" "${priv_a}" "${WG_PORT_A}" "${pub_b}" "${outer_ip_b}" "${WG_PORT_B}" "${tun_host_b}"
			set_peer_with_wg "${cont_b}" "${priv_b}" "${WG_PORT_B}" "${pub_a}" "${outer_ip_a}" "${WG_PORT_A}" "${tun_host_a}"
			;;
		amneziawg-go)
			configure_userspace_iface "${cont_a}" "${tun_ip_a}" "${tun_host_b}"
			configure_userspace_iface "${cont_b}" "${tun_ip_b}" "${tun_host_a}"
			set_peer_with_uapi "${cont_a}" "$(b64_to_hex "${priv_a}")" "${WG_PORT_A}" "$(b64_to_hex "${pub_b}")" "${outer_ip_b}" "${WG_PORT_B}" "${tun_host_b}" "${amnezia_device_lines}"
			set_peer_with_uapi "${cont_b}" "$(b64_to_hex "${priv_b}")" "${WG_PORT_B}" "$(b64_to_hex "${pub_a}")" "${outer_ip_a}" "${WG_PORT_A}" "${tun_host_a}" "${amnezia_device_lines}"
			;;
		kernel)
			configure_kernel_iface "${cont_a}" "${tun_ip_a}" "${tun_host_b}"
			configure_kernel_iface "${cont_b}" "${tun_ip_b}" "${tun_host_a}"
			set_peer_with_wg "${cont_a}" "${priv_a}" "${WG_PORT_A}" "${pub_b}" "${outer_ip_b}" "${WG_PORT_B}" "${tun_host_b}"
			set_peer_with_wg "${cont_b}" "${priv_b}" "${WG_PORT_B}" "${pub_a}" "${outer_ip_a}" "${WG_PORT_A}" "${tun_host_a}"
			;;
	esac
}

record_subject_metadata() {
	local subject="$1"
	local cont="$2"
	append_log ""
	append_log "## ${subject}"
	append_log ""
		case "${subject}" in
			wgo)
				append_log "- Revision: \`$(git -C "${ROOT_DIR}" rev-parse --short HEAD)\`"
				;;
			wgo-amnezia)
				append_log "- Revision: \`$(git -C "${ROOT_DIR}" rev-parse --short HEAD)\`"
				append_log "- Profile: non-default Amnezia UAPI fields (`jc=2`, `jmin=11`, `jmax=23`, `s1=13`, `s2=17`, `s3=19`, `s4=29`)"
				;;
			wireguard-go)
				append_log "- Upstream revision: \`$(docker_shell "${cont}" "cat /usr/local/share/wireguard-go.commit" | cut -c1-12)\`"
				;;
			amneziawg-go)
				append_log "- Upstream revision: \`$(docker_shell "${cont}" "cat /usr/local/share/amneziawg-go.commit" | cut -c1-12)\`"
				append_log "- Profile: non-default Amnezia UAPI fields (`jc=2`, `jmin=11`, `jmax=23`, `s1=13`, `s2=17`, `s3=19`, `s4=29`)"
				;;
		kernel)
			append_log "- Kernel release: \`$(docker_shell "${cont}" "uname -r")\`"
			;;
	esac
	append_log ""
}

run_subject() {
	local subject="$1"
	local network="${RUN_ID}-${subject}-net"
	local cont_a="${RUN_ID}-${subject}-a"
	local cont_b="${RUN_ID}-${subject}-b"
	local tun_ip_a="10.88.0.1/32"
	local tun_ip_b="10.88.0.2/32"
	local tun_host_a="10.88.0.1"
	local tun_host_b="10.88.0.2"
	local outer_ip_a outer_ip_b

	mkdir -p "$(subject_dir "${subject}")"

	run docker network create "${network}"
	NETWORKS+=("${network}")

	start_subject_containers "${subject}" "${network}" "${cont_a}" "${cont_b}" "${tun_ip_a}" "${tun_ip_b}"

	outer_ip_a="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${cont_a}")"
	outer_ip_b="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${cont_b}")"

	record_subject_metadata "${subject}" "${cont_a}"
	configure_subject "${subject}" "${cont_a}" "${cont_b}" "${tun_ip_a}" "${tun_ip_b}" "${tun_host_a}" "${tun_host_b}" "${outer_ip_a}" "${outer_ip_b}"
	benchmark_subject "${subject}" "${cont_a}" "${cont_b}" "${tun_host_a}" "${tun_host_b}"
}

main() {
	require_cmd docker
	require_cmd base64
	require_cmd od
	require_cmd go

	: >"${PERF_LOG}"
	append_log "# WireGuard Performance Report"
	append_log ""
	append_log "- Generated: $(date -u +"%Y-%m-%d %H:%M:%SZ")"
	append_log "- Duration per iperf run: ${IPERF_SECONDS}s"
	append_log "- Omit window: ${IPERF_OMIT_SECONDS}s"
	append_log "- MTU: ${MTU}"
	append_log ""

	run go build -o "${SUMMARY_BIN}" ./tests/perf/cmd/iperf_summary
	run docker build -f tests/perf/docker/kernel-peer.Dockerfile -t "${KERNEL_IMAGE}" "${ROOT_DIR}"
	run docker build -f tests/perf/docker/wgo-peer.Dockerfile -t "${WGO_IMAGE}" "${ROOT_DIR}"
	run docker build -f tests/perf/docker/upstream-peer.Dockerfile -t "${UPSTREAM_IMAGE}" "${ROOT_DIR}"
	run docker build -f tests/perf/docker/amnezia-peer.Dockerfile -t "${AMNEZIA_IMAGE}" "${ROOT_DIR}"

	for subject in "${SUBJECTS[@]}"; do
		log "running ${subject} performance benchmarks"
		run_subject "${subject}"
	done

	log "performance suite passed"
	log "artifacts: ${TMP_DIR}"
	log "summary log: performance-log.md"
}

main "$@"
