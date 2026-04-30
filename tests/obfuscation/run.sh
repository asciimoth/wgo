#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN_ID="wgo-obfuscation-$$"
TMP_DIR="${ROOT_DIR}/.tmp/obfuscation/${RUN_ID}"
MTU="${MTU:-1420}"
WG_PORT="${WG_PORT:-51820}"
CAPTURE_DURATION="${CAPTURE_DURATION:-8}"
CAPTURE_PACKET_COUNT="${CAPTURE_PACKET_COUNT:-16}"

WGO_IMAGE="wgo-obfuscation-wgo:${RUN_ID}"
ANALYZER_IMAGE="wgo-obfuscation-analyzer:${RUN_ID}"

mkdir -p "${TMP_DIR}"

CONTAINERS=()
NETWORKS=()
IMAGES=("${WGO_IMAGE}" "${ANALYZER_IMAGE}")

log() {
	printf '==> %s\n' "$*" >&2
}

run() {
	log "$*"
	"$@"
}

require_cmd() {
	command -v "$1" >/dev/null 2>&1 || {
		echo "missing required command: $1" >&2
		exit 1
	}
}

remember_container() {
	CONTAINERS+=("$1")
}

remember_network() {
	NETWORKS+=("$1")
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
	local log_file="$3"
	local reply
	reply="$(
		printf '%s\n\n' "${payload}" \
			| docker exec -i "${cont}" sh -ceu '
				exec socat - UNIX-CONNECT:/var/run/wireguard/wg0.sock
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

start_capture() {
	local capture_cont="$1"
	local target_cont="$2"
	local case_dir="$3"
	local capture_file="$4"

	run docker run -d \
		--name "${capture_cont}" \
		--network "container:${target_cont}" \
		--cap-add NET_ADMIN \
		--cap-add NET_RAW \
		-v "${case_dir}:/artifacts" \
		"${ANALYZER_IMAGE}" \
		sh -ceu "timeout ${CAPTURE_DURATION} tcpdump -ni eth0 udp port ${WG_PORT} -c ${CAPTURE_PACKET_COUNT} -w /artifacts/${capture_file}; status=\$?; [ \"\${status}\" -eq 0 ] || [ \"\${status}\" -eq 124 ]"
	remember_container "${capture_cont}"
	sleep 1
}

write_capture_report() {
	local case_dir="$1"
	local capture_file="$2"
	local report_file="$3"

	docker run --rm \
		-e WG_PORT="${WG_PORT}" \
		-v "${case_dir}:/artifacts" \
		"${ANALYZER_IMAGE}" \
		sh -ceu "$(cat <<'EOF'
capture_file="$1"
tshark -n -r "/artifacts/${capture_file}" -Y "udp.port == ${WG_PORT}" -T fields -e udp.payload \
	| awk '
		BEGIN {
			total = 0
			initiation = 0
			response = 0
			cookie = 0
			transport = 0
		}
		{
			payload = $0
			gsub(":", "", payload)
			if (payload == "") {
				next
			}

			total++
			payload_len = length(payload) / 2
			prefix = substr(payload, 1, 8)

			if (prefix == "01000000" && payload_len == 148) {
				initiation++
			} else if (prefix == "02000000" && payload_len == 92) {
				response++
			} else if (prefix == "03000000" && payload_len == 64) {
				cookie++
			} else if (prefix == "04000000" && payload_len >= 32) {
				transport++
			}
		}
		END {
			printf "packet_count=%d\n", total
			printf "initiation_packets=%d\n", initiation
			printf "response_packets=%d\n", response
			printf "cookie_packets=%d\n", cookie
			printf "transport_packets=%d\n", transport
			printf "wireguard_signature_packets=%d\n", initiation + response + cookie + transport
		}
	'
EOF
)" sh "${capture_file}" >"${report_file}"
}

assert_case_result() {
	local case_name="$1"
	local report_file="$2"
	local expected_mode="$3"
	local packet_count
	local initiation_packets
	local response_packets
	local transport_packets
	local wireguard_signature_packets

	packet_count="$(awk -F= '/^packet_count=/{print $2}' "${report_file}")"
	initiation_packets="$(awk -F= '/^initiation_packets=/{print $2}' "${report_file}")"
	response_packets="$(awk -F= '/^response_packets=/{print $2}' "${report_file}")"
	transport_packets="$(awk -F= '/^transport_packets=/{print $2}' "${report_file}")"
	wireguard_signature_packets="$(awk -F= '/^wireguard_signature_packets=/{print $2}' "${report_file}")"

	if [[ -z "${packet_count}" || -z "${wireguard_signature_packets}" ]]; then
		echo "missing analyzer output for ${case_name}" >&2
		exit 1
	fi
	if (( packet_count == 0 )); then
		echo "expected captured traffic for ${case_name}, but capture was empty" >&2
		exit 1
	fi

	case "${expected_mode}" in
		wireguard-visible)
			if (( initiation_packets == 0 || response_packets == 0 || transport_packets == 0 )); then
				echo "expected standard WireGuard signatures for ${case_name}" >&2
				exit 1
			fi
			;;
		wireguard-hidden)
			if (( wireguard_signature_packets != 0 )); then
				echo "expected obfuscation to hide standard WireGuard signatures for ${case_name}" >&2
				exit 1
			fi
			;;
		*)
			echo "unknown expected mode: ${expected_mode}" >&2
			exit 1
			;;
	esac
}

run_case() {
	local case_name="$1"
	local tun_a_cidr="$2"
	local tun_a_host="$3"
	local tun_b_cidr="$4"
	local tun_b_host="$5"
	local extra_device_lines="$6"
	local expected_mode="$7"
	local case_dir network cont_a cont_b capture_cont outer_ip_a outer_ip_b
	local a_priv_b64 a_pub_b64 b_priv_b64 b_pub_b64 a_priv_hex b_priv_hex a_pub_hex b_pub_hex
	local capture_file report_file

	case_dir="${TMP_DIR}/${case_name}"
	network="${RUN_ID}-${case_name}-net"
	cont_a="${RUN_ID}-${case_name}-a"
	cont_b="${RUN_ID}-${case_name}-b"
	capture_cont="${RUN_ID}-${case_name}-capture"
	capture_file="outer-traffic.pcapng"
	report_file="${case_dir}/analysis.txt"

	mkdir -p "${case_dir}"
	chmod 0777 "${case_dir}"

	log "starting ${case_name} obfuscation case"
	run docker network create "${network}"
	remember_network "${network}"

	run docker run -d \
		--name "${cont_a}" \
		--hostname "${case_name}-a" \
		--network "${network}" \
		--network-alias "${case_name}-a" \
		--privileged \
		"${WGO_IMAGE}" \
		-iface wg0 \
		-tun-local "${tun_a_cidr}" \
		-peer-route "${tun_b_cidr}" \
		-listen-port "${WG_PORT}" \
		-mtu "${MTU}" \
		-log-level debug
	remember_container "${cont_a}"

	run docker run -d \
		--name "${cont_b}" \
		--hostname "${case_name}-b" \
		--network "${network}" \
		--network-alias "${case_name}-b" \
		--privileged \
		"${WGO_IMAGE}" \
		-iface wg0 \
		-tun-local "${tun_b_cidr}" \
		-peer-route "${tun_a_cidr}" \
		-listen-port "${WG_PORT}" \
		-mtu "${MTU}" \
		-log-level debug
	remember_container "${cont_b}"

	wait_for_cmd "${cont_a}" "test -S /var/run/wireguard/wg0.sock"
	wait_for_cmd "${cont_a}" "ip link show dev wg0"
	wait_for_cmd "${cont_b}" "test -S /var/run/wireguard/wg0.sock"
	wait_for_cmd "${cont_b}" "ip link show dev wg0"

	outer_ip_a="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${cont_a}")"
	outer_ip_b="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${cont_b}")"

	read -r a_priv_b64 a_pub_b64 <<<"$(new_key_pair "${cont_a}")"
	read -r b_priv_b64 b_pub_b64 <<<"$(new_key_pair "${cont_a}")"

	a_priv_hex="$(b64_to_hex "${a_priv_b64}")"
	b_priv_hex="$(b64_to_hex "${b_priv_b64}")"
	a_pub_hex="$(b64_to_hex "${a_pub_b64}")"
	b_pub_hex="$(b64_to_hex "${b_pub_b64}")"

	configure_wgo_peer "${cont_a}" "${case_dir}/a-uapi.log" "${a_priv_hex}" "${WG_PORT}" "${b_pub_hex}" "${outer_ip_b}" "${WG_PORT}" "${tun_b_host}" "${extra_device_lines}"
	configure_wgo_peer "${cont_b}" "${case_dir}/b-uapi.log" "${b_priv_hex}" "${WG_PORT}" "${a_pub_hex}" "${outer_ip_a}" "${WG_PORT}" "${tun_a_host}" "${extra_device_lines}"

	start_capture "${capture_cont}" "${cont_a}" "${case_dir}" "${capture_file}"

	expect_ping_success "${cont_a}" "${tun_b_host}"
	expect_ping_success "${cont_b}" "${tun_a_host}"
	docker_shell "${cont_a}" "ping -c 5 -W 1 -i 0.2 ${tun_b_host}"
	docker_shell "${cont_b}" "ping -c 5 -W 1 -i 0.2 ${tun_a_host}"

	run docker wait "${capture_cont}" >/dev/null
	docker logs "${capture_cont}" >"${case_dir}/capture.log" 2>&1 || true

	write_capture_report "${case_dir}" "${capture_file}" "${report_file}"
	assert_case_result "${case_name}" "${report_file}" "${expected_mode}"

	capture_state "${cont_a}" "${case_dir}" "a"
	capture_state "${cont_b}" "${case_dir}" "b"
}

main() {
	require_cmd docker
	require_cmd base64
	require_cmd od

	run docker build -f tests/compat/docker/wgo-peer.Dockerfile -t "${WGO_IMAGE}" "${ROOT_DIR}"
	run docker build -f tests/obfuscation/docker/analyzer.Dockerfile -t "${ANALYZER_IMAGE}" "${ROOT_DIR}"

	run_case "vanilla" "10.91.0.1/32" "10.91.0.1" "10.91.0.2/32" "10.91.0.2" "" "wireguard-visible"
	run_case "amnezia" "10.92.0.1/32" "10.92.0.1" "10.92.0.2/32" "10.92.0.2" "$(amnezia_device_config_payload)"$'\n' "wireguard-hidden"

	log "obfuscation suite passed"
	log "artifacts: ${TMP_DIR}"
}

main "$@"
