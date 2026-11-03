#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
for binary in helios-server helios-daemon heliosctl; do
    test -x "target/release/$binary" || { echo "build target/release/$binary first" >&2; exit 1; }
done
for command in openssl python3 curl; do
    command -v "$command" >/dev/null || { echo "missing $command" >&2; exit 1; }
done
transport=${SMOKE_TRANSPORT:-quic}
[[ $transport == quic || $transport == tls ]] || { echo 'SMOKE_TRANSPORT must be quic or tls' >&2; exit 1; }

base=${HELIOS_TEST_PORT_BASE:-$((20000 + RANDOM % 20000))}
server_port=$base
socks_port=$((base + 1))
http_port=$((base + 2))
control_port=$((base + 3))
dns_port=$((base + 4))
origin_port=$((base + 5))
work=$(mktemp -d)
server_pid='' daemon_pid='' origin_pid=''
cleanup() {
    status=$?
    if (( status != 0 )); then
        tail -n 25 "$work/server.log" "$work/daemon.log" 2>/dev/null || true
    fi
    for pid in "$daemon_pid" "$server_pid" "$origin_pid"; do
        if [[ -n $pid ]]; then kill "$pid" 2>/dev/null || true; fi
    done
    for pid in "$daemon_pid" "$server_pid" "$origin_pid"; do
        if [[ -n $pid ]]; then wait "$pid" 2>/dev/null || true; fi
    done
    rm -r -- "$work"
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=localhost' \
    -addext 'subjectAltName=DNS:localhost' \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -addext 'extendedKeyUsage=serverAuth' \
    -keyout "$work/key.pem" -out "$work/cert.pem" >/dev/null 2>&1
cp "$work/cert.pem" "$work/ca.pem"
target/release/helios-server credential generate --output "$work/token.hex" >/dev/null
sed -e "s|0.0.0.0:443|127.0.0.1:$server_port|" \
    -e "s|max_sessions = 64|max_sessions = ${SMOKE_MAX_SESSIONS:-64}|" \
    config/server.example.toml > "$work/server.toml"
sed -e "s|127.0.0.1:1080|127.0.0.1:$socks_port|" \
    -e "s|127.0.0.1:8080|127.0.0.1:$http_port|" \
    -e "s|127.0.0.1:9080|127.0.0.1:$control_port|" \
    -e "s|127.0.0.1:1053|127.0.0.1:$dns_port|" \
    -e "s|203.0.113.10:443|127.0.0.1:$server_port|" \
    -e 's|vpn.example.com|localhost|' \
    -e "s|preferred_transport = \"quic\"|preferred_transport = \"$transport\"|" \
    -e 's|health_probe_seconds = 30|health_probe_seconds = 60|' \
    config/daemon.example.toml > "$work/daemon.toml"
truncate -s 32M "$work/32m.bin"
truncate -s 1M "$work/1m.bin"

python3 -m http.server "$origin_port" --bind 127.0.0.1 --directory "$work" > "$work/origin.log" 2>&1 & origin_pid=$!
target/release/helios-server run --config "$work/server.toml" > "$work/server.log" 2>&1 & server_pid=$!
target/release/helios-daemon run --config "$work/daemon.toml" > "$work/daemon.log" 2>&1 & daemon_pid=$!
sleep 2
for pid in "$origin_pid" "$server_pid" "$daemon_pid"; do kill -0 "$pid"; done

proxy=(--noproxy '' --proxy "http://127.0.0.1:$http_port" --proxytunnel)
curl --fail --silent --show-error "${proxy[@]}" --max-time 30 --output /dev/null \
    --write-out "local $transport 32 MiB: %{time_total}s (%{speed_download} B/s)\n" \
    "http://127.0.0.1:$origin_port/32m.bin"
echo "RSS before: server $(ps -o rss= -p "$server_pid") KiB; daemon $(ps -o rss= -p "$daemon_pid") KiB"
seq 1 "${SOAK_REQUESTS:-100}" | xargs -P "${SOAK_PARALLEL:-8}" -I X curl --fail --silent --show-error \
    "${proxy[@]}" --max-time 20 --output /dev/null \
    "http://127.0.0.1:$origin_port/1m.bin"
echo "${SOAK_REQUESTS:-100} parallel requests passed"
echo "RSS after: server $(ps -o rss= -p "$server_pid") KiB; daemon $(ps -o rss= -p "$daemon_pid") KiB"
sleep "${IDLE_SECONDS:-35}"
curl --fail --silent --show-error "${proxy[@]}" --max-time 20 --output /dev/null \
    "http://127.0.0.1:$origin_port/1m.bin"
if [[ $transport == quic ]] && grep -q 'quic_flow_failed' "$work/daemon.log"; then
    echo 'QUIC session dropped during idle; request fell back to TLS' >&2
    exit 1
fi
echo "$transport survived ${IDLE_SECONDS:-35}s idle"
