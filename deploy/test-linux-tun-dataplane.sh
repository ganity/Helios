#!/bin/sh
# Two disposable namespaces joined only to each other; never use host networking.
set -eu
if [ "$(uname -s)" != Linux ] || [ "$#" -gt 1 ]; then
    echo "usage (on Linux): sh $0 [DOCKER_IMAGE]" >&2
    exit 2
fi
image=${1:-ubuntu:24.04}
script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd)
cd "$script_dir/.."
command -v docker >/dev/null
command -v ip >/dev/null
command -v openssl >/dev/null
test -c /dev/net/tun
if [ "${HELIOS_TEST_RESOLVED:-0}" = 1 ]; then
    test -x /usr/lib/systemd/systemd-resolved
    command -v dbus-daemon >/dev/null
    command -v busctl >/dev/null
    command -v setpriv >/dev/null
    command -v pkexec >/dev/null
    test -x /usr/lib/polkit-1/polkitd
fi
assets=$(mktemp -d)
peer=""
client_name="helios-tun-client-$$"
cleanup() {
    docker rm -f "$client_name" >/dev/null 2>&1 || true
    if [ -n "$peer" ]; then docker rm -f "$peer" >/dev/null 2>&1 || true; fi
    rm -rf "$assets"
}
trap cleanup 0
trap 'exit 1' HUP INT TERM
cargo build -p helios-daemon -p helios-helper -p helios-server --message-format=json >"$assets/build.json"
python3 - "$assets" <<'PY'
import json, pathlib, sys
output = pathlib.Path(sys.argv[1])
for line in (output / 'build.json').read_text().splitlines():
    item = json.loads(line)
    if item.get('reason') == 'compiler-artifact' and item.get('executable'):
        (output / (item['target']['name'] + '.path')).write_text(item['executable'])
PY
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
    -addext subjectAltName=DNS:localhost -addext basicConstraints=critical,CA:FALSE \
    -keyout "$assets/key.pem" -out "$assets/cert.pem" >/dev/null 2>&1
chmod 644 "$assets/key.pem"
set --
if [ "${HELIOS_TEST_RESOLVED:-0}" = 1 ]; then
    cargo test -p tproxy-config -p helios-client --features tproxy-config/secure-state-file --no-run --message-format=json >"$assets/tests.json"
    test_binary=$(python3 - "$assets/tests.json" <<'PYTHON'
import json, sys
for line in open(sys.argv[1]):
    item = json.loads(line)
    if item.get('reason') == 'compiler-artifact' and item['target']['name'] == 'tproxy_config' and item['profile']['test'] and item.get('executable'):
        print(item['executable'])
        break
else:
    sys.exit('missing tproxy-config test binary')
PYTHON
)
    client_test_binary=$(python3 - "$assets/tests.json" <<'PYTHON'
import json, sys
for line in open(sys.argv[1]):
    item = json.loads(line)
    if item.get('reason') == 'compiler-artifact' and item['target']['name'] == 'helios-client' and item['profile']['test'] and item.get('executable'):
        print(item['executable'])
        break
else:
    sys.exit('missing desktop test binary')
PYTHON
)
    # Docker follows this symlink when mounting its generated resolver. No SYS_ADMIN/unmount.
    mkdir -p "$assets/client-etc/systemd" "$assets/client-etc/pam.d"
    chmod 755 "$assets"
    chmod 755 "$assets/client-etc" "$assets/client-etc/systemd" "$assets/client-etc/pam.d"
    for file in passwd group machine-id nsswitch.conf systemd/resolved.conf pam.d/polkit-1; do
        touch "$assets/client-etc/$file"
    done
    ln -s /run/systemd/resolve/stub-resolv.conf "$assets/client-etc/resolv.conf"
    set -- --mount "type=bind,src=$assets/client-etc,dst=/etc" \
        --mount "type=bind,src=$test_binary,dst=/tproxy-test,readonly" \
        --mount "type=bind,src=$client_test_binary,dst=/client-test,readonly" \
        --mount "type=bind,src=$script_dir/com.helios.tun.policy,dst=/tun.policy,readonly" \
        --tmpfs /usr/libexec:rw,exec,nodev,mode=755 --tmpfs /usr/share/polkit-1:rw,nodev,mode=755 \
        --tmpfs /etc/polkit-1:rw,nodev,mode=755 \
        --cap-add CHOWN --cap-add SETPCAP --cap-add NET_RAW
fi
# Bind files individually: no workspace, host network, D-Bus, or Docker socket enters the containers.
peer=$(docker run -d --network none --label helios.tun-test=dataplane --hostname helios-tun-peer \
    --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE --pids-limit 128 \
    --sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.default.disable_ipv6=0 \
    --mount type=bind,src=/usr,dst=/usr,readonly \
    --mount type=bind,src=/lib,dst=/lib,readonly \
    --mount type=bind,src=/lib64,dst=/lib64,readonly \
    --mount "type=bind,src=$(cat "$assets/helios-server.path"),dst=/server,readonly" \
    --mount "type=bind,src=$assets/cert.pem,dst=/cert.pem,readonly" \
    --mount "type=bind,src=$assets/key.pem,dst=/key.pem,readonly" \
    --mount "type=bind,src=$script_dir/test-linux-tun-dataplane.py,dst=/test.py,readonly" \
    --entrypoint /usr/bin/python3 "$image" /test.py peer)
if ! docker run --rm --name "$client_name" --network none --label helios.tun-test=dataplane --pid "container:$peer" --hostname helios-tun-client \
    --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE --cap-add SETUID --cap-add SETGID --cap-add KILL --cap-add SYS_PTRACE --pids-limit 128 \
    "$@" -e HELIOS_TEST_RESOLVED -e RUST_LOG=info --device /dev/net/tun --sysctl net.ipv6.conf.all.disable_ipv6=0 \
    --sysctl net.ipv6.conf.default.disable_ipv6=0 \
    --mount type=bind,src=/usr,dst=/usr,readonly \
    --mount type=bind,src=/lib,dst=/lib,readonly \
    --mount type=bind,src=/lib64,dst=/lib64,readonly \
    --mount "type=bind,src=$(cat "$assets/helios-daemon.path"),dst=/daemon,readonly" \
    --mount "type=bind,src=$(cat "$assets/helios-helper.path"),dst=/helper,readonly" \
    --mount "type=bind,src=$assets/cert.pem,dst=/cert.pem,readonly" \
    --mount "type=bind,src=$script_dir/test-linux-tun-dataplane.py,dst=/test.py,readonly" \
    --entrypoint /usr/bin/python3 "$image" /test.py client
then
    docker logs "$peer" >&2
    exit 1
fi
