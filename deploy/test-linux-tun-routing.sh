#!/bin/sh
# Run only in disposable network/mount namespaces; never grant NET_ADMIN on the host.
set -eu
if [ "$(uname -s)" != Linux ] || [ "$#" -gt 1 ]; then
    echo "usage (on Linux): sh $0 [DOCKER_IMAGE]" >&2
    exit 2
fi
image=${1:-ubuntu:24.04}
script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd)
cd "$script_dir/.."
command -v ip >/dev/null
command -v docker >/dev/null
manifest=$(mktemp)
trap 'rm -f "$manifest"' 0
trap 'exit 1' HUP INT TERM
cargo test -p tproxy-config --features secure-state-file --no-run --message-format=json >"$manifest"
test_binary=$(python3 - "$manifest" <<'PY'
import json
import sys
for line in open(sys.argv[1]):
    artifact = json.loads(line)
    if (artifact.get("reason") == "compiler-artifact"
            and artifact["target"]["name"] == "tproxy_config"
            and artifact["profile"]["test"] and artifact.get("executable")):
        print(artifact["executable"])
        break
else:
    sys.exit("tproxy-config test binary was not built")
PY
)
for test_name in \
    isolated_sigkill_recovery_preserves_routes_dns_and_rejects_foreign_context \
    isolated_source_policy_routes_bound_sockets_and_recovers_after_sigkill
do
    # Host runtime is read-only to match the Rust binary's glibc; no workspace is mounted.
    docker run --rm --network none --hostname helios-tun-test \
        --cap-drop ALL --cap-add NET_ADMIN --pids-limit 64 \
        -e HELIOS_ISOLATED_TUN_TEST=1 \
        --mount type=bind,src=/usr,dst=/usr,readonly \
        --mount type=bind,src=/lib,dst=/lib,readonly \
        --mount type=bind,src=/lib64,dst=/lib64,readonly \
        --mount "type=bind,src=$test_binary,dst=/test,readonly" \
        --entrypoint /test "$image" \
        --exact "linux::recovery::tests::$test_name" --ignored --nocapture
done
