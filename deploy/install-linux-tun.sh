#!/bin/sh
# Install the privileged component separately from the per-user desktop application.
set -eu
if [ "$#" -ne 1 ] || [ "$(uname -s)" != Linux ] || [ "$(id -u)" -ne 0 ]; then
    echo "usage (as root): sh $0 BUILD_DIRECTORY" >&2
    exit 2
fi
build_dir=$1
script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd)
stage=${DESTDIR:-}
case "$stage" in ''|/*) ;; *) echo 'DESTDIR must be absolute' >&2; exit 2 ;; esac
for file in "$build_dir/helios-helper" "$script_dir/com.helios.tun.policy" "$script_dir/helios-tun-recover.service"; do
    test -f "$file" || { echo "missing file: $file" >&2; exit 2; }
done
test -x "$build_dir/helios-helper"
install -d -o 0 -g 0 -m 0755 "$stage/usr/libexec" "$stage/usr/share/polkit-1/actions" "$stage/usr/lib/systemd/system"
install -o 0 -g 0 -m 0755 "$build_dir/helios-helper" "$stage/usr/libexec/helios-helper"
install -o 0 -g 0 -m 0644 "$script_dir/com.helios.tun.policy" "$stage/usr/share/polkit-1/actions/com.helios.tun.policy"
install -o 0 -g 0 -m 0644 "$script_dir/helios-tun-recover.service" "$stage/usr/lib/systemd/system/helios-tun-recover.service"
if [ -z "$stage" ] && command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable helios-tun-recover.service
fi
printf 'Linux TUN system component installed. The desktop requests administrator authorization when enabling TUN.\n'
