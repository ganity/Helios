#!/bin/sh
set -eu

if [ "$#" -ne 2 ] || [ "$(uname -s)" != Linux ]; then
    echo "usage (on Linux): sh $0 BUILD_DIRECTORY OUTPUT_DIRECTORY" >&2
    exit 2
fi
build_dir=$1
output_dir=$2
script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd)
for name in helios-client helios-daemon helios-helper heliosctl; do
    test -x "$build_dir/$name" || { echo "missing executable: $build_dir/$name" >&2; exit 2; }
done
mkdir -p "$output_dir"
stage=$(mktemp -d "$output_dir/.helios-package.XXXXXX")
cleanup() { rm -rf "$stage"; }
trap cleanup 0
trap 'exit 1' HUP INT TERM
for name in helios-client helios-daemon helios-helper heliosctl; do
    install -m 0755 "$build_dir/$name" "$stage/$name"
done
for file in install-linux-client.sh install-linux-tun.sh com.helios.tun.policy helios-tun-recover.service; do
    install -m 0644 "$script_dir/$file" "$stage/$file"
done
install -m 0644 "$script_dir/linux-package-README.md" "$stage/README.md"
install -m 0644 "$script_dir/../assets/helios-icon-512.png" "$stage/helios-icon.png"
(
    cd "$stage"
    sha256sum helios-client helios-daemon helios-helper heliosctl install-linux-client.sh install-linux-tun.sh com.helios.tun.policy helios-tun-recover.service README.md helios-icon.png > SHA256SUMS
)
archive="$output_dir/helios-linux-$(uname -m).tar.gz"
if [ -e "$archive" ]; then
    echo "refusing to overwrite existing package: $archive" >&2
    exit 2
fi
tar -czf "$archive" -C "$stage" .
sha256sum "$archive"
