#!/bin/sh
set -eu

if [ "$#" -ne 2 ] || [ "$(uname -s)" != Linux ]; then
    echo "usage (on Linux): sh $0 BUILD_DIRECTORY OUTPUT_DIRECTORY" >&2
    exit 2
fi
build_dir=$1
output_dir=$2
script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd)
for name in helios-client helios-daemon heliosctl; do
    test -x "$build_dir/$name" || { echo "missing executable: $build_dir/$name" >&2; exit 2; }
done
mkdir -p "$output_dir"
stage=$(mktemp -d "$output_dir/.helios-package.XXXXXX")
cleanup() {
    rm -f "$stage/helios-client" "$stage/helios-daemon" "$stage/heliosctl" \
        "$stage/install-linux-client.sh" "$stage/README.md" "$stage/SHA256SUMS"
    rmdir "$stage"
}
trap cleanup 0
trap 'exit 1' HUP INT TERM
for name in helios-client helios-daemon heliosctl; do
    install -m 0755 "$build_dir/$name" "$stage/$name"
done
install -m 0644 "$script_dir/install-linux-client.sh" "$stage/install-linux-client.sh"
install -m 0644 "$script_dir/linux-package-README.md" "$stage/README.md"
(
    cd "$stage"
    sha256sum helios-client helios-daemon heliosctl install-linux-client.sh README.md > SHA256SUMS
)
archive="$output_dir/helios-linux-$(uname -m).tar.gz"
if [ -e "$archive" ]; then
    echo "refusing to overwrite existing package: $archive" >&2
    exit 2
fi
tar -czf "$archive" -C "$stage" .
sha256sum "$archive"
