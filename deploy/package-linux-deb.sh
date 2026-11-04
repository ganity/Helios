#!/bin/sh
set -eu

if [ "$#" -ne 2 ] || [ "$(uname -s)" != Linux ]; then
    echo "usage (on Linux): sh $0 BUILD_DIRECTORY OUTPUT_DIRECTORY" >&2
    exit 2
fi
build_dir=$1
output_dir=$2
script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd)
case "$(dpkg --print-architecture)" in
    amd64|arm64) architecture=$(dpkg --print-architecture) ;;
    *) echo "unsupported Debian architecture: $(dpkg --print-architecture)" >&2; exit 2 ;;
esac
for name in helios-client helios-daemon helios-helper heliosctl; do
    test -x "$build_dir/$name" || { echo "missing executable: $build_dir/$name" >&2; exit 2; }
done
mkdir -p "$output_dir"
stage=$(mktemp -d "$output_dir/.helios-deb.XXXXXX")
cleanup() { rm -rf "$stage"; }
trap cleanup 0
trap 'exit 1' HUP INT TERM
chmod 0755 "$stage"
install -d "$stage/DEBIAN" "$stage/usr/bin" "$stage/usr/share/applications" "$stage/usr/share/icons/hicolor/512x512/apps"
for name in helios-client helios-daemon helios-helper heliosctl; do
    install -m 0755 "$build_dir/$name" "$stage/usr/bin/$name"
done
install -m 0644 "$script_dir/helios-client.desktop" "$stage/usr/share/applications/helios-client.desktop"
install -m 0644 "$script_dir/../assets/helios-icon-512.png" "$stage/usr/share/icons/hicolor/512x512/apps/helios.png"
{
    echo 'Package: helios'
    echo 'Version: 0.1.0'
    echo 'Section: net'
    echo 'Priority: optional'
    echo 'Architecture: '"$architecture"
    echo 'Maintainer: Helios'
    echo 'Description: Helios encrypted network desktop client'
    echo 'Depends: libc6, libgcc-s1, libegl1, libgl1, libwayland-client0, libx11-6, libxkbcommon0'
} >"$stage/DEBIAN/control"
package="$output_dir/helios_${architecture}.deb"
if [ -e "$package" ]; then
    echo "refusing to overwrite existing package: $package" >&2
    exit 2
fi
dpkg-deb --build --root-owner-group "$stage" "$package"
sha256sum "$package"
