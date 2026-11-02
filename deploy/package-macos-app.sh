#!/bin/sh
set -eu

if [ "$#" -ne 3 ] || [ "$(uname -s)" != Darwin ]; then
    echo "usage (on macOS): sh $0 BUILD_DIRECTORY OUTPUT_DIRECTORY VERSION" >&2
    exit 2
fi
build_dir=$1
output_dir=$2
version=$3
for name in helios-client helios-daemon helios-helper heliosctl; do
    test -x "$build_dir/$name" || { echo "missing executable: $build_dir/$name" >&2; exit 2; }
done
mkdir -p "$output_dir"
dmg="$output_dir/Helios-macos-$(uname -m).dmg"
if [ -e "$dmg" ]; then
    echo "refusing to overwrite existing macOS package output" >&2
    exit 2
fi
stage=$(mktemp -d "$output_dir/.helios-dmg.XXXXXX")
app="$stage/Helios.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
trap 'rm -rf "$stage"' 0
trap 'exit 1' HUP INT TERM
for name in helios-client helios-daemon helios-helper heliosctl; do
    install -m 0755 "$build_dir/$name" "$app/Contents/MacOS/$name"
done
cat >"$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>helios-client</string>
<key>CFBundleIdentifier</key><string>net.helios.desktop</string>
<key>CFBundleName</key><string>Helios</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$version</string>
<key>CFBundleVersion</key><string>$version</string>
<key>LSMinimumSystemVersion</key><string>12.0</string>
</dict></plist>
EOF
codesign --force --deep --sign - "$app"
ln -s /Applications "$stage/Applications"
hdiutil create -quiet -volname Helios -srcfolder "$stage" -ov -format UDZO "$dmg"
trap - 0 HUP INT TERM
shasum -a 256 "$dmg"
