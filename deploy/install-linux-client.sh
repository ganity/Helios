#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: sh $0 BUILD_DIRECTORY [INSTALL_PREFIX]" >&2
    exit 2
fi

build_dir=$1
prefix=${2:-"${HOME:?HOME is required}/.local"}
case "$prefix" in
    /*) ;;
    *) echo "install prefix must be absolute" >&2; exit 2 ;;
esac
# Desktop Exec quoting is not shell quoting; reject paths needing additional escaping.
case "$prefix" in
    *[\\\"\`\$%]*|*'
'*) echo 'install prefix cannot contain backslashes, quotes, backticks, dollar signs, percent signs or newlines' >&2; exit 2 ;;
esac

for name in helios-client helios-daemon heliosctl; do
    if [ ! -f "$build_dir/$name" ] || [ ! -x "$build_dir/$name" ]; then
        echo "missing executable: $build_dir/$name" >&2
        exit 2
    fi
done

install -d "$prefix/bin" "$prefix/share/applications"
for name in helios-client helios-daemon heliosctl; do
    temporary=$(mktemp "$prefix/bin/.$name.XXXXXX")
    trap 'rm -f "$temporary"' 0
    trap 'exit 1' HUP INT TERM
    install -m 0755 "$build_dir/$name" "$temporary"
    mv -f "$temporary" "$prefix/bin/$name"
done

icon=network-vpn
if [ -f "$build_dir/helios-icon.png" ]; then
    install -d "$prefix/share/icons/hicolor/512x512/apps"
    install -m 0644 "$build_dir/helios-icon.png" "$prefix/share/icons/hicolor/512x512/apps/helios.png"
    rm -f "$prefix/share/icons/hicolor/scalable/apps/helios.svg"
    icon=helios
fi

temporary=$(mktemp "$prefix/share/applications/.helios-client.XXXXXX")
{
    echo '[Desktop Entry]'
    echo 'Type=Application'
    echo 'Name=Helios'
    echo 'Comment=Encrypted network client'
    printf 'Exec="%s/bin/helios-client"\n' "$prefix"
    printf 'Icon=%s\n' "$icon"
    echo 'Terminal=false'
    echo 'Categories=Network;'
    echo 'StartupNotify=true'
} >"$temporary"
chmod 0644 "$temporary"
mv -f "$temporary" "$prefix/share/applications/helios-client.desktop"
trap - 0 HUP INT TERM
printf 'Helios installed under %s; existing ~/.helios configuration was not changed.\n' "$prefix"
