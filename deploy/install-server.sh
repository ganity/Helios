#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 HELIOS_SERVER_BINARY TLS_CERTIFICATE TLS_PRIVATE_KEY" >&2
    exit 2
fi

binary=$1
certificate=$2
private_key=$3
root=${DESTDIR:-}

for file in "$binary" "$certificate" "$private_key"; do
    if [ ! -f "$file" ]; then
        echo "required file does not exist: $file" >&2
        exit 2
    fi
done

if [ -z "$root" ] && [ "$(id -u)" -ne 0 ]; then
    echo "run as root, or set DESTDIR for a staged install" >&2
    exit 1
fi

if [ -z "$root" ] && ! id helios >/dev/null 2>&1; then
    useradd --system --home /nonexistent --shell /usr/sbin/nologin helios
fi

owner=root
group=root
secret_owner=root
if [ -z "$root" ]; then
    group=helios
    secret_owner=helios
else
    owner=$(id -un)
    group=$(id -gn)
    secret_owner=$owner
fi

install -d -o "$owner" -g "$group" -m 0750 "$root/etc/helios"
install -d -o "$owner" -g "$owner" -m 0755 "$root/usr/local/bin"
install -d -o "$owner" -g "$owner" -m 0755 "$root/etc/systemd/system"
install -o "$owner" -g "$owner" -m 0755 "$binary" "$root/usr/local/bin/helios-server"
install -o "$owner" -g "$group" -m 0640 "$certificate" "$root/etc/helios/cert.pem"
install -o "$secret_owner" -g "$group" -m 0600 "$private_key" "$root/etc/helios/key.pem"

token_file="$root/etc/helios/token.hex"
if [ ! -e "$token_file" ]; then
    umask 077
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n' >"$token_file"
fi
chown "$secret_owner:$group" "$token_file"
chmod 0600 "$token_file"

config_file="$root/etc/helios/server.toml"
if [ ! -e "$config_file" ]; then
    config_tmp=$(mktemp "$root/etc/helios/server.toml.XXXXXX")
    trap 'rm -f "$config_tmp"' 0
    trap 'exit 1' HUP INT TERM
    cat >"$config_tmp" <<'EOF'
schema_version = 1
listen = "0.0.0.0:443"

[tls]
certificate = "cert.pem"
private_key = "key.pem"

[auth]
id = "desktop-main"
token_file = "token.hex"

[limits]
handshake_timeout_seconds = 10
max_sessions = 64
max_flows_per_session = 1024
EOF
    install -o "$owner" -g "$group" -m 0640 "$config_tmp" "$config_file"
    rm -f "$config_tmp"
    trap - 0
    trap - HUP INT TERM
fi
chown "$owner:$group" "$config_file"
chmod 0640 "$config_file"

script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd)
install -o "$owner" -g "$owner" -m 0644 \
    "$script_dir/helios-server.service" \
    "$root/etc/systemd/system/helios-server.service"

if [ -z "$root" ]; then
    systemctl daemon-reload
    systemctl enable --now helios-server
    echo "Helios server installed. Copy /etc/helios/token.hex to the client over a secure channel."
else
    echo "Helios server staged under $root"
fi
