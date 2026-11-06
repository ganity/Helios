# Helios vendoring note

- Upstream: `ssrlive/tproxy-config`
- Version: `7.0.9`
- License: MIT
- Vendored scope: route and DNS setup/restoration used by `helios-helper`

The local patch adds the `secure-state-file` feature: the privileged caller supplies one absolute
recovery path, state is written with exclusive creation and atomic rename, Unix directories/files
use `0700`/`0600`, and `tproxy_remove(None)` restores from that protected record after an abnormal exit.

Linux desktop recovery journals route/DNS changes before applying them and preserves external
changes on conflict. Optional `TproxyArgs.source_bypass` uses a separate TUN table and source-policy
rules so a daemon binding its outbound sockets to uplink addresses can use the original main table.
It requires protected recovery and standard Linux policy rules. Rule messages are bounded and
journaled with routes. Existing callers without source bypass retain the legacy routing path.
The helper/daemon integration of source bypass and unmanaged regular resolv.conf is implemented.
The standard systemd-resolved stub uses a journaled per-TUN DNS/~. lease via the existing
zbus dependency. Physical/global DNS is not changed; competing routing/search domains
and other resolver managers are refused. Entry/recovery flush resolved caches. Recovery
checks service/bus identity, interface ownership and staged snapshots, preserving external
changes. The real-resolved disposable-container test covers conflicts, interrupted calls,
cache cleanup and service restart. The desktop now uses an installed, fixed-path pkexec helper with path-free stdin IPC;
lease checks monitor routing and DNS during the session. Boot recovery validates
machine-id and only restores an unchanged static DNS file, never old kernel state; see
`docs/15-linux-tun-implementation.md` in the repository root.

The upstream `unsafe-state-file` feature remains disabled because it uses a predictable shared
temporary path.
