# Helios Linux client (preview)

Extract this archive into a new directory, then run:

```sh
sha256sum -c SHA256SUMS
sh install-linux-client.sh .
```

The installer defaults to `~/.local` and leaves `~/.helios` configuration untouched.
An optional second argument selects an absolute install prefix. Exit the client
before upgrading. The generated desktop entry uses an absolute executable path.
Client, daemon and CLI must stay together; update any existing custom daemon path
in Settings after moving an installation.

This build uses local control schema 4. Quit the old Helios from its tray before
upgrading the matching executables together. Do not replace a running daemon by force.
New desktop-managed daemons restore their saved system proxy lease on graceful
exit; reopening the UI authenticates the daemon before attempting lease recovery.
In system-proxy mode, UI exit/crash leaves the daemon running. A source-bound TUN
session instead owns lifetime pipes for its helper and daemon; exiting the UI stops it. A detached watchdog waits for the daemon's
lease lock and restores the previous system proxy after an ungraceful daemon exit.

Run `./helios-client` directly for portable use. Do not run the GUI as root.
Use Settings/Nodes to configure the server address, TLS name, trusted CA and token
file. No server credentials are included in this package.

Requires a Linux graphical session (X11 or Wayland), OpenGL/EGL, fonts, and compatible
system libraries. This is a native build, not a universal/static Linux binary;
older glibc distributions may require a local source build.

Automatic HTTP/HTTPS system proxy configuration supports GNOME GSettings only.
Linux tray support uses StatusNotifierItem over the user session D-Bus; GNOME
usually requires an AppIndicator extension. Without a tray host, closing exits the
window normally. KDE automatic proxy integration is not included yet.
The checksums detect corruption but are not a release signature; verify the source
of this archive separately. This preview has not passed production VPN acceptance.

Linux TUN is available from the desktop after installing its system component once:

```sh
sudo sh install-linux-tun.sh .
```

This installs `/usr/libexec/helios-helper`, an administrator-authenticated polkit
policy, and a boot recovery service. Keep these resources with the archive; the
ordinary user installer does not install privileged files. Enabling TUN obtains
physical source addresses and real DNS upstreams automatically, restarts the matching
daemon, requests authorization and verifies actual TUN DNS before reporting ready.
The desktop and daemon remain unprivileged. The GUI must never be run as root.

Supported DNS is an unmanaged regular resolver file or the standard systemd-resolved
stub with no competing routing/search domains. Other VPN/policy rules and direct
NetworkManager-managed resolver files are refused. Network changes stop and restore
TUN; enable it again to acquire the new uplink. A detached root watchdog restores
a killed helper's lease. Failed or conflicting recovery is retained for retry via
the desktop, rather than overwriting another manager's changes.
