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
upgrading all three executables together. Do not replace a running daemon by force.
New desktop-managed daemons restore their saved system proxy lease on graceful
exit; reopening the UI authenticates the daemon before attempting lease recovery.
UI exit/crash leaves the daemon running. A detached watchdog waits for the daemon's
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
window normally. Linux TUN and KDE automatic proxy integration are not included yet.
The checksums detect corruption but are not a release signature; verify the source
of this archive separately. This preview has not passed production VPN acceptance.
