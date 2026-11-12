# Helios NSH mobile development client

This isolated workspace contains a shared Rust NSH UI, Android VPN host,
and iOS containing app/Packet Tunnel implementation.
It is under development, not a finished cross-platform release.

## Implemented

- Import `helios://` links into application-private storage without replacing
  unrelated nodes. Certificate and token files are imported automatically.
- Select individual nodes, edit names, addresses, certificate names and
  credential identifiers, remember the selection across restarts, and delete
  a node with confirmation.
- Open `helios://` links from Android/iOS into the import field; importing still
  requires a tap so an external link cannot silently replace a node.
- Test the selected node's authenticated connection latency asynchronously (QUIC with TLS fallback).
  Android protects the probe socket when its VPN service is running.
- Android VPN consent, foreground service with notification stop action,
  protected outbound sockets, IPv4/IPv6 TUN routes, TCP and UDP forwarding over QUIC/TLS.
- Poll service state, show consent cancellation/startup errors, and report
  success only after authenticating the node and opening a UDP association.
  iOS additionally checks node health every 30 seconds and after network changes.
- Show TUN IP-byte speeds, cumulative counters and active forwarding tasks;
  keep a bounded diagnostic log. Forwarding tasks are limited to 512 on
  Android and 64 in the iOS extension.
- A signed ARM64 development APK, reproducible through the local build script.

Both hosts currently force **full proxy**. The packet engine supports IP-only
rules in tests; domain rules, fake-IP DNS and Android rule-mode controls are
not integrated. Mobile transport honors each node's QUIC/TLS preference;
QUIC failures fall back to TLS. With an updated server, UDP uses negotiated
reliable streams up to 1472 bytes (IPv6 TUN payloads up to 1452); older servers
retain the 1200-byte limit and their original QUIC datagram mode. No IP fragmentation.
iOS can switch nodes by restarting the VPN without a separate disconnect tap,
configure an IPv4/IPv6 upstream DNS resolver, reconnect using system on-demand
rules, and rotate through imported fallback nodes. Recovery runs in the extension
even when the app is backgrounded. Settings take effect on the next connect.
Android still requires a disconnect before switching nodes. If a remembered node was removed, restart selects the first remaining node.

## Build and validate

NSH is pinned to revision `034c11b4537156d12cda1d12b5b4878d29f3bf42`.
It requires Rust 1.97 or newer; validation used Rust stable 1.99.1.
The main Helios workspace keeps its existing toolchain.

```sh
cargo +stable test --manifest-path experiments/helios-client-nsh/core/Cargo.toml --features ios-ffi --locked
cargo +stable test --manifest-path experiments/helios-client-nsh/Cargo.toml --locked
cargo +stable clippy --manifest-path experiments/helios-client-nsh/Cargo.toml --all-targets --locked -- -D warnings
```

On Linux with JDK 17+, Android SDK platform/build-tools 36, NDK 28, and the
Rust `aarch64-linux-android` target installed:

```sh
export ANDROID_HOME=/path/to/Android/Sdk
python3 experiments/helios-client-nsh/android/build.py
```

The script builds the final JNI host, locates the pinned NSH Java sources in
Cargo's checkout, strips debug symbols from a copy of the library, compiles
Java/dex, packages the APK, signs it and verifies the signature.
It prints the output path under `android/runner/target/artifacts/`.
`--release` optimizes the Rust library but still uses a **development key**.
Keep the adjacent debug.keystore for repeat installations; never use this key
for a store release.

## Outstanding validation and work

The ARM64 library and Java host compile, native entry points link, unit and
packet-forwarding tests pass, and the APK signature verifies. The validation
host has no connected Android device. Its ARM64 emulator image cannot run on
the x86 host, and KVM is unavailable. UI rendering, installation, VPN consent,
real network routing, DNS, suspend/resume and revoke/reconnect need device tests.

iOS now has containing-app and Packet Tunnel sources, a separate UI-free Rust
data plane, DNS-over-proxy-TCP, system status/counter messages, shared storage,
network-change reauthentication, an Xcode project generator and an unsigned
macOS CI workflow. See [the iOS guide](ios/README.md). Apple SDK compilation,
signing and device validation have not run; no iOS binary has been built.

Full Android domain/IP routing, release signing,
and both platforms' device acceptance remain required before a mobile release.

## CI downloads

The **Mobile packages (IPA and APK)** workflow in
`.github/workflows/mobile-ios.yml` runs on mobile-source/dependency changes and
supports manual dispatch. Download `helios-ios-ipa` for
`Helios-ios-arm64-unsigned.ipa`, or `helios-android-apk` for
`helios-arm64-release.apk`. Both include SHA256SUMS. iOS signing is deferred;
the IPA must be signed before device installation. The APK uses a development
key, so CI builds are for testing rather than production distribution.
