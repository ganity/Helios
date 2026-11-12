# iOS containing app and Packet Tunnel

This is the iOS implementation, with one shared NSH Rust interface and a small
Swift platform host. The first version forces **full proxy**, as agreed.
Signing is deferred. The project is not yet an accepted device release.

## Components

- `App`: hosts the NSH view inside UIKit, imports external `helios://` links
  into the confirmation field, manages system VPN preferences and consent,
  observes actual VPN state, and fetches extension counters/errors.
- `PacketTunnel`: installs IPv4/IPv6 default routes and the tunnel DNS server,
  feeds `NEPacketTunnelFlow` packets to the Rust core and writes replies back,
  stops cleanly, authenticates after path changes and checks health every 30 seconds.
  Optional recovery backs off from 2 to 60 seconds and rotates fallback nodes;
  failover alone tries each alternative once, auto-reconnect keeps retrying.
  Startup remains bounded by 25 seconds.
- `../core`: QUIC/TLS certificate/name and token authentication, packet-to-TCP/UDP
  forwarding, a DNS gateway that uses TCP over the proxy, bounded packet queues,
  diagnostics and the extension C ABI. It links no NSH/UIKit.
- `runner`: a static library exposing the shared NSH view to Swift.
- `generate.py`: generates the app and extension Xcode targets, an embedded
  extension dependency, matching App Group entitlements and a shared scheme.
- `build_rust.py`: Xcode build phase for device/simulator Rust libraries and
  their native linker requirements.

The NSH app's data directory is under the App Group container. VPN preferences
contain node metadata and file paths, not the token. The extension verifies
credential files resolve inside that container. Imported tokens keep mode 0600.
Shared storage uses protection until first user unlock after reboot.

DNS is sent to virtual `10.88.0.1`, then to the configured resolver
(default `1.1.1.1:53`) **through Helios TCP**. The shared UI accepts an IPv4
or bracketed IPv6 resolver and saves it atomically. Large UDP DNS replies
request a TCP retry. DNS never needs a parallel local resolver.

The connection settings page also exposes automatic reconnect/on-demand and
fallback-node switching; both default to off. Explicit disconnect disables
system on-demand before stopping. Connecting a different selected node stops
the current tunnel and restarts it with the new configuration. Existing flows
are interrupted. Cancelling during preference saving prevents the pending start.
Automatic fallback publishes the actual active node in status snapshots.

## Unsigned automated builds

`.github/workflows/mobile-ios.yml` (Mobile packages) configures separate macOS
and Ubuntu jobs. The macOS job tests the shared engine, generates and validates
the Xcode project, and compiles simulator and unsigned device apps. It packages
the device app and embedded Packet Tunnel as `Payload/Helios.app` inside
`Helios-ios-arm64-unsigned.ipa`, validates the ZIP, and writes SHA256SUMS.
Download the `helios-ios-ipa` artifact from the workflow run; the
`helios-ios-simulator` artifact contains a ZIP preserving app permissions.
The Android job produces the `helios-android-apk` artifact with a development-signed
ARM64 APK and SHA256SUMS. Both jobs run on relevant pushes and pull requests,
and the workflow can also be started using Run workflow.
No Apple account, certificate or Team ID is needed for these build checks.
The workflow must be present in the remote branch before GitHub can run it.

Equivalent commands on macOS (Xcode and Rust stable with the Apple targets):

```sh
python3 experiments/helios-client-nsh/ios/generate.py
xcodebuild -project experiments/helios-client-nsh/ios/Helios.xcodeproj \
  -scheme Helios -sdk iphoneos -destination 'generic/platform=iOS' \
  -derivedDataPath experiments/helios-client-nsh/ios/build/device \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO build
```

`generate.py` creates `Config.xcconfig` once and preserves subsequent edits.
It contains the bundle ID, App Group ID and optional Team ID. App/extension
identifiers and entitlements use these values consistently. The generated
project and local build/signing settings are ignored by Git.

An unsigned app bundle is for build validation and inspection, **not an
installable VPN app**. Eventual iPhone installation needs both targets signed
with matching App Group and Network Extension provisioning.

## Checks possible on Linux

```sh
cargo +stable test --manifest-path experiments/helios-client-nsh/core/Cargo.toml --features ios-ffi --locked
cargo +stable test --manifest-path experiments/helios-client-nsh/Cargo.toml --locked
python3 experiments/helios-client-nsh/ios/test_project.py
```

These exercise node persistence, certificate/token verification, TCP/UDP,
IPv4/IPv6 packet forwarding, bounded packet queues, the extension C ABI's
custom IPv6 DNS path and stop/restart, QUIC TCP and both legacy/large UDP modes,
TLS fallback when UDP is blocked, concurrent TCP/UDP connection reuse and
reconnection after peer closure, settings persistence/validation,
UI commands/status/link copying, and project
generation consistency. They do not type-check Swift or UIKit code.

## Required acceptance before calling it usable

Apple SDK compilation/linking has not run in the current Linux session.
The macOS workflow is configured locally, not executed. No iOS app/IPA has
been produced or tested on an iPhone. The following remain acceptance gates:

1. macOS simulator and device builds pass, including extension-safe linking.
2. Signed iPhone app imports a real node and prompts for system VPN consent.
3. Safari and other apps reach IPv4/IPv6 destinations; DNS works without a
   parallel local resolver or proxy; wrong credentials fail visibly.
4. Connection survives app backgrounding and lock/unlock; Wi-Fi/cellular
   changes recover new requests; revoke, stop and reconnect work without leaks.
5. Memory and battery use stay acceptable under load. The iOS engine caps
   forwarding flows at 64, queues at 128 packets/direction and worker threads
   at 2, but these limits still need real-device measurement.

Current limits: full proxy only, no raw ICMP or fragmented IP forwarding.
The tunnel MTU is 1500. Negotiated large UDP streams require this server update;
limits are 1472-byte IPv4 and 1452-byte IPv6 payloads through the TUN. Legacy
servers retain 1200-byte UDP support (also subject to QUIC datagram path MTU).
A network change/restart establishes new flows; existing TCP flows do not migrate.
TCP and negotiated UDP streams reuse one authenticated QUIC connection per
session/node, including concurrent flows. A closed connection is replaced on
the next request; path changes discard the cached connection before checking
the node again. Legacy UDP datagram associations remain isolated because the
wire protocol uses a single connection-wide datagram receive queue. Memory
and battery still need real-device measurement.
Swift lifecycle, on-demand and failover require Apple SDK and device validation,
not just the portable Rust engine tests.
