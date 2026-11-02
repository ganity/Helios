# Helios GPUI prototype

This isolated workspace proves that a GPUI frontend can read the same
`helios-client-model` profile as the production egui client without adding GPUI
to the production dependency graph.

The prototype displays the routing mode and active node from `desktop.json`,
then uses `helios-client-control` to perform authenticated daemon requests.
Status refreshes every two seconds on a background executor, and the Refresh
button triggers the same bounded request without blocking the UI or allowing
duplicate in-flight requests. Rule, Global Proxy, and Global Direct buttons
atomically save both desktop and daemon configuration before applying the new
rules through the authenticated control channel. The node list runs the same
authenticated TLS/QUIC latency probe as the production egui client and reports
success or failure without blocking the window.
Nodes can be imported from the existing node JSON export using the native file
picker (64 KiB maximum), selected, latency-tested, or deleted. The active node
cannot be deleted.
Selecting another node restarts a daemon owned by this window; an external
daemon is left running and the UI asks its owner to restart it. Connect and Stop
control only start or stop a daemon owned by this window.

GPUI is pinned to Zed commit
`33d111eac45ef581324592352d90efc91c5ec98d`; update it only as an explicit,
reviewed dependency change.

## Run

```sh
cargo run --manifest-path experiments/helios-client-gpui/Cargo.toml
```

Linux builds need the development packages for XKB Common and Fontconfig. On a
runtime-only system, `RUST_FONTCONFIG_DLOPEN=1` avoids the Fontconfig pkg-config
requirement, but the XKB Common linker names are still required.

The production client remains `cargo run -p helios-client`.
