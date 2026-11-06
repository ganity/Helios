# Helios vendoring note

- Upstream: https://github.com/tun2proxy/tun2proxy
- Version: 0.8.3 (crates.io source)
- License: MIT, retained in LICENSE

The DNS-over-TCP receive framing is patched. Upstream discarded any partial TCP
length/body at the end of each read. Helios's daemon can write the length and payload
separately; the original code reproducibly lost DNS answers in the real TUN test.
The local patch retains incomplete frames between reads and handles coalesced frames.
The retained buffer is bounded by the 16-bit frame length plus one 4096-byte read.

Regression checks:

```sh
cargo test -p tun2proxy --lib dns_tcp_retains
sh deploy/test-linux-tun-dataplane.sh [DOCKER_IMAGE]
```

Linux helper uses the public device-based `run` API to pass its explicit source-policy
configuration through tproxy-config, and DNS over TCP to share daemon's dual-stack
Fake-IP cache. Windows/macOS continue to use the unchanged general API.

The Windows build script queries metadata from the Helios workspace manifest, with
`--locked` and the actual target, instead of the vendored crate directory. The
vendored crate is not a workspace member; querying it directly fails before the
Wintun DLL can be found. Metadata errors retain Cargo stderr for diagnosis.
