# Helios vendoring note

- Upstream: `ssrlive/tproxy-config`
- Version: `7.0.9`
- License: MIT
- Vendored scope: route and DNS setup/restoration used by `helios-helper`

Helios keeps the upstream platform route implementation unchanged. The local patch adds the
`secure-state-file` feature: the privileged caller supplies one absolute recovery path, state is
written with exclusive creation and atomic rename, Unix directories/files use `0700`/`0600`, and
`tproxy_remove(None)` restores from that protected record after an abnormal exit.

The upstream `unsafe-state-file` feature remains disabled because it uses a predictable shared
temporary path.
