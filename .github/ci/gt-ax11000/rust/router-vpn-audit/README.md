# Read-only W9 VPN policy audit

`vpn-policy-audit --check-live` captures all ten OpenVPN/WireGuard profile
slots, enabled VPN Director sources, effective filter rules and policy routes.
It checks the typed `router-policy::vpn_runtime` requirements and re-reads the
inputs to detect concurrent changes. This is not an atomic kernel/NVRAM
snapshot and **does not enforce policy or change forwarding**.

`--self-test` exercises the actual target-specific Linux `O_NOFOLLOW` flag.
Run it under ARM QEMU or on the router as well as on the host: the historical
x86 flag was ineffective on ARM. The shared constants also protect the
firmware's `router-security` C ABI reader.

Build with the pinned ARMv7 soft-float vendor toolchain and RAM-backed paths:

```sh
export CARGO_TARGET_DIR=/tmp/asuswrt-vpn-audit-target
export TMPDIR=/tmp
export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABI_LINKER=/path/to/locked/vendor-gcc
RUSTFLAGS='-Dwarnings -Ctarget-cpu=cortex-a9 -Clink-arg=-Wl,-z,relro,-z,now' \
  cargo +1.85.1 build --manifest-path .github/ci/gt-ax11000/rust/Cargo.toml \
  --release --locked --offline --target armv7-unknown-linux-gnueabi \
  -p router-vpn-audit --bin vpn-policy-audit
```

On 2026-09-09 the earlier, equivalent audit binary passed its native ARM
self-test and live read-only check with **zero active client requirements**.
That is not an active VPN leak-protection test. Live enforcement still needs
active OpenVPN/WireGuard fixtures, server-peer route exceptions, VPN table
contents, IPv6 kill-switch semantics and scoped failure/recovery design.

Connection sampling and the web panel are intentionally absent from this
branch. Their independent work continues on
`codex/gt-ax11000-connection-diagnostics`; that add-on can reuse these helpers
without the security work depending on the sampler or its startup hook.
