#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
: "${DIAGNOSTICS_LINKER:?Set the pinned ARM soft-float vendor gcc path}"
: "${DIAGNOSTICS_STRIP:?Set the corresponding pinned ARM strip path}"
: "${DIAGNOSTICS_OUTPUT:?Set a fresh absolute tmpfs package directory}"
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/tmp/asuswrt-diagnostics-target}
export TMPDIR=${TMPDIR:-/tmp}
for path in "$DIAGNOSTICS_OUTPUT" "$CARGO_TARGET_DIR" "$TMPDIR"; do
    [[ "$path" = /* ]]
    ancestor=$path
    while [[ ! -e "$ancestor" ]]; do ancestor=$(dirname "$ancestor"); done
    [[ $(findmnt -n -o FSTYPE -T "$ancestor") = tmpfs ]] || { echo "Not RAM-backed: $path" >&2; exit 1; }
done
[[ ! -e "$DIAGNOSTICS_OUTPUT" ]]
export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABI_LINKER="$DIAGNOSTICS_LINKER"
export RUSTFLAGS='-Dwarnings -Ctarget-cpu=cortex-a9 -Clink-arg=-Wl,-z,relro,-z,now'
cd "$root/rust"
cargo +1.85.1 build --manifest-path "$root/rust/Cargo.toml" \
    --release --locked --offline --target armv7-unknown-linux-gnueabi \
    -p router-diagnostics -p router-vpn-audit
mkdir -m 700 "$DIAGNOSTICS_OUTPUT"
for program in link-health wifi-observe vpn-policy-audit; do
    install -m 700 "$CARGO_TARGET_DIR/armv7-unknown-linux-gnueabi/release/$program" "$DIAGNOSTICS_OUTPUT/$program"
    "$DIAGNOSTICS_STRIP" "$DIAGNOSTICS_OUTPUT/$program"
done
for file in index.asp panel.js ping.json control.sh install.sh update-panel.sh; do
    install -m 600 "$root/diagnostics/$file" "$DIAGNOSTICS_OUTPUT/$file"
done
chmod 700 "$DIAGNOSTICS_OUTPUT/control.sh"
(cd "$DIAGNOSTICS_OUTPUT" && sha256sum link-health wifi-observe vpn-policy-audit index.asp panel.js ping.json control.sh install.sh update-panel.sh > SHA256SUMS)
echo "Diagnostic package built (not a firmware image): $DIAGNOSTICS_OUTPUT"
