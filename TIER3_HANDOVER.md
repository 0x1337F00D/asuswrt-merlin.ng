# Tier 3 handover (written 2026-09-10 by Claude Fable 5.1 for the next Claude session)

Read this before touching anything. It records the state of truth, what
Tier 3 is, what is still owed from Tier 1 and 2, and the rules that were
learned the hard way. Every claim below was checked against the tree or a
running process on 2026-09-10, not copied from a summary.

## 1. State of truth

**The router is running the combined Tier 1 + Tier 2 image.** Codex built
candidate `123e6fb4621` (filesystem image SHA-256
`fb0936818724e40be51f67109375ac4d9176fcdec964f1b7df74435fff2f1856`), booted it
one-shot, ran health and a 15-minute soak, proved the Part2 fallback, and
**permanently promoted it on Part1 at 2026-09-10T13:41:49Z**. Part2 still holds
the previous alpha1 as fallback. Evidence: `CLAUDE_FINAL_REVIEW.md` and
`TIER2_REVIEW_FIXES.md` on Codex's branch. A **24-hour read-only observation
is the current phase**: no flashing, no saturation tests, no router changes
until it ends.

**The base for all further work is Codex's branch, not mine.**

| Branch | Where | Status |
|---|---|---|
| `codex/tier2-stable-boundaries` @ `b2bae581786` | `/home/paul/asuswrt-merlin-rust` (persistent disk, remote `fork` = SSH) and `/dev/shm/gt-tier2-review` (tmpfs) | **The deployed state. Not on GitHub.** |
| `claude/gt-ax11000-integrate` @ `a296a406c7c` | `/dev/shm/claude-integrate`, pushed to `fork` | **Superseded.** Do not merge it onto Codex's base: 10 conflicting files, and Codex already re-implemented its substance. |
| `claude/gt-ax11000-tier1` @ `7c6446acfe0` | pushed | Historical. |

First thing to do: push `codex/tier2-stable-boundaries` to the fork over SSH
from `/home/paul/asuswrt-merlin-rust` (or confirm Codex has), so the source
state that matches the flashed image cannot be lost with a reboot of the
tmpfs clone. Then create your **own** worktree from it under `/dev/shm/` with
a new directory name; never work inside a Codex directory.

**What Codex did on top of my `210da6e7b2e`** (53 files, +3045/-629), so you
do not redo it: an HTTP C transport returning an explicit
complete/empty/incomplete/error result before the Rust parser; typed LLTD
receive/admission state where tokens and generation commit only after a
successful send; wsdd2 transport separation, monotonic budget clock and a
behavioural `wsdd2/tests/socket_order.rs`; the in-process WLAN runner
replaced by a separate `/usr/sbin/wlif-exec` supervisor using `posix_spawn`
(a **fourteenth** relinked artifact; all consumer listings now count 14);
the vendor `libshared.so` link brought from 1,757,492 to about 637,000
stripped bytes by resolving `libgcc_s` before the Rust archive, with a gate
rejecting a library over 1 MiB; clean-build DAG fixes (libusbmuxd after
libplist, qrencode after libpng); a firmware iteration file
`.github/ci/gt-ax11000/firmware-iteration` with alpha2 reserved.

**What Codex did *not* take from my later commits** (verified by grep on
`b2bae581786`), each small and worth re-applying on the new base:

1. `/opt/sbin` and `/opt/bin` are still in `WLIF_CLI_DIRS`
   (`patches/wlif-shell-hardening.patch` line 101) and that list is still the
   resolver (`const char *directories[] = { WLIF_CLI_DIRS };`, line 157) in
   the new supervisor. `/opt` is `ln -sf tmp/opt opt` and `rc/usb.c` mounts
   USB storage there with `umask=0000` and no `noexec`/`nosuid`; both CLIs
   install to `/usr/sbin`. Removing the two entries and pinning their absence
   in `security-overlay-check.sh` was commit `7292e1cb11b` on my branch.
2. LLTD has no test that the device pin precedes `bind` (wsdd2 and ntp now
   do). My structural check `tests/socket-bind-order.sh` (commit
   `a296a406c7c`) catches the pin being moved after the bind; a behavioural
   test like Codex's wsdd2 one is better if you can find an observable.
3. The rustls scoping table with measured numbers (commit `840ca0f33ea`,
   section "scoping: what a rustls port of mssl actually involves" in my
   `DEBTS_AND_TODOS.md`) is only referenced, not carried, on Codex's branch.
4. Codex's `DEBTS_AND_TODOS.md` (around line 485) still says the profile
   builds `UTF8_SSID=y`; `config_base` line 99 says `# RTCONFIG_UTF8_SSID is
   not set` and Codex's own `wlif-policy/src/lib.rs:208` agrees. Fix the
   stale sentence.

**Two review gaps remain open:**

- **wsdd2 never received an independent adversarial review.** My review
  subagent died on a rate limit in the middle of mutation testing. Codex then
  changed wsdd2 itself, but that is the author checking the author. The three
  other Tier 2 packages each yielded real defects under independent review
  (LLTD: permanent mapper suppression from eight frames; httpd: an ABI layout
  nothing could detect). Assume wsdd2 has comparable defects until reviewed.
- Codex corrected my firewall reading: the *live* `INPUT` policy is `ACCEPT`
  with a terminal `DROP`, and an interface-unbound UDP multicast accept
  (everything except port 1900) includes port 9999. WAN multicast isolation
  is **not proved**. `infosvr` relies on that firewall, not on a device pin.

## 2. What Tier 3 is

The stated goal is to port nearly the whole firmware to Rust. After Tier 1
(zlib-rs, client list, wlif policy, ntp) and Tier 2 (httparse, lltd, wsdd2),
the original plan named `rustls-ffi` next. Tier 3 therefore has two lanes.

### Lane A: TLS, `mssl` to rustls

Scope is far smaller than `mssl.c` suggests. Measured on 2026-09-10:

- `mssl.h` declares seven functions. On GT-AX11000 **only `httpd` consumes
  `libmssl`** and only through `ssl_server_fopen` (`httpd.c:2878`). The four
  `-lmssl` linkers are httpd, libwebapi, uploader, aws-iot; `config_base`
  leaves `RTCONFIG_AWSIOT` and `RTCONFIG_UPLOADER` unset. **`ssl_client_fopen`
  and `ssl_client_fopen_name` have no caller.** So this is a server-side port
  with four live entry points: `mssl_init_ex`, `mssl_ctx_free`,
  `ssl_server_fopen`, `mssl_cert_key_match`.
- `mssl.c` names 78 OpenSSL identifiers, but about a third of the file is a
  bundled musl `fopencookie` that `#if !defined(__GLIBC__)` compiles out here.
  glibc 2.26 supplies `fopencookie`; call it directly. Do not reimplement
  stdio.
- Latent trap, not a shipped bug: `SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE,
  NULL)` at `mssl.c:567` is unconditional and `SSL_set_verify(kuki->ssl,
  SSL_VERIFY_NONE, NULL)` at `:380` runs before the `if (client)` branch.
  Correct for a server; the first component to enable a client consumer gets
  a TLS client that accepts any certificate. rustls verifies by default.
- **Both backends build for the target** (`armv7-unknown-linux-gnueabi`,
  Broadcom GCC 5.5 as linker and `CC`, Rust 1.85.1): rustls 0.23.44 with ring
  0.17.14 yields a 7,113,828-byte release staticlib, with aws-lc-rs 1.18.1
  an 8,714,690-byte one. Both are ARMv7 with no `Tag_ABI_VFP_args`, i.e. the
  soft-float ABI the firmware requires. **Caveat:** `aws-lc-sys` objects
  carry `Tag_FP_arch: VFPv2`, ring objects carry no FP tag; the ISA gate in
  `verify-rust-firmware.sh` checks only the VFP argument ABI and CP15
  barriers, so shipping aws-lc needs an explicit decision about FP
  instructions. A staticlib is not shipped size: measure a linked, stripped
  `libmssl.so` replacement doing a real server handshake before choosing.
  ring is the smaller archive and needs no cmake or C++ build.
- **Blocking decision for the user, not for you:** the fork's hard rule is
  that `rust/vendor` gains no new crates.io dependency (Codex rejected
  `ntpd-rs` on exactly that rule). rustls, ring, webpki and pki-types are all
  new crates. Do not vendor them until the user relaxes the rule explicitly
  for this purpose.
- Design items with no answer yet: an equivalent of `mssl_cert_key_match`
  (it inspects RSA moduli and EC public keys through OpenSSL; rustls has no
  such API); whether to implement the callerless client half at all; cipher
  policy parity with `SSL_CTX_set_cipher_list(ciphers)` and the conditional
  `SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1` at `mssl.c:533`.

### Lane B: the remaining closed-source blobs

The inventory of prebuilt objects still shipped for this profile
(`release/src/router/*/prebuild/GT-AX11000/` and `*/prebuilt/`, counted by
package): rc 45, wlceventd 24, libbcm 22, eventd 22, bwdpi_source 20, bsd 19,
shared 16, vpmstats 14, dnsspoof 14, networkmap 4, cfg_mnt 4, wlc_nt 3,
aaews 3, sw-hw-auth 2, httpd 2, fsmd 2, asd 2, amas-utils 2, and singles.

Order by exposure, not by size. Network-facing blobs that parse untrusted
input come first: `dnsspoof` (DNS), `cfg_mnt` (AiMesh configuration sync
between nodes), `wlceventd` and `eventd` (wireless and system events), the
remaining `networkmap` prebuilds, and the two `httpd` prebuilds
(`web_hook.o` holds `auth_check`, `referer_check`, `check_user_agent`: the
functions the httparse review could not verify because they are closed).
`bwdpi_source` is a DPI engine and almost certainly out of reach. For each
candidate, in this order: (1) prove it is built and installed on GT-AX11000
by rendering the Makefile with `make -n` in both overlay modes, as the lltd
gate does, not by reading `ifeq` chains; (2) find every caller with `git
grep` on `6be5bc84b50`; (3) check `readelf -s` for whether the blob is
stripped, because the LLTD port was only possible because `lld2d.hnd` was
not; (4) Codex's rule: build typed Rust state and a narrow boundary, do not
re-implement C control flow in Rust.

### Lane C: debts that block calling Tier 1 and 2 done

These are hardware and behaviour gates, all listed with dates in
`DEBTS_AND_TODOS.md`, `TIER1_REVIEW_FIXES.md` and `TIER2_REVIEW_FIXES.md` on
Codex's branch. The ones that matter most: real WPS start/cancel, AP and
supplicant operations through the new supervisor; the NTP kernel step/slew
and rc readiness lifecycle, holdover behaviour, and cold-boot entropy on a
4.1 kernel; browser login, settings apply and client list against the
prebuilt auth hooks; Windows discovery for both LLTD (name TLV terminator
and sees-list byte order deliberately differ from the blob) and wsdd2
(WSDAPI); factory-reset restore of the encrypted backup. None of these is
inferred from the successful CI or the soak.

## 3. Rules that were learned the hard way

Repository shape:

- Vendor sources are **not on disk**: the checkout is sparse. Read them with
  `git -C /home/paul/asuswrt-merlin.ng show "6be5bc84b50:<path>"`. Always
  quote the ref in zsh. zsh does not word-split unquoted variables: a loop
  that builds compiler flags in a string silently passes one argument; use
  `bash -c` with arrays.
- The fork is an additive quilt overlay. Never edit `release/`. Changes are
  patches in `.github/ci/gt-ax11000/patches/` plus `series`, which is the
  order authority; a new patch is appended at the end. Apply with `git apply
  --recount --check` then `--recount`.
- The input lock: `patched_diff_sha256` is computed on the replayed tree
  **without** `rust-components` copied in, in that order. `tools/input_lock.py
  diff-hash --source <tree>`, then `update --lock <lock> --upstream-sha
  6be5bc84b50ea37be7b5d4307c5042771c3cf95b --patched-diff-sha256 <hash>`,
  then `verify --lock --series --patch-root --source --toolchains
  /home/paul/am-toolchains --rust-toolchain 1.85.1 --rust-target
  armv7-unknown-linux-gnueabi --rust-target-cpu cortex-a9`.
- A gate that reads a file no patch touches fails in CI because the sparse
  verification checkout does not contain it. Add such paths to the explicit
  list in `.github/workflows/build-gt-ax11000.yml` next to `config_base` and
  `rc/usb.c`.
- Cargo resolves the vendored registry from the **working directory**, not
  `--manifest-path`: always `cd .github/ci/gt-ax11000/rust` first. `cargo
  vendor --locked --versioned-dirs <tmp>` diffed against `rust/vendor` must
  be empty. Use your own `CARGO_TARGET_DIR`.
- Consumer listings must move together or `test_shared_repack.py` fails:
  `build.sh rust_relinked_consumers`, `rust-repack.mk` (promote, `rm -rf`,
  manifest), both `sha256sum` lines and both `rootfs_excludes` blocks in the
  workflow, and the hard-coded count in the test. Read the count from the
  branch; do not trust "fourteen" from this document.

Toolchain and CI:

- Broadcom cross compiler at `/home/paul/am-toolchains/brcm-arm-hnd/
  crosstools-arm-gcc-5.5-linux-4.1-glibc-2.26-binutils-2.28.1/bin/`; export
  `LD_LIBRARY_PATH=<tc>/lib:<tc>/usr/lib` first or `cc1` fails on libmpc.
  Rust 1.85.1, `-Ctarget-cpu=cortex-a9`, soft-float: no `Tag_ABI_VFP_args`,
  no CP15 barriers. No `qemu-arm` and no `jq` on this host; CI has qemu.
- Push over SSH (`git@github.com:0x1337F00D/asuswrt-merlin.ng.git`): the
  OAuth token lacks `workflow` scope. CI concurrency is per ref with
  cancel-in-progress: a push while a firmware build runs cancels it. Hold
  commits locally until the build finishes, let the push run's gates finish,
  then `gh workflow run build-gt-ax11000.yml --ref <branch>`; the Firmware
  job is skipped on push events.
- `/dev/shm` is tmpfs. Anything only there is gone after a reboot. Commit and
  push, or at least keep a copy under `/home`.

Method:

- Every fix needs a test that fails on the unfixed code. Mutate the fix and
  re-run before claiming it. Assertions that compare a value against the
  constant that defines it prove nothing; pin measured numbers.
- A diagnostic must never decide whether a gate passes.
- Check whether the code you fixed is compiled on this profile before
  claiming a security win. Live here: `CONFIG_HOSTAPD`, `RTCONFIG_HTTPS`.
  Dead here: `MULTIAP`, `WIFI7_SDK_*`, `RTCONFIG_WISP`, `RTCONFIG_BCMWL6`,
  `RTCONFIG_AWSIOT`, `RTCONFIG_UPLOADER`, `RTCONFIG_UTF8_SSID`.
- Review the other agent's work against the code, never against its prose,
  and let an independent subagent review yours. Both directions found real
  defects on 2026-09-10, in every package they looked at.
- Record what you decide not to fix in `DEBTS_AND_TODOS.md` with its
  reachability on this profile. Report failures with their output.

## 4. Suggested order

1. Push Codex's base to the fork; make your own worktree from it.
2. Re-apply the four small unsalvaged items from section 1.
3. Get wsdd2 independently reviewed with mutation testing, fix what it finds.
4. Ask the user for the two decisions Lane A needs: relaxing the no-new-crate
   rule for rustls, and ring versus aws-lc-rs. Prototype only after that.
5. Start Lane B with the feasibility triage of `cfg_mnt`, `dnsspoof` and
   `wlceventd`.
6. Do not touch the router until the 24-hour observation has ended and the
   user says so.
