## Scope

- Task ID:
- Risk and rollback:
- Upstream/vendor files remain unchanged in Git: yes / no / not applicable

## Evidence

- [ ] Negative regression test reproduces every security fix.
- [ ] Rust format, tests, Clippy and target checks pass.
- [ ] Security-overlay checks pass on the locked patched source.
- [ ] A clean firmware build passes when required by the change.
- [ ] `DEBTS_AND_TODOS.md` is updated.
- [ ] Logs and fixtures contain no secrets, SSIDs, MAC addresses or packet contents.

## Security-sensitive review

Check every applicable boundary and explain any exception:

- [ ] FFI and every `unsafe` block
- [ ] HTTP authentication, sessions, CSRF and parsers
- [ ] NVRAM reads/writes and country/test-lab policy
- [ ] Firewall, VPN, WLAN, WPS and WAN listeners
- [ ] Updater, image verification, boot state and MTD access
- [ ] Workflows, Actions and dependency/input pinning
- [ ] Shell/command execution, JFFS hooks and generated configuration
- [ ] setuid/setgid, capabilities, file descriptors and privilege drop

## Hardware evidence

- [ ] Not required; no runtime, rootfs, recovery or hardware-facing change.
- [ ] One-shot HIL evidence is attached and the known fallback was verified.
- [ ] Candidate was returned to the known-good persistent partition.
