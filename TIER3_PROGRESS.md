# Tier 3 checkpoint

Historical checkpoint; superseded by TIER3_IMPLEMENTATION.md.

Base b2bae581786 is pushed to fork/codex/tier2-stable-boundaries.
Working branch: codex/tier3-implementation. Router unchanged.

Restricted WLIF_CLI_DIRS to /usr/sbin; added overlay assertions against /opt;
corrected the UTF8_SSID profile claim. All 33 patches replayed successfully.
Input lock regenerated before copying Rust sources. Existing WLAN runtime
tests passed. New assertions and negative mutation tests remain unverified.

LLTD already has an inactive-socket setup seam with a behavioural unit test.
rustls offers CertifiedKey::keys_match; do not write custom key comparison
based on the outdated handover claim alone.

The independent wsdd2 review was blocked by the subagent service with a
cybersecurity access restriction. No review result was obtained. Do not
bypass this restriction. Backend choice is pending user response.

TLS implementation, blob triage, full gates and final independent review
remain outstanding. No new dependencies, firmware build or deployment.
This checkpoint is not approved for release.
