# router-policy

Pure, side-effect-free validation for security-sensitive router settings.  The
crate deliberately has no dependencies and forbids all unsafe Rust.  It does
not execute commands, access files, open sockets, or read/write NVRAM.

## Public policy surfaces

- `firewall::FirewallManifest::parse` consumes a canonical manifest derived
  from the effective IPv4/IPv6 rules. `validate` requires terminal INPUT and
  FORWARD drops for both families, WAN denial for every declared admin port,
  and complete VPN kill-switch coverage when enabled.
- `vpn::WireGuardEndpoint` parses DNS, IPv4, and bracketed IPv6 endpoints.
  `vpn::AllowedIpSet` accepts canonical CIDRs and requires a separate explicit
  flag for either default route. `IpsecProfile` and `OpenVpnProfile` only expose
  modern, typed algorithms and require OpenVPN peer verification.
- `wlan::WlanSecurityTuple` represents authentication, cipher, PMF, and WPS as
  one value. The default policy permits WPA2-AES/CCMP with PMF and WPA3-SAE with
  mandatory PMF; WEP, TKIP, open authentication, transition mode, and WPS fail
  closed unless a narrowly scoped compatibility exception exists.
- `testlab::TestlabRequest` validates country and transmit-power requests, but
  produces an `AuthorizedTestlabRequest` only for the exact versioned consent
  token after showing `TESTLAB_WARNING`. Authorization still performs no
  mutation and does not establish regulatory compliance.

## Recommended C integration

Keep this crate as a safe `rlib` and add a small, separately audited `staticlib`
adapter at each existing C boundary. Each adapter should:

1. accept `(const uint8_t *, size_t)` rather than an unbounded C string;
2. reject null pointers, oversized input, embedded NUL, and invalid UTF-8 before
   calling this crate;
3. return a fixed integer status plus a stable, non-secret error code, never a
   Rust allocation or Rust struct across the ABI;
4. validate the complete candidate configuration before the legacy code begins
   applying any part of it;
5. fail closed on policy errors and avoid a legacy fallback for security
   decisions;
6. build firewall manifests from the effective rules after rule generation and
   validate again before atomically loading the rule set.

The adapter is the only place that should contain the narrowly documented
`unsafe` required by C FFI. Test its length and pointer boundary independently.
