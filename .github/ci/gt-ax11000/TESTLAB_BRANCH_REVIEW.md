# Retired test-lab branch: 2026-09-09

Decision: **archive and delete the obsolete branch; salvage no code**.
Do not merge or replay `advanced-testlab-ui.patch` into the current overlay.

Reviewed tips (identical on GitHub `fork`, local `origin` and the original
`/home/paul/asuswrt-merlin-rust` branch):

- `codex/gt-ax11000-testlab-ui`:
  `e8ba9d2832ee23976fc09d57ebf64c9718d33471`.
- Unique commits: `4604d2332b6` (original implementation) and `e8ba9d2832e`
  (const-warning adjustment). Only four files differ from the common ancestor:
  the 692-line patch and its README/build/workflow wiring.
- Patch SHA-256:
  `c78fb7cb6fb3cec8e07b864b10db55fe4f10280278352b8072bfc9831c36d3b9`.
- Recovery tag: `archive/gt-ax11000-testlab-ui-20260909`, verified on GitHub
  before branch deletion. The tag retains both commits and the exact patch.

## Feature-by-feature disposition

| Old implementation | Current disposition |
| --- | --- |
| Separate `Advanced_TestLab_Content.asp`, new ROG tab | Superseded by the existing Advanced Wireless UI in `wireless-policy-ui.patch`; avoid another confusing settings surface. |
| Three-radio status and driver channels | Already covered by `regulatory_lab_render_status`; preserve current country/channel/DFS/requested-power read-back. |
| Reject `ALL`/`#a` and power requests above 100 | Conflicts with the explicitly requested country-only profile design. Current Rust authorization and warning remain unchanged. |
| Per-radio temporary chanspec, `restore_power` | Conflicts with the single country-profile mutation boundary; do not restore independent channel or power actions. |
| Ten-minute forked radio rollback | Not a reliable transaction: no model of the original runtime state; predictable public `/tmp/advanced_testlab_wlN.rollback` opened with `fopen`; changes radio before proving rollback can be scheduled; repeated requests spawn sleepers. A generation marker is not a verified recovery mechanism. |
| Temporary `ASUS_TESTLAB_V6` FORWARD reject switch | Not country selection and not a substitute for the current IPv4/IPv6 firewall policy. Removal loops without a bound if checks keep finding a jump whose deletion fails. Do not add this second firewall owner. |
| `const` warning adjustment | Only affects the rejected per-radio chanspec path; no independent fix to carry. |
| Build/workflow patch wiring | Superseded by canonical `patches/series` and immutable input/diff locks. |

Additional review concern: old NVRAM values are interpolated into JavaScript
string literals before the later HTML escaping helper runs. This is not an
audited safe transport boundary; no live exploit is claimed here.

The valuable ideas (warning, three-radio status, fixed-argv commands) already
exist in the supported overlay. Importing this branch would add obsolete
mutation paths and weaken the current tests. The overlay gate now rejects the
old endpoint, firewall chain and standalone page as regression tripwires.

## Recovery

```sh
git fetch fork refs/tags/archive/gt-ax11000-testlab-ui-20260909:refs/tags/archive/gt-ax11000-testlab-ui-20260909
git switch -c review/old-testlab archive/gt-ax11000-testlab-ui-20260909
git show archive/gt-ax11000-testlab-ui-20260909:.github/ci/gt-ax11000/patches/advanced-testlab-ui.patch
```

Archiving is not approval to build or install the old code. No router settings,
country profile, NVRAM, firewall, firmware or network service were changed as
part of this review.
