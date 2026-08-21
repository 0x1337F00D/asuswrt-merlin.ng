# GT-AX11000 one-shot trial controller

`controller.py` turns the already tested manual trial procedure into a strict
host-side state machine:

1. verify a regular `.w` file against an explicitly supplied SHA-256;
2. require model `GT-AX11000`, the expected known-good partition, persistent
   fallback boot state, firmware version, and no Merlin commit marker;
3. copy to a unique `/tmp` name and verify the same SHA-256 again with the
   router image's fixed `/usr/sbin/openssl dgst -sha256`;
4. require both `firmware_check=1` and the GT-AX11000-specific successful
   `hnd-write`/`hndwr` status `99`;
5. prove that the writer selected the inactive partition, then replace that
   persistent selection with the symbolic `BOOT_SET_PART*_IMAGE_ONCE` state;
6. reboot, require the candidate partition and already-consumed known-good
   fallback state, then run `router-health.sh` and the read-only infosvr test;
7. explicitly reboot again and require the original partition, boot state and
   version before recording `PASS`.

There is no candidate-promotion command or `nvram commit` in the controller.
The successful path uses only symbolic `BOOT_SET_PART*_IMAGE_ONCE` arguments so
the vendor utility's numeric CLI mapping cannot be confused with the values in
Broadcom headers. If `hnd-write` selected the candidate but a pre-boot gate then
fails, the only permitted persistent setter restores the recorded known-good
baseline partition. Evidence contains only phases, hashes, sizes, partition and
state names, versions, and PASS/failure codes; command output that could expose
router configuration is not persisted.

## Dry-run first

Dry-run is the default. It only reads and hashes the local image:

```sh
python3 .github/ci/gt-ax11000/trial/controller.py \
  --image /tmp/asuswrt-merlin-current/output-v2/GT-AX11000_3006_102.8_2_ubi.w \
  --expected-sha256 SHA256_FROM_BUILD_MANIFEST \
  --baseline-partition First \
  --baseline-version 3.0.0.4/388.11/0 \
  --candidate-version 3.0.0.6/102.8/2
```

Execution additionally needs all of the following:

- `--execute`;
- `--acknowledge-risk GT-AX11000-ONE-SHOT-TRIAL`;
- a new, non-existing `--evidence-dir`;
- an already configured SSH key/agent and a matching known-host entry.

The OpenSSH adapter enforces batch mode and strict host-key checking. It has no
password, key-copying, GitHub, runner, or credential-management facility.

## Recovery boundary

The ordinary successful path is automatic, including the explicit second
reboot. If the candidate never becomes reachable over SSH, software running on
the host cannot power-cycle the router. The already consumed one-shot state
still points at the known-good partition, but triggering that reboot requires a
separately authenticated out-of-band power controller. Until such a transport
is implemented and tested, an unreachable-candidate timeout is intentionally a
hard failure and is never misreported as rollback success.

Run the fake-transport regression suite without a router:

```sh
python3 -m unittest discover -s .github/ci/gt-ax11000/trial \
  -p 'test_*.py' -v
```

## Persistent promotion guard

`router-persistent-guard.sh` is deliberately separate from the one-shot trial
controller. It describes the validated deployment: candidate on partition 1
and known-good fallback on partition 2. Candidate identity requires the model,
version, running partition, final test-lab UI marker and final `httpd` NVRAM
marker; the shared firmware version string alone is not sufficient.

On every persistent candidate boot, `arm` selects partition 2 for one boot.
The delayed `services-start` hook invokes `promote` after 120 seconds. Only the
complete services, WAN/DNS, three-radio, firewall, kernel-log and UI-marker
health gate restores persistent partition 1. A reachable health failure selects
partition 2 persistently and requests a reboot. A candidate that never becomes
reachable still requires out-of-band power control to trigger the already armed
fallback, as documented above.
