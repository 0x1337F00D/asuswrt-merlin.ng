# GT-AX11000 binary-component triage

Prepared upstream: 6be5bc84b50ea37be7b5d4307c5042771c3cf95b.
Overlay: d4f3886eaa1. No router access or execution of vendor blobs.
Feasibility analysis only; no replacements or runtime exposure claims.

## Build selection

The generated configuration selects RTCONFIG_CFGSYNC=y,
RTCONFIG_WLCEVENTD=y and RTCONFIG_HND_ROUTER=y. The model profile
targets/94908HND/94908HND.GT-AX11000 selects BUILD_DNSSPOOF=dynamic.
The HND dnsspoof target prefers TOP_PLATFORM, which resolves to
src-rt-5.02axhnd/router-sysdep, not generic release/src/router.

dry-run.sh runs make -n all install in isolated package copies, with the
actual generated configuration read-only. RUST_COMPONENTS_DIR switches
between the installed overlay and a verified absent directory. Both modes
give identical recipes for the three vendor packages. The mssl control run
changes from OpenSSL to libmssl_server.a, confirming the mode switch.
These package dry-runs do not replace final-image membership verification.

| Package | Selected binary input | Install paths |
| --- | --- | --- |
| cfg_mnt | prebuild/GT-AX11000/{cfg_server,cfg_client,cfg_reportstatus,libcfgmnt.so} | usr/sbin/{cfg_server,cfg_client,cfg_reportstatus,gencfgcert.sh}, usr/lib/libcfgmnt.so |
| wlceventd | prebuilt/GT-AX11000/wlceventd | usr/sbin/wlceventd |
| dnsspoof | router-sysdep/dnsspoof/prebuilt/dnsspoof, PREBUILT_BCMBIN=1 | bin/dnsspoof |

The generic dnsspoof Makefile.fullsrc lacks dnsspoof.c and is not this
model's selected package. Its presence is not proof of available source.

## Replacement boundaries

- cfg_mnt: rc/services.c:start_cfgsync selects server/client using mode and
  NVRAM. LAN/service hooks restart it; watchdog checks process and pid files;
  NTP signals it. libcfgmnt also has binary consumers, including wlceventd.
  Imports include versioned OpenSSL 1.1, JSON-C, nvram/shared, mesh/LLDP,
  SQLite and notification APIs. system/popen imports are not proof of
  injection. First document cfg_*/cm_* exports, IPC/wire framing, peer
  authentication, configuration transactions and event ordering. Replacing
  an executable alone does not remove the library or its legacy crypto.
- dnsspoof: libc-only ARM binary with socket/bind/recvfrom/sendto/strtol.
  Strings require a local-IP argument. No source caller was found in the
  searched router C/shell/UI sources; closed consumers remain possible.
  Determine actual startup, bind scope, wire format, response semantics,
  length/endian limits and shutdown before porting. Name alone proves no
  exposure or port number.
- wlceventd: rc/services.c start/stop hooks with factory/media-bridge
  conditions; wlcsm/nvram/shared, cfgmnt and notification dependencies.
  A port needs the Broadcom event ABI, interface/lifecycle contracts,
  message-length checks and reconnect behavior. It does not replace the
  proprietary driver.

Raw readelf imports and source matches: symbols.txt and callers.txt.
WAN multicast isolation, live process state and hardware compatibility
remain unproven.
