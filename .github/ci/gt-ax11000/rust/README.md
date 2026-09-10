# GT-AX11000 Rust components

This workspace contains memory-safe replacements that are copied into the
ephemeral Asuswrt-Merlin CI source tree. Upstream sources stay unchanged.

The first component is `infosvr`. It preserves the read-only 512-byte ASUS
discovery protocol used by the GT-AX11000 while deliberately rejecting legacy
configuration and manufacturing opcodes. NVRAM access is read-only.

The second component is `rstats`. It preserves the 30-second bandwidth
sampling, signal interface, ISP-meter integration, JavaScript output and the
existing ARM binary formats. History V0 files are migrated to V1, and speed
archives now correctly accept any valid count from zero through 35 records.

The third component is `httpd-parsers`, a Rust static library used by the
existing C web server. It parses URL-encoded query/form and multipart filename
boundaries, rejects encoded NUL bytes, protects WLAN identity/regulatory and
raw calibration keys, authorizes only a country-profile test-lab request, and
validates complete WLAN authentication/cipher/PMF/WPS tuples. The HTTP state
machine, CGI hash table and request handlers remain in C.

`httpd-parsers` also owns the HTTP request line and header block. The vendor
`handle_request()` split the request line with `strsep()` and matched headers
with `strncasecmp()` prefixes inside one shared 10,000-byte `char line[]`,
advancing a cursor only for the headers it kept, so there was no bound on the
number or size of headers, `Content-Length` was read with
`strtoul(cp, NULL, 0)` into an `int` (making `0x10` and `010` hexadecimal and
octal), and an embedded NUL could never be seen because `fgets()` hides it.
`src/request.rs` replaces that with `httparse 1.10.1`
(`default-features = false`, so no `std` and no SIMD) behind explicit caps:
32,768 bytes per request block, 8,192 bytes of request line, 128 header
fields, 8,192 bytes per header value, a 4,096-byte request target, and a
`Content-Length` that has to be plain decimal in 0..=2,147,483,647. Only the
headers `httpd.c` actually consumes come back - `Host`, `User-Agent`,
`Cookie`, `Referer`, `Accept-Language`, `Range`, `If-None-Match`,
`Content-Length`, `Transfer-Encoding` and the `boundary=` parameter - each
copied into a fixed field of one `#[repr(C)]` result whose `sizeof` the caller
must pass in. `httpd.c` keeps the socket read, which stops at the terminating
empty line so `handler->input()` still frames the body itself; the request
target, the CGI dispatch, the `.asp`/`.htm` no-cache and CSRF paths and the
authentication flow are unchanged. Every failure is a distinct negative
sentinel and leaves the result fully zeroed.

The fourth component is `wanduck-transition`. It owns the pure, duplicated
dual-WAN failover/failback transition logic while PHY probes, NVRAM access,
restart actions and logging stay in the existing C daemon. Its typed state
model covers link edges, physical reconnection, data limits, modem PIN/scan
states and disconnect-counter policy.

The fifth component is `nt-event`. ASUS does not publish the GT-AX11000 source
for `nt_center`, `nt_monitor` or `libnt`, so this deliberately replaces only
the source-reconstructable `Notify_Event2NC` input boundary. It strictly parses
the hexadecimal event identifier, bounds the message to the public 512-byte
ABI and then hands the typed event to the unchanged proprietary `libnt`
transport.

The sixth component is `router-security`, the shell-free security boundary
linked into `rc`. It owns the narrow apply/NVRAM allowlist, strict IPsec
identity and basename validation, atomic WireGuard endpoint replacement, and
bounded parsing of effective IPv4/IPv6 firewall rules exported to private
temporary files. Keeping these policy and filesystem operations separate
leaves `wanduck-transition` as a pure WAN state machine.

The seventh component is `router-policy`, a dependency-free typed policy
library. Its country-only test-lab and WLAN modules are enforced through
`httpd-parsers`; its effective terminal-DROP invariant is enforced through
`router-security`. WAN-admin coverage is wired into the running firewall. The
per-profile OpenVPN/WireGuard inbound-block and policy-route kill-switch
validator is typed, fuzzed and exercised through its C ABI, but is not yet
wired into the running firewall.

The eighth component is `zlib-static`, a static C-ABI zlib built from
`zlib-rs` (`libz-rs-sys` with `export-symbols`, `gz` and the C allocator).
It is linked into exactly one isolated consumer, the vendor `wget`, which uses
streaming `inflate` for HTTP gzip bodies and `gzdopen`/`gzwrite`/`gzclose` for
WARC output. Every other zlib user resolves the
`zlib-shared` `libz.so.1` below at run time; `wget` keeps its own copy so a
regression in the shared object cannot also take the firmware downloader
down. `gzprintf` is not enabled (nightly only, unused).
The crate forbids unsafe code; `tests/c_abi_roundtrip.rs` and the C ABI smoke
fixture `tests/c-abi/zlib.c` exercise the exported entry points the way wget
calls them, and `verify-rust-firmware.sh` checks that the installed `wget` has
no `libz.so` dependency, carries the `1.3.0-zlib-rs-` marker and starts under
QEMU.

The ninth component is `clientlist`, the GT-AX11000 Web UI client list. It
replaces the json-c based readers of `httpd/web.c` (`get_client_detail_info`,
`ej_get_clientlist`, `get_clientlist_ex`, `get_client_name`,
`get_sdn_client_num`, `ej_get_clientlist_from_json_database`,
`ej_get_all_basic_clientlist`, `get_basic_clientlist_info` and
`search_device_name_in_clientlist`). `layout.rs` carries `#[repr(C)]`
descriptions of the closed daemon's 174,964-byte legacy table and the public
173,436-byte table with compile-time size and offset assertions; the legacy
view is selected only for `productid` `GT-AX11000` with exactly that segment
size, the public view only for exactly its size, and anything else fails
closed. `shm.rs` takes the vendor `file_lock("networkmap")` (`fcntl`
`F_SETLKW`), attaches the existing segment read-only without ever creating
it, copies it whole and detaches; parsing works on the copy, reads every
string inside its own field width, takes the trailer from the segment end
and clamps the count to 0..=255. The typed model is enriched from
`custom_clientlist`, `qos_rulelist`, `wtf_rulelist`, the `MULTIFILTER_*`
set (including the weekday/hour schedule check), `rog_clientlist` and the
AiMesh RE details, and rendered with `serde_json` through an
insertion-ordered value that keeps json-c's replace-in-place key order. The
C side keeps the `networkmap` process gate, the `nmp_wl_offline_check`
flag, the `delete_mac` trailer write and the AiMesh `is_re_node`/
`get_amas_info` lookups (passed as a callback and a text list); output goes
into a caller-provided 1 MiB buffer, atomic `/tmp/nmp_cache.js` writes are
done in Rust and no `json_object` crosses the boundary. The crate's FFI is
re-exported by `httpd-parsers`, so `httpd` still links one Rust archive.
`serde`/`serde_json` are the only new dependencies (the vendored
`serde_derive`/`syn` tree is a `cfg(any())` placeholder of `serde_core` that
is never compiled).

The tenth component is `zlib-shared`, the rootfs `/usr/lib/libz.so.1`. It
carries the same `libz-rs-sys` feature set as `zlib-static` (`std`,
`c-allocator`, `export-symbols`, `gz`; no `gzprintf`) and replaces the vendor
zlib 1.2.12 shared object for every package that links `-lz`: `rc`, `curl`,
`libxml2`, `libpng`, `tor`, `strongswan`, `minidlna`, `rsyslog`, `mtd`,
`mtd-utils`, `networkmap`, `nt_center`, `aws-iot`, `google_client`, `aaews`
and `samba`. The vendor `zlib` package is still configured, built and staged:
it owns `zlib.h`/`zconf.h`, the link-time `libz.so` every package compiles
against and the `libz.a` archive. Only the object installed into the image
changes.

The crate is compiled to a static archive and
`release/src/router/Makefile` performs the final `$(CC) -shared` link with
`-Wl,-soname,libz.so.1` and `-Wl,--version-script=zlib-shared/libz.map`. A
`cdylib` cannot be used: `rustc` unconditionally appends its own *anonymous*
version script to every `cdylib` and GNU `ld` 2.28.1 rejects the combination
("anonymous version tag cannot be combined with other version tags"), which
would leave the library unversioned and make every consumer that recorded
`inflate@ZLIB_1.2.0` fall back to the base definition with a loader warning.
`libz.map` reproduces the vendor `zlib/zlib.map` node for node, so the
exported versioned symbol set of the replacement is identical to the vendor
object except for `gzprintf`/`gzvprintf`, which `zlib-rs` only provides on
nightly and which no consumer in `release/src/router` calls. The vendor
`local:` symbols (`inflate_fast`, `inflate_table`, `z_errmsg`, `zcalloc`,
`zcfree`, `gz_error`, ...) were never exported by the vendor library either,
and neither are the zlib-rs-only extensions (`compress_z`, `deflateUsed`,
...).

Nothing is relinked against `libz.so.1`; consumers bind it by SONAME, so
`rust-repack.mk` only re-runs `zlib-install` on the rust-fast path. The crate
forbids unsafe code and asserts the `z_stream`/`gz_header` sizes at compile
time for whichever target is built. `tests/c_abi_roundtrip.rs`, the C ABI
smoke fixture `tests/c-abi/zlib-shared.c` (linked with `-lz` against the real
shared object) and `verify-rust-firmware.sh` cover it; the verifier checks the
SONAME, all fourteen `ZLIB_*` nodes, the ARMv7 soft-float attributes, the
`1.3.0-zlib-rs-` marker, that no internal symbol leaked, and that no installed
consumer needs `gzprintf`/`gzvprintf` or a `ZLIB_*` node the object lacks.
The eleventh component is `wlif-policy`, the only Rust archive linked into
`libshared.so`. The vendor `shared/wlif_utils_ax.c` is compiled into that
library for this profile (`shared/Makefile` adds `wlif_utils_ax.o` when
`RTCONFIG_HND_ROUTER_AX=y`, and the HND-94908 GT-AX11000 sets it) and used to
build 25 `system()`/`popen()` command strings from interface names, SSIDs,
PSKs, WPS PINs and DPP blobs. The overlay rewrites every one of them to a
fixed `argv[]` run through the vendor `_eval()`, or through a local
pipe-capturing `execvp` for the two that read output, and routes each
interpolated value through this crate first. Identifiers (interface names,
control-interface prefixes, CLI verbs, DPP blobs, PINs) get a strict ASCII
charset, may not start with `-` and may not contain `/` or a shell
metacharacter; SSIDs and passphrases stay opaque byte strings that are only
bounded and checked for NUL, control characters and encoding, and are never
placed on a command line at all. Control-socket paths are built by the crate,
not by the caller. Everything fails closed with the error value the vendor
function already returned.

`wlif-policy` deliberately does not reuse `router-policy`/`router-security`:
`librouter_security.a` is already linked into `rc`, its code is one LTO
object, and pulling it into `libshared.so` would duplicate every `rust_*`
symbol and add unrelated filesystem code to a library that roughly sixty
packages and seventeen prebuilt vendor blobs load. The crate also references
nothing from the Rust standard library except `strlen` - the UTF-8 validator
is written out rather than calling `core::str::from_utf8`, because `core`
ships as a single object and one call pulls the whole panic/backtrace runtime
in. Measured with the Broadcom `arm-buildroot-linux-gnueabi` linker, a shared
object built from the archive is 9,664 bytes stripped (6,129 bytes of text)
against 1,130,592 bytes for the same code calling `core::str::from_utf8`, and
it needs no shared library beyond `libc` and `libgcc_s`. `libshared.a` keeps
the plain object list: nothing in the tree links it.

The twelfth component is `ntp`, the SNTP/NTPv4 time daemon installed as
`/usr/sbin/ntp`. It replaces the busybox `ntpd` applet, which reached that
path through the `CONFIG_FEATURE_NTPD_NTP_ALIAS` applet alias; `ntp-rust.patch`
turns that alias and `CONFIG_NTPD` off, so `rc/Makefile` is the only remaining
producer of the path. Nothing in `rc/ntpd.c` changes: `start_ntpd()` still
execs `/usr/sbin/ntp -t -S /sbin/ntpd_synced -p SERVER [-p SERVER] [-l -I
IFACE]` through `_eval`, `stop_ntpd()` still matches the process by the name
`ntp`, and the daemon still runs `/sbin/ntpd_synced step` (one argument, plus
the `stratum`/`freq_drift_ppm`/`poll_interval`/`offset` environment variables)
when it steps the clock, which is what sets `ntp_ready`, `ntp_diff_ts` and the
DDNS/OpenVPN restarts hanging off it. The library half forbids unsafe Rust and
holds the wire format, reply validation, the peer clock filter, Marzullo peer
selection and the step/slew state machine; the daemon half keeps every system
call in `src/sys.rs`.

`ntp` security boundary:

- a reply is matched against the 64-bit transmit nonce before any other field
  is read, so an off-path spoofer has to guess it first. The nonce is eight
  fresh bytes of `/dev/urandom` per query, read through a `File` the daemon
  holds open; the poll-interval jitter keeps a separate xorshift generator,
  because the jitter is observable from the LAN and xorshift64 is invertible.
  The xorshift is the nonce source only when the kernel pool cannot be read,
  and that fallback is reported once at warning level;
- only mode-4 replies at version 3 or 4 and stratum 1..=15 are used; stratum 0
  is decoded as a kiss-o'-death and never as time. `RATE` backs the peer off;
  `DENY`/`RSTR` retires the *address* that sent it -- RFC 5905 section 7.4
  demobilises the association with that server, not the configured name, and
  `ntp_server0` defaults to `pool.ntp.org` -- and the reachability register
  keeps shifting for a refused peer, so a refusal ends in a loss-of-sync
  report rather than in a stale stratum served to the LAN;
- root distance, round-trip delay and the absolute time the server claims are
  all range-checked, and a datagram that is neither 48 nor 68 bytes is rejected
  before decoding;
- the reply the local clock is disciplined with is the one Marzullo
  intersection agrees on, so a single lying peer out of three cannot move it.
  No two peers may hold the same resolved address: the check runs on every
  lookup, not once at startup, and a peer that becomes a duplicate keeps no
  address and has its clock filter emptied, so it can offer neither a sample
  nor a candidate while a single source would be voting twice;
- server mode is pinned to the LAN interface with `SO_BINDTODEVICE` *before*
  the port is bound, so the socket is never reachable on the WAN, not even
  briefly, and a bind failure disables server mode with a warning instead of
  taking the client half down with it. It stays silent until the local clock
  is disciplined, answers only mode-3 requests with a fixed 48-byte reply,
  echoes nothing but the mandatory origin timestamp, publishes a reference
  timestamp truncated to whole seconds so the exact instant of the last
  upstream reply is not disclosed, and has no mode-6 (control) or mode-7
  (`monlist`) handler at all;
- the 64-replies-per-second budget is charged only for a reply that is
  actually sent, so a flood of malformed, mode-7 or oversized datagrams cannot
  spend a legitimate client's share, and one readable wakeup handles at most
  64 datagrams before the client half gets a turn;
- the `-S` program is executed argv-only, never through a shell, and unknown
  command-line options are a startup error rather than silently ignored. A
  `-p` value is trimmed and may be a bracketed IPv6 literal, because
  `rc/ntpd.c` passes `ntp_server0` verbatim from an unvalidated free-text
  field; an unusable one is a logged skip while another peer remains;
- the daemon touches no NVRAM, exactly as the busybox applet did not.

The thirteenth component is `lltd`, the Link Layer Topology Discovery
responder installed as `/usr/sbin/lld2d`. It replaces a prebuilt binary, not
open C: `release/src/router/lltd.arm` contains no `.c` file at all, only
`lld2d`, `lld2d.hnd` and `lld2d.6755axhnd`. The shipped `lld2d.hnd` is an
unstripped build of the Microsoft LLTD responder sample, "RELEASE 1.2",
compiled from `packetio.c`, `state.c`, `sessionmgr.c`, `mapping.c`,
`enumeration.c`, `band.c`, `seeslist.c`, `tlv.c`, `qospktio.c` and
`osl-linux.c`, none of which is in this tree. It answers raw EtherType 0x88D9
frames from any device on the LAN bridge, as root, before any
authentication. Nothing in `rc` changes: `start_lltd()` still runs
`eval("lld2d", "br0")` after `chdir("/usr/sbin")` and `stop_lltd()` still
matches the process by the name `lld2d` through `killall_tk()`. The library
half forbids unsafe Rust and holds the demultiplex header, the property
encoder, the emission budget and the responder itself; the daemon half keeps
every system call in `src/sys.rs`.

`lltd` implements a deliberately reduced subset. `Discover` is answered with a
broadcast `Hello` carrying eleven small inline properties, `Query` with an
empty `QueryResp`, and `Reset` is accepted without a reply. `Emit`, `Train`,
`Probe`, `Ack`, `Charge`, `Flat` and the two large-TLV opcodes are refused, as
is the QoS diagnostics service the blob routes to `qosrcvpkt`. `Emit` is
refused on purpose rather than left for later: it asks the responder to
transmit frames carrying attacker-chosen source and destination addresses,
once per descriptor in the request, which is both an unauthenticated
layer-2 injection primitive and the only real amplifier in the protocol. The
cost of refusing it is that a Windows network map can find and name the
router but cannot infer its position in the layer-2 topology from these
replies; `DEBTS_AND_TODOS.md` records that, and that no Windows interop test
has been run on hardware.

The advertised properties and their constants were read out of the blob's own
24-entry `Tlvs` table and its getters rather than guessed: Host ID (0x01),
Characteristics (0x02, the constant `30 00 00 00`), Physical Medium (0x03,
IANA ifType 6), IPv4 Address (0x07), Performance Counter Frequency (0x0A,
1,000,000), the `get_pause_granule` property (0x0B), Machine Name (0x0F),
Friendly Name (0x11), QoS Characteristics (0x14, zero), the `get_uptime`
property (0x17) and Sees-List Working Set (0x19, 4). Names are little-endian
UCS-2 with a two-byte terminator, which is what the blob's
`util_copy_ascii_to_ucs2` produces. Three properties the blob advertises are
deliberately not: the icon and jumbo icon, because on this model they cannot
work at all (`lltd.arm/Makefile` replaces `/usr/sbin/icon.ico` with a symlink
to `/tmp/icon.ico`, and `write_lltd_conf()` populates that path by copying
`/usr/sbin/icon_default.ico`, which the GT-AX11000 branch of the same
Makefile never installs), and Link Speed, because the blob obtains it from a
`wl_ioctl(WLC_GET_RATE)` on a wireless interface, which is not a meaningful
number for the bridge the responder is bound to.

`lltd` security boundary:

- the socket is `AF_PACKET`/`SOCK_RAW` filtered to EtherType 0x88D9 by both
  `socket()` and `bind()`, and `SO_BINDTODEVICE` is applied *before* the bind,
  so the responder is never briefly listening on another interface and a
  missing interface fails before anything is bound;
- the parser accepts one exact frame shape. Below 32 bytes, above 1514 bytes,
  a foreign EtherType, a version other than 1, a Type of Service other than 0,
  a non-zero reserved byte, a function byte above 12, a real destination that
  is neither this station nor broadcast, a source that claims to be this
  station, a group source address, or a sequence number that contradicts the
  opcode are all silent drops. Nothing is ever answered with an error;
- there is no unbounded allocation and no indexing on any path a frame can
  reach: the receive buffer is a fixed 1514 bytes, the duplicate-suppression
  table is a fixed 32-entry array, the TLV count is capped at 16 and a TLV
  value at 255 bytes. The workspace builds with `panic = "abort"`, so this is
  the difference between a dropped frame and a remotely triggered crash;
- a reply is bounded twice, by a 300-byte hard cap and by four times the
  request length, and properties that do not fit are dropped rather than the
  reply being split or truncated. `QueryResp` is held to the strict rule that
  it may never exceed the request at all. A byte-for-byte version of that rule
  cannot be applied to `Hello`: the shortest conforming `Discover` is one
  60-byte Ethernet minimum-length frame and the 46-byte Hello header leaves 13
  bytes, which is not enough for a name, so the ratio plus the budget below is
  what bounds it;
- the emission budget, eight replies refilling one per 250 ms, is charged only
  once a complete, size-checked reply exists. Charging on receipt is what lets
  a flood of malformed frames spend the budget and silence the responder for
  the real mapper. A mapper's (address, generation number) pair is also
  remembered for three seconds, so a repeated Discover sweep produces one
  Hello rather than one per copy;
- the daemon touches no NVRAM. The blob reads `lld2d_hostname`, defaulting it
  to `ASUS_ROUTER`, and unconditionally *writes* the NVRAM variable
  `friendly_name` with the fixed string "802.11 Broadcom Reference" from
  inside its packet handler; this port takes the kernel hostname instead and
  writes nothing;
- with no interface argument the daemon refuses to start. The blob assumed
  `eth1`.
The thirteenth component is `wsdd2`, the WS-Discovery and LLMNR responder
installed as `/usr/sbin/wsdd2`. It replaces the NETGEAR/Samba `wsdd2` the
firmware builds for `RTCONFIG_SAMBASRV`, which is how a Windows client finds
the router's SMB shares in Explorer's Network view. `wsdd2-rust.patch` changes
only `release/src/router/wsdd2/Makefile`, behind the usual
`ifneq ($(wildcard $(RUST_WSDD2_MANIFEST)),)` guard with the vendor C build in
the `else` branch, so `wsdd2-install` in `release/src/router/Makefile` remains
the single producer of the installed path and `rc/usb.c` is untouched:
`start_wsdd()` still execs `/usr/sbin/wsdd2 -d -w -i <lan_ifname> -b
sku:<productid>,serial:<mac>` through `_eval`, and `stop_wsdd()` still matches
the process with `pids("wsdd2")` / `killall_tk("wsdd2")`. Note what that `-w`
means: on this firmware only WS-Discovery is served, so LLMNR is implemented
but never reached by the `rc` invocation. The library half forbids unsafe Rust
and holds a strict namespace-aware XML scanner, the SOAP request and reply
shapes, the LLMNR question parser and response builder, the HTTP framing of
the WS-Transfer metadata endpoint and the reply budget; the daemon half keeps
every system call in `src/sys.rs`.

`wsdd2` security boundary:

- the XML scanner is not a general parser and fails closed. Document type
  declarations, entity declarations, `CDATA`, comments and processing
  instructions other than a leading XML declaration are all refused, and so is
  anything after the root element. Total length, nesting depth, element count,
  attribute count, name length, text length and live namespace bindings are
  each capped before anything is allocated, and entity expansion is limited to
  the five predefined entities plus printable-ASCII character references, so
  no input can expand. Namespaces are resolved through the prefix bindings
  actually in scope and mapped onto a closed set of six URIs, so an unknown
  namespace can never be mistaken for a known one. The vendor "parser" it
  replaces was two `strstr` calls over a NUL-terminated copy of the datagram
  (`wsd.c:353-420`) with no structural validation at all;
- a request is answered only when the SOAP envelope, the `wsa:Action`, the
  body element and the `wsa:To` all agree. The vendor dispatched on the action
  string alone and never looked at the body;
- a `Probe` is answered only when its `wsd:Types` is absent or names
  `wsdp:Device` or `pub:Computer`, and a `Resolve` only when its endpoint
  reference address is this device's own UUID. The vendor read neither field
  and answered every probe and every resolve on the segment, printer and
  scanner discovery included;
- the `wsa:MessageID` is the one attacker-controlled string a reply must
  carry. It is capped at 128 bytes and restricted to RFC 3986 URI characters
  minus `&` and `'`, so echoing it into `wsa:RelatesTo` can neither change the
  length of the reply nor open an element;
- a datagram reply is built from a fixed template whose only variable parts
  are this device's own UUIDs, its own address literal and that message id, so
  the reply length does not grow with the request: a padded probe produces a
  byte-identical answer. Five namespace prefixes are declared where the vendor
  declared seven in every message, and the total is capped at 1,400 bytes so
  one datagram in can never produce more than one un-fragmented datagram out.
  WS-Discovery cannot be made strictly non-amplifying -- a conforming
  `ProbeMatches` is larger than the smallest conforming `Probe` -- so what is
  guaranteed is that the amplification is bounded and constant;
- the LLMNR response is *rebuilt* from the parsed question rather than copied
  from the datagram. The vendor did `calloc(inlen + answer_len)` and
  `memcpy(out, in, inlen)` into a 9,217-byte receive buffer
  (`llmnr.c:275-277`), so a 9 KiB query with one valid label was reflected in
  full, additional records and all; here a padded query yields a *smaller*
  response and `ARCOUNT` is forced to zero;
- the LLMNR question is parsed inside the received slice. The vendor's label
  loop (`llmnr.c:172-193`) walked `*in_name_p` with no bound against `inlen`
  and then read four more bytes for `QTYPE`/`QCLASS`, which a 13-byte datagram
  is enough to reach;
- both service sockets are pinned to the LAN interface with `SO_BINDTODEVICE`
  *before* the port is bound, so they are never reachable on the WAN, not even
  briefly. The address advertised in `wsd:XAddrs` and returned in an LLMNR
  answer comes from a route lookup on that pinned socket, so a request whose
  source address does not route back through the LAN interface is never
  answered at all;
- the 32-replies-per-second budget, per protocol, is charged only for a reply
  that is actually sent, so a flood of malformed, wrong-type or wrong-endpoint
  datagrams cannot spend a legitimate client's share, and one readable wakeup
  handles at most 32 datagrams before the loop moves on;
- the metadata endpoint answers a refused request with a status line and an
  empty body. The vendor followed its status line with a ~700-byte SOAP fault
  whose text echoed its own internal error string (`wsd.c:1114-1119`);
- unknown command-line options are a startup error rather than silently
  ignored, and every value that can reach a log line or a reply is sanitised;
- the daemon touches no NVRAM, exactly as the vendor did not.

`infosvr` security boundary:

- the packet parser requires an exact 512-byte PDU and accepts only the four
  read-only discovery opcodes;
- all fixed-width protocol strings are bounded and NUL-terminated;
- the protocol library forbids unsafe Rust;
- the daemon's reviewed FFI boundary is limited to read-only NVRAM/feature
  helpers and Linux `SO_BINDTODEVICE`;
- disk statistics use `Command` with a validated argument and never a shell;
- `infosvr` never writes or commits NVRAM.

`rstats` has a different, explicitly reviewed boundary because traffic-meter
compatibility requires NVRAM writes. Its parser and binary codecs forbid unsafe
Rust; the daemon limits unsafe code to the existing NVRAM/network classifier
ABI and POSIX process/signal/time calls. gzip is invoked with a fixed absolute
program and fixed arguments, never through a shell, and decompressed output is
hard-limited before it reaches a codec. State and JavaScript files use atomic
replacement.

`httpd-parsers` exposes small, bounded C-ABI functions. It performs no
allocation across the ABI and never retains a caller pointer. Unit tests cover
malformed escapes, encoded delimiters, empty fields, mixed separators,
parameter smuggling, raw regulatory/calibration writes, exact country consent,
and fail-closed WLAN security combinations.

`wanduck-transition` accepts and returns fixed-layout C structs, performs no
I/O or allocation, and leaves unknown legacy states to the existing C fallback.
Its tests exercise transition priority and retry-counter invariants without
requiring router hardware.

`router-security` rejects null pointers, invalid UTF-8, unknown apply keys,
path-like IPsec names and malformed WireGuard endpoints. WireGuard updates
reject symlinks and oversized files, write a new mode-0600 file, sync it and
atomically rename it over the old configuration. Effective firewall snapshots
also reject symlinks, non-ASCII or oversized input and require INPUT/FORWARD to
end in unconditional DROP rules before forwarding is enabled. It never invokes
a shell.

`wlif-policy` forbids allocation and I/O, keeps no caller pointer and returns
`1`/`0` across its C ABI. Its unit tests cover every accepted vendor shape,
the exact length limits, option-like and path-like names, NUL, newline and
every other control byte, shell metacharacters, non-UTF-8 SSIDs, non-hex
64-character PSKs, short output buffers and null pointers; the UTF-8
validator is checked against `core::str::from_utf8` over every one- and
two-byte sequence and a boundary set of three- and four-byte ones.

`nt-event` rejects empty, signed, overflowing and partially parsed event IDs.
The ARM-only FFI is limited to the documented `initial_nt_event`,
`send_trigger_event` and `nt_event_free` functions, with a null check before
the event allocation is accessed.

Host tests:

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
bash ../tests/security-overlay-check.sh /path/to/patched/source
```

The structured fuzz runner covers the HTTP query/URL and multipart
boundaries, NVRAM-facing WLAN/test-lab policy, OpenVPN/IPsec/WireGuard
parsers, the wireless-interface identifier/credential policy, infosvr PDUs,
rstats codecs, the wanduck transition machine, the WS-Discovery/LLMNR
boundary (the XML scanner, the SOAP request parser and reply builders, the
LLMNR question parser and its rebuilt response, the HTTP framer and the
command line, driven with random bytes, with mutations and truncations of a
real Probe, and with every message shape, record type and record class),
the client-list parsers
(synthetic legacy/public shared-memory segments with random counts and
unterminated fields, the NVRAM list/schedule parsers, the AiMesh details
file, the cache check and the persistent-database transform) and the whole
NTP path a reply takes: random datagrams at random lengths with the query
nonce both matched and mismatched, every mode and stratum boundary, and --
because random bytes are rejected long before a sample exists -- headers
built to be accepted, with and without a flipped bit, driven through the
eight-deep peer filter, the fitness test, Marzullo selection and the
step/slew discipline for one to four peers over many poll rounds. It is
deterministic and keeps Cargo state and artifacts in tmpfs:

```sh
ASUSWRT_REQUIRE_TMPFS=1 \
RUST_FUZZ_ITERATIONS=250000 \
bash ../tests/rust-fuzz-smoke.sh
```

Three fixed seeds are always run, along with explicit maximum-length,
pair-count, encoded-NUL, codec-record, protocol-opcode and client-count/
segment-size boundary cases.

The C ABI smoke suite compiles strict C11 fixtures against the release Rust
archives and executes the same entry points used by `httpd`, `rc`, `wanduck`
and `libshared`; `tests/c-abi/clientlist.c` creates a real SysV segment with
a private key, fills the legacy GT-AX11000 layout and checks the rendered
document, the cache and database views and the NULL/small-buffer/wrong-size/
missing-segment failure codes. This catches layout, symbol, ownership and
non-mutation regressions without claiming to replace full firmware-consumer
or hardware tests:

```sh
ASUSWRT_REQUIRE_TMPFS=1 \
bash ../tests/c-abi-smoke.sh
```

The CI additionally checks the ARM target and exhaustively verifies that all
unimplemented 16-bit opcodes are rejected.

All firmware Rust code uses the `armv7-unknown-linux-gnueabi` standard library
and is compiled with `-Ctarget-cpu=cortex-a9`. The generic
`arm-unknown-linux-gnueabi` standard library contains deprecated ARMv6 CP15
barriers which the GT-AX11000's ARMv8 compatibility kernel deliberately does
not emulate. A CPU flag alone cannot repair instructions in Rust's precompiled
standard library. The ARMv7 soft-float target matches the Broadcom C toolchain
and uses architectural `dmb` barriers instead.

After the firmware build, `tests/verify-rust-firmware.sh` inspects the five
standalone Rust programs and the `httpd`/`rc` consumers. It rejects obsolete
CP15 barriers, hard-float or non-ARMv7 output, and then executes safe startup
paths for `infosvr`, `Notify_Event2NC`, `rstats`, `ntp` and `lld2d` under
`qemu-arm` using the generated firmware root filesystem. `ntp --self-test`
runs the packet, discipline and refusal paths without opening a socket or
writing the clock; `ntp` with no arguments must refuse to start.
`lld2d --self-test` runs the frame parser, the property encoder and the
emission budget without opening a socket, because a raw `AF_PACKET` socket
needs `CAP_NET_RAW` that the runner does not have; `lld2d` with no arguments
must refuse to start. The same step proves the installed `/usr/sbin/lld2d`
carries none of the prebuilt responder's marker strings.

The firmware Makefiles cross-compile with the existing Broadcom
`arm-buildroot-linux-gnueabi` linker and install the results as
`/usr/sbin/infosvr`, `/bin/rstats`, `/usr/sbin/ntp` and `/usr/sbin/lld2d`. The
time daemon is owned by `rc/Makefile` because `rc` is its only consumer, so it
is staged and promoted on the `rust-fast` relink path together with `sbin/rc`.
The LLTD responder keeps its own package Makefile, `lltd.arm/Makefile`, so it
is relinked on `rust-fast` in its own right rather than carried.
paths for `infosvr`, `Notify_Event2NC`, `rstats`, `ntp` and `wsdd2` under
`qemu-arm` using the generated firmware root filesystem. `ntp --self-test`
runs the packet, discipline and refusal paths without opening a socket or
writing the clock; `ntp` with no arguments must refuse to start.
`wsdd2 --self-test` parses a Windows Probe, a Resolve for another endpoint, a
padded LLMNR query and a metadata POST and checks each reply, again without a
socket; `wsdd2 -h` prints the vendor usage and exits 0, and `wsdd2 -i` with no
argument must refuse to start.

The firmware Makefiles cross-compile with the existing Broadcom
`arm-buildroot-linux-gnueabi` linker and install the results as
`/usr/sbin/infosvr`, `/bin/rstats`, `/usr/sbin/ntp` and `/usr/sbin/wsdd2`. The
time daemon is owned by `rc/Makefile` because `rc` is its only consumer, so it
is staged and promoted on the `rust-fast` relink path together with `sbin/rc`.
The discovery responder keeps its own package directory: `rust-repack.mk`
names the `wsdd2` build target before `wsdd2-install`, because the vendor
install rule has no build prerequisite, and then promotes
`fs.install/wsdd2/usr/sbin/wsdd2` into the flat tree like every other package
artifact. Both are relinked on `rust-fast`, not carried.

Rust sources are not added to `release/src/router` in the fork. The build
script copies this directory to the ephemeral build tree and
`rust-components.patch` only changes the temporary component Makefiles and
selected parser call sites. This keeps upstream merges independent of the
ports.
