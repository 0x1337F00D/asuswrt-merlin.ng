#!/bin/sh
set -eu

if [ "$#" -ne 5 ]; then
	printf '%s\n' 'RESULT=FAIL' 'FAILED_CHECK=ARGUMENTS'
	exit 2
fi

EXPECTED_PARTITION=$1
EXPECTED_NEXT_BOOT_STATE=$2
EXPECTED_FIRMVER=$3
EXPECTED_BUILDNO=$4
EXPECTED_EXTENDNO=$5

umask 077
TMP_DIR=/tmp/router-health.$$
if ! mkdir "$TMP_DIR" 2>/dev/null; then
	printf '%s\n' 'RESULT=FAIL' 'FAILED_CHECK=TEMP_DIRECTORY'
	exit 1
fi
trap 'rm -rf "$TMP_DIR"' 0 1 2 3 15

fail() {
	printf 'RESULT=FAIL\nFAILED_CHECK=%s\n' "$1"
	exit 1
}

pass() {
	printf '%s=PASS\n' "$1"
}

need_command() {
	if ! which "$1" >/dev/null 2>&1; then
		fail "$2"
	fi
}

need_command bcm_bootstate BCM_BOOTSTATE_COMMAND
need_command nvram NVRAM_COMMAND
need_command pidof PIDOF_COMMAND
need_command dmesg DMESG_COMMAND
need_command awk AWK_COMMAND
need_command grep GREP_COMMAND
need_command cmp CMP_COMMAND
need_command ping PING_COMMAND
need_command nslookup NSLOOKUP_COMMAND
need_command iptables IPTABLES_COMMAND
need_command ip6tables IP6TABLES_COMMAND
need_command wl WL_COMMAND
need_command wget WGET_COMMAND

check_nvram() {
	CHECK_VALUE=''
	if ! CHECK_VALUE=$(nvram get "$1" 2>"$TMP_DIR/nvram.err"); then
		fail "NVRAM_$1"
	fi
	if [ "$CHECK_VALUE" != "$2" ]; then
		fail "NVRAM_$1"
	fi
}

if ! bcm_bootstate >"$TMP_DIR/bootstate.out" 2>&1; then
	fail BOOTSTATE_READ
fi
if ! grep -Fq "Booted Partition: $EXPECTED_PARTITION" "$TMP_DIR/bootstate.out"; then
	fail BOOT_PARTITION
fi
if ! grep -Fq "Boot image state: $EXPECTED_NEXT_BOOT_STATE" "$TMP_DIR/bootstate.out"; then
	fail NEXT_BOOT_STATE
fi
check_nvram firmver "$EXPECTED_FIRMVER"
check_nvram buildno "$EXPECTED_BUILDNO"
check_nvram extendno "$EXPECTED_EXTENDNO"
pass BOOT_AND_VERSION

# Merlin's post-boot image promotion hook uses this exact persistent marker.
# A one-shot trial must never create it.
if [ -e /data/commit_image_after_reboot ]; then
	fail COMMIT_MARKER
fi
pass NO_COMMIT_MARKER

SERVICES='httpd dnsmasq wanduck infosvr rstats nt_monitor'
for service in $SERVICES; do
	if ! pidof "$service" >"$TMP_DIR/$service.pid.before" 2>/dev/null; then
		fail "SERVICE_${service}"
	fi
done
pass SERVICES

find_binary() {
	for BINARY_PATH in "$1" "$2"; do
		if [ -x "$BINARY_PATH" ]; then
			printf '%s\n' "$BINARY_PATH"
			return 0
		fi
	done
	return 1
}

RSTAT_BIN=''
if ! RSTAT_BIN=$(find_binary /bin/rstats /usr/sbin/rstats); then
	fail RSTATS_BINARY
fi
INFOSVR_BIN=''
if ! INFOSVR_BIN=$(find_binary /usr/sbin/infosvr /bin/infosvr); then
	fail INFOSVR_BINARY
fi
NT_EVENT_BIN=''
if ! NT_EVENT_BIN=$(find_binary /usr/sbin/Notify_Event2NC /bin/Notify_Event2NC); then
	fail NT_EVENT_BINARY
fi

if "$RSTAT_BIN" --self-test >"$TMP_DIR/rstats.out" 2>&1; then
	RSTAT_STATUS=0
else
	RSTAT_STATUS=$?
fi
[ "$RSTAT_STATUS" -eq 0 ] || fail RSTATS_SELFTEST
pass RSTATS_SELFTEST

if "$INFOSVR_BIN" >"$TMP_DIR/infosvr.out" 2>&1; then
	INFOSVR_STATUS=0
else
	INFOSVR_STATUS=$?
fi
[ "$INFOSVR_STATUS" -eq 1 ] || fail INFOSVR_SAFE_EXIT
pass INFOSVR_SAFE_EXIT

if "$NT_EVENT_BIN" >"$TMP_DIR/nt-event.out" 2>&1; then
	NT_EVENT_STATUS=0
else
	NT_EVENT_STATUS=$?
fi
[ "$NT_EVENT_STATUS" -eq 2 ] || fail NT_EVENT_SAFE_EXIT
pass NT_EVENT_SAFE_EXIT

WAN_PING_TARGET=${ROUTER_HEALTH_WAN_PING_TARGET:-8.8.8.8}
DNS_NAME=${ROUTER_HEALTH_DNS_NAME:-www.asus.com}
if ! ping -c 1 -W 3 "$WAN_PING_TARGET" >"$TMP_DIR/ping.out" 2>&1; then
	fail WAN_PING
fi
pass WAN_PING
if ! nslookup "$DNS_NAME" 127.0.0.1 >"$TMP_DIR/dns.out" 2>&1; then
	fail LOCAL_DNS
fi
pass LOCAL_DNS

for radio_nvram in wl0_radio wl1_radio wl2_radio; do
	check_nvram "$radio_nvram" 1
done
pass RADIO_NVRAM

for radio_if in eth6 eth7 eth8; do
	RADIO_OUT="$TMP_DIR/$radio_if.radio"
	if ! wl -i "$radio_if" radio >"$RADIO_OUT" 2>&1; then
		fail "RADIO_${radio_if}"
	fi
	if ! grep -Eq '^0x0000[[:space:]]*$' "$RADIO_OUT"; then
		fail "RADIO_${radio_if}"
	fi
done
pass RADIO_PHY

if [ ! -d /www ] || [ ! -r /www/index.asp ]; then
	fail WEBROOT
fi
HTTPD_BEFORE=''
if ! HTTPD_BEFORE=$(pidof httpd 2>"$TMP_DIR/httpd-before.err"); then
	fail HTTPD_BEFORE
fi
WGET_BIN=$(which wget)
# A malformed percent-NUL request may legitimately return an HTTP error. The
# health condition is that the request does not terminate the httpd process.
"$WGET_BIN" -q -T 5 -O /dev/null -Y off \
	'http://127.0.0.1/index.asp?health=%00' >"$TMP_DIR/httpd-request.out" 2>&1 || true
sleep 1
if ! pidof httpd >"$TMP_DIR/httpd-after.out" 2>&1; then
	fail HTTPD_MALFORMED_REQUEST
fi
pass WEBROOT_AND_MALFORMED_REQUEST

check_terminal_drop() {
	CHECK_RULES="$TMP_DIR/$1.rules"
	if ! "$2" -S >"$CHECK_RULES" 2>&1; then
		fail "$1_RULES"
	fi
	for CHECK_CHAIN in INPUT FORWARD; do
		if ! CHECK_RESULT=$(awk -v chain="$CHECK_CHAIN" '
			$1 == "-A" && $2 == chain { last = $0 }
			END {
				if (last ~ /(^|[[:space:]])-j[[:space:]]+DROP([[:space:]]|$)/)
					print "PASS"
			}' "$CHECK_RULES"); then
			fail "$1_${CHECK_CHAIN}_DROP"
		fi
		[ "$CHECK_RESULT" = PASS ] || fail "$1_${CHECK_CHAIN}_DROP"
	done
}
check_terminal_drop IPV4 iptables
check_terminal_drop IPV6 ip6tables
pass TERMINAL_DROP_RULES

if ! dmesg >"$TMP_DIR/dmesg.out" 2>&1; then
	fail DMESG_READ
fi
if grep -Eiq 'sigill|illegal instruction|undefined instruction|segmentation fault|segfault|kernel oops|oops|kernel panic|panic' "$TMP_DIR/dmesg.out"; then
	fail DMESG_FAULT
fi
pass DMESG_FAULT_FREE

# A supervised daemon that crashes and is restarted is still a failed trial.
# Require the same service PID sets at the end of the complete health gate.
for service in $SERVICES; do
	if ! pidof "$service" >"$TMP_DIR/$service.pid.after" 2>/dev/null; then
		fail "SERVICE_${service}_AFTER"
	fi
	if ! cmp -s "$TMP_DIR/$service.pid.before" "$TMP_DIR/$service.pid.after"; then
		fail "SERVICE_${service}_RESTARTED"
	fi
done
pass SERVICE_PID_STABILITY

printf '%s\n' 'RESULT=PASS'
exit 0
