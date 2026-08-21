#!/bin/sh
set -u

PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH

TRIAL_DIR=/data/firmware-trial-rollback
STATE_FILE="$TRIAL_DIR/state"
LOG_FILE="$TRIAL_DIR/guard.log"
CANDIDATE_STATE=BOOT_SET_PART1_IMAGE
FALLBACK_STATE=BOOT_SET_PART2_IMAGE
FALLBACK_ONCE_STATE=BOOT_SET_PART2_IMAGE_ONCE
WEB_PAYLOAD_MANIFEST_SHA256=d564d4ecace0465d7b004c6aeee54ab0dc9374310edb7ce19dc590878237e4f9
WEB_SYMLINK_MANIFEST_SHA256=e651541e58c5ae985d833ccc6782752281b2c4f6f8d0b2782bf0000fc5f6b0bf

log_guard() {
	mkdir -p "$TRIAL_DIR" 2>/dev/null || return 0
	printf '%s action=%s model=%s version=%s/%s/%s %s\n' \
		"$(date -R)" "$1" "$(nvram get productid)" "$(nvram get firmver)" \
		"$(nvram get buildno)" "$(nvram get extendno)" "$2" >> "$LOG_FILE"
	chmod 600 "$LOG_FILE" 2>/dev/null || true
}

set_state() {
	mkdir -p "$TRIAL_DIR"
	printf '%s\n' "$1" > "$STATE_FILE.new"
	chmod 600 "$STATE_FILE.new"
	mv "$STATE_FILE.new" "$STATE_FILE"
	sync
}

bootstate_has() {
	/bin/bcm_bootstate 2>/dev/null | grep -Eq \
		"^[[:space:]]*Boot image state:[[:space:]]*$1[[:space:]]*$"
}

verify_web_payload() {
	expected_count=$(wc -l < /usr/share/codex/web-payload.sha256) || return 1
	actual_count=$(find /www -print | while IFS= read -r path; do
		[ -f "$path" ] && [ ! -L "$path" ] && printf 'x\n'
	done | wc -l) || return 1
	[ "$actual_count" -eq "$expected_count" ] || return 1
	while read -r expected path; do
		case "$path" in
			www/*) ;;
			*) return 1 ;;
		esac
		[ -f "/$path" ] || return 1
		actual=$(/usr/sbin/openssl dgst -sha256 "/$path" 2>/dev/null | awk '{print $NF}') ||
			return 1
		[ "$actual" = "$expected" ] || return 1
	done < /usr/share/codex/web-payload.sha256
}

verify_web_symlinks() {
	expected_count=$(wc -l < /usr/share/codex/web-symlinks.manifest) || return 1
	actual_count=$(find /www -print | while IFS= read -r path; do
		[ -L "$path" ] && printf 'x\n'
	done | wc -l) || return 1
	[ "$actual_count" -eq "$expected_count" ] || return 1
	while IFS="$(printf '\t')" read -r link target; do
		case "$link" in
			www/*) ;;
			*) return 1 ;;
		esac
		[ -L "/$link" ] && [ "$(readlink "/$link")" = "$target" ] || return 1
	done < /usr/share/codex/web-symlinks.manifest
}

is_candidate_identity() {
	[ "$(nvram get productid)" = "GT-AX11000" ] &&
	[ "$(nvram get firmver)" = "3.0.0.6" ] &&
	[ "$(nvram get buildno)" = "102.8" ] &&
	[ "$(nvram get extendno)" = "4" ] &&
	/bin/bcm_bootstate 2>/dev/null | grep -q 'Booted Partition: First' &&
	grep -Fq 'id="regulatory_lab_country"' /www/Advanced_WAdvanced_Content.asp &&
	grep -Fq 'regulatory_lab_store_acknowledgement' /www/Advanced_WAdvanced_Content.asp &&
	[ -s /www/EN.dict ] &&
	[ -s /www/DE.dict ] &&
	[ -s /usr/share/codex/web-payload.sha256 ] &&
	[ -s /usr/share/codex/web-symlinks.manifest ] &&
	[ "$(/usr/sbin/openssl dgst -sha256 /usr/share/codex/web-payload.sha256 2>/dev/null | awk '{print $NF}')" = "$WEB_PAYLOAD_MANIFEST_SHA256" ] &&
	[ "$(/usr/sbin/openssl dgst -sha256 /usr/share/codex/web-symlinks.manifest 2>/dev/null | awk '{print $NF}')" = "$WEB_SYMLINK_MANIFEST_SHA256" ] &&
	grep -aFq 'rust_regulatory_testlab_ack_v1' /usr/sbin/httpd
}

is_candidate() {
	is_candidate_identity &&
	verify_web_payload &&
	verify_web_symlinks
}

healthy() {
	is_candidate || return 1
	[ ! -e /data/commit_image_after_reboot ] || return 1
	for service in httpd dnsmasq wanduck infosvr rstats nt_monitor; do
		pidof "$service" >/dev/null 2>&1 || return 1
	done
	[ "$(nvram get wan0_state_t)" = "2" ] || return 1
	ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1 || return 1
	nslookup www.asus.com 127.0.0.1 >/dev/null 2>&1 || return 1
	for radio_nvram in wl0_radio wl1_radio wl2_radio; do
		[ "$(nvram get "$radio_nvram")" = "1" ] || return 1
	done
	for radio_if in eth6 eth7 eth8; do
		wl -i "$radio_if" radio 2>/dev/null | grep -Eq '^0x0000[[:space:]]*$' || return 1
	done
	for tool in iptables ip6tables; do
		"$tool" -S 2>/dev/null | awk '
			$1 == "-A" && ($2 == "INPUT" || $2 == "FORWARD") { last[$2] = $0 }
			END {
				if (last["INPUT"] !~ /(^|[[:space:]])-j[[:space:]]+DROP([[:space:]]|$)/)
					exit 1
				if (last["FORWARD"] !~ /(^|[[:space:]])-j[[:space:]]+DROP([[:space:]]|$)/)
					exit 1
			}' || return 1
	done
	! dmesg | grep -Eiq \
		'sigill|illegal instruction|undefined instruction|segmentation fault|segfault|kernel oops|kernel panic'
}

case "${1:-}" in
	arm)
		is_candidate_identity || exit 0
		if bootstate_has "$CANDIDATE_STATE"; then
			/bin/bcm_bootstate "$FALLBACK_ONCE_STATE" >/dev/null || exit 1
			set_state BOOT_GUARD_PART1_ARMED
			log_guard arm fallback-partition2-once
		fi
		;;
	promote)
		if healthy; then
			/bin/bcm_bootstate "$CANDIDATE_STATE" >/dev/null || exit 1
			set_state PROMOTED_UI_NVRAM_PART1
			log_guard promote health-pass
			exit 0
		fi
		if is_candidate_identity; then
			/bin/bcm_bootstate "$FALLBACK_STATE" >/dev/null || exit 1
			set_state HEALTH_FAIL_FALLBACK_PART2
			log_guard rollback health-fail-auto-reboot
			sync
			(sleep 2; /sbin/reboot) >/dev/null 2>&1 &
		fi
		exit 1
		;;
	*)
		exit 2
		;;
esac

exit 0
