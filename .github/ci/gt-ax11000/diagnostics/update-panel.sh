#!/bin/sh
# Hot update of static UI + an INACTIVE finite observer only. No collector,
# firmware, NVRAM, startup hook, WLAN or other network-service changes.
set -eu
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
umask 077
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
destination=/jffs/addons/link-health
web=/tmp/var/wwwext/link-health
: "${EXPECTED_PANEL_SHA256:?Inspect installed and RAM panel before updating}"
: "${EXPECTED_INDEX_SHA256:?Inspect installed and RAM index before updating}"
: "${EXPECTED_MANIFEST_SHA256:?Inspect installed manifest before updating}"
[ "$(nvram get productid)" = GT-AX11000 ]
[ "$(nvram get location_code)" = ALL ]
[ -d "$destination" ] && [ ! -L "$destination" ]
[ -d "$web" ] && [ ! -L "$web" ]
[ ! -e /tmp/link-health-wifi-runtime ] && [ ! -L /tmp/link-health-wifi-runtime ]
[ -z "$(pidof wifi-observe || true)" ]
hash() { openssl dgst -sha256 "$1" | awk '{print $NF}'; }
old_files_match() {
    for dir in "$destination" "$web"; do
        [ -f "$dir/panel.js" ] && [ ! -L "$dir/panel.js" ]
        [ -f "$dir/index.asp" ] && [ ! -L "$dir/index.asp" ]
        [ "$(hash "$dir/panel.js")" = "$EXPECTED_PANEL_SHA256" ]
        [ "$(hash "$dir/index.asp")" = "$EXPECTED_INDEX_SHA256" ]
    done
    [ -f "$destination/SHA256SUMS" ] && [ ! -L "$destination/SHA256SUMS" ]
    [ "$(hash "$destination/SHA256SUMS")" = "$EXPECTED_MANIFEST_SHA256" ]
    if [ -n "${EXPECTED_OBSERVER_SHA256:-}" ]; then
        [ -f "$destination/wifi-observe" ] && [ ! -L "$destination/wifi-observe" ]
        [ "$(hash "$destination/wifi-observe")" = "$EXPECTED_OBSERVER_SHA256" ]
    else
        [ ! -e "$destination/wifi-observe" ] && [ ! -L "$destination/wifi-observe" ]
    fi
}
old_files_match
for file in panel.js index.asp wifi-observe; do
    [ -f "$source_dir/$file" ] && [ ! -L "$source_dir/$file" ]
    expected=$(awk -v name="$file" '$2 == name {print $1}' "$source_dir/SHA256SUMS")
    [ "${#expected}" = 64 ] && [ "$(hash "$source_dir/$file")" = "$expected" ]
done
backup="$destination/panel-before-$(date +%Y%m%dT%H%M%S)-$$"
mkdir -m 700 "$backup"
for file in panel.js index.asp SHA256SUMS; do cp -p "$destination/$file" "$backup/$file"; done
if [ -n "${EXPECTED_OBSERVER_SHA256:-}" ]; then cp -p "$destination/wifi-observe" "$backup/wifi-observe"; fi
for file in panel.js index.asp wifi-observe; do cp "$source_dir/$file" "$backup/$file.new"; done
chmod 700 "$backup/wifi-observe.new"
old_files_match
# Backup is deliberately retained even if deployment fails. No auto-start.
for file in panel.js index.asp wifi-observe; do mv "$backup/$file.new" "$destination/$file"; done
for file in panel.js index.asp; do
    cp "$destination/$file" "$web/.$file.update.$$"
    mv "$web/.$file.update.$$" "$web/$file"
done
for file in link-health vpn-policy-audit wifi-observe index.asp panel.js ping.json control.sh install.sh; do
    printf '%s  %s\n' "$(hash "$destination/$file")" "$file"
done > "$backup/SHA256SUMS.new"
mv "$backup/SHA256SUMS.new" "$destination/SHA256SUMS"
for file in panel.js index.asp; do [ "$(hash "$destination/$file")" = "$(hash "$web/$file")" ]; done
echo "Panel updated; observer NOT started. Recovery copy: $backup"
