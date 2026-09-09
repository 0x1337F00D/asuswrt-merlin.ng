#!/bin/sh
# First installation only. Compare-and-swap services-start; back up before edit.
# No firmware flash, reboot, firewall/WLAN action, NVRAM set or NVRAM commit.
set -eu
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
umask 077
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
destination=/jffs/addons/link-health
hook=/jffs/scripts/services-start
: "${EXPECTED_SERVICES_SHA256:?Provide the previously inspected services-start SHA-256}"
[ "$(nvram get productid)" = GT-AX11000 ]
[ ! -e "$destination" ] && [ ! -L "$destination" ]
[ -f "$hook" ] && [ ! -L "$hook" ]
[ "$(head -n 1 "$hook")" = '#!/bin/sh' ]
[ "$(openssl dgst -sha256 "$hook" | awk '{print $NF}')" = "$EXPECTED_SERVICES_SHA256" ]
for file in link-health wifi-observe vpn-policy-audit index.asp panel.js ping.json control.sh install.sh update-panel.sh; do
    [ -f "$source_dir/$file" ] && [ ! -L "$source_dir/$file" ]
    expected=$(awk -v name="$file" '$2 == name {print $1}' "$source_dir/SHA256SUMS")
    [ "$(openssl dgst -sha256 "$source_dir/$file" | awk '{print $NF}')" = "$expected" ]
done
mkdir -m 700 "$destination"
for file in link-health wifi-observe vpn-policy-audit index.asp panel.js ping.json control.sh install.sh update-panel.sh SHA256SUMS; do
    cp "$source_dir/$file" "$destination/$file"
done
chmod 700 "$destination/control.sh" "$destination/link-health" "$destination/wifi-observe" "$destination/vpn-policy-audit"
cp -p "$hook" "$destination/services-start.before"
temporary_dir=/jffs/scripts/.link-health-stage.$$
mkdir -m 700 "$temporary_dir"
temporary=$temporary_dir/services-start
trap 'rm -f "$temporary"; rmdir "$temporary_dir"' EXIT HUP INT TERM
awk 'NR==1 {print; print "sh /jffs/addons/link-health/control.sh start >/tmp/link-health-start.log 2>&1 & # link-health-bootstrap"; next} {print}' "$hook" > "$temporary"
sh -n "$temporary"
chmod 755 "$temporary"
[ "$(openssl dgst -sha256 "$hook" | awk '{print $NF}')" = "$EXPECTED_SERVICES_SHA256" ]
mv "$temporary" "$hook"
rmdir "$temporary_dir"
trap - EXIT HUP INT TERM
sh "$destination/control.sh" stop
sh "$destination/control.sh" start
echo 'Installed; original services-start is backed up privately inside the add-on directory.'
