#!/bin/sh
set -eu

rootfs=${1:?rootfs path required}

if [ ! -d "$rootfs" ]; then
	echo "rootfs does not exist: $rootfs" >&2
	exit 2
fi

for path in \
	usr/bwdpi \
	usr/sbin/wred \
	usr/sbin/wred_set_conf \
	usr/sbin/wred_set_wbl \
	usr/sbin/dcd \
	usr/sbin/tcd \
	usr/sbin/shn_ctrl \
	usr/sbin/tdts_rule_agent \
	usr/sbin/sample.bin \
	sbin/bwdpi \
	sbin/bwdpi_check \
	sbin/bwdpi_wred_alive \
	sbin/bwdpi_db_10 \
	www/mobile/pages/tmtos_page.html; do
	if [ -e "$rootfs/$path" ] || [ -L "$rootfs/$path" ]; then
		echo "proprietary QoS/DPI rootfs artifact remains: /$path" >&2
		exit 1
	fi
done

for library in $(find "$rootfs/lib" "$rootfs/usr/lib" -maxdepth 1 \
	\( -name 'libbwdpi*.so*' -o -name 'libshn*.so*' -o -name 'libtdts*.so*' \) \
	-print 2>/dev/null); do
	if [ "$library" != "$rootfs/usr/lib/libbwdpi.so" ]; then
		echo "proprietary QoS/DPI library remains in rootfs: $library" >&2
		exit 1
	fi
done

for path in \
	www/QoS_EZQoS.asp \
	www/client_function.js \
	usr/sbin/httpd \
	usr/sbin/networkmap \
	usr/lib/libbwdpi.so \
	sbin/rc; do
	if [ ! -f "$rootfs/$path" ]; then
		echo "required local QoS/client-view artifact is missing: /$path" >&2
		exit 1
	fi
done

# ASUS provides Network Map only as a prebuilt binary with an unconditional
# libbwdpi DT_NEEDED entry. The sole library bearing that ABI name must be our
# three-symbol fail-closed Rust shim, never the Trend Micro implementation.
for symbol in check_bwdpi_nvram_setting bwdpi_client_info rust_bwdpi_compat_v1; do
	if ! readelf -Ws "$rootfs/usr/lib/libbwdpi.so" | grep -Eq "[[:space:]]${symbol}$"; then
		echo "local Rust Network Map compatibility symbol is missing: $symbol" >&2
		exit 1
	fi
done
if ! readelf -d "$rootfs/usr/lib/libbwdpi.so" | grep -Fq 'Library soname: [libbwdpi.so]' ||
   grep -Eiq 'Trend Micro|Deep Packet Inspection|tdts' "$rootfs/usr/lib/libbwdpi.so"; then
	echo "libbwdpi ABI provider is not the bounded local compatibility shim" >&2
	exit 1
fi

if ! grep -Fq 'Array.isArray(originData.fromNetworkmapd[0].maclist)' \
	"$rootfs/www/client_function.js"; then
	echo "rootfs client list lacks fail-soft hook handling" >&2
	exit 1
fi

if ! grep -Fq 'value !== "0" && value !== "2"' "$rootfs/www/QoS_EZQoS.asp" ||
   ! grep -Fq 'style="display:none;" type="radio" disabled' "$rootfs/www/QoS_EZQoS.asp"; then
	echo "rootfs QoS UI can expose a proprietary or unknown QoS mode" >&2
	exit 1
fi

echo "proprietary QoS/DPI exclusion and local Network Map ABI verified"
