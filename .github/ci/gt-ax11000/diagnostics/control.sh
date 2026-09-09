#!/bin/sh
# GT-AX11000 diagnostic add-on. No restart of networking; no NVRAM writes.
set -eu
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
umask 077
package=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
web=/tmp/var/wwwext/link-health
runtime=/tmp/link-health-runtime

case "${1:-}" in
start)
    [ "$(nvram get productid)" = GT-AX11000 ] || { echo 'Wrong router model' >&2; exit 1; }
    [ ! -e "$runtime" ] && [ ! -L "$runtime" ] || { echo 'Collector lock exists; inspect status first' >&2; exit 1; }
    [ ! -L "$web" ] || { echo 'Refusing symlink output directory' >&2; exit 1; }
    mkdir -p "$web"
    chmod 700 "$web"
    for name in index.asp panel.js ping.json; do
        [ -f "$package/$name" ] && [ ! -L "$package/$name" ]
        cp "$package/$name" "$web/.$name.new"
        mv "$web/.$name.new" "$web/$name"
    done
    [ -x "$package/link-health" ] && [ ! -L "$package/link-health" ]
    # Stdio explicitly detached so SSH closure cannot retain an output pipe.
    nohup "$package/link-health" --run </dev/null >/tmp/link-health.log 2>&1 &
    echo 'Collector starting. Panel: /ext/link-health/index.asp'
    ;;
stop)
    # Cooperative shutdown checks this marker once per bounded probe round.
    # No killall, PID reuse risk, service restart, or firewall action.
    [ -d "$runtime" ] && [ ! -L "$runtime" ] || exit 0
    : > "$runtime/stop"
    i=0
    while [ -d "$runtime" ] && [ "$i" -lt 5 ]; do sleep 1; i=$((i + 1)); done
    [ ! -d "$runtime" ] || { echo 'Stop not acknowledged; inspect collector, do not remove its lock blindly' >&2; exit 1; }
    echo 'Collector stopped. RAM history remains visible as stale until reboot.'
    ;;
status)
    if [ -f "$runtime/pid" ] && [ ! -L "$runtime/pid" ]; then
        read -r pid < "$runtime/pid"
        case "$pid" in ''|*[!0-9]*) exit 1 ;; esac
        if kill -0 "$pid" 2>/dev/null && [ "$(basename "$(readlink "/proc/$pid/exe")")" = link-health ]; then
            echo "Collector running: PID $pid"
            awk '/VmRSS|Threads/ {print}' "/proc/$pid/status"
        else
            echo 'Stale lock / collector unavailable' >&2; exit 1
        fi
    else
        echo 'Collector stopped'; exit 1
    fi
    ;;
audit)
    exec "$package/vpn-policy-audit" --check-live
    ;;
*) echo 'usage: control.sh start|stop|status|audit' >&2; exit 2 ;;
esac
