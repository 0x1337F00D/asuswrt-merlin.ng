#!/usr/bin/env python3
"""Real Chromium render, loopback fixtures only; profile/screenshot in tmpfs.

This is deliberately NOT an authenticated live-router browser test.
"""
import argparse
import http.server
import json
from pathlib import Path
import subprocess
import tempfile
import threading


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--chromium", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1] / "diagnostics"
    output = Path(args.output).resolve()
    if not str(output).startswith("/tmp/"):
        parser.error("output must be a /tmp RAM directory")
    output.mkdir(mode=0o700, exist_ok=True)
    assert subprocess.check_output(["findmnt", "-n", "-o", "FSTYPE", "-T", str(output)], text=True).strip() == "tmpfs"
    target = dict(ip="192.0.2.1", last_ms=15.5, replies=599, misses=1, unknown=0,
                  mean_ms=16.2, p95_ms=24.0, max_ms=142.2, rtt_variation_ms=3.1, max_miss_streak=1)
    data = dict(schema=1, sequence=600, epoch_ms=1788945916101, window_samples=600,
                interface="eth0", targets=[target, target, target],
                events=[dict(epoch_ms=1788945906101, lag_ms=0, rtt=[10.0, -1, 142.2])])

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            name = self.path.split("?", 1)[0].rsplit("/", 1)[-1]
            types = {"index.asp": "text/html", "panel.js": "text/javascript", "ping.json": "application/json"}
            if name == "wifi.json":
                body = json.dumps(dict(schema=1, sequence=1, epoch_ms=1788945916101, target_ip="192.168.0.236", finished=True,
                    all_profile=True, bsd_running=False, roamast_running=False,
                    points=[dict(epoch_ms=1788945916101, state="associated", band=1, channel="64/160", rssi=-87, power_save=False, retry_delta=3, ping_ms=2.8, span_ms=40)],
                    events=["Sep  9 13:01:08 eth7 ReAssoc"])).encode()
                mime = "application/json"
            elif name == "status.json":
                body = json.dumps(data).encode()
                mime = "application/json"
            elif name in types:
                body = (root / name).read_bytes()
                mime = types[name]
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", mime + "; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix="chromium-", dir=output) as profile:
            result = subprocess.run([
                args.chromium, "--headless", "--no-sandbox", "--disable-gpu",
                "--disable-background-networking", "--disable-extensions",
                "--no-first-run", "--no-default-browser-check", "--disable-sync",
                "--disable-breakpad", "--disable-dev-shm-usage",
                "--user-data-dir=" + profile, "--window-size=1365,1100",
                "--virtual-time-budget=2500", "--dump-dom",
                "--screenshot=" + str(output / "panel.png"),
                f"http://127.0.0.1:{server.server_port}/ext/link-health/index.asp",
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=35)
            if result.returncode:
                raise RuntimeError(result.stderr[-3000:])
            (output / "rendered.html").write_text(result.stdout)
            assert 'id="state" class="good">Messung aktiv' in result.stdout
            assert "600 Messrunden" in result.stdout
            assert "15.5 ms" in result.stdout
            assert "ALL bestätigt · bsd gestoppt · roamast gestoppt" in result.stdout
            assert "-87 dBm" in result.stdout
            assert "keine Antwort" in result.stdout
            assert "unbekannt" not in result.stdout.split('<tbody id="targets">')[1].split('</tbody>')[0]
            print("BROWSER_FIXTURE=PASS screenshot=" + str(output / "panel.png"))
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
