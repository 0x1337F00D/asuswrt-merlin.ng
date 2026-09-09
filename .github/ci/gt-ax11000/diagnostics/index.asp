<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Cache-Control" content="no-store">
<title>Verbindungsdiagnose · GT-AX11000</title>
<style>
:root{color-scheme:dark;font:16px system-ui,sans-serif;background:#17212c;color:#e7edf3}body{max-width:1080px;margin:28px auto;padding:0 18px}a{color:#90d8fa}h1{font-size:1.8rem;margin-bottom:8px}h2{font-size:1.2rem}p{line-height:1.55}.muted{color:#b0bcc9}.card{background:#22303f;border:1px solid #3a4d60;border-radius:10px;padding:18px;margin:18px 0}.good{color:#98e5b9}.warn{color:#ffcf87}.bad{color:#ff9999}table{border-collapse:collapse;width:100%;font-size:.92rem}th,td{text-align:left;padding:10px 8px;border-bottom:1px solid #405064}th{color:#b8cad9}.scroll{overflow:auto}button{background:#32485e;color:inherit;border:1px solid #667d90;border-radius:6px;padding:8px 12px;cursor:pointer}#local-events li{margin:8px 0;font-family:monospace}.pill{display:inline-block;margin-right:18px}code{font-size:.9em}
</style>
</head>
<body>
<a href="/index.asp">← Router-Übersicht</a>
<h1>Verbindungsdiagnose</h1>
<p class="muted">WLAN/LAN und Internet getrennt beobachten. Die Messung verändert keine Funk-, VPN- oder Firewall-Einstellungen.</p>
<section class="card" aria-live="polite">
<div id="state">Messwerte werden geladen …</div>
<p><span class="pill">Browser → Router: <strong id="local">noch keine Messung</strong></span><span class="pill">Letzte Aktualisierung: <span id="updated">–</span></span></p>
<div id="interpretation" class="muted">Für WLAN-Aussetzer diese Seite direkt auf dem betroffenen Handy oder Tablet geöffnet lassen.</div>
</section>
<section class="card">
<h2>Router → Internet · letzte maximal 10 Minuten</h2>
<div class="scroll"><table><thead><tr><th>Ziel</th><th>Aktuell</th><th>Mittel</th><th>p95</th><th>Maximum</th><th>RTT-Schwankung</th><th>Keine Antwort</th><th>Unbekannt</th></tr></thead><tbody id="targets"></tbody></table></div>
<p class="muted" id="coverage">–</p>
</section>
<section class="card">
<h2>Auffällige Internet-Messpunkte</h2>
<p class="muted">Letzte 30 Messpunkte mit fehlender ICMP-Antwort, &gt;100 ms RTT oder verspäteter Messung. Mehrere fehlende Antworten sind ein Indiz, kein Beweis für einen Leitungsausfall.</p>
<div class="scroll"><table><thead><tr><th>Zeit</th><th>Gateway</th><th>Cloudflare</th><th>Google</th><th>Sampler-Verzug</th></tr></thead><tbody id="events"></tbody></table></div>
</section>
<section class="card">
<h2>Lokale Browser-Messung</h2>
<p class="muted">Letzte 30 Auffälligkeiten nur in diesem Tab. Ein gesperrtes Gerät oder ein Hintergrund-Tab pausiert die Messung; das zählt nicht als Netzausfall.</p>
<button id="clear" type="button">Lokale Ereignisse leeren</button>
<ul id="local-events"><li>Noch keine Auffälligkeiten.</li></ul>
</section>
<details class="card"><summary>Was wird gemessen – und was nicht?</summary>
<p>Drei kleine ICMP-Anfragen pro Sekunde: WAN-Gateway, 1.1.1.1 und 8.8.8.8. Sie gehen ausdrücklich über die WAN-Schnittstelle, auch wenn ein VPN eingerichtet ist. Es werden keine Nutzdaten übertragen. Der Router hält maximal 600 Messpunkte im RAM; keine Historie im Flash und keine Cloud-Telemetrie. Die öffentlichen Ziele sehen wie bei jedem Ping deine öffentliche IP.</p>
<p>„RTT-Schwankung“ ist die mittlere absolute Differenz aufeinanderfolgender Ping-Laufzeiten, nicht der RTP-Jitter eines Telefonats. ICMP kann gefiltert oder nachrangig beantwortet werden. DNS, Paketverlust innerhalb eines VPNs und einzelne Gesprächsserver sind damit nicht geprüft.</p>
<p>Ist nur die Browser-Strecke auffällig, kommen WLAN/LAN, das Endgerät oder der Webserver infrage. Sind mehrere externe Ziele gleichzeitig auffällig, spricht das eher für WAN/Upstream oder Last im Router. Ein einzelnes Ziel reicht nicht zur Schuldzuweisung. Sehr kurze Aussetzer unter einer Sekunde können zwischen Messpunkten liegen.</p>
<p>Die Seite fragt ausschließlich den bereits geschützten Router-Webserver ab. Es gibt keinen zusätzlichen offenen Port. Die Diagnose führt keine automatischen Neustarts oder Reparaturen aus.</p>
</details>
<script src="/ext/link-health/panel.js"></script>
</body>
</html>
