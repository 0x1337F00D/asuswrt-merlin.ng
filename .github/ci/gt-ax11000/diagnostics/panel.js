/* Local-only, bounded read-only dashboard. Never insert response text as HTML. */
"use strict";
(() => {
  const el = id => document.getElementById(id);
  const ms = value => Number.isFinite(value) && value >= 0 ? value.toFixed(1) + " ms" : value === -1 ? "keine Antwort" : "unbekannt";
  const names = ["WAN-Gateway", "Cloudflare", "Google"];
  let sequence = null, lastChange = 0, lastCycle = performance.now(), paused = document.hidden;
  let localEvents = [];
  function localEvent(message) {
    localEvents.unshift(new Date().toLocaleTimeString() + " · " + message);
    localEvents = localEvents.slice(0, 30);
    const list = el("local-events");
    list.replaceChildren();
    for (const message of localEvents) {
      const row = document.createElement("li"); row.textContent = message; list.appendChild(row);
    }
  }
  function table(id, rows) {
    const body = el(id); body.replaceChildren();
    for (const values of rows) {
      const row = document.createElement("tr");
      for (const value of values) { const cell = document.createElement("td"); cell.textContent = String(value); row.appendChild(cell); }
      body.appendChild(row);
    }
  }
  async function get(path, maxBytes) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1800);
    try {
      const response = await fetch(path + "?t=" + Date.now(), {cache:"no-store", credentials:"same-origin", signal:controller.signal, redirect:"error"});
      if (!response.ok) throw new Error("HTTP " + response.status);
      const text = await response.text();
      if (text.length > maxBytes || !text.trimStart().startsWith("{")) throw new Error("Anmeldung prüfen oder ungültige Messdaten");
      return JSON.parse(text);
    } finally { clearTimeout(timeout); }
  }
  function render(data, now) {
    if (data.schema !== 1 || !Number.isSafeInteger(data.sequence) || !Array.isArray(data.targets) || data.targets.length !== 3 || !Array.isArray(data.events) || data.events.length > 30) throw new Error("Ungültiges Messformat");
    if (sequence !== data.sequence) { sequence = data.sequence; lastChange = now; }
    const stale = now - lastChange > 4000;
    el("state").textContent = stale ? "Messwerte veraltet – Sammler möglicherweise gestoppt. Kein Nachweis eines Internetausfalls." : "Messung aktiv · keine automatischen Eingriffe";
    el("state").className = stale ? "warn" : "good";
    el("updated").textContent = new Date(data.epoch_ms).toLocaleTimeString();
    table("targets", data.targets.map((target, index) => {
      const total = target.replies + target.misses;
      const loss = total > 0 ? target.misses + "/" + total + " (" + (100 * target.misses / total).toFixed(1) + " %)" : "noch keine verwertbaren Proben";
      return [names[index] + " · " + (target.ip || "nicht verfügbar"), ms(target.last_ms), ms(target.mean_ms), ms(target.p95_ms), ms(target.max_ms), ms(target.rtt_variation_ms), loss, target.unknown];
    }));
    el("coverage").textContent = data.window_samples + " Messrunden · 1 Probe/Ziel/Sekunde · WAN: " + data.interface + " · unbekannte Werte sind nicht als Verlust gerechnet.";
    table("events", data.events.length ? data.events.map(event => [new Date(event.epoch_ms).toLocaleTimeString(), ...event.rtt.map(ms), event.lag_ms + " ms"]) : [["Noch keine Auffälligkeiten im Messfenster.", "", "", "", ""]]);
    const externalMisses = data.targets.slice(1).filter(target => target.last_ms === -1).length;
    el("interpretation").textContent = stale ? "Bitte Collector-Status prüfen; alte Daten erlauben keine aktuelle Netzdiagnose." : externalMisses === 2 ? "Beide externen ICMP-Ziele antworten derzeit nicht. WAN/Upstream oder Router-Last prüfen; ICMP allein beweist keinen Totalausfall." : "Für WLAN-Aussetzer diese Seite direkt auf dem betroffenen Handy oder Tablet geöffnet lassen.";
  }
  async function cycle() {
    const begin = performance.now();
    if (document.hidden) { paused = true; lastCycle = begin; setTimeout(cycle, 1000); return; }
    const gap = begin - lastCycle > 3000;
    if (paused || gap) { localEvent("Browser-Messpause/Timer-Verzug – nicht als Netzausfall gewertet"); lastChange = begin; }
    const ignoreTiming = paused || gap;
    paused = false; lastCycle = begin;
    // Run both independently: a slow WAN snapshot does not block LAN timing.
    const probe = (async () => {
      const start = performance.now();
      try {
        const result = await get("/ext/link-health/ping.json", 128);
        if (result.ok !== true) throw new Error("ungültige Probe");
        const elapsed = performance.now() - start;
        el("local").textContent = ms(elapsed);
        if (!ignoreTiming && !document.hidden && elapsed > 100) localEvent("Browser → Router " + ms(elapsed) + " (inkl. HTTP/Browser)");
      } catch (error) {
        el("local").textContent = "nicht messbar / Anmeldung prüfen";
        if (!ignoreTiming && !document.hidden) localEvent("Lokale Anfrage fehlgeschlagen: " + error.message);
      }
    })();
    const status = (async () => {
      try { render(await get("/ext/link-health/status.json", 20000), performance.now()); }
      catch (error) { el("state").textContent = "Keine gültigen Messwerte: " + error.message; el("state").className = "warn"; }
    })();
    await Promise.allSettled([probe, status]);
    setTimeout(cycle, Math.max(100, 1000 - (performance.now() - begin)));
  }
  el("clear").addEventListener("click", () => { localEvents = []; el("local-events").replaceChildren(); });
  cycle();
})();
