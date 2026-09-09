/* Local-only, bounded read-only dashboard. Never insert response text as HTML. */
"use strict";
(() => {
  const el = id => document.getElementById(id);
  const ms = value => Number.isFinite(value) && value >= 0 ? value.toFixed(1) + " ms" : value === -1 ? "keine Antwort" : "unbekannt";
  const names = ["WAN-Gateway", "Cloudflare", "Google"];
  const deadlineMs = 1800;
  const pending = new Set();
  class ProbeError extends Error {
    constructor(kind, message) { super(message); this.kind = kind; }
  }
  let sequence = null, lastChange = 0, lastCycle = performance.now(), paused = document.hidden;
  let localEvents = [];
  let wifiPoll = -5000, wifiSequence = null, wifiChange = 0;
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
    const request = {controller, timedOut:false, paused:false};
    pending.add(request);
    const timeout = setTimeout(() => { request.timedOut = true; controller.abort(); }, deadlineMs);
    try {
      const response = await fetch(path + "?t=" + Date.now(), {cache:"no-store", credentials:"same-origin", signal:controller.signal, redirect:"error"});
      if (response.status === 401 || response.status === 403) throw new ProbeError("auth", "Anmeldung erforderlich (HTTP " + response.status + ")");
      if (!response.ok) throw new ProbeError("http", "Router-Webserver: HTTP " + response.status);
      const text = await response.text();
      // The real login page exceeds the tiny ping payload limit. Recognize
      // only non-JSON login responses before applying the endpoint's limit.
      if (!text.trimStart().startsWith("{") && /Main_Login\.asp|login_authorization|<html>login<\/html>/i.test(text.slice(0, 20000))) throw new ProbeError("auth", "Router liefert die Anmeldeseite – bitte erneut anmelden");
      if (text.length > maxBytes) throw new ProbeError("data", "Messantwort überschreitet das Größenlimit");
      if (!text.trimStart().startsWith("{")) {
        throw new ProbeError("data", "Ungültige Messantwort (kein JSON)");
      }
      try { return JSON.parse(text); }
      catch (_) { throw new ProbeError("data", "Ungültige JSON-Messdaten"); }
    } catch (error) {
      if (request.paused || document.hidden) throw new ProbeError("paused", "Browser-Messung pausiert");
      if (request.timedOut) throw new ProbeError("timeout", "HTTP-Zeitlimit nach " + deadlineMs + " ms; Ursache offen (WLAN/LAN, Browser oder Webserver)");
      if (error instanceof ProbeError) throw error;
      throw new ProbeError("network", "HTTP-Anfrage abgebrochen oder nicht erreichbar; kein Nachweis eines Anmelde- oder Internetausfalls");
    } finally { clearTimeout(timeout); pending.delete(request); }
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
  function renderWifi(data, now) {
    if (data.schema !== 1 || !Number.isSafeInteger(data.sequence) || !Array.isArray(data.points) || data.points.length > 60 || !Array.isArray(data.events) || data.events.length > 30) throw new ProbeError("data", "Ungültige WLAN-Messdaten");
    if (wifiSequence !== data.sequence) { wifiSequence = data.sequence; wifiChange = now; }
    const stale = data.finished === true || now - wifiChange > 6000 || Date.now() - data.epoch_ms > 15000;
    const service = value => value === true ? "läuft" : value === false ? "gestoppt" : "unbekannt";
    el("wifi-state").textContent = "Client " + data.target_ip + " · " + (data.all_profile === true ? "ALL bestätigt" : "Profil unbestätigt") + " · bsd " + service(data.bsd_running) + " · roamast " + service(data.roamast_running) + " · " + (stale ? "Beobachtung beendet/veraltet" : "Beobachtung aktiv") + " (Dienststatus bis zu 10 s alt)";
    el("wifi-state").className = stale ? "warn" : "good";
    const bands = ["2,4 GHz", "5 GHz-1", "5 GHz-2"];
    table("wifi-points", data.points.slice(-30).reverse().map(p => [new Date(p.epoch_ms).toLocaleTimeString(), p.state === "associated" && Number.isInteger(p.band) && p.band >= 0 && p.band <= 2 ? bands[p.band] : p.state === "not-associated" ? "nicht assoziiert" : p.state === "overlap" ? "mehrere Bänder gemeldet" : "unbekannt", p.channel || "–", Number.isFinite(p.rssi) ? p.rssi + " dBm" : "–", p.power_save === true ? "PS gemeldet" : p.power_save === false ? "kein PS gemeldet" : "unbekannt", ms(p.ping_ms), Number.isSafeInteger(p.retry_delta) && p.retry_delta >= 0 ? p.retry_delta : "–", p.span_ms + " ms"]));
    table("wifi-events", data.events.length ? data.events.slice().reverse().map(s => [s]) : [["Keine passenden Ereignisse im erfassten Log-Ausschnitt."]]);
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
        el("local").textContent = error.kind === "timeout" ? "HTTP-Zeitlimit (" + deadlineMs + " ms)" : error.message;
        if (!ignoreTiming && !document.hidden && error.kind !== "paused") localEvent("Lokale Anfrage fehlgeschlagen: " + error.message);
      }
    })();
    const status = (async () => {
      try { render(await get("/ext/link-health/status.json", 20000), performance.now()); }
      catch (error) {
        el("state").textContent = error.kind === "paused" ? error.message : "Keine aktuellen Messwerte: " + error.message + ". Angezeigte Internetwerte stammen aus der letzten erfolgreichen Abfrage.";
        el("state").className = "warn";
      }
    })();
    await Promise.allSettled([probe, status]);
    if (!document.hidden && el("wifi-state") && performance.now() - wifiPoll >= 5000) {
      wifiPoll = performance.now();
      try { renderWifi(await get("/ext/link-health/wifi.json", 40000), performance.now()); }
      catch (error) {
        el("wifi-state").textContent = error.message === "Router-Webserver: HTTP 404" ? "WLAN-Korrelation nicht gestartet (separater, zeitlich begrenzter Test)." : "Keine aktuellen WLAN-Korrelationsdaten: " + error.message;
        el("wifi-state").className = "warn";
      }
    }
    setTimeout(cycle, Math.max(100, 1000 - (performance.now() - begin)));
  }
  el("clear").addEventListener("click", () => { localEvents = []; el("local-events").replaceChildren(); });
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) return;
    paused = true;
    el("local").textContent = "Browser-Messung pausiert";
    el("state").textContent = "Browser-Messung pausiert – angezeigte Internetwerte werden nicht aktualisiert";
    el("state").className = "warn";
    for (const request of pending) { request.paused = true; request.controller.abort(); }
  });
  cycle();
})();
