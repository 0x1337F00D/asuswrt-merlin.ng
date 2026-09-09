"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");
const source = fs.readFileSync(path.join(__dirname, "../diagnostics/panel.js"), "utf8");
class Element {
  constructor() { this.textContent = ""; this.children = []; this.className = ""; }
  replaceChildren() { this.children = []; }
  appendChild(child) { this.children.push(child); }
  addEventListener() {}
}
function status() {
  const target = {ip:"192.0.2.1", last_ms:15, replies:20, misses:0, unknown:0, mean_ms:15, p95_ms:20, max_ms:23, rtt_variation_ms:2, max_miss_streak:0};
  return {schema:1, sequence:20, epoch_ms:100000, window_samples:20, interface:"eth0", targets:[{...target},{...target},{...target}], events:[]};
}
function wifiStatus() {
  return {schema:1,sequence:1,epoch_ms:Date.now(),target_ip:"192.168.0.236",finished:false,all_profile:true,bsd_running:false,roamast_running:false,
    points:[{epoch_ms:Date.now(),band:1,state:"associated",channel:"64/160",rssi:-87,power_save:false,retry_delta:3,ping_ms:2.8,span_ms:40}],events:["Sep  9 13:01:08 eth7 ReAssoc"]};
}
async function harness(data, options = {}) {
  const elements = new Map();
  const timers = new Map();
  let next = 1;
  const state = {now:0, hidden:!!options.hidden, data};
  const listeners = new Map();
  const context = {
    document: {get hidden(){return state.hidden;}, addEventListener(name, callback){listeners.set(name,callback);}, getElementById(id) {if (!elements.has(id)) elements.set(id,new Element()); return elements.get(id);}, createElement(){return new Element();}},
    performance:{now:()=>state.now}, Date, AbortController,
    setTimeout(callback, delay){const id=next++; timers.set(id,{callback,delay}); return id;},
    clearTimeout(id){timers.delete(id);},
    fetch:options.fetch || (async url => ({ok:true,status:200,text:async()=> url.includes("ping.json") ? '{"ok":true}' : options.login ? '<html>login</html>' : JSON.stringify(url.includes("wifi.json") ? options.wifi || wifiStatus() : state.data)}))
  };
  vm.runInNewContext(source, context);
  async function settle(){for(let i=0;i<20;i++) await Promise.resolve();}
  await settle();
  return {state,elements,
    async visibility(hidden){state.hidden=hidden; listeners.get("visibilitychange")(); await settle();},
    async deadlines(){for(const [id,t] of [...timers]) {if(t.delay===1800){timers.delete(id); t.callback();}} await settle();},
    async tick(now){state.now=now; const entry=[...timers].find(([,t])=>t.delay<=1000); assert.ok(entry); timers.delete(entry[0]); entry[1].callback(); await settle();}};
}
test("renders real values without zeros for missing probes", async()=>{
  const data=status(); data.targets[0].last_ms=null; data.targets[0].mean_ms=null;
  const h=await harness(data);
  assert.match(h.elements.get("state").textContent,/Messung aktiv/);
  assert.equal(h.elements.get("targets").children[0].children[1].textContent,"unbekannt");
  assert.equal(h.elements.get("targets").children[0].children[2].textContent,"unbekannt");
});
test("login redirect is not presented as successful WAN telemetry",async()=>{
  const h=await harness(status(),{login:true});
  assert.match(h.elements.get("state").textContent,/Anmeldeseite/);
});
test("realistic login page is recognized even for the 128-byte ping endpoint",async()=>{
  const body='<html>'+" ".repeat(512)+'<script>location.href="/Main_Login.asp";</script></html>';
  const h=await harness(status(),{fetch:async()=>({ok:true,status:200,text:async()=>body})});
  assert.match(h.elements.get("local").textContent,/Anmeldeseite/);
});
test("login-like text inside oversized JSON does not bypass payload limits",async()=>{
  const body=JSON.stringify({ok:true,text:"Main_Login.asp".repeat(2000)});
  const h=await harness(status(),{fetch:async()=>({ok:true,status:200,text:async()=>body})});
  assert.match(h.elements.get("local").textContent,/Größenlimit/);
});
function aborted(signal) {
  return new Promise((_,reject)=>signal.addEventListener("abort",()=>reject(new Error("signal is aborted without reason")),{once:true}));
}
for (const phase of ["headers", "body"]) test("classifies own timeout during " + phase + " without blaming login",async()=>{
  const h=await harness(status(),{fetch:async(_, {signal})=> phase==="headers" ? aborted(signal) : {ok:true,status:200,text:()=>aborted(signal)}});
  await h.deadlines();
  assert.match(h.elements.get("local").textContent,/HTTP-Zeitlimit \(1800 ms\)/);
  assert.match(h.elements.get("state").textContent,/letzten erfolgreichen Abfrage/);
  assert.doesNotMatch(h.elements.get("state").textContent,/Anmeldung|signal is aborted/);
});
test("hidden in-flight requests become a measurement pause, not an outage",async()=>{
  const h=await harness(status(),{fetch:async(_, {signal})=>aborted(signal)});
  await h.visibility(true);
  assert.match(h.elements.get("local").textContent,/pausiert/);
  assert.equal(h.elements.get("local-events"),undefined);
});
for (const code of [401,403,500]) test("distinguishes HTTP " + code,async()=>{
  const h=await harness(status(),{fetch:async()=>({ok:false,status:code})});
  assert.match(h.elements.get("local").textContent,code===500 ? /Router-Webserver: HTTP 500/ : /Anmeldung erforderlich/);
});
for (const body of ["<html>maintenance</html>", "{invalid", "{".repeat(20001)]) test("bad payload is not a login diagnosis: " + body.slice(0,20),async()=>{
  const h=await harness(status(),{fetch:async()=>({ok:true,status:200,text:async()=>body})});
  assert.match(h.elements.get("local").textContent,/Ungültig|Größenlimit/);
  assert.doesNotMatch(h.elements.get("local").textContent,/Anmeldung/);
});
test("network error is not presented as proven loss or login failure",async()=>{
  const h=await harness(status(),{fetch:async()=>{throw new TypeError("Failed to fetch");}});
  assert.match(h.elements.get("local").textContent,/Ursache|kein Nachweis/);
  assert.doesNotMatch(h.elements.get("local").textContent,/Anmeldung prüfen/);
});
test("repeated sequence becomes stale, hidden tab does not count as outage",async()=>{
  const h=await harness(status());
  for(const now of [1000,2000,3000,4000,5000]) await h.tick(now);
  assert.match(h.elements.get("state").textContent,/veraltet/);
  h.state.hidden=true; await h.tick(6000);
  h.state.hidden=false; await h.tick(7000);
  assert.match(h.elements.get("local-events").children[0].textContent,/nicht als Netzausfall/);
});
test("response strings stay text; no HTML injection sink",async()=>{
  const data=status(); data.targets[0].ip='<img src=x onerror=alert(1)>';
  const h=await harness(data);
  assert.match(h.elements.get("targets").children[0].children[0].textContent,/<img/);
  assert.doesNotMatch(source,/\.innerHTML|\beval\(|new Function/);
  assert.doesNotMatch(source,/https?:\/\//);
});
test("shows actual stopped steering daemons under ALL, not configured Smart Connect",async()=>{
  const h=await harness(status());
  assert.match(h.elements.get("wifi-state").textContent,/ALL bestätigt · bsd gestoppt · roamast gestoppt/);
  assert.equal(h.elements.get("wifi-points").children[0].children[1].textContent,"5 GHz-1");
  assert.equal(h.elements.get("wifi-points").children[0].children[3].textContent,"-87 dBm");
});
test("completed Wi-Fi experiment stays marked completed",async()=>{
  const data=wifiStatus();data.finished=true;
  const h=await harness(status(),{wifi:data});
  assert.match(h.elements.get("wifi-state").textContent,/beendet\/veraltet/);
});
test("unknown or overlapping association is not a confirmed band",async()=>{
  const data=wifiStatus();data.points[0].state="overlap";
  data.events=['<img src=x onerror=alert(1)>'];
  const h=await harness(status(),{wifi:data});
  assert.equal(h.elements.get("wifi-points").children[0].children[1].textContent,"mehrere Bänder gemeldet");
  assert.equal(h.elements.get("wifi-events").children[0].children[0].textContent,data.events[0]);
});
