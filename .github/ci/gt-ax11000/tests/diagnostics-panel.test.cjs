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
async function harness(data, options = {}) {
  const elements = new Map();
  const timers = new Map();
  let next = 1;
  const state = {now:0, hidden:!!options.hidden, data};
  const context = {
    document: {get hidden(){return state.hidden;}, getElementById(id) {if (!elements.has(id)) elements.set(id,new Element()); return elements.get(id);}, createElement(){return new Element();}},
    performance:{now:()=>state.now}, Date, AbortController,
    setTimeout(callback, delay){const id=next++; timers.set(id,{callback,delay}); return id;},
    clearTimeout(id){timers.delete(id);},
    fetch:async url => ({ok:true,status:200,text:async()=> url.includes("ping.json") ? '{"ok":true}' : options.login ? '<html>login</html>' : JSON.stringify(state.data)})
  };
  vm.runInNewContext(source, context);
  async function settle(){for(let i=0;i<20;i++) await Promise.resolve();}
  await settle();
  return {state,elements,async tick(now){state.now=now; const entry=[...timers].find(([,t])=>t.delay<=1000); assert.ok(entry); timers.delete(entry[0]); entry[1].callback(); await settle();}};
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
  assert.match(h.elements.get("state").textContent,/Keine gültigen Messwerte/);
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
