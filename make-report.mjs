// Turns a Tripwire JSON report into a standalone, shareable HTML test report.
// usage: node make-report.mjs report-deployed.json [out.html]
import { readFileSync, writeFileSync } from "node:fs";

const inFile = process.argv[2];
if (!inFile) { console.log("usage: node make-report.mjs report-<token>.json [out.html]"); process.exit(2); }
const r = JSON.parse(readFileSync(inFile, "utf8"));
const outFile = process.argv[3] || inFile.replace(/\.json$/, ".html");

const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const fnv = (s) => { let h = 2166136261; for (const c of s) { h ^= c.charCodeAt(0); h = Math.imul(h, 16777619); } return (h >>> 0).toString(16).toUpperCase().padStart(8, "0"); };

const attacks = r.attacks.filter((a) => !a.control);
const ctrl = r.attacks.find((a) => a.control);
const groups = {};
for (const a of attacks) (groups[a.rule] ||= []).push(a);
const rules = Object.entries(groups).map(([name, list]) => ({ name, list, bad: list.filter((a) => a.breach) }));
const held = rules.filter((g) => !g.bad.length).length;
const total = rules.length;
const ok = held === total && !(ctrl && ctrl.breach);
const serial = "TW-" + fnv(JSON.stringify(r.attacks.map((a) => [a.label, a.breach, a.tx]))).slice(0, 6);
const when = new Date().toISOString().replace("T", " ").slice(0, 16) + " UTC";
const t = r.rules || {};
const terms = [
  t.lockupDays && `Lock-up ${t.lockupDays} days`,
  t.accreditedOnly && "Accredited investors only",
  t.holderCap && `Holder cap ${t.holderCap}`,
  (t.blocked || []).length && `Blocked: ${t.blocked.join(", ")}`,
].filter(Boolean).join(" · ");

const row = (a) => `<tr><td>${esc(a.label)}</td><td>${esc(a.via)}</td><td class="${a.breach ? "b" : "h"}">${a.breach ? "Got through" : "Reverted"}</td><td class="tx">${a.tx ? esc(a.tx) : "none (reverted)"}</td></tr>`;
const section = (g) => `<section class="rl"><div class="rh"><b>${esc(g.name)}</b><span class="stamp ${g.bad.length ? "b" : "h"}">${g.bad.length ? "Breached" : "Held"}</span></div>
<table><thead><tr><th>Attack</th><th>Path</th><th>Result</th><th>Evidence</th></tr></thead><tbody>${g.list.map(row).join("")}</tbody></table></section>`;

const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Tripwire test report ${serial}</title>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:ital,wght@0,500..700;1,500&family=IBM+Plex+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
:root{--bg:#0a101b;--pp:#efe7d3;--pi:#1c1810;--pm:#6e6650;--pr:#c8372a;--pt:#0b7a64}
*{box-sizing:border-box}body{margin:0;background:var(--bg);padding:28px 14px;font:17px/1.55 "Fraunces",Georgia,serif;color:var(--pi)}
.paper{max-width:820px;margin:0 auto;background:var(--pp);padding:30px 34px 34px;border-radius:3px;box-shadow:0 18px 50px rgba(0,0,0,.5)}
.mono,.hd,.sub,th,td.tx,.stamp,.fine{font-family:"IBM Plex Mono",ui-monospace,Menlo,Consolas,monospace}
.hd{display:flex;justify-content:space-between;gap:12px;border-bottom:2px solid var(--pi);padding-bottom:10px;font-weight:600;font-size:13px;letter-spacing:.14em;text-transform:uppercase}
h1{font-size:30px;line-height:1.1;margin:18px 0 6px;font-weight:600}
.sub{color:var(--pm);font-size:13px;margin:2px 0}.sub b{color:var(--pi)}
.vd{display:flex;justify-content:space-between;align-items:center;gap:14px;margin:20px 0;padding:16px;border:2px solid var(--pi)}
.vd b{font-size:26px;line-height:1.1}.vd small{display:block;color:var(--pm);font:12px "IBM Plex Mono",monospace;letter-spacing:.1em;text-transform:uppercase}
.stamp{display:inline-block;font-weight:600;font-size:14px;letter-spacing:.12em;padding:7px 11px;border:2px solid currentColor;border-radius:3px;text-transform:uppercase;transform:rotate(-6deg);white-space:nowrap}
.stamp.big{font-size:19px;padding:9px 14px}.stamp.b{color:var(--pr)}.stamp.h{color:var(--pt)}
.rl{margin-top:22px}.rh{display:flex;justify-content:space-between;align-items:center;border-bottom:1px dashed #b9ae92;padding-bottom:8px}.rh b{font-size:20px}
table{width:100%;border-collapse:collapse;margin-top:8px;font-size:13px}
th{text-align:left;color:var(--pm);font-weight:400;letter-spacing:.08em;text-transform:uppercase;font-size:11.5px;padding:6px 8px 6px 0}
td{padding:8px 8px 8px 0;border-top:1px solid #d6ccb2;vertical-align:top;font-family:"Fraunces",Georgia,serif;font-size:15px}
td.b{color:var(--pr);font-weight:600}td.h{color:var(--pt);font-weight:600}td.tx{font-size:11.5px;word-break:break-all;color:var(--pm)}
.fine{color:var(--pm);font-size:12px;margin-top:26px;border-top:1px solid #b9ae92;padding-top:14px}
@media(max-width:600px){.paper{padding:20px 16px}table,thead,tbody,tr,td{display:block}thead{display:none}tr{border-top:1px solid #d6ccb2;padding:8px 0}td{border:0;padding:2px 0}}
</style></head><body><main class="paper">
<div class="hd"><span>Tripwire · Test report</span><span>No. ${serial}</span></div>
<h1>${esc(ok ? "Every promise was enforced" : held + " of " + total + " promises held")}</h1>
<p class="sub">Specimen: <b>${esc(r.mode === "patched" ? "ART reference token (patched build)" : r.mode === "deployed" ? "ART reference token (deployed build)" : r.mode)}</b></p>
<p class="sub">Terms tested: ${esc(terms)}</p>
<p class="sub">Executed: ${when} · local EVM chain (anvil)</p>
<div class="vd"><div><small>Verdict</small><b>${ok ? "All promises enforced" : total - held + " promise" + (total - held === 1 ? "" : "s") + " breached"}</b></div><span class="stamp big ${ok ? "h" : "b"}">${ok ? "Certified" : "Not certified"}</span></div>
${rules.map(section).join("")}
<section class="rl"><div class="rh"><b>Control check</b><span class="stamp ${ctrl && ctrl.breach ? "b" : "h"}">${ctrl && ctrl.breach ? "Over-blocking" : "Passed"}</span></div>
<p class="sub" style="margin-top:8px">A fully compliant transfer must still go through. ${ctrl ? esc(ctrl.result) : ""}</p></section>
<p class="fine">Tripwire tests whether a token mechanically enforces the listed terms. It does not judge whether the terms are legally sufficient and is not legal advice. Reproduce this report with the project repository (run.mjs) on a local anvil chain. Evidence column lists the transaction hash of each attack that succeeded.</p>
</main></body></html>`;

writeFileSync(outFile, html);
console.log(`wrote ${outFile}  (${serial}, ${held} of ${total} promises held)`);
