// Tripwire probe CLI (read-only).
//   node probe.mjs --rpc <url> --token 0x.. --holder 0x.. [--control 0x..] [--block N] [--memo memo.txt]
//   node probe.mjs --verify probe-SYMBOL.json --rpc <archive url>      re-runs the report from its recorded inputs and compares hashes
import { readFileSync, writeFileSync } from "node:fs";
import { probeToken } from "./probe-core.mjs";
import { hashReport, diffSections } from "./report-hash.mjs";

const arg = (k) => { const i = process.argv.indexOf("--" + k); return i > -1 ? process.argv[i + 1] : undefined; };
const rpc = arg("rpc") || process.env.RPC;
const verifyFile = arg("verify");

if (verifyFile) {
  if (!rpc) { console.log("usage: node probe.mjs --verify report.json --rpc <archive https url>"); process.exit(2); }
  const old = JSON.parse(readFileSync(verifyFile, "utf8")), r = old.reproduce;
  if (!r) { console.log("This report has no reproduce section."); process.exit(1); }
  const recomputed = hashReport(old);
  console.log(`stored hash:     ${old.reportHash}\nrecomputed hash: ${recomputed}  ${recomputed === old.reportHash ? "(file is unmodified)" : "(FILE WAS MODIFIED after it was written)"}`);
  let d;
  try { d = await probeToken({ rpc, token: r.token, holder: r.holder, control: r.control || undefined, block: r.block, memo: old.memo?.supplied ? old.memo.text : "" }); }
  catch (e) { console.log("Error: " + e.message); process.exit(1); }
  if (r.blockHash && d.blockHash !== r.blockHash) console.log(`WARNING: block ${r.block} has hash ${d.blockHash} on this RPC, not ${r.blockHash}. Different chain or a reorg.`);
  console.log(`re-run hash:     ${d.reportHash}`);
  if (d.reportHash === recomputed && recomputed === old.reportHash) { console.log("\nMATCH: re-running block " + r.block + " with the same memo reproduces this report exactly."); process.exit(0); }
  console.log("\nDIFFERENT. Sections that differ: " + (diffSections(old, d).join(", ") || "(none; only the stored hash was edited)"));
  process.exit(1);
}

const token = arg("token"), holder = arg("holder"), control = arg("control"), block = arg("block"), memoFile = arg("memo");
if (!rpc || !token || !holder) {
  console.log("usage: node probe.mjs --rpc <https url> --token 0x... --holder 0x... [--control 0x...] [--block N] [--memo memo.txt]");
  console.log("  holder  = an address that currently holds the token (find one on the block explorer)");
  console.log("  control = optional wallet you assert is allowed to hold the token (another current holder)");
  console.log("  block   = optional block number to test at (default: latest; old blocks need an archive RPC)");
  console.log("  memo    = optional text file with the offering terms; without it there is no verdict of any kind");
  process.exit(2);
}
let d;
try { d = await probeToken({ rpc, token, holder, control, block, memo: memoFile ? readFileSync(memoFile, "utf8") : "" }); } catch (e) { console.log("Error: " + e.message); process.exit(1); }
console.log(`\nTripwire probe (read-only) | ${d.name || "unnamed"} (${d.symbol || "?"}) | chain ${d.chainId} | block ${d.block} | hash ${d.blockHash}`);
console.log(`holder balance (actual): ${d.holderBalance}`);
const ov = d.balanceOverride;
console.log(ov.applied ? `balance override: applied (${ov.layout} mapping index ${ov.mappingIndex}, read-back ${ov.readBack})` : `balance override: NOT applied. ${ov.reason}${ov.detail ? " " + ov.detail : ""}`);
for (const w of d.warnings) console.log("WARNING: " + w);
if (d.restrictionCodes.length) console.log("descriptions returned by the token's own messageForTransferRestriction: " + d.restrictionCodes.map((c) => `${c.code}=${c.message}`).join(" | "));
for (const c of d.checks) {
  console.log(`\n  fresh wallet ${c.recipient}  [${c.stateUsed}]\n    outcome: ${c.outcome}\n    decoded: ${c.transferSimulation}`);
  if (c.rawRevertData !== undefined) console.log(`    raw revert data: ${c.rawRevertData === null ? "(none returned by RPC)" : c.rawRevertData}`);
  if (c.detail) console.log(`    note: ${c.detail}`);
  const t = c.detectTransferRestriction;
  console.log(`    detectTransferRestriction: ${t.status}${t.code !== null ? " code " + t.code + " (raw word " + t.rawReturn + ")" : ""}  | vs simulation: ${c.codeVsSimulation}`);
  if (t.code !== null) console.log(t.message !== null ? `    contract's own ${t.messageSource} returned: "${t.message}"\n      raw return: ${t.messageRawReturn}` : `    ${t.label}`);
}
console.log("\n" + "=".repeat(72));
if (d.promises === null) console.log("No terms supplied. Observations only; no verdict of any kind.");
else {
  console.log(`Terms supplied (memo sha256 ${d.memo.sha256}). One verdict per promise; no overall score.`);
  for (const p of d.promises) {
    console.log(`\n[${p.verdict}] ${p.category}  (${p.id}, rule ${p.rule})\n  memo: "${p.quote}"\n  why:  ${p.reason}\n  scope: ${p.scope}`);
    for (const t of p.tests) console.log(`  test: ${t.name} -> expected ${t.expected}; observed ${t.observed.outcome}${t.observed.rawRevertData ? " " + t.observed.rawRevertData : ""}\n        inputs: recipient ${t.inputs.recipient ?? "-"}, state ${t.inputs.stateUsed ?? "-"}, block ${t.inputs.block}${t.inputs.blockTimeOverride ? ", clock " + t.inputs.blockTimeOverride : ""}`);
    if (p.observed) console.log("  observed: " + JSON.stringify(p.observed).slice(0, 400));
    const e = p.evidence;
    if (!e) console.log(`  evidence: none. ${p.evidenceNote}`);
    else if (!e.available) console.log(`  evidence: source unavailable. ${e.reason}`);
    else if (!e.located) console.log(`  evidence: source found, line not located. ${e.note}`);
    else { console.log(`  evidence: ${e.function ?? "(outside a function)"} in ${e.file} lines ${e.startLine}-${e.endLine}, matched by: ${e.matchedBy}`); for (const l of e.snippet) console.log(`    ${l.marked ? ">>" : "  "} ${String(l.line).padStart(4)} | ${l.text}`); if (e.truncated) console.log("    (snippet truncated)"); }
  }
  for (const x of d.rejectedPromises || []) console.log(`\n[REJECTED BY VALIDATOR] "${x.quote}": ${x.problems.join("; ")}`);
  for (const u of d.notExtracted || []) console.log(`\n[NOT A PROMISE] "${u.quote}": ${u.note}`);
}
console.log(`\nreport hash: ${d.reportHash}\nreproduce:   ${d.reproduce.command}`);
const file = `probe-${d.symbol || "token"}.json`;
writeFileSync(file, JSON.stringify(d, null, 2));
console.log(`wrote ${file}\nRead-only simulation: no transaction was sent. Share any finding privately with the issuer first.`);
