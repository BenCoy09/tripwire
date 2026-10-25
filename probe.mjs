// Tripwire probe CLI (read-only). usage: node probe.mjs --rpc <https url> --token 0x... --holder 0x...
import { writeFileSync } from "node:fs";
import { probeToken } from "./probe-core.mjs";

const arg = (k) => { const i = process.argv.indexOf("--" + k); return i > -1 ? process.argv[i + 1] : undefined; };
const rpc = arg("rpc") || process.env.RPC, token = arg("token"), holder = arg("holder");
if (!rpc || !token || !holder) {
  console.log("usage: node probe.mjs --rpc <https url> --token 0x... --holder 0x...");
  console.log("  holder = an address that currently holds the token (find one on the block explorer)");
  process.exit(2);
}
let d;
try { d = await probeToken({ rpc, token, holder }); } catch (e) { console.log("Error: " + e.message); process.exit(1); }
console.log(`\nTripwire probe (read-only) | ${d.name || "unnamed"} (${d.symbol || "?"}) | block ${d.block} | hash ${d.blockHash}`);
console.log(`holder balance (actual): ${d.holderBalance}`);
const ov = d.balanceOverride;
console.log(ov.applied ? `balance override: applied (${ov.layout} mapping index ${ov.mappingIndex}, read-back ${ov.readBack})` : `balance override: NOT applied. ${ov.reason}`);
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
const file = `probe-${d.symbol || "token"}.json`;
writeFileSync(file, JSON.stringify(d, null, 2));
console.log(`\nwrote ${file}\nRead-only simulation: no transaction was sent. Observations only; no verdict without supplied terms.`);
