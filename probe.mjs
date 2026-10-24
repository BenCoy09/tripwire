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
console.log(`\nTripwire probe (read-only) | ${d.name} (${d.symbol}) | block ${d.block}`);
console.log(`holder balance: ${d.holderBalance}`);
for (const w of d.warnings) console.log("WARNING: " + w);
console.log(d.restrictionCodes.length ? "restriction codes: " + d.restrictionCodes.map((c) => `${c.code}=${c.message}`).join(" | ") : "No ERC-1404 restriction messages found. This token may not implement ERC-1404.");
for (const c of d.checks) console.log(`\n  fresh wallet ${c.recipient}\n    restriction code: ${c.restrictionCode} ${c.restrictionMessage ? "(" + c.restrictionMessage + ")" : ""}\n    transfer simulation: ${c.transferSimulation}\n    => ${c.verdict}`);
const file = `probe-${d.symbol || "token"}.json`;
writeFileSync(file, JSON.stringify(d, null, 2));
console.log(`\nwrote ${file}\nRead-only simulation: no transaction was sent. Share any finding privately with the issuer first.`);
