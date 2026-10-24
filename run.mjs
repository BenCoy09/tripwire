// Tripwire runner: fires should-be-illegal transfers at a real token on a local anvil chain.
// usage: node run.mjs deployed|patched [rules.json]
import { readFileSync, writeFileSync } from "node:fs";
import { createPublicClient, createWalletClient, createTestClient, http } from "viem";
import { foundry } from "viem/chains";

const mode = process.argv[2];
if (!["deployed", "patched"].includes(mode)) {
  console.log("usage: node run.mjs deployed|patched [rules.json]");
  process.exit(2);
}
const rules = JSON.parse(readFileSync(process.argv[3] || "rules.json", "utf8"));
const art = JSON.parse(readFileSync("out/RestrictedToken.sol/RestrictedToken.json", "utf8"));
const abi = art.abi, bytecode = art.bytecode.object;

const url = process.env.RPC || "http://127.0.0.1:8545";
const pub = createPublicClient({ chain: foundry, transport: http(url), pollingInterval: 50 });
const wal = createWalletClient({ chain: foundry, transport: http(url), pollingInterval: 50 });
const tst = createTestClient({ chain: foundry, mode: "anvil", transport: http(url), pollingInterval: 50 });
const [admin, investor, spender, nonAcc, restricted, newHolder, friend] = await wal.getAddresses();

const DAY = 86400;
const L = rules.lockupDays, base = L + 10;
const cc = (s) => "0x" + Buffer.from(s).toString("hex");
const REASONS = ["LockupActive", "NotAccredited", "HolderCapReached", "BlockedJurisdiction", "NoAllowance", "Balance"];
const CFG = {
  deployed: { lockupDays: 180, accFrom: false, capOnTx: false },
  patched: { lockupDays: 360, accFrom: true, capOnTx: true },
}[mode];

async function send(args) {
  try {
    const hash = await wal.writeContract({ abi, chain: foundry, ...args });
    const rc = await pub.waitForTransactionReceipt({ hash });
    if (rc.status !== "success") return { ok: false, reason: "revert" };
    return { ok: true, hash };
  } catch (e) {
    const m = [e.details, e.shortMessage, e.message].filter(Boolean).join(" ");
    return { ok: false, reason: REASONS.find((r) => m.includes(r)) || "revert" };
  }
}

// every attack gets a fresh token, so evidence transactions stay on the chain
async function world() {
  const hash = await wal.deployContract({
    abi, bytecode, account: admin, chain: foundry,
    args: ["Aurelia Real Estate Token", "ART", BigInt(CFG.lockupDays), BigInt(rules.holderCap || 0),
           CFG.accFrom, CFG.capOnTx, (rules.blocked || []).map(cc)],
  });
  const { contractAddress } = await pub.waitForTransactionReceipt({ hash });
  const call = (functionName, args, account) => send({ address: contractAddress, functionName, args, account });
  await call("register", [investor, true, cc("US")], admin);
  await call("register", [friend, true, cc("CA")], admin);
  await call("issue", [investor, 100n], admin);
  return { call, address: contractAddress };
}
const wait = async (days) => {
  await tst.increaseTime({ seconds: Math.round(days * DAY) });
  await tst.mine({ blocks: 1 });
};
const synth = (i) => "0x" + (0x1000 + i).toString(16).padStart(40, "0");

const A = []; // {rule, label, via, control?, run(w)}
if (L) {
  A.push({ rule: "Lock-up", label: `Direct transfer on day ${L - 1}`, via: "transfer",
    run: async (w) => { await wait(L - 1); return w.call("transfer", [friend, 1n], investor); } });
  A.push({ rule: "Lock-up", label: "Approved spender moves tokens on day 1", via: "transferFrom",
    run: async (w) => { await w.call("approve", [spender, 1n], investor); await wait(1);
      return w.call("transferFrom", [investor, friend, 1n], spender); } });
}
if (rules.accreditedOnly) {
  A.push({ rule: "Accredited only", label: "Transfer to a non-accredited wallet", via: "transfer",
    run: async (w) => { await w.call("register", [nonAcc, false, cc("US")], admin); await wait(base);
      return w.call("transfer", [nonAcc, 1n], investor); } });
  A.push({ rule: "Accredited only", label: "Spender sends to a non-accredited wallet", via: "transferFrom",
    run: async (w) => { await w.call("register", [nonAcc, false, cc("US")], admin);
      await w.call("approve", [spender, 1n], investor); await wait(base);
      return w.call("transferFrom", [investor, nonAcc, 1n], spender); } });
}
if (rules.holderCap) {
  A.push({ rule: "Holder cap", label: `New holder when all ${rules.holderCap} slots are taken`, via: "transfer",
    run: async (w) => {
      console.log(`    filling ${rules.holderCap - 1} holders (this takes a moment)...`);
      for (let i = 0; i < rules.holderCap - 1; i++) {
        await w.call("register", [synth(i), true, cc("CA")], admin);
        await w.call("issue", [synth(i), 1n], admin);
      }
      await w.call("register", [newHolder, true, cc("CA")], admin);
      await wait(base);
      return w.call("transfer", [newHolder, 1n], investor);
    } });
}
for (const c of rules.blocked || []) {
  A.push({ rule: "Blocked jurisdictions", label: `Transfer to a wallet in ${c}`, via: "transfer",
    run: async (w) => { await w.call("register", [restricted, true, cc(c)], admin); await wait(base);
      return w.call("transfer", [restricted, 1n], investor); } });
}
A.push({ rule: "Control", control: true, label: "Compliant transfer after the lock-up", via: "transfer",
  run: async (w) => { await wait(base); return w.call("transfer", [friend, 1n], investor); } });

console.log(`\nTripwire | token: ${mode} | rules: ${JSON.stringify(rules)}\n`);
const out = [];
for (const a of A) {
  const r = await a.run(await world());
  const breach = a.control ? !r.ok : r.ok;
  const line = r.ok ? `succeeded, tx ${r.hash}` : `reverted: ${r.reason}`;
  console.log(`  ${breach ? "BREACH" : "held  "}  [${a.rule}] ${a.label} (${a.via}) -> ${line}`);
  out.push({ rule: a.rule, label: a.label, via: a.via, control: !!a.control, breach, result: line, tx: r.hash || null });
}

const byRule = {};
for (const o of out.filter((o) => !o.control)) (byRule[o.rule] ||= []).push(o);
const names = Object.keys(byRule);
const heldN = names.filter((n) => !byRule[n].some((o) => o.breach)).length;
console.log("");
for (const n of names) console.log(`  ${byRule[n].some((o) => o.breach) ? "BREACHED" : "held    "}  ${n}`);
const ctrl = out.find((o) => o.control);
console.log(`\n  ${heldN} of ${names.length} promises held. Control: ${ctrl.breach ? "token blocked a legal transfer" : "legal transfer succeeded"}.\n`);
writeFileSync(`report-${mode}.json`, JSON.stringify({ mode, rules, heldN, total: names.length, attacks: out }, null, 2));
console.log(`  wrote report-${mode}.json`);
process.exit(names.length - heldN > 0 || ctrl.breach ? 1 : 0);
