// Tripwire verdicts. One per promise: ENFORCED, NOT_ENFORCED, UNTESTABLE, UNVERIFIABLE. No aggregate, no score.
//   UNTESTABLE   = this tool cannot build a simulation that exercises the promise.
//   UNVERIFIABLE = simulations ran (or evidence was gathered) but cannot establish the promise either way.
// ENFORCED is returned only when a simulation behaved exactly as the memo says AND a control rules out another cause.
import { selector, encodeCall, keccak256, toChecksum } from "./evm-lite.mjs";
import { evidenceFor } from "./source.mjs";

const DAY = 86400;
const SIG_TRANSFER = "transfer(address,uint256)";
const CLOCK_CODE = "0x4260005260206000f3"; // TIMESTAMP, PUSH1 0, MSTORE, PUSH1 0x20, PUSH1 0, RETURN: proves a block-time override took effect
const CLOCK_ADDR = toChecksum("0x" + keccak256("tripwire-clock").slice(26));
const SUBGROUP = /\b(insiders?|founders?|team|advisors?|employees?|affiliates?|sponsors?|issuer|management|officers?|directors?|seed|private[-\s]sale|pre-?sale|strategic|early|certain|specified|designated)\b/i;
const FORCE_SIGS = ["forcedTransfer(address,address,uint256)", "forceTransfer(address,address,uint256)", "controllerTransfer(address,address,uint256,bytes,bytes)", "controllerRedeem(address,uint256,bytes,bytes)", "freeze(address)", "freezePartialTokens(address,uint256)", "setAddressFrozen(address,bool)"];
const PAUSE_SIGS = ["pause()", "unpause()", "paused()"];

const blocked = (s) => s.outcome.startsWith("revert") || s.outcome === "returned_false";
const passed = (s) => s.outcome === "success";
const errored = (s) => s.outcome === "rpc_error";
const hasSel = (code, sel) => typeof code === "string" && code.toLowerCase().includes("63" + sel.slice(2));
const obs = (s) => ({ outcome: s.outcome, returnData: s.returnData, rawRevertData: s.rawRevertData, decoded: s.decoded, detail: s.detail });
const units = (raw, dec) => { const s = raw.toString().padStart(dec + 1, "0"), i = s.slice(0, s.length - dec), f = s.slice(s.length - dec).replace(/0+$/, ""); return f ? `${i}.${f}` : i; };

export async function evaluate(promises, ctx) {
  const { out } = ctx;
  let srcPromise = null;
  const getSource = () => (srcPromise ||= ctx.getSource());
  const scope = `Tested for holder ${ctx.holder} only. A holder exempt from the rule (an issuer or treasury wallet, say) would behave differently from an ordinary one.`;

  const V = (p, verdict, rule, reason, tests = [], evidence = null, extra = {}) => ({
    id: p.id, category: p.category, quote: p.quote, span: p.span, parameters: p.parameters,
    verdict, rule, reason, scope, block: out.block, blockHash: out.blockHash, tests, evidence,
    ...(evidence ? {} : { evidenceNote: "Nothing was simulated that failed or reverted in a way that points at code, so there is no function or line to cite." }), ...extra,
  });
  const ev = async (sim, role, names = ["transfer"]) => {
    const src = await getSource(); let e = null;
    for (const n of names) { e = evidenceFor(src, sim, role, n); if (e.located !== false) break; }
    return e;
  };
  async function simulate({ to, state, time }) {
    const data = encodeCall(SIG_TRANSFER, [to, 1n]), overrides = state === "override" ? ctx.overrides : null;
    const sim = ctx.classify(await ctx.call(ctx.token, data, ctx.holder, overrides, time ? { time: "0x" + time.toString(16) } : null));
    return { sim, inputs: { from: ctx.holder, to: ctx.token, data, recipient: to, amount: "1", block: out.block, stateUsed: state === "override" ? "balance overridden" : "actual on-chain state", stateOverride: overrides, blockTimeOverride: time ? String(time) : null } };
  }
  const rec = (name, purpose, expected, { sim, inputs }) => ({ name, purpose, expected, inputs, observed: obs(sim) });

  async function transferRestriction(p) {
    const classes = p.parameters.recipientClasses || [];
    if (classes.some((c) => /non-u\.s\./i.test(c))) return V(p, "UNTESTABLE", "TR-0", "The memo defines the allowed recipients by exclusion (non-U.S. persons). An unused fresh wallet is not known to be inside or outside that class, so no simulated transfer can show the promise held or failed.");
    const tests = out.checks.map((c, i) => ({ name: `fresh wallet ${i + 1}`, purpose: "A recipient with no attestation of any kind. The memo says it must not be able to receive.", expected: "revert or returned false",
      inputs: { ...c.simulation, recipient: c.recipient, amount: c.amount, stateUsed: c.stateUsed, blockTimeOverride: null }, observed: obs(c) }));
    if (out.checks.some(errored)) return V(p, "UNTESTABLE", "TR-1", "The RPC could not simulate one or more transfers, so the behaviour is unknown.", tests);
    const ok = out.checks.find(passed);
    if (ok) return V(p, "NOT_ENFORCED", "TR-2", `A transfer to a fresh wallet (${ok.recipient}) completed without reverting. The memo says only eligible recipients may receive tokens.`, tests, await ev(ok, "entry"));
    if (!ctx.control) return V(p, "UNVERIFIABLE", "TR-3", "Every transfer to a fresh wallet was blocked, but no control recipient was supplied. Without one, the block cannot be attributed to a recipient rule rather than a pause, a freeze on the holder, or a balance problem.", tests, await ev(out.checks[0], "revert"));
    const c = await simulate({ to: ctx.control, state: ctx.overrides ? "override" : "actual" });
    tests.push(rec("control recipient", "A recipient the person running the probe asserts is eligible. The tool does not verify that claim.", "success", c));
    if (errored(c.sim)) return V(p, "UNVERIFIABLE", "TR-4", "The control transfer could not be simulated, so the fresh-wallet blocks cannot be attributed to a recipient rule.", tests, await ev(out.checks[0], "revert"));
    if (passed(c.sim)) return V(p, "ENFORCED", "TR-5", `Transfers to all three fresh wallets were blocked, and the transfer to the control recipient (${ctx.control}, asserted eligible by the operator) succeeded under identical inputs.`, tests, await ev(out.checks[0], "revert"));
    return V(p, "UNVERIFIABLE", "TR-6", "The control transfer was blocked too. The blocks may come from something other than a recipient rule, or the control wallet is not eligible.", tests, await ev(out.checks[0], "revert"));
  }

  async function lockup(p) {
    const endsAt = p.parameters.endsAt, endTs = Date.parse(endsAt + "T00:00:00Z") / 1000, blockTs = Number(out.blockTimestamp);
    if (!Number.isFinite(endTs) || !Number.isFinite(blockTs)) return V(p, "UNTESTABLE", "LU-0", "The end date or the block time could not be read.");
    if (blockTs >= endTs + DAY) return V(p, "UNVERIFIABLE", "LU-1", `The lock-up end date (${endsAt}) had already passed at block ${out.block}. Simulating an earlier clock against today's state cannot rule out changes made after the lock-up expired. Re-run against a block from before the end date using --block (needs an archive RPC).`);
    if (blockTs > endTs - DAY) return V(p, "UNVERIFIABLE", "LU-2", `Block ${out.block} is within one day of the lock-up end date (${endsAt}), so the boundary is ambiguous. Use a block more than a day earlier.`);
    if (!ctx.realBalance || ctx.realBalance < 1n) return V(p, "UNTESTABLE", "LU-3", "The holder has no tokens in actual state. A balance override is deliberately not used for lock-up tests because it would bypass per-holder lock tracking.");
    const to = ctx.control || out.checks[0].recipient;
    const t1 = await simulate({ to, state: "actual" });
    const tests = [rec("before the end date", `Transfer at the block's own clock, ${endsAt} not yet reached. The memo says transfers are not allowed.`, "revert or returned false", t1)];
    if (errored(t1.sim)) return V(p, "UNTESTABLE", "LU-4", "The RPC could not simulate the transfer.", tests);
    const sub = SUBGROUP.exec(p.quote);
    if (passed(t1.sim)) {
      if (sub) return V(p, "UNVERIFIABLE", "LU-5", `The transfer succeeded before the end date, but the memo limits this promise to a subgroup ("${sub[0]}") and the tested holder's membership is unknown.`, tests, await ev(t1.sim, "entry"));
      return V(p, "NOT_ENFORCED", "LU-6", `A transfer from the holder succeeded before the lock-up end date (${endsAt}). The memo says transfers are not allowed until then.`, tests, await ev(t1.sim, "entry"));
    }
    const after = endTs + DAY, clock = await ctx.call(CLOCK_ADDR, "0x", null, { [CLOCK_ADDR]: { code: CLOCK_CODE } }, { time: "0x" + after.toString(16) });
    const clockOk = !clock.error && clock.result && BigInt(clock.result) === BigInt(after);
    tests.push({ name: "clock override check", purpose: "Proves the RPC applied a block-time override before it is relied on.", expected: `clock reads ${after}`, inputs: { blockTimeOverride: String(after), block: out.block }, observed: { outcome: clockOk ? "success" : "rpc_error", returnData: clock.result } });
    if (!clockOk) return V(p, "UNVERIFIABLE", "LU-7", "The transfer was blocked before the end date, but this RPC did not apply a block-time override, so the block cannot be shown to depend on time.", tests, await ev(t1.sim, "revert"));
    const t2 = await simulate({ to, state: "actual", time: after });
    tests.push(rec("one day after the end date", "The same transfer with the clock set one day past the end date. The memo says transfers are then allowed.", "success", t2));
    if (passed(t2.sim)) return V(p, "ENFORCED", "LU-8", `The transfer was blocked before ${endsAt} and succeeded with the clock one day after it, all other inputs identical.`, tests, await ev(t1.sim, "revert"));
    return V(p, "UNVERIFIABLE", "LU-9", "The transfer was blocked before the end date and also after it. The block does not depend on the lock-up date alone, or the recipient is not eligible.", tests, await ev(t1.sim, "revert"));
  }

  async function supplyCap(p) {
    const max = p.parameters.maxSupply;
    if (!Number.isSafeInteger(max)) return V(p, "UNTESTABLE", "SC-0", "The memo's supply figure is not a whole number the tool can compare exactly.");
    if (out.totalSupply == null) return V(p, "UNTESTABLE", "SC-1", "totalSupply() could not be read.");
    const d = await ctx.call(ctx.token, selector("decimals()")), dec = !d.error && d.result && d.result !== "0x" ? Number(BigInt(d.result)) : null;
    if (dec === null || dec > 36) return V(p, "UNTESTABLE", "SC-2", "decimals() could not be read, so raw supply cannot be converted to the memo's units.");
    const cap = BigInt(max) * 10n ** BigInt(dec), supply = BigInt(out.totalSupply);
    const observed = { totalSupplyRaw: out.totalSupply, decimals: dec, totalSupplyUnits: units(supply, dec), memoMaxSupply: String(max) };
    const e = await ev({ outcome: "success" }, "entry", ["mint", "_mint"]);
    if (supply > cap) return V(p, "NOT_ENFORCED", "SC-3", `totalSupply() at block ${out.block} is ${observed.totalSupplyUnits} tokens, above the memo's ${max}.`, [], e, { observed });
    return V(p, "UNVERIFIABLE", "SC-4", `totalSupply() is ${observed.totalSupplyUnits} tokens, within the memo's ${max}. That does not show the code prevents minting past it. A mint simulation needs minter authority the tool does not have.`, [], e, { observed });
  }

  async function capability(p, sigs, label, extraObs) {
    const rows = sigs.map((sig) => ({ signature: sig, selector: selector(sig), inTokenBytecode: hasSel(ctx.codes.token, selector(sig)), inImplementationBytecode: ctx.codes.impl ? hasSel(ctx.codes.impl, selector(sig)) : null }));
    const found = rows.filter((r) => r.inTokenBytecode || r.inImplementationBytecode);
    const e = found.length ? await ev(null, "entry", found.map((r) => r.signature.split("(")[0])) : null;
    const reason = `${found.length ? `Found in bytecode: ${found.map((r) => r.signature).join(", ")}. ` : `None of the ${label} selectors the tool checks were found in bytecode. `}A function existing, or not matching a known name, does not show that the memo's named actor holds the power or that it works as described. That needs a call signed by that actor, which a read-only tool cannot make.`;
    return V(p, "UNVERIFIABLE", "CP-1", reason, [], e, { observed: { selectorsChecked: rows, ...(extraObs ? await extraObs() : {}) } });
  }

  const results = [];
  for (const p of promises) {
    if (!p.testable) { results.push(V(p, "UNTESTABLE", "EX-0", p.reason || "The extractor marked this promise untestable.")); continue; }
    switch (p.category) {
      case "TRANSFER_RESTRICTION": results.push(await transferRestriction(p)); break;
      case "LOCKUP": results.push(await lockup(p)); break;
      case "SUPPLY_CAP": results.push(await supplyCap(p)); break;
      case "HOLDER_CAP": results.push(V(p, "UNTESTABLE", "HC-0", "A holder cap needs a holder count or many sequential transfers. eth_call simulates one call at a time and there is no standard on-chain way to read a holder count.")); break;
      case "JURISDICTION_BLOCK": results.push(V(p, "UNTESTABLE", "JB-0", "Testing a jurisdiction block needs a wallet registered in the blocked jurisdiction, and the token's identity or compliance registry layout is not known to the tool.")); break;
      case "FORCED_TRANSFER_OR_FREEZE": results.push(await capability(p, FORCE_SIGS, "forced-transfer and freeze")); break;
      case "PAUSABILITY": results.push(await capability(p, PAUSE_SIGS, "pause", async () => {
        const r = await ctx.call(ctx.token, selector("paused()")); return { pausedNow: !r.error && r.result && /^0x[0-9a-f]{64}$/i.test(r.result) ? BigInt(r.result) !== 0n : null };
      })); break;
      default: results.push(V(p, "UNTESTABLE", "XX-0", "No test exists for this category."));
    }
  }
  return results;
}
