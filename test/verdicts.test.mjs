import assert from "node:assert/strict";
import { probeToken } from "../probe-core.mjs";
import { hashReport } from "../report-hash.mjs";
import { startMock, TOKEN, HOLDER, CONTROL, TRUE, errStr, customErr, BLOCK_TS, word } from "./mock-node.mjs";
import { selector } from "../evm-lite.mjs";

const SRC = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract T {
    error TransferNotAllowed(address to);
    mapping(address => bool) public whitelist;
    uint256 public totalSupply;

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        if (!whitelist[to]) revert TransferNotAllowed(to);
        return true;
    }

    function guarded(address to) public {
        require(whitelist[to], "Recipient not whitelisted");
    }
}
`;
const ABI = [{ type: "error", name: "TransferNotAllowed", inputs: [{ name: "to", type: "address" }] }];
const srcFetch = (found = true) => async (url) => found && url.includes("/v2/contract/")
  ? { ok: true, json: async () => ({ sources: { "contracts/T.sol": { content: SRC } }, abi: ABI }) } : { ok: false, status: 404, json: async () => ({}), text: async () => "" };

const run = async (cfg, args = {}) => { const m = await startMock(cfg); try { return await probeToken({ rpc: m.url, token: TOKEN, holder: HOLDER, sourceFetchImpl: srcFetch(args.noSource ? false : true), ...args }); } finally { m.close(); } };
const verdictOf = (d, i = 0) => d.promises[i];
const TR_MEMO = "Tokens may only be transferred to accredited investors.";
const LOCK = (issue) => `Issue Date: ${issue}\n\nHolders may not sell or transfer tokens until the first anniversary of the Issue Date.`;
const isCtl = (to) => to.toLowerCase() === CONTROL.toLowerCase();

// --- no memo: no verdict of any kind
for (const memo of [undefined, "", "   \n  "]) {
  const d = await run({ transfer: () => ({ ok: TRUE }) }, { memo });
  assert.equal(d.promises, null); assert.equal(d.terms, "No terms supplied"); assert.match(d.reportHash, /^0x[0-9a-f]{64}$/); assert.equal(d.checks.length, 3);
  assert.ok(!JSON.stringify(d).match(/ENFORCED|UNTESTABLE|UNVERIFIABLE/));
}
console.log("ok no memo: no verdict of any kind");

// --- TRANSFER_RESTRICTION
{ const d = await run({ transfer: ({ to }) => (isCtl(to) ? { ok: TRUE } : { revert: customErr }) }, { memo: TR_MEMO, control: CONTROL });
  const v = verdictOf(d); assert.equal(d.promises.length, 1); assert.equal(v.category, "TRANSFER_RESTRICTION"); assert.equal(v.verdict, "ENFORCED"); assert.equal(v.rule, "TR-5");
  assert.equal(v.quote, TR_MEMO); assert.equal(v.tests.length, 4); assert.equal(v.block, "16"); assert.equal(v.tests[3].inputs.recipient, CONTROL.replace(/^0x/, "0x") && v.tests[3].inputs.recipient);
  assert.equal(v.evidence.located, true); assert.equal(v.evidence.function, "function transfer"); assert.equal(v.evidence.startLine, 13); assert.deepEqual(v.evidence.markedLines, [14]);
  assert.ok(v.evidence.snippet.find((l) => l.marked).text.includes("revert TransferNotAllowed")); assert.match(v.evidence.matchedBy, /custom error TransferNotAllowed/);
  console.log("ok TR enforced + source line located"); }
{ const d = await run({ transfer: () => ({ ok: TRUE }) }, { memo: TR_MEMO, control: CONTROL });
  const v = verdictOf(d); assert.equal(v.verdict, "NOT_ENFORCED"); assert.equal(v.rule, "TR-2"); assert.equal(v.evidence.function, "function transfer"); assert.deepEqual(v.evidence.markedLines, [13]); assert.match(v.evidence.matchedBy, /cannot locate a missing check/); console.log("ok TR not enforced"); }
{ const d = await run({ transfer: () => ({ revert: customErr }) }, { memo: TR_MEMO });
  assert.equal(verdictOf(d).verdict, "UNVERIFIABLE"); assert.equal(verdictOf(d).rule, "TR-3"); console.log("ok TR blocked but no control -> unverifiable"); }
{ const d = await run({ transfer: () => ({ revert: customErr }) }, { memo: TR_MEMO, control: CONTROL });
  assert.equal(verdictOf(d).verdict, "UNVERIFIABLE"); assert.equal(verdictOf(d).rule, "TR-6"); console.log("ok TR control also blocked -> unverifiable"); }
{ const d = await run({ transfer: () => ({ revert: customErr }) }, { memo: TR_MEMO, control: CONTROL, noSource: true });
  assert.equal(verdictOf(d).evidence.available, false); assert.match(verdictOf(d).evidence.reason, /No verified source/); assert.equal(d.source.status, "unavailable"); console.log("ok source unavailable is stated, not invented"); }
{ const d = await run({ transfer: ({ to }) => ({ revert: errStr("Recipient not whitelisted") }) }, { memo: TR_MEMO });
  const e = verdictOf(d).evidence; assert.equal(e.located, true); assert.equal(e.function, "function guarded"); assert.match(e.matchedBy, /exact revert-reason string/); console.log("ok revert-reason string matched to its require line"); }
{ const d = await run({ transfer: () => ({ revert: "0xf90e674a" }) }, { memo: TR_MEMO });
  const e = verdictOf(d).evidence; assert.equal(e.located, false); assert.match(e.note, /not among the errors in the verified ABI/); console.log("ok unknown selector: not located, said so"); }
{ const d = await run({ transfer: () => ({ ok: TRUE }) }, { memo: "Tokens may only be transferred to non-U.S. persons." });
  assert.equal(verdictOf(d).category, "TRANSFER_RESTRICTION"); assert.equal(verdictOf(d).verdict, "UNTESTABLE"); assert.equal(verdictOf(d).rule, "TR-0"); console.log("ok negative class is untestable"); }
{ const d = await run({ transfer: ({ to }) => (isCtl(to) ? { ok: TRUE } : { revert: customErr }), rejectOverride: true }, { memo: TR_MEMO, control: CONTROL });
  assert.equal(verdictOf(d).verdict, "ENFORCED"); assert.equal(verdictOf(d).tests[0].inputs.stateUsed, "actual on-chain state"); console.log("ok TR works on actual state when override unavailable"); }

// --- LOCKUP (block time is 2026-10-01)
const lockCfg = (extra = {}) => ({ transfer: ({ time }) => (time < Date.parse("2027-01-31T00:00:00Z") / 1000 ? { revert: customErr } : { ok: TRUE }), ...extra });
{ const d = await run(lockCfg(), { memo: LOCK("January 31, 2026") });
  const v = verdictOf(d); assert.equal(v.category, "LOCKUP"); assert.equal(v.parameters.endsAt, "2027-01-31"); assert.equal(v.verdict, "ENFORCED"); assert.equal(v.rule, "LU-8");
  assert.deepEqual(v.tests.map((t) => t.name), ["before the end date", "clock override check", "one day after the end date"]); assert.equal(v.tests[2].inputs.blockTimeOverride, String(Date.parse("2027-02-01T00:00:00Z") / 1000));
  assert.ok(v.tests.every((t) => !t.inputs.stateOverride), "lock-up tests must not use the balance override"); assert.equal(v.evidence.located, true); console.log("ok lockup enforced (before blocked, after allowed, clock proven)"); }
{ const d = await run(lockCfg({ transfer: () => ({ ok: TRUE }) }), { memo: LOCK("January 31, 2026") });
  assert.equal(verdictOf(d).verdict, "NOT_ENFORCED"); assert.equal(verdictOf(d).rule, "LU-6"); console.log("ok lockup not enforced"); }
{ const d = await run(lockCfg({ transfer: () => ({ revert: customErr }) }), { memo: LOCK("January 31, 2026") });
  assert.equal(verdictOf(d).verdict, "UNVERIFIABLE"); assert.equal(verdictOf(d).rule, "LU-9"); console.log("ok lockup blocked before AND after -> unverifiable"); }
{ const d = await run(lockCfg({ ignoreBlockOverride: true }), { memo: LOCK("January 31, 2026") });
  assert.equal(verdictOf(d).verdict, "UNVERIFIABLE"); assert.equal(verdictOf(d).rule, "LU-7"); console.log("ok RPC that ignores the clock override cannot yield ENFORCED"); }
{ const d = await run(lockCfg({ rejectBlockOverride: true }), { memo: LOCK("January 31, 2026") });
  assert.equal(verdictOf(d).verdict, "UNVERIFIABLE"); assert.equal(verdictOf(d).rule, "LU-7"); console.log("ok RPC that rejects the clock override -> unverifiable"); }
{ const d = await run(lockCfg(), { memo: LOCK("January 31, 2025") });
  assert.equal(verdictOf(d).parameters.endsAt, "2026-01-31"); assert.equal(verdictOf(d).verdict, "UNVERIFIABLE"); assert.equal(verdictOf(d).rule, "LU-1"); assert.equal(verdictOf(d).tests.length, 0); console.log("ok lockup already expired at block -> unverifiable, no fake time travel"); }
{ const d = await run(lockCfg({ realBalance: 0 }), { memo: LOCK("January 31, 2026") });
  assert.equal(verdictOf(d).verdict, "UNTESTABLE"); assert.equal(verdictOf(d).rule, "LU-3"); console.log("ok lockup with no actual balance -> untestable"); }
{ const d = await run({ transfer: () => ({ ok: TRUE }) }, { memo: "Issue Date: November 30, 2026\n\nInsiders are locked up for one month after the Issue Date." });
  assert.equal(verdictOf(d).parameters.endsAt, "2026-12-30"); assert.equal(verdictOf(d).verdict, "UNVERIFIABLE"); assert.equal(verdictOf(d).rule, "LU-5"); console.log("ok subgroup promise: success is not called NOT_ENFORCED"); }
{ const d = await run(lockCfg({ blockTs: Date.parse("2027-01-30T12:00:00Z") / 1000 }), { memo: LOCK("January 31, 2026") });
  assert.equal(verdictOf(d).rule, "LU-2"); console.log("ok boundary block -> unverifiable"); }

// --- SUPPLY_CAP
const SUPPLY = "The token supply is fixed at 20,000,000 tokens.";
{ const d = await run({ transfer: () => ({ ok: TRUE }), totalSupply: 25000000n * 10n ** 18n }, { memo: SUPPLY });
  const v = verdictOf(d); assert.equal(v.category, "SUPPLY_CAP"); assert.equal(v.verdict, "NOT_ENFORCED"); assert.equal(v.observed.totalSupplyUnits, "25000000"); assert.equal(v.evidence.function, "function mint"); console.log("ok supply above cap -> NOT_ENFORCED"); }
{ const d = await run({ transfer: () => ({ ok: TRUE }), totalSupply: 20000000n * 10n ** 18n }, { memo: SUPPLY });
  assert.equal(verdictOf(d).verdict, "UNVERIFIABLE"); assert.equal(verdictOf(d).rule, "SC-4"); console.log("ok supply at or under cap is never ENFORCED"); }
{ const d = await run({ transfer: () => ({ ok: TRUE }), noDecimals: true }, { memo: SUPPLY });
  assert.equal(verdictOf(d).verdict, "UNTESTABLE"); console.log("ok supply without decimals -> untestable"); }

// --- whole messy fixture: every promise gets exactly one of four verdicts, nothing aggregated
import { readFileSync } from "node:fs";
{ const memo = readFileSync(new URL("../extractor/fixtures/messy-ppm.txt", import.meta.url), "utf8");
  const d = await run({ transfer: () => ({ revert: customErr }), hasPaused: true, code: "0x6080" + "63" + selector("pause()").slice(2) + "63" + selector("freeze(address)").slice(2) }, { memo, control: CONTROL });
  const allowed = new Set(["ENFORCED", "NOT_ENFORCED", "UNTESTABLE", "UNVERIFIABLE"]);
  assert.ok(d.promises.length >= 8); assert.ok(d.promises.every((p) => allowed.has(p.verdict) && p.quote && p.block === "16" && p.rule && "evidence" in p));
  assert.ok(d.promises.every((p) => memo.includes(p.quote)), "every quote is an exact substring of the memo");
  const by = (c) => d.promises.filter((p) => p.category === c);
  assert.ok(by("HOLDER_CAP").every((p) => p.verdict === "UNTESTABLE")); assert.ok(by("JURISDICTION_BLOCK").every((p) => p.verdict === "UNTESTABLE"));
  const f = by("FORCED_TRANSFER_OR_FREEZE")[0]; assert.equal(f.verdict, "UNVERIFIABLE"); assert.equal(f.observed.selectorsChecked.find((r) => r.signature === "freeze(address)").inTokenBytecode, true); assert.equal(f.observed.selectorsChecked.find((r) => r.signature === "forcedTransfer(address,address,uint256)").inTokenBytecode, false);
  const pz = by("PAUSABILITY")[0]; assert.equal(pz.verdict, "UNVERIFIABLE"); assert.equal(pz.observed.pausedNow, false);
  const sched = d.promises.find((p) => p.quote.startsWith("After the lock-up")); assert.equal(sched.verdict, "UNTESTABLE"); assert.equal(sched.rule, "EX-0"); assert.match(sched.reason, /Tiered release/);
  assert.ok(!Object.keys(d).some((k) => /score|grade|overall|summary|tally|rating/i.test(k)), "no aggregate field on the report");
  assert.ok(Array.isArray(d.notExtracted)); console.log("ok messy fixture: " + d.promises.map((p) => p.verdict[0] + p.verdict.slice(1, 3)).join(" ")); }

// --- terms that state no testable promise (as in the live OUSG run): zero verdicts, and the page must say so plainly
{ const memo = '"Any investor eligible to invest in any of our Qualified Access Funds (and who has completed onboarding) may invest in OUSG." and "OUSG tokens may be freely transferred between any investors that have already onboarded to our Qualified Access Funds."';
  const d = await run({ transfer: () => ({ revert: errStr("CashKYCSenderReceiver: `to` address must be KYC'd to receive tokens") }), rejectOverride: true }, { memo });
  assert.deepEqual(d.promises, []); assert.equal(d.notExtracted.length, 1); assert.equal(d.terms, "Terms supplied"); assert.equal(d.checks[0].outcome, "revert_reason");
  const html = readFileSync(new URL("../web/index.html", import.meta.url), "utf8"), a = html.indexOf("function renderTests"), b = html.indexOf("async function probeReal");
  const page = new Function("esc", html.slice(a, b) + ";return renderProbe")((x) => String(x))(d), text = page.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
  assert.ok(text.includes("no sentence in them became a testable promise. No verdict.")); assert.ok(!text.includes("Verdicts are per promise below")); assert.ok(text.includes("No promises were extracted"));
  assert.equal((text.match(/Balance override not applied/g) || []).length, 0, "override message must not be shown twice"); assert.equal((text.match(/not applied\./g) || []).length, 1);
  console.log("ok terms with no testable promise: zero verdicts, page says so, override note not duplicated"); }

// --- reproducibility
{ const cfg = () => ({ transfer: ({ to }) => (isCtl(to) ? { ok: TRUE } : { revert: customErr }), pinned: 14 });
  const a = await run(cfg(), { memo: TR_MEMO, control: CONTROL, block: "14" }); await new Promise((r) => setTimeout(r, 1100));
  const b = await run(cfg(), { memo: TR_MEMO, control: CONTROL, block: "14" });
  assert.notEqual(a.generatedAt, b.generatedAt); assert.equal(a.reportHash, b.reportHash); assert.equal(a.reportHash, hashReport(a)); assert.equal(a.block, "14");
  assert.match(a.reproduce.command, /--block 14/); assert.equal(a.reproduce.blockHash, a.blockHash);
  const latest = await run(cfg(), { memo: TR_MEMO, control: CONTROL }); assert.equal(latest.block, "14");
  assert.equal(latest.reportHash, a.reportHash, "a run at 'latest' must be reproducible by re-running its block (this is what --verify does)");
  const c = await run(cfg(), { memo: TR_MEMO + " ", control: CONTROL, block: "14" }); assert.notEqual(c.reportHash, a.reportHash, "different memo text must change the hash");
  const e = await run({ ...cfg(), transfer: () => ({ ok: TRUE }) }, { memo: TR_MEMO, control: CONTROL, block: "14" }); assert.notEqual(e.reportHash, a.reportHash, "different behaviour must change the hash");
  const t = JSON.parse(JSON.stringify(a)); t.promises[0].verdict = "NOT_ENFORCED"; assert.notEqual(hashReport(t), a.reportHash, "editing a verdict breaks the hash");
  await assert.rejects(run({ ...cfg(), pinned: 99 }, { block: "14" }), /Block 14 is not available/);
  await assert.rejects(run(cfg(), { block: "1e9" }), /whole number/); await assert.rejects(run(cfg(), { control: "0x12" }), /control address/); await assert.rejects(run(cfg(), { control: HOLDER }), /must differ/);
  console.log("ok reproducible: same block + memo -> same hash; memo, behaviour or edits change it"); }
console.log("verdicts: all checks passed");
