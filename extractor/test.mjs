import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { extractPromises, addMonths } from "./extract.mjs";
import { validatePromises } from "./validate.mjs";

const fx = (n) => readFileSync(fileURLToPath(new URL("./fixtures/" + n, import.meta.url)), "utf8");
const by = (out, cat) => out.promises.filter((p) => p.category === cat);
let n = 0; const ok = (name, fn) => { fn(); n++; console.log("ok  " + name); };

ok("calendar months clip at month end", () => { assert.equal(addMonths("2026-01-31", 1), "2026-02-28"); assert.equal(addMonths("2025-12-01", 12), "2026-12-01"); });

const A = extractPromises(fx("aurelia.txt"));
ok("aurelia: four promises, all categories right", () => assert.deepEqual(A.promises.map((p) => p.category).sort(), ["HOLDER_CAP", "JURISDICTION_BLOCK", "LOCKUP", "TRANSFER_RESTRICTION"]));
ok("aurelia: per-holder lock-up is untestable with a reason", () => { const l = by(A, "LOCKUP")[0]; assert.equal(l.testable, false); assert.equal(l.parameters.startRule, "PER_HOLDER_ACQUISITION"); assert.match(l.reason, /own purchase date/); });
ok("aurelia: cap 500, blocked Iran/North Korea/Syria with codes", () => { assert.equal(by(A, "HOLDER_CAP")[0].parameters.maxHolders, 500); assert.deepEqual(by(A, "JURISDICTION_BLOCK")[0].parameters.codes, ["IR", "KP", "SY"]); });
ok("aurelia: validator clean", () => assert.deepEqual(validatePromises(fx("aurelia.txt"), A.promises), []));

const S = extractPromises(fx("saft-style.txt"));
ok("saft: lock-up end date worked out from the memo's closing date", () => { const l = by(S, "LOCKUP")[0]; assert.equal(l.testable, true); assert.equal(l.parameters.anchor.date, "2026-03-15"); assert.equal(l.parameters.endsAt, "2027-03-15"); });
ok("saft: supply cap two million parsed from words", () => assert.equal(by(S, "SUPPLY_CAP")[0].parameters.maxSupply, 2000000));
ok("saft: transfer restriction has class and approver", () => { const t = by(S, "TRANSFER_RESTRICTION")[0].parameters; assert.deepEqual(t.recipientClasses, ["accredited investors"]); assert.equal(t.approval.by, "company"); });
ok("saft: U.S. persons becomes a jurisdiction block with qualifier", () => { const j = by(S, "JURISDICTION_BLOCK")[0].parameters; assert.deepEqual(j.blocked, ["United States"]); assert.equal(j.qualifier, "U.S. persons"); });
ok("saft: pause power with condition", () => { const p = by(S, "PAUSABILITY")[0].parameters; assert.equal(p.direction, "CAN_PAUSE"); assert.equal(p.actor, "company"); assert.equal(p.condition, "a security incident"); });
ok("saft: on-chain enforcement claim is flagged, not turned into a promise", () => assert.ok(S.unclassified.some((u) => /smart contract/.test(u.quote) && /Claims on-chain/.test(u.note))));
ok("saft: validator clean", () => assert.deepEqual(validatePromises(fx("saft-style.txt"), S.promises), []));

const M = extractPromises(fx("messy-ppm.txt"));
const L = by(M, "LOCKUP");
ok("messy: anniversary lock-up resolves to 2027-01-31", () => { const l = L.find((p) => p.parameters.derivedFrom === "anniversary"); assert.equal(l.parameters.endsAt, "2027-01-31"); assert.equal(l.testable, true); });
ok("messy: one month after Jan 31 clips to Feb 28", () => assert.equal(L.find((p) => p.parameters.duration && p.parameters.duration.value === 1).parameters.endsAt, "2026-02-28"));
ok("messy: tiered schedule is untestable", () => { const t = L.find((p) => p.parameters.schedule); assert.equal(t.testable, false); assert.equal(t.parameters.schedule[0].fromDay, 366); });
ok("messy: fewer than 2,000 holders means max 1,999", () => { const c = by(M, "HOLDER_CAP")[0].parameters; assert.equal(c.statedNumber, 2000); assert.equal(c.maxHolders, 1999); });
ok("messy: consent-only transfer restriction and vague one", () => { const t = by(M, "TRANSFER_RESTRICTION"); assert.equal(t.length, 2); assert.equal(t.find((p) => p.testable).parameters.approval.by, "transfer agent"); assert.equal(t.find((p) => !p.testable).parameters.recipientClasses.length, 0); });
ok("messy: freeze plus forced transfer by transfer agent under a court order", () => { const f = by(M, "FORCED_TRANSFER_OR_FREEZE")[0].parameters; assert.deepEqual(f.powers, ["FREEZE", "FORCED_TRANSFER"]); assert.equal(f.condition, "a court order"); });
ok("messy: fixed supply 20 million", () => assert.equal(by(M, "SUPPLY_CAP")[0].parameters.maxSupply, 20000000));
ok("messy: Crimea region is unmapped, not guessed", () => { const j = by(M, "JURISDICTION_BLOCK")[0].parameters; assert.deepEqual(j.codes, ["CU", "RU", "BY", null]); assert.deepEqual(j.unmappedNames, ["Crimea region"]); });
ok("messy: suspend with no condition", () => { const p = by(M, "PAUSABILITY")[0].parameters; assert.equal(p.direction, "CAN_PAUSE"); assert.equal(p.condition, null); });
ok("messy: the transparency sentence produces nothing", () => assert.ok(!M.promises.some((p) => /transparency/.test(p.quote)) && !M.unclassified.some((u) => /transparency/.test(u.quote))));
ok("messy: validator clean", () => assert.deepEqual(validatePromises(fx("messy-ppm.txt"), M.promises), []));

ok("validator rejects a doctored quote, a made-up category and a wrong date", () => {
  const memo = fx("saft-style.txt"), base = JSON.parse(JSON.stringify(S.promises));
  const a = JSON.parse(JSON.stringify(base)); a[0].quote += " extra"; assert.ok(validatePromises(memo, a).some((x) => /exact substring/.test(x.problem)));
  const b = JSON.parse(JSON.stringify(base)); b[1].category = "REPUTATION_SCORE"; assert.ok(validatePromises(memo, b).some((x) => /fixed list/.test(x.problem)));
  const c = JSON.parse(JSON.stringify(base)); const l = c.find((p) => p.category === "LOCKUP"); l.parameters.endsAt = "2027-04-01"; assert.ok(validatePromises(memo, c).some((x) => /endsAt/.test(x.problem)));
});
console.log(`\n${n} checks passed`);
