// End to end: run the real CLI against the mock node, then --verify the file it wrote, then tamper with it.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { startMock, TOKEN, HOLDER, CONTROL, TRUE, customErr } from "./mock-node.mjs";

const cli = fileURLToPath(new URL("../probe.mjs", import.meta.url)), dir = mkdtempSync(join(tmpdir(), "tw-"));
const run = (args) => new Promise((r) => execFile("node", [cli, ...args], { cwd: dir, timeout: 90000 }, (e, so, se) => r({ code: e ? e.code : 0, out: so + se })));
const m = await startMock({ pinned: 20, transfer: ({ to }) => (to.toLowerCase() === CONTROL ? { ok: TRUE } : { revert: customErr }) });
writeFileSync(join(dir, "memo.txt"), "Tokens may only be transferred to accredited investors.");
const base = ["--rpc", m.url, "--token", TOKEN, "--holder", HOLDER, "--control", CONTROL, "--block", "20", "--memo", join(dir, "memo.txt")];

let r = await run(base); assert.equal(r.code, 0, r.out);
assert.match(r.out, /\[ENFORCED\] TRANSFER_RESTRICTION/); assert.match(r.out, /memo: "Tokens may only be transferred to accredited investors\."/); assert.match(r.out, /report hash: 0x[0-9a-f]{64}/);
assert.match(r.out, /reproduce:.*--block 20/); assert.ok(!/score|grade/i.test(r.out.replace("no overall score", "")));
const file = join(dir, "probe-MCK.json"), rep = JSON.parse(readFileSync(file, "utf8")); assert.equal(rep.promises[0].verdict, "ENFORCED");

r = await run(["--verify", file, "--rpc", m.url]); assert.equal(r.code, 0, r.out); assert.match(r.out, /file is unmodified/); assert.match(r.out, /MATCH: re-running block 20/);

rep.promises[0].verdict = "NOT_ENFORCED"; writeFileSync(file, JSON.stringify(rep));
r = await run(["--verify", file, "--rpc", m.url]); assert.equal(r.code, 1); assert.match(r.out, /FILE WAS MODIFIED/); assert.match(r.out, /DIFFERENT\. Sections that differ: promises/);

r = await run(["--rpc", m.url, "--token", TOKEN, "--holder", HOLDER, "--block", "20"]); assert.equal(r.code, 0, r.out); assert.match(r.out, /No terms supplied\. Observations only; no verdict of any kind\./); assert.ok(!/ENFORCED|UNVERIFIABLE|UNTESTABLE/.test(r.out));
m.close(); console.log("cli: all checks passed (run, verify match, tamper detected, no-memo has no verdict)"); process.exit(0);
