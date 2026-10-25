// Tests anchoring against a MOCK node. The mock is our own model of a JSON-RPC node, not a real chain.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { execFile, spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyAnchor, verifyReportAnchor, PROVES } from "../anchor.mjs";
import { hashReport } from "../report-hash.mjs";

const TX = "0x" + "cd".repeat(32), HASH = "0x" + "ab".repeat(32), TESTER = "0x9999999999999999999999999999999999999999";
function mockChain(cfg = {}) {
  const srv = createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => {
      const { id, method, params } = JSON.parse(b), ok = (result) => res.end(JSON.stringify({ jsonrpc: "2.0", id, result }));
      if (method === "eth_chainId") return ok("0x" + (cfg.chainId ?? 84532).toString(16));
      if (method === "eth_blockNumber") return ok("0x" + (cfg.latest ?? 1010).toString(16));
      if (method === "eth_getTransactionByHash") {
        if (cfg.noTx || params[0] !== TX) return ok(null);
        const t = { hash: TX, from: TESTER, to: TESTER, blockNumber: cfg.pending ? null : "0x3e8", value: "0x0" };
        t[cfg.dataField || "input"] = cfg.data ?? HASH; return ok(t);
      }
      if (method === "eth_getTransactionReceipt") return ok({ status: cfg.failed ? "0x0" : "0x1", blockNumber: "0x3e8", blockHash: "0x" + "ee".repeat(32) });
      if (method === "eth_getBlockByNumber") return ok({ hash: "0x" + "ee".repeat(32), timestamp: "0x" + (cfg.blockTs ?? 1_800_000_000).toString(16) });
      ok(null);
    });
  });
  return new Promise((r) => srv.listen(0, () => r({ url: "http://127.0.0.1:" + srv.address().port, close: () => srv.close() })));
}
const withChain = async (cfg, fn) => { const m = await mockChain(cfg); try { return await fn(m.url); } finally { m.close(); } };
const names = (r) => r.checks.map((c) => c.name + ":" + (c.pass ? "pass" : "FAIL")).join(" | ");

// success
await withChain({}, async (rpc) => {
  const r = await verifyAnchor({ rpc, reportHash: HASH, testedBlockTimestamp: 1_700_000_000, txHash: TX, expectChainId: 84532 });
  assert.ok(r.ok, names(r)); assert.equal(r.anchor.network, "Base Sepolia"); assert.equal(r.anchor.testnet, true); assert.equal(r.anchor.blockNumber, "1000"); assert.equal(r.anchor.confirmations, 10);
  assert.equal(r.anchor.blockTimeIso, new Date(1_800_000_000 * 1000).toISOString()); assert.equal(r.anchor.explorerUrl, "https://sepolia.basescan.org/tx/" + TX); assert.equal(r.anchor.from, TESTER);
  assert.equal(r.proves, PROVES); assert.match(r.testnetNote, /no permanence guarantee/); console.log("ok anchor verified (network, testnet flag, block, time, explorer link, who sent it)");
});
await withChain({ dataField: "data" }, async (rpc) => { assert.ok((await verifyAnchor({ rpc, reportHash: HASH, txHash: TX })).ok); console.log("ok older nodes that call the field 'data' still work"); });
// every failure mode must fail, never pass
const bad = async (cfg, args, re, label) => withChain(cfg, async (rpc) => { const r = await verifyAnchor({ rpc, reportHash: HASH, txHash: TX, ...args }); assert.equal(r.ok, false, label + " must not verify: " + names(r)); assert.match(JSON.stringify(r.checks.filter((c) => !c.pass)), re, label); console.log("ok fails: " + label); });
await bad({ data: "0x" + "00".repeat(32) }, {}, /not the report hash/, "wrong data");
await bad({ data: "0x" }, {}, /empty/, "empty data");
await bad({ noTx: true }, {}, /No transaction/, "transaction not found");
await bad({ pending: true }, {}, /pending/, "pending transaction");
await bad({ failed: true }, {}, /status 0/, "failed transaction");
await bad({ chainId: 8453 }, { expectChainId: 84532 }, /expected chain 84532/, "RPC on the wrong chain");
await bad({ blockTs: 1_600_000_000 }, { testedBlockTimestamp: 1_700_000_000 }, /older than the block/, "anchor older than the tested block");
await withChain({}, async (rpc) => { const r = await verifyAnchor({ rpc, reportHash: HASH, txHash: "0x1234" }); assert.equal(r.ok, false); assert.match(r.checks[0].detail, /64 hex/); console.log("ok fails: malformed transaction hash"); });
await withChain({}, async (rpc) => { await assert.rejects(verifyAnchor({ rpc, reportHash: "0x12", txHash: TX }), /32-byte/); console.log("ok rejects malformed report hash"); });
await assert.rejects(verifyAnchor({ rpc: "http://127.0.0.1:1", reportHash: HASH, txHash: TX }), /unavailable/);
// hash is case-insensitive on the wire but still exact
await withChain({ data: HASH.toUpperCase().replace("0X", "0x") }, async (rpc) => assert.ok((await verifyAnchor({ rpc, reportHash: HASH, txHash: TX })).ok));

// with the report file: edits after writing are caught
const report = { token: "0xT", block: "5", blockTimestamp: "1700000000", promises: [{ verdict: "ENFORCED" }] }; report.reportHash = hashReport(report);
const REP_TX_DATA = report.reportHash;
await withChain({ data: REP_TX_DATA }, async (rpc) => {
  let r = await verifyReportAnchor({ rpc, report, txHash: TX, expectChainId: 84532 }); assert.ok(r.ok, names(r)); assert.equal(r.checks[0].name, "report file matches its own hash");
  const t = JSON.parse(JSON.stringify(report)); t.promises[0].verdict = "NOT_ENFORCED";
  r = await verifyReportAnchor({ rpc, report: t, txHash: TX }); assert.equal(r.ok, false); assert.match(r.checks[0].detail, /edited after it was written/); console.log("ok edited report file fails even though the chain data is fine");
});

// CLI end to end
const dir = mkdtempSync(join(tmpdir(), "tw-anchor-")), cli = fileURLToPath(new URL("../probe.mjs", import.meta.url));
const sh = (args) => new Promise((r) => execFile("node", [cli, ...args], { cwd: dir, timeout: 60000 }, (e, so, se) => r({ code: e ? e.code : 0, out: so + se })));
writeFileSync(join(dir, "r.json"), JSON.stringify(report));
await withChain({ data: REP_TX_DATA }, async (rpc) => {
  let r = await sh(["--verify-anchor", join(dir, "r.json"), "--tx", TX, "--rpc", rpc, "--expect-chain", "84532"]); assert.equal(r.code, 0, r.out);
  assert.match(r.out, /ANCHOR VERIFIED/); assert.match(r.out, /sepolia\.basescan\.org\/tx\/0xcdcd/); assert.match(r.out, /not prove the report is right/); assert.match(r.out, /testnet/);
  r = await sh(["--verify-anchor", join(dir, "r.json"), "--tx", "0x" + "11".repeat(32), "--rpc", rpc]); assert.equal(r.code, 1); assert.match(r.out, /ANCHOR NOT VERIFIED/);
  console.log("ok CLI --verify-anchor: verified and not-verified paths");
});

// server route
const chain = await mockChain({ data: HASH });
const port = 3917 + Math.floor(Math.random() * 50), child = spawn("node", [fileURLToPath(new URL("../server.mjs", import.meta.url))], { env: { ...process.env, PORT: String(port), RPC_BASE_SEPOLIA: chain.url }, stdio: "ignore" });
try {
  for (let i = 0; i < 50; i++) { try { await fetch(`http://127.0.0.1:${port}/healthz`); break; } catch { await new Promise((r) => setTimeout(r, 100)); } }
  const post = (body) => fetch(`http://127.0.0.1:${port}/api/anchor`, { method: "POST", body: JSON.stringify(body) }).then(async (r) => ({ status: r.status, j: await r.json() }));
  let r = await post({ chain: "base-sepolia", reportHash: HASH, tx: TX, testedBlockTimestamp: "1700000000" }); assert.equal(r.status, 200); assert.ok(r.j.ok); assert.equal(r.j.anchor.network, "Base Sepolia"); assert.equal(r.j.reportContentChecked, false);
  r = await post({ chain: "base-sepolia", reportHash: "0x" + "00".repeat(32), tx: TX }); assert.equal(r.status, 200); assert.equal(r.j.ok, false);
  r = await post({ chain: "ethereum", reportHash: HASH, tx: TX }); assert.equal(r.status, 400); assert.match(r.j.error, /Unsupported/);
  r = await post({ chain: "base-sepolia", reportHash: "0x12", tx: TX }); assert.equal(r.status, 400);
  console.log("ok server /api/anchor: verified, wrong hash, unsupported chain, malformed hash");
} finally { child.kill(); chain.close(); }

// page copy: what it proves, testnet label, no stronger claim than the evidence
const html = readFileSync(new URL("../web/index.html", import.meta.url), "utf8");
assert.ok(html.includes("Testnet anchor (Base Sepolia)")); assert.ok(html.includes("does not prove the report is right, and it was sent by the tester, not the issuer"));
assert.ok(html.includes("holds no keys and sends nothing")); assert.ok(!/timestamped on.?chain|immutable|guarantee(s|d)? (the )?(report|accuracy)|legally binding|notariz/i.test(html), "no overclaiming copy");
console.log("ok page copy: testnet labelled, says what it proves and does not prove");
console.log("anchor: all checks passed"); process.exit(0);
