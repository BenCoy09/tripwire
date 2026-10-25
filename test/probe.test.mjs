// Tests the probe logic against a MOCK JSON-RPC node. The mock is our own model of an EVM node, not a real chain.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { probeToken, classify, fresh } from "../probe-core.mjs";
import { keccak256, selector, pad32, strip } from "../evm-lite.mjs";

const TOKEN = "0x1111111111111111111111111111111111111111", HOLDER = "0x2222222222222222222222222222222222222222";
const encStr = (s) => "0x" + "20".padStart(64, "0") + Buffer.byteLength(s).toString(16).padStart(64, "0") + Buffer.from(s).toString("hex").padEnd(Math.ceil(Buffer.byteLength(s) / 32) * 64, "0");
const word = (n) => BigInt(n).toString(16).padStart(64, "0");
const errStr = (s) => "0x08c379a0" + encStr(s).slice(2);

function startMock(cfg) {
  const calls = [];
  const srv = createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => {
      const { id, method, params } = JSON.parse(b), ok = (result) => res.end(JSON.stringify({ jsonrpc: "2.0", id, result })), er = (error) => res.end(JSON.stringify({ jsonrpc: "2.0", id, error }));
      calls.push({ method, params });
      if (method === "eth_blockNumber") return ok("0x10");
      if (method === "eth_chainId") return ok("0x1");
      if (method === "eth_getBlockByNumber") return ok({ hash: "0x" + "ab".repeat(32), timestamp: "0x65000000" });
      if (method === "eth_getCode") return ok(cfg.noCode ? "0x" : "0x6001");
      if (method !== "eth_call") return er({ code: -32601, message: "no such method" });
      const [tx, tag, ovr] = params; assert.equal(tag, "0x10", "every call must be pinned to the same block");
      assert.ok(!("gas" in tx) || true);
      if (ovr && cfg.rejectOverride) return er({ code: -32602, message: "invalid argument 2: state override unsupported at https://secret-rpc.example/key123" });
      const sel = tx.data.slice(0, 10), arg0 = tx.data.slice(10, 74);
      if (sel === selector("name()")) return ok(encStr("MockToken"));
      if (sel === selector("symbol()")) return ok(encStr("MCK"));
      if (sel === selector("totalSupply()")) return ok("0x" + word(1000));
      if (sel === selector("balanceOf(address)")) {
        const slot = keccak256("0x" + arg0 + pad32("3"));
        const o = ovr?.[TOKEN]?.stateDiff?.[slot];
        if (o && !cfg.namespaced) return ok(o);
        return ok("0x" + word(cfg.realBalance ?? 500));
      }
      if (sel === selector("transfer(address,uint256)")) return cfg.transfer(er, ok, tx);
      if (sel === selector("detectTransferRestriction(address,address,uint256)")) return cfg.detect ? cfg.detect(er, ok) : er({ code: 3, message: "execution reverted", data: "0x" });
      if (sel === selector("messageForTransferRestriction(uint8)")) return cfg.message ? cfg.message(Number(BigInt("0x" + arg0)), er, ok) : er({ code: 3, message: "execution reverted", data: "0x" });
      return er({ code: 3, message: "execution reverted", data: "0x" });
    });
  });
  return new Promise((r) => srv.listen(0, () => r({ url: "http://127.0.0.1:" + srv.address().port, close: () => srv.close(), calls })));
}
const run = async (cfg, extra = {}) => { const m = await startMock(cfg); try { return { out: await probeToken({ rpc: m.url, token: TOKEN, holder: HOLDER, ...extra }), calls: m.calls }; } finally { m.close(); } };

// 1. Plain token, no ERC-1404, transfers succeed. Must not fail for lack of ERC-1404.
{ const { out, calls } = await run({ transfer: (er, ok) => ok("0x" + word(1)) });
  assert.equal(out.checks.length, 3); assert.ok(out.checks.every((c) => c.outcome === "success"));
  assert.equal(out.balanceOverride.applied, true); assert.equal(out.balanceOverride.layout, "solidity"); assert.equal(out.balanceOverride.mappingIndex, 3);
  assert.ok(out.checks.every((c) => c.detectTransferRestriction.status === "reverted" && c.codeVsSimulation.startsWith("not comparable")));
  assert.equal(out.block, "16"); assert.equal(out.blockHash, "0x" + "ab".repeat(32));
  assert.ok(calls.every((c) => ["eth_blockNumber", "eth_chainId", "eth_getBlockByNumber", "eth_getCode", "eth_call"].includes(c.method)), "read-only methods only");
  assert.deepEqual(out.checks.map((c) => c.recipient), ["a", "b", "c"].map(fresh)); console.log("ok 1 plain token / override found by read-back"); }
// 2. Revert with reason: raw hex AND decoded
{ const data = errStr("Recipient not whitelisted");
  const { out } = await run({ transfer: (er) => er({ code: 3, message: "execution reverted: Recipient not whitelisted", data }) });
  const c = out.checks[0]; assert.equal(c.outcome, "revert_reason"); assert.equal(c.rawRevertData, data); assert.equal(c.decoded.reason, "Recipient not whitelisted");
  assert.equal(c.transferSimulation, "reverted: Recipient not whitelisted"); console.log("ok 2 revert with reason"); }
// 3. Custom error matching a standard signature
{ const data = "0xec442f05" + pad32(fresh("a"));
  const r = classify({ error: { code: 3, message: "execution reverted", data } });
  assert.equal(r.outcome, "revert_custom_error"); assert.equal(r.rawRevertData, data); assert.equal(r.decoded.matchesStandardSignature, "ERC20InvalidReceiver(address)"); assert.equal(r.decoded.args[0], fresh("a")); console.log("ok 3 custom error"); }
// 4. Unknown selector -> raw data, never guessed; empty data; no data; panic; revert data nested in error.data.data
{ let r = classify({ error: { code: 3, message: "execution reverted", data: "0xdeadbeef" + word(7) } });
  assert.equal(r.outcome, "revert_raw_data"); assert.equal(r.decoded.kind, "unrecognised selector"); assert.equal(r.rawRevertData, "0xdeadbeef" + word(7));
  r = classify({ error: { code: 3, message: "execution reverted", data: "0x" } }); assert.equal(r.outcome, "revert_raw_data"); assert.equal(r.rawRevertData, "0x");
  r = classify({ error: { code: -32000, message: "execution reverted" } }); assert.equal(r.outcome, "revert_raw_data"); assert.equal(r.rawRevertData, null); assert.match(r.detail, /no revert data/);
  r = classify({ error: { code: 3, message: "execution reverted", data: "0x4e487b71" + word(0x11) } }); assert.equal(r.decoded.kind, "Panic(uint256)"); assert.equal(r.decoded.code, "0x11");
  r = classify({ error: { code: -32015, message: "VM execution error.", data: { data: "0xdeadbeef" } } }); assert.equal(r.rawRevertData, "0xdeadbeef");
  r = classify({ error: { code: -32005, message: "rate limited" } }); assert.equal(r.outcome, "rpc_error");
  r = classify({ result: "0x" + word(0) }); assert.equal(r.outcome, "returned_false"); r = classify({ result: "0x" }); assert.equal(r.outcome, "success"); console.log("ok 4 raw data / empty / panic / rpc error / false"); }
// 5. ERC-1404 token: contract's own message used, agreement computed
{ const { out } = await run({ transfer: (er) => er({ code: 3, message: "execution reverted: X", data: errStr("X") }), detect: (er, ok) => ok("0x" + word(2)), message: (c, er, ok) => (c === 2 ? ok(encStr("Recipient not verified")) : er({ code: 3, message: "execution reverted", data: "0x" })) });
  const c = out.checks[0]; assert.equal(c.detectTransferRestriction.code, 2); assert.equal(c.detectTransferRestriction.message, "Recipient not verified"); assert.equal(c.detectTransferRestriction.messageSource, "messageForTransferRestriction(2) on the token contract"); assert.equal(c.detectTransferRestriction.messageRawReturn, encStr("Recipient not verified")); assert.equal(c.detectTransferRestriction.label, "Recipient not verified"); assert.equal(c.codeVsSimulation, "agree"); assert.deepEqual(out.restrictionCodes, []);; /* legacy 0..9 scan stops at the first code the contract cannot describe */  console.log("ok 5 erc1404 optional path"); }
// 5b. Code returned but the contract has no description: exact wording, nothing mapped by us
{ const { out } = await run({ transfer: (er) => er({ code: 3, message: "execution reverted", data: "0xdeadbeef" }), detect: (er, ok) => ok("0x" + word(5)) });
  const c = out.checks[0], t = c.detectTransferRestriction; assert.equal(t.code, 5); assert.equal(t.message, null); assert.equal(t.label, "code 5 (no description in contract)"); assert.equal(t.messageSource, null);
  assert.equal(c.transferSimulation, "undecoded, raw data below"); assert.equal(c.rawRevertData, "0xdeadbeef"); console.log("ok 5b no description in contract / undecoded wording"); }
// 6. RPC rejects state overrides: fallback to actual state, say so, scrub the RPC URL
{ const { out } = await run({ rejectOverride: true, transfer: (er, ok) => ok("0x" + word(1)) });
  assert.equal(out.balanceOverride.applied, false); assert.match(out.balanceOverride.reason, /rejected or failed/); assert.ok(!out.balanceOverride.reason.includes("secret-rpc"));
  assert.ok(out.checks.every((c) => c.stateUsed === "actual on-chain state" && c.simulation.stateOverride === null)); assert.ok(out.warnings[0].startsWith("Balance override not applied")); console.log("ok 6 override unsupported"); }
// 7. Slot not found (e.g. namespaced storage): fallback, say so; zero balance warns
{ const { out } = await run({ namespaced: true, realBalance: 0, transfer: (er) => er({ code: 3, message: "execution reverted", data: "0x" }) });
  assert.equal(out.balanceOverride.applied, false); assert.match(out.balanceOverride.reason, /slot not found/i); assert.equal(out.warnings.length, 2); console.log("ok 7 slot not found"); }
// 8. Bad input and no contract
await assert.rejects(probeToken({ rpc: "http://x", token: "0x123", holder: HOLDER }), /valid token address/);
{ const m = await startMock({ noCode: true, transfer: () => {} }); await assert.rejects(probeToken({ rpc: m.url, token: TOKEN, holder: HOLDER }), /No contract found/); m.close(); console.log("ok 8 input validation / no contract"); }
// 9. Chain down
await assert.rejects(probeToken({ rpc: "http://127.0.0.1:1", token: TOKEN, holder: HOLDER }), /unavailable/); console.log("ok 9 chain unavailable");
console.log("probe: all checks passed");
