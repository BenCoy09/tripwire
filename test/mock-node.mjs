// A MOCK JSON-RPC node for tests. It is our own model of an EVM node, not a real chain.
import { createServer } from "node:http";
import assert from "node:assert/strict";
import { keccak256, selector, pad32 } from "../evm-lite.mjs";

export const TOKEN = "0x1111111111111111111111111111111111111111", HOLDER = "0x2222222222222222222222222222222222222222", CONTROL = "0x3333333333333333333333333333333333333333";
export const word = (n) => BigInt(n).toString(16).padStart(64, "0");
export const encStr = (s) => "0x" + "20".padStart(64, "0") + Buffer.byteLength(s).toString(16).padStart(64, "0") + Buffer.from(s).toString("hex").padEnd(Math.ceil(Buffer.byteLength(s) / 32) * 64, "0");
export const errStr = (s) => "0x08c379a0" + encStr(s).slice(2);
export const BLOCK_TS = Date.parse("2026-10-01T00:00:00Z") / 1000;
const CLOCK_CODE = "0x4260005260206000f3";

// cfg.transfer({to, time, hasOverride}) -> {revert: "0x.." } | {ok: "0x.."}
export function startMock(cfg = {}) {
  const calls = [];
  const srv = createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => {
      const { id, method, params } = JSON.parse(b), ok = (result) => res.end(JSON.stringify({ jsonrpc: "2.0", id, result })), er = (error) => res.end(JSON.stringify({ jsonrpc: "2.0", id, error }));
      calls.push({ method, params });
      const pin = cfg.pinned ?? 16, tagHex = "0x" + pin.toString(16);
      if (method === "eth_blockNumber") return ok(tagHex);
      if (method === "eth_chainId") return ok("0x1");
      if (method === "eth_getBlockByNumber") return params[0] !== tagHex && !cfg.anyBlock ? ok(null) : ok({ hash: "0x" + "ab".repeat(32), timestamp: "0x" + (cfg.blockTs ?? BLOCK_TS).toString(16) });
      if (method === "eth_getCode") return ok(params[0].toLowerCase() === TOKEN ? (cfg.code ?? "0x6001") : "0x6001");
      if (method === "eth_getStorageAt") return ok("0x" + word(0));
      if (method !== "eth_call") return er({ code: -32601, message: "no such method" });
      const [tx, tag, ovr, blockOv] = params;
      if (!cfg.anyBlock) assert.equal(tag, tagHex, "every call must use the pinned block");
      if (blockOv && cfg.rejectBlockOverride) return er({ code: -32602, message: "too many arguments" });
      const time = blockOv?.time && !cfg.ignoreBlockOverride ? parseInt(blockOv.time, 16) : (cfg.blockTs ?? BLOCK_TS);
      if (tx.to.toLowerCase() !== TOKEN) { // clock contract
        const code = ovr?.[tx.to]?.code;
        return code === CLOCK_CODE ? ok("0x" + word(time)) : ok("0x");
      }
      if (ovr && cfg.rejectOverride) return er({ code: -32602, message: "invalid argument 2: state override unsupported" });
      const sel = tx.data.slice(0, 10), arg0 = tx.data.slice(10, 74);
      if (sel === selector("name()")) return ok(encStr("MockToken"));
      if (sel === selector("symbol()")) return ok(encStr("MCK"));
      if (sel === selector("totalSupply()")) return ok("0x" + word(cfg.totalSupply ?? 1000));
      if (sel === selector("decimals()")) return cfg.noDecimals ? er({ code: 3, message: "execution reverted", data: "0x" }) : ok("0x" + word(cfg.decimals ?? 18));
      if (sel === selector("paused()")) return cfg.hasPaused ? ok("0x" + word(0)) : er({ code: 3, message: "execution reverted", data: "0x" });
      if (sel === selector("balanceOf(address)")) {
        const o = ovr?.[TOKEN]?.stateDiff?.[keccak256("0x" + arg0 + pad32("3"))];
        return o ? ok(o) : ok("0x" + word(cfg.realBalance ?? 500));
      }
      if (sel === selector("transfer(address,uint256)")) {
        const r = cfg.transfer({ to: "0x" + tx.data.slice(34, 74), time, hasOverride: !!ovr });
        return r.revert !== undefined ? er({ code: 3, message: "execution reverted", data: r.revert }) : ok(r.ok);
      }
      return er({ code: 3, message: "execution reverted", data: "0x" });
    });
  });
  return new Promise((r) => srv.listen(0, () => r({ url: "http://127.0.0.1:" + srv.address().port, port: srv.address().port, close: () => srv.close(), calls })));
}
export const TRUE = "0x" + word(1);
export const customErr = "0x" + selector("TransferNotAllowed(address)").slice(2) + word(0);
