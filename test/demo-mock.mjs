// Starts a mock node on :8599 whose token reverts with Error("Recipient not whitelisted"). For CLI/UI smoke tests only.
import { createServer } from "node:http";
import { keccak256, selector, pad32 } from "../evm-lite.mjs";
const T = "0x1111111111111111111111111111111111111111";
const encStr = (s) => "0x" + "20".padStart(64, "0") + Buffer.byteLength(s).toString(16).padStart(64, "0") + Buffer.from(s).toString("hex").padEnd(64, "0");
const w = (n) => BigInt(n).toString(16).padStart(64, "0");
export const start = (port) => new Promise((r) => { const srv = createServer((req, res) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => {
  const { id, method, params } = JSON.parse(b), ok = (result) => res.end(JSON.stringify({ jsonrpc: "2.0", id, result })), er = (error) => res.end(JSON.stringify({ jsonrpc: "2.0", id, error }));
  if (method === "eth_blockNumber") return ok("0x10"); if (method === "eth_chainId") return ok("0x1");
  if (method === "eth_getBlockByNumber") return ok({ hash: "0x" + "ab".repeat(32), timestamp: "0x65000000" }); if (method === "eth_getCode") return ok("0x6001");
  const [tx, , ovr] = params, sel = tx.data.slice(0, 10);
  if (sel === selector("name()")) return ok(encStr("MockToken")); if (sel === selector("symbol()")) return ok(encStr("MCK")); if (sel === selector("totalSupply()")) return ok("0x" + w(1000));
  if (sel === selector("balanceOf(address)")) return ok(ovr?.[T]?.stateDiff?.[keccak256("0x" + tx.data.slice(10, 74) + pad32("3"))] ?? "0x" + w(500));
  if (sel === selector("transfer(address,uint256)")) { const d = "0x08c379a0" + encStr("Recipient not whitelisted").slice(2); return er({ code: 3, message: "execution reverted: Recipient not whitelisted", data: d }); }
  if (sel === selector("detectTransferRestriction(address,address,uint256)")) return ok("0x" + w(1));
  if (sel === selector("messageForTransferRestriction(uint8)")) return Number(BigInt("0x" + tx.data.slice(10, 74))) === 1 ? ok(encStr("transfer-blocked")) : er({ code: 3, message: "execution reverted", data: "0x" });
  return er({ code: 3, message: "execution reverted", data: "0x" });
}); }); srv.listen(port, () => r(srv)); });
