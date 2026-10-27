// Tripwire anchoring (verification only). The tool never holds a key and never sends a transaction.
// The tester sends a 0-value transaction from their own wallet whose data field is the report hash; this module
// reads that transaction back and checks that it really carries the hash, then reports the block and block time.
import { hashReport } from "./report-hash.mjs";

export const NETWORKS = {
  1: { name: "Ethereum", testnet: false, explorer: "https://etherscan.io/tx/" },
  8453: { name: "Base", testnet: false, explorer: "https://basescan.org/tx/" },
  42161: { name: "Arbitrum One", testnet: false, explorer: "https://arbiscan.io/tx/" },
  84532: { name: "Base Sepolia", testnet: true, explorer: "https://sepolia.basescan.org/tx/" },
  11155111: { name: "Ethereum Sepolia", testnet: true, explorer: "https://sepolia.etherscan.io/tx/" },
};
export const PROVES = "The transaction proves this report existed at that block time and has not been edited since (any edit changes the hash); it does not prove the report is right, and it was sent by the tester, not the issuer.";
export const PROVES_WRAPPED = "The transaction proves this report existed at that block time and has not been edited since (any edit changes the hash), because the exact hash is inside the call; it does not prove the report is right, and because the transaction was relayed, the sender shown is not necessarily the tester's wallet.";
export const TESTNET_NOTE = "Testnet anchor: free to make, but testnet data carries no permanence guarantee. Use a mainnet for a record you must keep.";

const fail = (m) => Object.assign(new Error(m), { userFacing: true });
const H32 = /^0x[0-9a-fA-F]{64}$/;

async function rpcCall(url, fetchImpl, method, params) {
  let r;
  for (let i = 0; i < 2; i++) {
    try { r = await (await fetchImpl(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), signal: AbortSignal.timeout(15000) })).json(); break; } catch { r = null; }
  }
  if (!r) throw fail("The chain connection is unavailable right now. Try again shortly.");
  return r.error ? { error: r.error } : { result: r.result };
}

export async function verifyAnchor({ rpc, reportHash, testedBlockTimestamp, txHash, expectChainId, fetchImpl = fetch }) {
  const checks = [], add = (name, pass, detail) => { checks.push({ name, pass, detail }); return pass; };
  const out = () => ({ ok: checks.every((c) => c.pass), checks, anchor, proves: anchor?.mode === "wrapped" ? PROVES_WRAPPED : PROVES, testnetNote: anchor?.testnet ? TESTNET_NOTE : null });
  let anchor = null, mode = null;
  if (!H32.test(reportHash || "")) throw fail("The report hash is not a 32-byte hex value.");
  if (!add("transaction hash is well formed", H32.test(txHash || ""), "Expected 0x followed by 64 hex characters.")) return out();
  const chain = await rpcCall(rpc, fetchImpl, "eth_chainId", []);
  const chainId = chain.result ? parseInt(chain.result, 16) : null, net = NETWORKS[chainId] || null;
  if (chainId === null) throw fail("The chain connection is unavailable right now. Try again shortly.");
  if (expectChainId !== undefined && !add("RPC is on the expected chain", chainId === expectChainId, chainId === expectChainId ? `chain ${chainId}` : `expected chain ${expectChainId}, this RPC is chain ${chainId}`)) return out();
  const tx = await rpcCall(rpc, fetchImpl, "eth_getTransactionByHash", [txHash]);
  if (!add("transaction found", !!tx.result, tx.result ? "found" : "No transaction with this hash on this chain.")) return out();
  const t = tx.result;
  if (!add("transaction is mined", !!t.blockNumber, t.blockNumber ? `block ${parseInt(t.blockNumber, 16)}` : "The transaction is still pending.")) return out();
  const rc = (await rpcCall(rpc, fetchImpl, "eth_getTransactionReceipt", [txHash])).result;
  if (!add("transaction succeeded", !!rc && rc.status === "0x1", rc && rc.status === "0x1" ? "status 1" : "The receipt is missing or shows status 0 (failed).")) return out();
  const data = String(t.input ?? t.data ?? "").toLowerCase();
  const want = reportHash.toLowerCase(), direct = data === want, wrapped = !direct && data.length > want.length && data.includes(want.slice(2));
  mode = direct ? "direct" : wrapped ? "wrapped" : null;
  add("transaction data carries the report hash", direct || wrapped, direct ? "exact match" : wrapped ? `The exact hash is inside a wrapper call (selector ${data.slice(0, 10)}). The transaction was relayed, so the sender shown is not necessarily the tester's wallet.` : `The data field is ${data === "" || data === "0x" ? "empty" : data.length > 80 ? data.slice(0, 80) + "…" : data}, not the report hash.`);
  const blk = (await rpcCall(rpc, fetchImpl, "eth_getBlockByNumber", [t.blockNumber, false])).result;
  const ts = blk?.timestamp ? parseInt(blk.timestamp, 16) : null;
  add("block time is readable", ts !== null, ts !== null ? new Date(ts * 1000).toISOString() : "The block could not be read.");
  if (ts !== null && testedBlockTimestamp !== undefined && testedBlockTimestamp !== null && testedBlockTimestamp !== "")
    add("anchored after the block the report tested", ts >= Number(testedBlockTimestamp), ts >= Number(testedBlockTimestamp) ? "consistent" : "The anchor is older than the block this report claims to test, so it cannot be this report.");
  const latest = (await rpcCall(rpc, fetchImpl, "eth_blockNumber", [])).result;
  const bn = parseInt(t.blockNumber, 16);
  anchor = {
    chainId, mode, network: net ? net.name : `chain ${chainId} (unrecognised)`, testnet: net ? net.testnet : null,
    txHash, from: t.from, to: t.to, blockNumber: String(bn), blockHash: rc.blockHash || blk?.hash || null,
    blockTime: ts, blockTimeIso: ts !== null ? new Date(ts * 1000).toISOString() : null,
    confirmations: latest ? Math.max(0, parseInt(latest, 16) - bn) : null, explorerUrl: net ? net.explorer + txHash : null,
  };
  return out();
}

// With the report file itself: also prove the file still hashes to the hash it states.
export async function verifyReportAnchor({ rpc, report, txHash, expectChainId, fetchImpl }) {
  const recomputed = hashReport(report), unmodified = recomputed === report.reportHash;
  const res = await verifyAnchor({ rpc, reportHash: report.reportHash, testedBlockTimestamp: report.blockTimestamp, txHash, expectChainId, fetchImpl });
  res.checks.unshift({ name: "report file matches its own hash", pass: unmodified, detail: unmodified ? "unmodified" : `The file hashes to ${recomputed}, not the ${report.reportHash} it states. It was edited after it was written.` });
  res.ok = res.checks.every((c) => c.pass);
  return res;
}
