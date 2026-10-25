// Tripwire probe core (step 1): behavioural, READ-ONLY probe. eth_call simulations only: no keys, no transactions.
// Pinned to one block. Does not require ERC-1404: it records what a transfer to a fresh wallet actually does.
import { keccak256, selector, encodeCall, decodeStatic, decodeString, pad32, toChecksum, isAddress, strip } from "./evm-lite.mjs";

const fail = (m) => Object.assign(new Error(m), { userFacing: true });
const clean = (s) => String(s || "").split("\n")[0].replace(/https?:\/\/\S+/g, "[url]").slice(0, 200);
export const fresh = (label) => toChecksum("0x" + keccak256("tripwire-fresh-" + label).slice(26));

const SIG = {
  transfer: "transfer(address,uint256)",
  balanceOf: "balanceOf(address)",
  detect: "detectTransferRestriction(address,address,uint256)",
  message: "messageForTransferRestriction(uint8)",
};
// Standard error signatures. A selector match is reported as "matches", never as a meaning. The contract's own ABI is not available.
const KNOWN_ERRORS = [
  "ERC20InsufficientBalance(address,uint256,uint256)", "ERC20InvalidSender(address)", "ERC20InvalidReceiver(address)",
  "ERC20InsufficientAllowance(address,uint256,uint256)", "EnforcedPause()", "ExpectedPause()",
  "OwnableUnauthorizedAccount(address)", "AccessControlUnauthorizedAccount(address,bytes32)",
].map((sig) => ({ sig, sel: selector(sig) }));

const OVERRIDE_VALUE = 10n ** 27n + 1n; // distinctive, so a read-back proves the slot is the balance slot

function makeRpc(url, fetchImpl) {
  let id = 0;
  return async function rpc(method, params) {
    let last;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const r = await fetchImpl(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params }), signal: AbortSignal.timeout(15000) });
        const j = await r.json();
        return j.error ? { error: j.error } : { result: j.result };
      } catch (e) { last = e; }
    }
    throw fail("The chain connection is unavailable right now. Try again shortly.");
  };
}

// Find revert data in whatever shape the RPC put it. Returns lowercase 0x hex or null if the RPC gave none.
function revertDataOf(err) {
  const seen = new Set();
  const walk = (v) => {
    if (typeof v === "string" && /^0x([0-9a-fA-F]{2})*$/.test(v)) return v.toLowerCase();
    if (v && typeof v === "object" && !seen.has(v)) { seen.add(v); for (const k of ["data", "originalError", "error"]) { const r = walk(v[k]); if (r !== null) return r; } }
    return null;
  };
  return walk(err);
}
const looksLikeRevert = (err) => err.code === 3 || /revert|vm execution error/i.test(err.message || "") || revertDataOf(err) !== null;

export function classify(resp) {
  if (!resp.error) {
    const data = (resp.result || "0x").toLowerCase();
    if (/^0x0{64}$/.test(data)) return { outcome: "returned_false", returnData: data, detail: "Call did not revert but returned false (bool 0)." };
    return { outcome: "success", returnData: data };
  }
  const err = resp.error;
  if (!looksLikeRevert(err)) return { outcome: "rpc_error", detail: `RPC error ${err.code}: ${clean(err.message)}`, rawRevertData: null };
  const raw = revertDataOf(err);
  if (raw === null) return { outcome: "revert_raw_data", rawRevertData: null, detail: `Reverted, but the RPC returned no revert data (${clean(err.message)}).` };
  if (raw === "0x") return { outcome: "revert_raw_data", rawRevertData: "0x", detail: "Reverted with empty revert data." };
  const sel = raw.slice(0, 10);
  if (sel === selector("Error(string)")) {
    const reason = decodeString("0x" + raw.slice(10));
    if (reason !== null) return { outcome: "revert_reason", rawRevertData: raw, decoded: { kind: "Error(string)", reason } };
  }
  if (sel === selector("Panic(uint256)") && raw.length >= 74) return { outcome: "revert_raw_data", rawRevertData: raw, decoded: { kind: "Panic(uint256)", code: "0x" + BigInt("0x" + raw.slice(10, 74)).toString(16) } };
  const known = KNOWN_ERRORS.find((k) => k.sel === sel);
  if (known) {
    const args = decodeStatic(known.sig, raw);
    if (args) return { outcome: "revert_custom_error", rawRevertData: raw, decoded: { kind: "custom error", matchesStandardSignature: known.sig, args, note: "Selector matches a standard signature. The token's own ABI was not available to confirm." } };
  }
  return { outcome: "revert_raw_data", rawRevertData: raw, decoded: raw.length >= 10 ? { kind: "unrecognised selector", selector: sel } : null };
}

const simText = (c) => {
  if (c.outcome === "success") return "succeeded";
  if (c.outcome === "returned_false") return "returned false";
  if (c.outcome === "rpc_error") return "not simulated: " + c.detail;
  const why = c.decoded?.reason ?? c.decoded?.matchesStandardSignature ?? (c.decoded?.kind === "Panic(uint256)" ? "Panic " + c.decoded.code : null);
  if (why) return "reverted: " + why;
  return c.rawRevertData !== null && c.rawRevertData !== undefined ? "undecoded, raw data below" : c.detail;
};

export async function probeToken({ rpc: url, token, holder, fetchImpl = fetch }) {
  if (!isAddress(token || "") || !isAddress(holder || "")) throw fail("Enter a valid token address and holder address (0x followed by 40 characters).");
  token = toChecksum(token); holder = toChecksum(holder);
  const rpc = makeRpc(url, fetchImpl);
  try {
    // Pin everything to one block
    const bn = await rpc("eth_blockNumber", []);
    if (bn.error) throw fail("The chain connection is unavailable right now. Try again shortly.");
    const tag = bn.result;
    const blk = (await rpc("eth_getBlockByNumber", [tag, false])).result || {};
    const chainId = (await rpc("eth_chainId", [])).result || null;
    const code = await rpc("eth_getCode", [token, tag]);
    if (code.error || !code.result || code.result === "0x") throw fail("No contract found at this address on this chain. Check that the chain and the address match.");

    const out = {
      generatedAt: new Date().toISOString(), token, holder, readOnly: true,
      chainId: chainId ? String(parseInt(chainId, 16)) : null,
      block: String(parseInt(tag, 16)), blockHash: blk.hash || null, blockTimestamp: blk.timestamp ? String(parseInt(blk.timestamp, 16)) : null,
      warnings: [], balanceOverride: null, restrictionCodes: [], checks: [],
    };
    const call = (to, data, from, overrides) => rpc("eth_call", [{ ...(from ? { from } : {}), to, data }, tag, ...(overrides ? [overrides] : [])]);
    const str = async (fn) => { const r = await call(token, selector(fn)); return r.result && r.result !== "0x" ? decodeString(r.result) : null; };
    out.name = await str("name()"); out.symbol = await str("symbol()");
    const ts = await call(token, selector("totalSupply()")); out.totalSupply = ts.result && ts.result !== "0x" ? BigInt(ts.result).toString() : null;
    const bal = await call(token, encodeCall(SIG.balanceOf, [holder]));
    const realBalance = bal.result && bal.result !== "0x" ? BigInt(bal.result) : null;
    out.holderBalance = realBalance === null ? null : String(realBalance);

    // Balance override: find the balance mapping slot by trial and prove it by read-back. Never assumed.
    const ov = { applied: false, reason: null, layout: null, slot: null, valueSet: null, readBack: null };
    let overrides = null;
    search: for (const layout of ["solidity", "vyper"]) {
      for (let i = 0; i < (layout === "solidity" ? 25 : 10); i++) {
        const key = layout === "solidity" ? keccak256("0x" + pad32(holder) + pad32(i.toString(16))) : keccak256("0x" + pad32(i.toString(16)) + pad32(holder));
        const value = "0x" + OVERRIDE_VALUE.toString(16).padStart(64, "0");
        const ovr = { [token]: { stateDiff: { [key]: value } } };
        const r = await call(token, encodeCall(SIG.balanceOf, [holder]), null, ovr);
        if (r.error) { ov.reason = "The RPC rejected or failed an eth_call with a state override: " + clean(r.error.message); break search; }
        if (r.result && r.result !== "0x" && BigInt(r.result) === OVERRIDE_VALUE) {
          Object.assign(ov, { applied: true, layout, slot: key, valueSet: OVERRIDE_VALUE.toString(), readBack: BigInt(r.result).toString(), mappingIndex: i });
          overrides = ovr; break search;
        }
      }
    }
    if (!ov.applied && !ov.reason) ov.reason = "Balance slot not found in the standard mapping layouts (Solidity slots 0-24, Vyper slots 0-9). The token may use a different storage layout.";
    out.balanceOverride = ov;
    const stateUsed = ov.applied ? "balance overridden" : "actual on-chain state";
    if (!ov.applied) {
      out.warnings.push("Balance override not applied. " + ov.reason + " Simulations ran against the holder's actual state.");
      if (!realBalance) out.warnings.push("The holder has no readable tokens in actual state, so these simulations may revert for balance reasons.");
    }

    // detectTransferRestriction is optional and never required
    for (let c = 0; c < 10; c++) {
      const r = await call(token, encodeCall(SIG.message, [c]));
      const m = r.result && r.result !== "0x" ? decodeString(r.result) : null;
      if (m === null) break;
      out.restrictionCodes.push({ code: c, message: m, source: `messageForTransferRestriction(${c}) on the token contract`, rawReturn: r.result });
    }

    for (const label of ["a", "b", "c"]) {
      const to = fresh(label), data = encodeCall(SIG.transfer, [to, 1n]);
      const sim = classify(await call(token, data, holder, overrides));
      const d = await call(token, encodeCall(SIG.detect, [holder, to, 1n]), holder);
      const det = { status: "no_response", code: null, rawReturn: null, rawRevertData: null, message: null, messageSource: null, messageRawReturn: null, label: null };
      if (!d.error && d.result && d.result !== "0x") {
        det.status = "returned"; det.rawReturn = d.result;
        if (/^0x[0-9a-f]{64}$/i.test(d.result)) {
          det.code = Number(BigInt(d.result));
          const m = await call(token, encodeCall(SIG.message, [det.code]));
          det.message = m.result && m.result !== "0x" ? decodeString(m.result) : null;
          if (det.message !== null) { det.messageSource = `messageForTransferRestriction(${det.code}) on the token contract`; det.messageRawReturn = m.result; det.label = det.message; }
          else det.label = `code ${det.code} (no description in contract)`; // never mapped by us
        }
      } else if (d.error) { det.status = looksLikeRevert(d.error) ? "reverted" : "rpc_error"; det.rawRevertData = revertDataOf(d.error); }
      let cmp = "not comparable: detectTransferRestriction gave no usable code";
      if (det.code !== null && sim.outcome !== "rpc_error") {
        const blockedByCode = det.code !== 0, blockedBySim = sim.outcome.startsWith("revert") || sim.outcome === "returned_false";
        cmp = blockedByCode === blockedBySim ? "agree" : `disagree: code ${det.code} vs simulation ${sim.outcome}`;
      }
      out.checks.push({
        recipient: to, amount: "1", stateUsed,
        simulation: { from: holder, to: token, data, block: out.block, stateOverride: overrides },
        ...sim, detectTransferRestriction: det, codeVsSimulation: cmp,
        // fields the current web UI reads
        restrictionCode: det.code, restrictionMessage: det.message, transferSimulation: simText(sim),
      });
    }
    return out;
  } catch (e) {
    if (e.userFacing) throw e;
    throw fail("The probe could not complete. Check the chain, token and holder addresses.");
  }
}
