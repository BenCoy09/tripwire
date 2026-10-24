// Tripwire probe core: READ-ONLY check of an ERC-1404 token. eth_call simulations only.
import { createPublicClient, http, encodeFunctionData, parseAbi, isAddress, keccak256, toHex, getAddress } from "viem";

const abi = parseAbi([
  "function name() view returns (string)",
  "function symbol() view returns (string)",
  "function totalSupply() view returns (uint256)",
  "function balanceOf(address) view returns (uint256)",
  "function transfer(address,uint256) returns (bool)",
  "function detectTransferRestriction(address,address,uint256) view returns (uint8)",
  "function messageForTransferRestriction(uint8) view returns (string)",
]);
const fail = (m) => Object.assign(new Error(m), { userFacing: true });
const msg = (e) => String(e.shortMessage || e.message || e).split("\n")[0].slice(0, 160);
export const fresh = (label) => getAddress("0x" + keccak256(toHex("tripwire-fresh-" + label)).slice(26));

export async function probeToken({ rpc, token, holder }) {
  if (!isAddress(token || "") || !isAddress(holder || "")) throw fail("Enter a valid token address and holder address (0x followed by 40 characters).");
  try {
    const client = createPublicClient({ transport: http(rpc, { timeout: 15000, retryCount: 1 }) });
    const read = (functionName, args = []) => client.readContract({ address: token, abi, functionName, args });
    const out = { generatedAt: new Date().toISOString(), token: getAddress(token), holder: getAddress(holder), readOnly: true, warnings: [], checks: [] };
    try { out.block = String(await client.getBlockNumber()); } catch { throw fail("The chain connection is unavailable right now. Try again shortly."); }
    try { out.name = await read("name"); out.symbol = await read("symbol"); out.totalSupply = String(await read("totalSupply")); }
    catch { throw fail("Could not read this token. Check that the chain and the address match."); }
    const bal = await read("balanceOf", [holder]).catch(() => 0n);
    out.holderBalance = String(bal);
    if (bal === 0n) out.warnings.push("The holder address has no tokens, so results may be meaningless.");

    const codes = [];
    for (let c = 0; c < 10; c++) {
      try { codes.push({ code: c, message: await read("messageForTransferRestriction", [c]) }); } catch { break; }
    }
    out.restrictionCodes = codes;

    for (const label of ["a", "b", "c"]) {
      const to = fresh(label);
      let code = null, why = "";
      try {
        code = Number(await read("detectTransferRestriction", [holder, to, 1n]));
        why = codes.find((c) => c.code === code)?.message || (await read("messageForTransferRestriction", [code]).catch(() => ""));
      } catch (e) { why = "detectTransferRestriction failed"; }
      let sim = "succeeded";
      try { await client.call({ account: holder, to: token, data: encodeFunctionData({ abi, functionName: "transfer", args: [to, 1n] }) }); }
      catch (e) { sim = "reverted: " + msg(e).replace(/https?:\/\/\S+/g, "[url]"); }
      const blockedByCode = code !== null && code !== 0, reverts = sim.startsWith("reverted");
      let verdict;
      if (code === null) verdict = "inconclusive (no detectTransferRestriction)";
      else if (blockedByCode && reverts) verdict = "consistent: an unknown wallet is blocked";
      else if (!blockedByCode && !reverts) verdict = "NOT BLOCKED: an unknown wallet could receive tokens";
      else if (blockedByCode && !reverts) verdict = "MISMATCH: restriction code says blocked, but the transfer simulation succeeds";
      else verdict = "MISMATCH: restriction code says allowed, but the transfer simulation reverts";
      out.checks.push({ recipient: to, restrictionCode: code, restrictionMessage: why, transferSimulation: sim, verdict });
    }
    return out;
  } catch (e) {
    if (e.userFacing) throw e;
    throw fail("The probe could not complete. Check the chain, token and holder addresses.");
  }
}
