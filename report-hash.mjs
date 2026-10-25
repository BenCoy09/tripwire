// Report hashing for reproducibility. The hash covers everything that is deterministic given (block, token, holder,
// control, memo): block, simulations, raw revert data, verdicts. It skips the clock, free-text RPC messages and itself.
import { keccak256 } from "./evm-lite.mjs";

const SKIP = new Set(["generatedAt", "reportHash", "detail", "warnings"]);
export function canonicalJson(v) {
  if (v === undefined) return undefined;
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map((x) => canonicalJson(x) ?? "null").join(",") + "]";
  return "{" + Object.keys(v).filter((k) => !SKIP.has(k) && v[k] !== undefined).sort().map((k) => JSON.stringify(k) + ":" + canonicalJson(v[k])).join(",") + "}";
}
export const hashReport = (report) => keccak256(canonicalJson(report));
// Which top-level sections differ between two reports (for --verify output)
export function diffSections(a, b) {
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]); const out = [];
  for (const k of keys) if (!SKIP.has(k) && canonicalJson(a[k]) !== canonicalJson(b[k])) out.push(k);
  return out.sort();
}
