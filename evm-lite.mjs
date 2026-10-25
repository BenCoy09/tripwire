// Minimal EVM helpers for the read-only probe: keccak256, selectors, static ABI encode, string decode.
// Exists so the probe has no dependency it cannot be tested without. Verified against known vectors in test/.
const M = (1n << 64n) - 1n;
const rotl = (v, n) => (n === 0n ? v : ((v << n) | (v >> (64n - n))) & M);
const RC = (() => {
  const out = []; let R = 1;
  for (let i = 0; i < 24; i++) {
    let rc = 0n;
    for (let j = 0; j < 7; j++) { R = ((R << 1) ^ ((R >> 7) * 0x71)) % 256; if (R & 2) rc ^= 1n << BigInt((1 << j) - 1); }
    out.push(rc);
  }
  return out;
})();
function permute(A) {
  for (let r = 0; r < 24; r++) {
    const C = [], D = [];
    for (let x = 0; x < 5; x++) C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
    for (let x = 0; x < 5; x++) D[x] = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1n);
    for (let i = 0; i < 25; i++) A[i] ^= D[i % 5];
    let x = 1, y = 0, cur = A[1];
    for (let t = 0; t < 24; t++) {
      [x, y] = [y, (2 * x + 3 * y) % 5];
      const tmp = A[x + 5 * y];
      A[x + 5 * y] = rotl(cur, BigInt((((t + 1) * (t + 2)) / 2) % 64));
      cur = tmp;
    }
    for (let yy = 0; yy < 5; yy++) {
      const T = A.slice(5 * yy, 5 * yy + 5);
      for (let xx = 0; xx < 5; xx++) A[xx + 5 * yy] = (T[xx] ^ (~T[(xx + 1) % 5] & T[(xx + 2) % 5])) & M;
    }
    A[0] ^= RC[r];
  }
}
// pad = 0x01 is Keccak (Ethereum). 0x06 is NIST SHA3 and is only used by the tests to cross-check against Python's hashlib.
export function keccakBytes(input, pad = 0x01) {
  const data = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const rate = 136, A = new Array(25).fill(0n);
  const len = Math.floor(data.length / rate) * rate + rate;
  const buf = new Uint8Array(len); buf.set(data); buf[data.length] ^= pad; buf[len - 1] ^= 0x80;
  for (let off = 0; off < len; off += rate) {
    for (let i = 0; i < rate / 8; i++) { let l = 0n; for (let b = 7; b >= 0; b--) l = (l << 8n) | BigInt(buf[off + i * 8 + b]); A[i] ^= l; }
    permute(A);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) for (let b = 0; b < 8; b++) out[i * 8 + b] = Number((A[i] >> BigInt(8 * b)) & 0xffn);
  return out;
}
export const bytesToHex = (u) => "0x" + [...u].map((b) => b.toString(16).padStart(2, "0")).join("");
export const hexToBytes = (h) => { const s = strip(h); return Uint8Array.from(s.match(/../g) || [], (x) => parseInt(x, 16)); };
export const keccak256 = (input) => bytesToHex(keccakBytes(typeof input === "string" && /^0x([0-9a-fA-F]{2})*$/.test(input) ? hexToBytes(input) : input));
export const strip = (h) => (h.startsWith("0x") ? h.slice(2) : h);
export const selector = (sig) => keccak256(sig).slice(0, 10);
export const pad32 = (h) => strip(h).toLowerCase().padStart(64, "0");

export function toChecksum(addr) {
  const a = strip(addr).toLowerCase(), h = strip(keccak256(a));
  return "0x" + [...a].map((c, i) => (parseInt(h[i], 16) >= 8 ? c.toUpperCase() : c)).join("");
}
export function isAddress(a) {
  if (typeof a !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(a)) return false;
  const s = a.slice(2);
  return s === s.toLowerCase() || s === s.toUpperCase() || toChecksum(a) === a;
}
const typesOf = (sig) => { const m = sig.match(/^[A-Za-z0-9_]+\((.*)\)$/); if (!m) throw new Error("bad signature " + sig); return m[1] === "" ? [] : m[1].split(","); };
const encodeArg = (type, v) => {
  if (type === "address") return pad32(v);
  if (type === "bytes32") return pad32(v);
  if (/^uint\d*$/.test(type)) return BigInt(v).toString(16).padStart(64, "0");
  throw new Error("unsupported type " + type);
};
export const encodeCall = (sig, args = []) => selector(sig) + typesOf(sig).map((t, i) => encodeArg(t, args[i])).join("");

// Decode static args (address / uintN / bytes32) from revert or return data after a 4-byte selector.
export function decodeStatic(sig, dataHex) {
  const types = typesOf(sig), body = strip(dataHex).slice(8);
  if (body.length < types.length * 64) return null;
  return types.map((t, i) => {
    const w = body.slice(i * 64, i * 64 + 64);
    if (t === "address") return toChecksum("0x" + w.slice(24));
    if (t === "bytes32") return "0x" + w;
    return BigInt("0x" + w).toString();
  });
}
// Decode a single ABI-encoded string (return value of a function returning string, or Error(string) payload).
export function decodeString(hex) {
  try {
    const s = strip(hex);
    const off = Number(BigInt("0x" + s.slice(0, 64))) * 2, len = Number(BigInt("0x" + s.slice(off, off + 64)));
    const start = off + 64, end = start + len * 2;
    if (len > 4096 || end > s.length) return null;
    return new TextDecoder("utf-8", { fatal: true }).decode(hexToBytes(s.slice(start, end)));
  } catch { return null; }
}
