// Tripwire source evidence: fetch VERIFIED source (Sourcify, no key) and locate, by exact match only,
// the lines behind a simulated revert. Nothing here guesses: no match means "not located".
import { keccak256, selector, strip, toChecksum } from "./evm-lite.mjs";

const SLOT_1967_IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const clean = (s) => String(s || "").split("\n")[0].replace(/https?:\/\/\S+/g, "[url]").slice(0, 160);

export async function resolveImplementation(rpc, token, tag) {
  const r = await rpc("eth_getStorageAt", [token, SLOT_1967_IMPL, tag]);
  if (r.error || typeof r.result !== "string") return null;
  const w = strip(r.result).padStart(64, "0");
  return /^0+$/.test(w) ? null : toChecksum("0x" + w.slice(24));
}

const hashSources = (sources) => keccak256(Object.keys(sources).sort().map((k) => k + "\u0000" + sources[k]).join("\u0001"));
const norm = (t) => String(t).replace(/\r\n/g, "\n");

export async function fetchVerifiedSource({ chainId, address, fetchImpl = fetch, timeoutMs = 15000 }) {
  if (!chainId) return { status: "unavailable", reason: "Chain id unknown, so verified source could not be looked up." };
  const get = async (url) => {
    const r = await fetchImpl(url, { signal: AbortSignal.timeout(timeoutMs) });
    if (!r.ok) throw new Error("HTTP " + r.status);
    return r;
  };
  const attempts = [];
  try { // Sourcify v2
    const j = await (await get(`https://sourcify.dev/server/v2/contract/${chainId}/${address}?fields=sources,abi`)).json();
    if (j && j.sources && Object.keys(j.sources).length) {
      const sources = {}; for (const [k, v] of Object.entries(j.sources)) sources[k] = norm(v.content ?? v);
      if (JSON.stringify(sources).length > 3e6) return { status: "unavailable", reason: "Verified source is larger than the 3 MB limit." };
      return { status: "found", via: "sourcify v2", address, sources, abi: Array.isArray(j.abi) ? j.abi : [], contentHash: hashSources(sources) };
    }
    attempts.push("v2: no sources in response");
  } catch (e) { attempts.push("v2: " + clean(e.message)); }
  for (const kind of ["full_match", "partial_match"]) { // Sourcify legacy repo
    try {
      const base = `https://repo.sourcify.dev/contracts/${kind}/${chainId}/${address}`;
      const meta = await (await get(base + "/metadata.json")).json();
      const sources = {};
      for (const k of Object.keys(meta.sources || {})) sources[k] = norm(await (await get(`${base}/sources/${k}`)).text());
      if (Object.keys(sources).length) return { status: "found", via: "sourcify repo " + kind, address, sources, abi: meta.output?.abi || [], contentHash: hashSources(sources) };
    } catch (e) { attempts.push(kind + ": " + clean(e.message)); }
  }
  return { status: "unavailable", reason: "No verified source found for this address. " + attempts.join("; ") };
}

// Replace comments and string literals with spaces (newlines kept) so brace matching and searches see code only.
export function mask(t) {
  let o = "", i = 0; const n = t.length;
  while (i < n) {
    const c = t[i], d = t[i + 1];
    if (c === "/" && d === "/") { while (i < n && t[i] !== "\n") { o += " "; i++; } }
    else if (c === "/" && d === "*") { o += "  "; i += 2; while (i < n && !(t[i] === "*" && t[i + 1] === "/")) { o += t[i] === "\n" ? "\n" : " "; i++; } o += "  "; i += 2; }
    else if (c === '"' || c === "'") { o += c; i++; while (i < n && t[i] !== c) { if (t[i] === "\\") { o += " "; i++; } o += t[i] === "\n" ? "\n" : " "; i++; } o += c; i++; }
    else { o += c; i++; }
  }
  return o.slice(0, n);
}
const lineStarts = (t) => { const a = [0]; for (let i = 0; i < t.length; i++) if (t[i] === "\n") a.push(i + 1); return a; };
const lineOf = (starts, idx) => { let lo = 0, hi = starts.length - 1; while (lo < hi) { const m = (lo + hi + 1) >> 1; if (starts[m] <= idx) lo = m; else hi = m - 1; } return lo + 1; };

export function indexFunctions(text) {
  const m = mask(text), starts = lineStarts(text), out = [];
  const re = /\b(function|modifier)\s+([A-Za-z_$][\w$]*)/g; let x;
  while ((x = re.exec(m))) {
    let i = re.lastIndex, depth = 0, body = false;
    for (; i < m.length; i++) {
      const c = m[i];
      if (c === "(") depth++; else if (c === ")") depth--;
      else if (depth === 0 && c === ";") break;
      else if (depth === 0 && c === "{") { body = true; break; }
    }
    if (!body) { out.push({ name: x[2], kind: x[1], startLine: lineOf(starts, x.index), endLine: lineOf(starts, i), hasBody: false }); continue; }
    let d = 0, j = i;
    for (; j < m.length; j++) { if (m[j] === "{") d++; else if (m[j] === "}") { d--; if (d === 0) break; } }
    out.push({ name: x[2], kind: x[1], startLine: lineOf(starts, x.index), endLine: lineOf(starts, j), hasBody: true });
  }
  return out;
}
const enclosing = (funcs, line) => funcs.filter((f) => f.hasBody && f.startLine <= line && line <= f.endLine).sort((a, b) => (a.endLine - a.startLine) - (b.endLine - b.startLine))[0] || null;

const errorSelectors = (abi) => (abi || []).filter((e) => e.type === "error" && !(e.inputs || []).some((i) => /tuple/.test(i.type)))
  .map((e) => ({ name: e.name, sel: selector(`${e.name}(${(e.inputs || []).map((i) => i.type).join(",")})`) }));

export function findRevertSites(files, abi, sim) {
  const sites = [];
  const push = (file, line) => { if (!sites.some((s) => s.file === file && s.line === line)) sites.push({ file, line }); };
  if (sim.outcome === "revert_reason" && sim.decoded?.reason) {
    const r = sim.decoded.reason;
    for (const [file, text] of Object.entries(files)) text.split("\n").forEach((l, i) => { if (l.includes(`"${r}"`) || l.includes(`'${r}'`)) push(file, i + 1); });
    return { matchedBy: "exact revert-reason string found in the verified source", sites: sites.slice(0, 8), note: sites.length ? null : "The revert reason string was not found in the verified source." };
  }
  const raw = sim.rawRevertData;
  if (typeof raw === "string" && raw.length >= 10 && !/^0x(08c379a0|4e487b71)/.test(raw)) {
    const sel = raw.slice(0, 10), hit = errorSelectors(abi).find((e) => e.sel === sel);
    if (!hit) return { matchedBy: null, sites: [], note: `Revert selector ${sel} is not among the errors in the verified ABI.` };
    for (const [file, text] of Object.entries(files)) {
      const masked = mask(text).split("\n");
      masked.forEach((l, i) => { if (new RegExp(`(?:\\brevert\\s+|,\\s*)${hit.name}\\s*\\(`).test(l) && !new RegExp(`\\berror\\s+${hit.name}\\b`).test(l)) push(file, i + 1); });
    }
    return { matchedBy: `custom error ${hit.name}: selector ${sel} matches the verified ABI`, errorName: hit.name, sites: sites.slice(0, 8), note: sites.length ? null : `Error ${hit.name} is in the ABI but no revert statement using it was found.` };
  }
  return { matchedBy: null, sites: [], note: "Empty, panic or undecodable revert data cannot be matched to a source line." };
}

function buildSnippet(text, fn, marks, cap = 60) {
  const lines = text.split("\n"); let from = fn.startLine, to = fn.endLine, truncated = false;
  if (to - from + 1 > cap) { const c = marks[0] || from; from = Math.max(fn.startLine, c - 15); to = Math.min(fn.endLine, c + 15); truncated = true; }
  const snippet = []; for (let n = from; n <= to; n++) snippet.push({ line: n, text: lines[n - 1] ?? "", marked: marks.includes(n) });
  return { snippet, truncated };
}

// role "revert": mark the line(s) that emit the simulated revert. role "entry": no revert happened, so mark the
// function header that executed; the tool cannot locate a MISSING check and says so.
export function evidenceFor(src, sim, role, fnName = "transfer") {
  if (!src || src.status !== "found") return { available: false, reason: src?.reason || "Source lookup not attempted." };
  const files = src.sources, meta = { via: src.via, address: src.address, contentHash: src.contentHash };
  const funcCache = {}; const funcs = (f) => (funcCache[f] ||= indexFunctions(files[f]));
  if (role === "revert") {
    const r = findRevertSites(files, src.abi, sim);
    if (!r.sites.length) return { available: true, located: false, note: r.note, ...meta };
    const first = r.sites[0], fn = enclosing(funcs(first.file), first.line);
    const marks = r.sites.filter((s) => s.file === first.file && (!fn || (s.line >= fn.startLine && s.line <= fn.endLine))).map((s) => s.line);
    const range = fn || { startLine: Math.max(1, first.line - 8), endLine: first.line + 8, name: null };
    const { snippet, truncated } = buildSnippet(files[first.file], range, marks);
    return { available: true, located: true, file: first.file, function: fn ? `${fn.kind} ${fn.name}` : null, startLine: range.startLine, endLine: range.endLine, markedLines: marks, matchedBy: r.matchedBy, candidateSites: r.sites.length, snippet, truncated, ...meta };
  }
  const cands = [];
  for (const f of Object.keys(files)) for (const fn of funcs(f)) if (fn.name === fnName && fn.hasBody && fn.kind === "function") cands.push({ f, fn });
  cands.sort((a, b) => /(^|\/)(I[A-Z]|interfaces?\/)/.test(a.f) - /(^|\/)(I[A-Z]|interfaces?\/)/.test(b.f));
  if (!cands.length) return { available: true, located: false, note: `No function named ${fnName} with a body was found in the verified source.`, ...meta };
  const { f, fn } = cands[0], { snippet, truncated } = buildSnippet(files[f], fn, [fn.startLine]);
  return { available: true, located: true, file: f, function: `function ${fn.name}`, startLine: fn.startLine, endLine: fn.endLine, markedLines: [fn.startLine], matchedBy: "entry point of the function that was simulated. The tool cannot locate a missing check; the marked line is where execution began.", candidateSites: cands.length, snippet, truncated, ...meta };
}
