// Tripwire app server: serves the site and runs read-only token probes.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { probeToken } from "./probe-core.mjs";
import { verifyAnchor } from "./anchor.mjs";

const root = join(fileURLToPath(new URL(".", import.meta.url)), "web");
const CHAINS = {
  ethereum: process.env.RPC_ETHEREUM || "https://ethereum-rpc.publicnode.com",
  base: process.env.RPC_BASE || "https://mainnet.base.org",
  arbitrum: process.env.RPC_ARBITRUM || "https://arb1.arbitrum.io/rpc",
};
const ANCHOR_CHAINS = { "base-sepolia": { rpc: process.env.RPC_BASE_SEPOLIA || "https://sepolia.base.org", chainId: 84532 } };
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".json": "application/json", ".mp4": "video/mp4", ".svg": "image/svg+xml" };
const hits = new Map();
const limited = (ip) => { const now = Date.now(); const a = (hits.get(ip) || []).filter((t) => now - t < 600000); a.push(now); hits.set(ip, a); return a.length > 12; };
const readBody = (req) => new Promise((resolve, reject) => {
  let s = "";
  req.on("data", (c) => { s += c; if (s.length > 64000) { reject(new Error("too large")); req.destroy(); } });
  req.on("end", () => resolve(s));
  req.on("error", reject);
});

const server = createServer(async (req, res) => {
  const send = (code, body, type = "application/json") => {
    res.writeHead(code, { "content-type": type, "x-content-type-options": "nosniff", "cache-control": "no-store" });
    res.end(Buffer.isBuffer(body) || typeof body === "string" ? body : JSON.stringify(body));
  };
  try {
    const url = new URL(req.url, "http://localhost");
    if (url.pathname === "/healthz") return send(200, "ok", "text/plain");
    if (url.pathname === "/api/probe" && req.method === "POST") {
      const ip = String(req.headers["x-forwarded-for"] || req.socket.remoteAddress).split(",")[0].trim();
      if (limited(ip)) return send(429, { error: "Too many probes from this address. Try again in a few minutes." });
      let b;
      try { b = JSON.parse(await readBody(req)); } catch { return send(400, { error: "Bad request." }); }
      const rpc = CHAINS[b.chain];
      if (!rpc) return send(400, { error: "Unsupported chain." });
      try {
        const out = await Promise.race([
          probeToken({ rpc, token: String(b.token || ""), holder: String(b.holder || ""), control: b.control ? String(b.control) : undefined, block: b.block ? String(b.block) : undefined, memo: b.memo ? String(b.memo) : "" }),
          new Promise((_, rej) => setTimeout(() => rej(Object.assign(new Error("The probe timed out. Try again."), { userFacing: true })), 120000)),
        ]);
        return send(200, out);
      } catch (e) { return send(400, { error: e.userFacing ? e.message : "The probe could not complete." }); }
    }
    if (url.pathname === "/api/anchor" && req.method === "POST") {
      const ip = String(req.headers["x-forwarded-for"] || req.socket.remoteAddress).split(",")[0].trim();
      if (limited(ip)) return send(429, { error: "Too many requests from this address. Try again in a few minutes." });
      let b;
      try { b = JSON.parse(await readBody(req)); } catch { return send(400, { error: "Bad request." }); }
      const net = ANCHOR_CHAINS[b.chain];
      if (!net) return send(400, { error: "Unsupported anchor chain." });
      try {
        const res = await verifyAnchor({ rpc: net.rpc, reportHash: String(b.reportHash || ""), testedBlockTimestamp: b.testedBlockTimestamp, txHash: String(b.tx || "").trim(), expectChainId: net.chainId });
        return send(200, { ...res, reportContentChecked: false });
      } catch (e) { return send(400, { error: e.userFacing ? e.message : "The anchor check could not complete." }); }
    }
    if (req.method !== "GET" && req.method !== "HEAD") return send(405, { error: "Method not allowed." });
    let p = decodeURIComponent(url.pathname);
    if (p === "/") p = "/index.html";
    const file = join(root, normalize(p));
    if (!file.startsWith(root + sep)) return send(403, { error: "Forbidden." });
    return send(200, await readFile(file), TYPES[extname(file)] || "application/octet-stream");
  } catch { return send(404, "Not found", "text/plain"); }
});
server.listen(process.env.PORT || 3000, () => console.log("Tripwire listening on " + (process.env.PORT || 3000)));
