import assert from "node:assert/strict";
import { indexFunctions, mask, findRevertSites, evidenceFor, fetchVerifiedSource } from "../source.mjs";

// comments and strings must not confuse function/brace detection
const SRC = `contract A {
    // function fake() { }
    string s = "function nope() {";
    /* function alsoFake() { */
    function real(uint256 x) public pure returns (uint256) {
        if (x > 1) { return 2; }
        return 1;
    }
    function declared(uint256 x) external;
    modifier onlyOwner() { _; }
}
`;
const fns = indexFunctions(SRC);
assert.deepEqual(fns.map((f) => [f.name, f.startLine, f.endLine, f.hasBody]), [["real", 5, 8, true], ["declared", 9, 9, false], ["onlyOwner", 10, 10, true]]);
assert.ok(!mask(SRC).includes("fake"));

const files = { "a.sol": `error Boom(uint256 a);\nfunction go() public {\n    if (x) revert Boom(1);\n    require(ok, "Not allowed");\n}\n` };
const abi = [{ type: "error", name: "Boom", inputs: [{ type: "uint256" }] }];
import { selector } from "../evm-lite.mjs";
const sel = selector("Boom(uint256)");
let r = findRevertSites(files, abi, { outcome: "revert_raw_data", rawRevertData: sel + "0".repeat(63) + "1" });
assert.deepEqual(r.sites, [{ file: "a.sol", line: 3 }]); assert.match(r.matchedBy, /custom error Boom/);
r = findRevertSites(files, abi, { outcome: "revert_reason", decoded: { reason: "Not allowed" } }); assert.deepEqual(r.sites, [{ file: "a.sol", line: 4 }]);
r = findRevertSites(files, abi, { outcome: "revert_reason", decoded: { reason: "Something else" } }); assert.equal(r.sites.length, 0); assert.match(r.note, /not found/);
r = findRevertSites(files, abi, { outcome: "revert_raw_data", rawRevertData: "0x" }); assert.equal(r.sites.length, 0);
r = findRevertSites(files, abi, { outcome: "revert_raw_data", rawRevertData: "0x4e487b71" + "0".repeat(62) + "11" }); assert.equal(r.sites.length, 0);
const e = evidenceFor({ status: "found", via: "t", address: "0x", sources: files, abi, contentHash: "0x" }, { outcome: "revert_reason", decoded: { reason: "Not allowed" } }, "revert");
assert.equal(e.function, "function go"); assert.equal(e.startLine, 2); assert.equal(e.endLine, 5); assert.deepEqual(e.markedLines, [4]);
assert.equal(evidenceFor({ status: "unavailable", reason: "nope" }, {}, "revert").available, false);

// fetch layer: v2 success, legacy fallback, total failure, no chain id
const ok = (j) => ({ ok: true, json: async () => j, text: async () => j });
let f = async (u) => (u.includes("/v2/") ? ok({ sources: { "x.sol": { content: "a\r\nb" } }, abi: [] }) : { ok: false, status: 404 });
let s = await fetchVerifiedSource({ chainId: "1", address: "0xabc", fetchImpl: f }); assert.equal(s.status, "found"); assert.equal(s.sources["x.sol"], "a\nb"); assert.match(s.contentHash, /^0x[0-9a-f]{64}$/);
f = async (u) => (u.includes("metadata.json") ? ok({ sources: { "y.sol": {} }, output: { abi: [1] } }) : u.includes("/sources/y.sol") ? ok("code") : { ok: false, status: 404 });
s = await fetchVerifiedSource({ chainId: "1", address: "0xabc", fetchImpl: f }); assert.equal(s.status, "found"); assert.match(s.via, /repo/); assert.equal(s.sources["y.sol"], "code");
s = await fetchVerifiedSource({ chainId: "1", address: "0xabc", fetchImpl: async () => { throw new Error("boom https://secret.example/key"); } }); assert.equal(s.status, "unavailable"); assert.ok(!s.reason.includes("secret.example"));
s = await fetchVerifiedSource({ chainId: null, address: "0xabc" }); assert.equal(s.status, "unavailable");
console.log("source: all checks passed");
