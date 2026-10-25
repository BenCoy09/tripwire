import assert from "node:assert/strict";
import { keccakBytes, keccak256, bytesToHex, selector, encodeCall, isAddress, toChecksum, decodeStatic, decodeString } from "../evm-lite.mjs";

// Known Keccak-256 vectors
assert.equal(keccak256(new Uint8Array(0)), "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
assert.equal(keccak256("abc"), "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
assert.equal(selector("transfer(address,uint256)"), "0xa9059cbb");
assert.equal(selector("balanceOf(address)"), "0x70a08231");
assert.equal(selector("Error(string)"), "0x08c379a0");
assert.equal(selector("Panic(uint256)"), "0x4e487b71");
// Multi-block correctness: same permutation as SHA3-256 (only the pad byte differs), cross-checked with Python hashlib
const vec = {"0": "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", "1": "e3ed56bd086d8958483a12734fa0ae7f5c8bb160ef9092c67e82ed9b19e4c7b2", "135": "d9dcf1f98e49a79b0643a9e68fef48079ff8777c5e7e7f93469ded65f192ac71", "136": "743bd32e775ac7387a57d4d574c89ddef5ebcb08bb5cc6b88c55a27b5035cc45", "137": "01d47e8d6dce6e3dcbf1baa6f845b6ace4ef74bd17da8176ecc49bc35dbe5d21", "272": "ddeb5151c079739970e780e6257d0c4d52d83bf82c6aa8d47d5195530b5d5f4b", "300": "064af3405aacb53d5d77ee858fec1e6e225480de3f14f06444e2b33d92d61879"};
for (const [n, want] of Object.entries(vec)) {
  const d = Uint8Array.from({ length: Number(n) }, (_, i) => (i * 7 + 3) % 256);
  assert.equal(bytesToHex(keccakBytes(d, 0x06)).slice(2), want, "sha3 cross-check len " + n);
}
// EIP-55 reference vector
assert.equal(toChecksum("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"), "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
assert.ok(isAddress("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"));
assert.ok(!isAddress("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD"));
// encode / decode round trips
const cd = encodeCall("transfer(address,uint256)", ["0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", 1n]);
assert.equal(cd.length, 2 + 8 + 128);
assert.deepEqual(decodeStatic("transfer(address,uint256)", cd), ["0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "1"]);
const enc = "0x" + "20".padStart(64, "0") + "5".padStart(64, "0") + Buffer.from("hello").toString("hex").padEnd(64, "0");
assert.equal(decodeString(enc), "hello");
assert.equal(decodeString("0x1234"), null);
console.log("evm-lite: all checks passed");
