# Tripwire

**Audits check if a token's code is safe. Tripwire checks if the code keeps the legal promises.**

Tokenized securities are sold with legal terms: lock-ups, accredited-only buyers, holder caps,
blocked countries. Those terms are meant to be enforced by the token's smart contract. Nobody
checks that the code and the paperwork match. Tripwire reads the terms, tries every move that
should be illegal against the token on a real EVM chain, and files a stamped test report.

## Try it
- Web demo: https://tripwire-uw6f.onrender.com (simulated token model)
- Real chain run: see "Run it" below. The deployed reference token holds 1 of 4 promises, the patched build 4 of 4.

## Run it (Linux, macOS, or Windows with WSL)
Requirements: Foundry (`forge`, `anvil`) and Node 18+.
```bash
npm install
forge build
anvil &                       # local chain
node run.mjs deployed         # expect: 1 of 4 promises held
node run.mjs patched          # expect: 4 of 4 promises held
npm run report                # writes report-deployed.html and report-patched.html
```
Each run writes `report-<token>.json` with every attack and its transaction hash. `make-report.mjs`
turns it into a standalone, shareable HTML test report with a serial number and verdict stamp.

## Use it in CI
`.github/workflows/tripwire.yml` runs the attacks on every push and fails the build if any promise
is breached, then uploads the report. The point: run Tripwire before every token upgrade, because an
upgrade or permission change can silently break a restriction.

## What it tests
Lock-up periods, accredited-only transfers (including the `transferFrom` bypass path), holder caps,
and blocked jurisdictions, plus a control check that a compliant transfer still goes through.
It tests mechanical enforcement, not legal sufficiency, and is not legal advice.

## Roadmap
1. **Real tokens.** Point Tripwire at a deployed ERC-1404 or ERC-3643 token on a forked chain, using
   a per-token profile instead of our reference contract.
2. **Real documents.** Replace the pattern-matching extractor with AI extraction, with a human
   confirming every rule before anything runs.
3. **Hosted app.** Upload terms, paste a token address, get a shareable report and a verification badge.
4. **Continuous mode.** Re-test on every upgrade and alert on drift.

## Repository
- `src/RestrictedToken.sol` reference token (deployed build with three planted defects, patched build)
- `run.mjs` attack runner, `make-report.mjs` HTML report, `rules.json` the promises under test
- `web/index.html` the web demo (static site, deployed on Render)

## Probe a live token (read-only, ERC-1404 not required)
```bash
node probe.mjs --rpc <https RPC url> --token 0xTOKEN --holder 0xSOME_CURRENT_HOLDER
```
Pins one block, overrides the holder's balance in an `eth_call` state override (slot found by trial and proven by
read-back, otherwise actual state is used and the report says so), simulates `transfer` to three fresh wallets and
records the outcome: success, revert with reason, revert with custom error, or revert with raw data, always with the raw
hex. `detectTransferRestriction` is called if present and never required. No transactions, no keys. Observations only: no verdict.
`npm test` runs the logic tests against a mock node.

## Terms, verdicts, reproducibility (v0.8)
Paste the offering terms (web box, or `--memo memo.txt`). The extractor pulls out each promise into one of seven fixed
categories with the exact quoted sentence; a validator rejects anything whose quote is not an exact substring of the memo.
**No memo means no verdict of any kind**: the report says "No terms supplied" and lists observations only.

One verdict per promise, no score, no grade:
- **ENFORCED**: a simulation behaved exactly as the memo says AND a control rules out another cause.
- **NOT_ENFORCED**: a simulation showed the opposite of the memo (or supply above a stated cap).
- **UNTESTABLE**: this tool cannot build a simulation that exercises the promise.
- **UNVERIFIABLE**: simulations or evidence exist but cannot settle it either way.

| Category | What is simulated | Can it say ENFORCED? |
|---|---|---|
| Transfer restriction | holder to 3 fresh wallets must be blocked, plus a control wallet you supply (`--control`) must succeed | yes, only with the control |
| Lock-up | same transfer at the block's own clock (must be blocked) and with the clock set one day after the end date (must succeed); clock override is proven first; actual state, no balance override | yes, only if the lock-up was still active at the block |
| Supply cap | totalSupply vs the memo number | never (above the cap is NOT_ENFORCED; under it is UNVERIFIABLE) |
| Holder cap, jurisdiction block | nothing | no, UNTESTABLE |
| Freeze / forced transfer, pause | bytecode selector scan, `paused()` read | no, UNVERIFIABLE |

Each verdict carries the memo quote, test inputs (calldata, state, clock), block number, and where verified source is
available (Sourcify, no key) the function, file, line range and snippet with the revert line marked. The line is found by
exact match only: the revert-reason string, or a custom error whose selector matches the verified ABI. If nothing matches, it says so.
When no revert happened (NOT_ENFORCED), the marked line is the entry point that ran; the tool cannot locate a missing check.

Verdicts apply to the tested holder only. Subgroup promises (insiders, founders...) are never called NOT_ENFORCED from one holder.

**Reproducibility.** Every report records the block, block hash, memo text and a `reportHash` (keccak256 of the canonical
report minus clock and free-text RPC messages). Re-run exactly:
```bash
node probe.mjs --verify probe-SYMBOL.json --rpc <archive RPC url>
```
It prints MATCH, or DIFFERENT with the sections that differ, and flags a file edited after it was written.
Old blocks need an archive RPC; the report says so if the RPC cannot serve the block.

## Anchoring a report (testnet)
Tripwire holds no keys and never sends a transaction. To anchor a report you do it yourself:
1. In your own wallet on **Base Sepolia** (a test network; the gas is free from a faucet), send a transaction of 0 ETH with the report's `reportHash` as the hex data, to any address that is not one of your own
   wallet accounts (for example the burn address `0x000000000000000000000000000000000000dEaD`; MetaMask refuses data on transactions to your own accounts).
2. Check it, either on the page (paste the transaction hash under the report) or with the CLI:
```bash
node probe.mjs --verify-anchor probe-SYMBOL.json --tx 0x<transaction hash> --rpc https://sepolia.base.org
```
It checks the transaction exists, succeeded, and carries exactly this hash, then prints the network, block, block time,
sender and a block explorer link. The CLI also checks that the report file still hashes to the hash it states, so an edited
file fails. The page cannot see the file, so it checks the hash only and says so.

**What it proves, in one sentence:** the transaction proves this report existed at that block time and has not been edited
since (any edit changes the hash); it does not prove the report is right, and it was sent by the tester, not the issuer.
It is a testnet anchor: free, but testnet data carries no permanence guarantee. Use a mainnet for a record you must keep.

## Wording
Reports say "enforced" and "not enforced", never "breach", and "All tests passed" instead of "certified".
Findings describe what the code does under test conditions. They are not accusations or legal conclusions.
Add `--private` to `make-report.mjs` to stamp a report as a private draft for issuer review.

## Run the app (live probe)
```bash
npm install
node server.mjs          # http://localhost:3000
```
The server serves the site and exposes `POST /api/probe`, which runs the read-only probe for any ERC-20 token
you paste in. Set `RPC_ETHEREUM`, `RPC_BASE`, `RPC_ARBITRUM` to your own RPC URLs for reliability.
Deploy on Render as a **Web Service** (build `npm install`, start `node server.mjs`); see `render.yaml`.
