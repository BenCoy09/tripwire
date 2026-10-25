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

## Wording
Reports say "enforced" and "not enforced", never "breach", and "All tests passed" instead of "certified".
Findings describe what the code does under test conditions. They are not accusations or legal conclusions.
Add `--private` to `make-report.mjs` to stamp a report as a private draft for issuer review.

## Run the app (live probe)
```bash
npm install
node server.mjs          # http://localhost:3000
```
The server serves the site and exposes `POST /api/probe`, which runs the read-only ERC-1404 probe for a token
you paste in. Set `RPC_ETHEREUM`, `RPC_BASE`, `RPC_ARBITRUM` to your own RPC URLs for reliability.
Deploy on Render as a **Web Service** (build `npm install`, start `node server.mjs`); see `render.yaml`.
