# Tripwire

Tokenized assets are sold with legal terms (lock-ups, accredited-only buyers, holder caps,
blocked countries). Nobody checks that the token's code enforces those terms.
Tripwire reads the terms, then tries to break each promise against the token on a real chain.

## What is in this repo
- `src/RestrictedToken.sol`  reference token. Two builds from one codebase: "deployed" (3 planted defects) and "patched".
- `run.mjs`                  attack runner. Deploys a fresh token per attack to a local anvil chain, fires the should-be-illegal transfer, records the revert reason or the breach tx hash.
- `rules.json`               the promises under test (the same four rule types the web app extracts from offering terms).

## Planted defects in the deployed build
1. Parameter drift: lock-up is 180 days, the terms promise 360.
2. Bypass path: `transferFrom()` skips the accredited-investor check.
3. Missing check: the holder cap is enforced at issuance only.

## Run it (Ubuntu)
```bash
# one-time
curl -L https://foundry.paradigm.xyz | bash && source ~/.bashrc && foundryup
sudo apt-get install -y nodejs npm      # Node 18+; or use nvm
npm install

# every time
forge build
anvil &                                  # local chain, leave running
node run.mjs deployed                    # expect: 1 of 4 promises held, exit code 1
node run.mjs patched                     # expect: 4 of 4 promises held, exit code 0
```
Each run writes `report-<token>.json` with every attack and its transaction hash.
The holder-cap attack fills the cap before attacking (about 1,000 transactions at 500 holders).
Lower `holderCap` in `rules.json` for quick tries.

## What this does and does not prove
It tests mechanical enforcement: does the code refuse what the terms forbid. It does not judge
whether the terms are legally sufficient and is not legal advice.

## Web app
`web/index.html` is the Tripwire app: paste offering terms, extract the promises, attack a token model, read the redline report.
It is a single static file with no build step. `render.yaml` deploys it to Render as a static site (publish directory `web`).
The chain runner (`run.mjs`) stays local; the web app uses a simulated token model.
