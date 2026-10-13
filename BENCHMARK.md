# erc20-vault proving cost: compactc vs the MinoCrab port

> **Dated record (2026-09-05).** These numbers are the seventeen-circuit vault of sig-net/midnight-examples `0d9c1660`. The vault was re-ported to upstream's flush-pattern redesign (29 circuits, `375071b`) in M44 — see `notes/vault-flush.org` — and the re-run on those circuits is that milestone's open item; the row counts the test suite freezes today are in `crates/minocrab-contracts/tests/row_snapshot.rs`.

MinoCrab is a Rust eDSL for Midnight that compiles to ZKIR, replacing the
Compact language. This report benchmarks the real sig-net cross-chain
contracts — all **17 circuits** of `erc20-vault` (sig-net/midnight-examples
`0d9c1660`, the Poseidon protocol with the Aave lending flows) plus the 3
circuits of its Signet singleton dependency (sig-net/midnight-integration
`fff3421c`) — at the same pinned toolchain versions, across two artifacts:

- **compactc** — the Compact contracts compiled by `compactc 0.33.0-rc.2`.
- **minocrab** — MinoCrab's direct port. Statement-identical to compactc:
  same typed schema, same shared `ProofPreimage`, equal public-input
  streams (`pis`/`pi_skips`), proven per circuit by the differential
  suite (`tests/erc20_vault_differential.rs`, 57 tests including guard
  and tamper agreement). Every cell below prices the **identical
  statement** under the two toolchains.

Earlier editions of this report had two more sides (the M10 optimized
fork and its M11 Borsh fork, which proved their *own* statements). Both
were retired in M28 after upstream adopted their avenues — Poseidon
commitments, per-flow refunds — into the protocol itself
(`notes/vault-refresh.org` §0); the two-sided comparison is now the whole
story, and it is the strong comparability claim throughout.

## Headline

On the same statement, the port never costs more than compactc and is
cheaper wherever a circuit is not floored by protocol-pinned crypto:

- **Every request circuit crosses at least one `k` boundary.** The three
  cheap requests drop three levels (`approveStata`, `approveRouter`,
  `startDeposit`: k14 → k11, prove −80..−81%, RSS −74..−77%); `startSwap`
  and `startRedeem` drop one (k16 → k15, prove −44..−46%, RSS −43..−47%);
  `startWithdraw` and `startSupply` cut 29% of rows inside k15 (prove
  −5..−6%).
- **The nine settle circuits are ECDSA-floored at k16 on both sides.**
  They cut 12–16% of rows but the secp256k1 verify (~24,450 rows) pins
  them above 2^15, so prove time and RSS are flat (±noise).
- **`initialise` is identical**: 891 rows on both sides at k10, the
  first circuit where the port's row count equals compactc's exactly —
  the protocol move took the two SHA blocks out of the deployer gate,
  which is where the port's earlier −43% on this circuit came from.
- **The singleton is unchanged from M7**: −97.5% rows, −95..−97% prove,
  five to six `k` levels lower.

Compared with the previous protocol's numbers (the nine-circuit vault),
the request-side wins **grew** and the settle-side wins **shrank**: the
port's advantage was always instruction selection around the vault's own
hashes, and the protocol move replaced most of those hashes (keccak
request ids and digests, SHA commitments) with Poseidon on both sides.
What is left to select better is the ABI-word and byte plumbing of the
request circuits — where compactc still lowers every `Bytes<20>` /
`Uint<128>` word through per-byte `div_mod` / `reconstitute_field`
chains — and nothing in the ECDSA-dominated settles.

## Results

All 40 cells from one session (2026-09-05, Apple Silicon, quiet
machine), prove = median of 3, one subprocess per cell for clean peak
RSS. Raw data: `target/bench/results.json`.

| circuit | side | k | rows | keygen (s) | prove (s) | verify (s) | proof (B) | peak RSS (MB) |
|---|---|---|---|---|---|---|---|---|
| initialise | compactc | 10 | 891 | 0.17 | 0.14 | 0.004 | 5,216 | 49 |
| initialise | minocrab | 10 | 891 | 0.17 | 0.14 | 0.004 | 5,216 | 49 |
| approveStata | compactc | 14 | 8,483 | 0.73 | 0.73 | 0.004 | 3,824 | 221 |
| approveStata | minocrab | **11** | 1,156 | 0.09 | **0.14** | 0.004 | 3,824 | **52** |
| approveRouter | compactc | 14 | 8,516 | 0.73 | 0.74 | 0.004 | 3,824 | 223 |
| approveRouter | minocrab | **11** | 1,189 | 0.09 | **0.14** | 0.004 | 3,824 | **54** |
| startDeposit | compactc | 14 | 11,406 | 0.89 | 0.76 | 0.004 | 3,824 | 205 |
| startDeposit | minocrab | **11** | 1,834 | 0.11 | **0.15** | 0.004 | 3,824 | **53** |
| completeDeposit | compactc | 16 | 40,776 | 3.92 | 4.21 | 0.005 | 6,336 | 1,496 |
| completeDeposit | minocrab | 16 | 35,846 | 3.61 | 4.21 | 0.005 | 6,336 | 1,598 |
| startWithdraw | compactc | 15 | 32,751 | 1.80 | 1.91 | 0.005 | 5,392 | 620 |
| startWithdraw | minocrab | 15 | 23,109 | 1.18 | 1.81 | 0.005 | 5,392 | 614 |
| completeWithdraw | compactc | 16 | 40,553 | 3.91 | 4.24 | 0.005 | 6,336 | 1,487 |
| completeWithdraw | minocrab | 16 | 35,625 | 3.57 | 4.23 | 0.005 | 6,336 | 1,474 |
| refundWithdraw | compactc | 16 | 40,273 | 3.94 | 4.23 | 0.005 | 6,336 | 1,609 |
| refundWithdraw | minocrab | 16 | 35,632 | 3.58 | 4.23 | 0.005 | 6,336 | 1,483 |
| startSwap | compactc | 16 | 43,592 | 3.31 | 3.35 | 0.005 | 5,392 | 1,189 |
| startSwap | minocrab | **15** | 23,955 | 1.23 | **1.82** | 0.005 | 5,392 | **674** |
| completeSwap | compactc | 16 | 52,536 | 4.28 | 4.36 | 0.005 | 6,336 | 1,613 |
| completeSwap | minocrab | 16 | 45,400 | 3.81 | 4.28 | 0.005 | 6,336 | 1,625 |
| refundSwap | compactc | 16 | 40,279 | 3.88 | 4.27 | 0.005 | 6,336 | 1,498 |
| refundSwap | minocrab | 16 | 35,638 | 3.57 | 4.24 | 0.005 | 6,336 | 1,625 |
| startSupply | compactc | 15 | 32,693 | 1.79 | 1.91 | 0.005 | 5,392 | 624 |
| startSupply | minocrab | 15 | 23,038 | 1.18 | 1.79 | 0.005 | 5,392 | 611 |
| completeSupply | compactc | 16 | 42,639 | 4.12 | 4.25 | 0.005 | 6,336 | 1,499 |
| completeSupply | minocrab | 16 | 35,645 | 3.59 | 4.17 | 0.005 | 6,336 | 1,489 |
| refundSupply | compactc | 16 | 40,283 | 3.89 | 4.20 | 0.005 | 6,336 | 1,484 |
| refundSupply | minocrab | 16 | 35,642 | 3.58 | 4.17 | 0.005 | 6,336 | 1,484 |
| startRedeem | compactc | 16 | 35,646 | 2.75 | 3.22 | 0.005 | 5,392 | 1,168 |
| startRedeem | minocrab | **15** | 23,220 | 1.18 | **1.80** | 0.005 | 5,392 | **615** |
| completeRedeem | compactc | 16 | 42,639 | 4.06 | 4.31 | 0.005 | 6,336 | 1,496 |
| completeRedeem | minocrab | 16 | 35,645 | 3.80 | 4.72 | 0.005 | 6,336 | 1,629 |
| refundRedeem | compactc | 16 | 40,283 | 3.91 | 4.23 | 0.005 | 6,336 | 1,472 |
| refundRedeem | minocrab | 16 | 35,642 | 3.81 | 4.52 | 0.005 | 6,336 | 1,657 |
| signBidirectional | compactc | 16 | 50,429 | 4.54 | 2.83 | 0.003 | 3,824 | 1,021 |
| signBidirectional | minocrab | **11** | 1,205 | 0.10 | **0.14** | 0.003 | 3,824 | **51** |
| respond | compactc | 16 | 40,931 | 3.88 | 2.69 | 0.003 | 3,824 | 904 |
| respond | minocrab | **10** | 1,004 | 0.07 | **0.09** | 0.003 | 3,824 | **41** |
| respondBidirectional | compactc | 16 | 40,931 | 3.89 | 2.68 | 0.003 | 3,824 | 896 |
| respondBidirectional | minocrab | **10** | 1,004 | 0.07 | **0.09** | 0.003 | 3,824 | **42** |

## Deltas, minocrab vs compactc

| circuit | k port / cc | rows Δ | prove Δ | RSS Δ |
|---|---|---|---|---|
| initialise | 10 / 10 | ±0% | +0.3% | −0.4% |
| approveStata | **11 / 14** | −86.4% | **−80.8%** | −76.6% |
| approveRouter | **11 / 14** | −86.0% | **−80.9%** | −75.6% |
| startDeposit | **11 / 14** | −83.9% | **−80.3%** | −74.0% |
| completeDeposit | 16 / 16 | −12.1% | −0.1% | +6.8% |
| startWithdraw | 15 / 15 | −29.4% | −5.3% | −0.9% |
| completeWithdraw | 16 / 16 | −12.2% | −0.3% | −0.9% |
| refundWithdraw | 16 / 16 | −11.5% | ±0% | −7.8% |
| startSwap | **15 / 16** | −45.0% | **−45.7%** | −43.3% |
| completeSwap | 16 / 16 | −13.6% | −1.9% | +0.8% |
| refundSwap | 16 / 16 | −11.5% | −0.8% | +8.5% |
| startSupply | 15 / 15 | −29.5% | −6.1% | −2.1% |
| completeSupply | 16 / 16 | −16.4% | −1.8% | −0.6% |
| refundSupply | 16 / 16 | −11.5% | −0.7% | ±0% |
| startRedeem | **15 / 16** | −34.9% | **−44.2%** | −47.3% |
| completeRedeem | 16 / 16 | −16.4% | +9.6% | +8.9% |
| refundRedeem | 16 / 16 | −11.5% | +6.9% | +12.5% |
| signBidirectional | **11 / 16** | −97.6% | **−95.0%** | −95.0% |
| respond | **10 / 16** | −97.5% | **−96.5%** | −95.4% |
| respondBidirectional | **10 / 16** | −97.5% | **−96.5%** | −95.3% |

## Where the wins come from

The vault is hash-bound: 95–99% of every circuit's rows are SHA-256,
Poseidon and secp256k1 ECDSA (per-circuit budgets reconstructed from
measured primitive costs — `cargo run -p minocrab-sim --example
cryptocost` — and confirmed by the region profiler under
`target/bench/profiles/`). Every hash the vault computes is now
**protocol-pinned**: the Poseidon request id and attestation digest (what
the MPC recomputes and what it signed), the Poseidon identity and refund
commitments (the MPC's key-derivation path and the settle gate), the
SHA-256 `tokenType`, coin commitment and nullifier (the ledger's own), and
the ECDSA verify (the only authentication gate). None of that is ours to
choose, so the two sides spend the same rows on it.

What differs is **instruction selection around those hashes**:

| what | compactc | the port | where it shows |
|---|---|---|---|
| ABI words (`evmAddressAbiWord`, `numericAbiWord`), 2–7 per request | per-byte `div_mod` + `reconstitute_field` explode/rebuild chains, ~640 rows a word | one `div_mod` at a byte boundary and a native `reverse_bytes` | every request circuit; the whole of the three-level drop on the 2-word requests |
| `Bytes<20>` `as Field as Bytes<32>` (the domain separator's input) | explode to bytes and rebuild | the address limb is the low limb, the high limb is the constant 0 | every circuit with a coin |
| `abiWordToUint128` | gone from the settles (the settle views carry typed amounts) | gone likewise | — |
| ledger op framing | identical Impact streams (PI-equal by construction) | identical | — |

The request circuits are where those words live: `startSwap` builds seven
of them and drops a level; the 2-word requests drop three. The settle
circuits build none and read their amounts off the settle views, so their
12–16% row cut is the domain-separator input plus framing, and stays
inside k16.

## Honest notes and limits

- **`initialise` is identical, not merely parity.** 891 rows on both
  sides: one Poseidon commitment, one point encode, seven cell writes.
  With the SHA blocks gone from the deployer gate there is nothing left
  to select differently.
- **The nine settle circuits are ECDSA-floored above 2^15.** They cut
  11.5–16.4% of rows but cannot cross k16 while the secp256k1 verify is
  pinned. Their prove column is noise: `completeRedeem` +9.6% and
  `refundRedeem` +6.9% at identical `k` and fewer rows are the same
  session's swing (the other seven k16 settles sit within ±2%, and the
  earlier editions recorded the same spread). Rows, `k` and proof sizes
  are exact; same-`k` prove and RSS deltas are not findings either way.
- **Sub-second cells are noise-dominated** in absolute terms; their `k`
  columns are the result.
- **The three lending flows have no earlier number to compare with**;
  they enter the report here. `startRedeem` crosses k16 → k15 like
  `startSwap` (three ABI words including two copies of the vault
  address); `startSupply` stays inside k15 like `startWithdraw`.
- **The API lineage is not in this table.** `erc20_vault_pending` (the
  vault on the typed Sig Network API) proves its own statement and is
  priced by rows only in `notes/benchmark.org` §2026-09-05 — 0.14–0.35×
  of compactc on the request circuits, 0.86–0.88× on the settles.

  **M37 rung D changed the STATEMENT of that lineage's eight settle
  circuits** (2026-09-06), so their numbers above are stale and the
  ones below are from the row snapshot rather than a bench run. The
  `Succeeded` / `Failed` split moved the executed-but-failed case out of
  `complete_withdraw` and into `refund_withdrawal`: the completion lost
  the refund branch it might not take (its coin mint, its commitment
  opening and its four witnesses) and each refund gained the second
  Poseidon preimage and the `cond_select` that pick the attestation
  digest by kind. Nine request circuits, `claim` and every other circuit
  in the tree are byte-identical.

  | circuit | before | after |
  |---|---|---|
  | `complete_withdraw` | k16 / 35,553 | **k15 / 25,655** |
  | `refund_withdrawal` | k16 / 35,547 | k16 / 35,605 |
  | `refund_swap` | k16 / 35,578 | k16 / 35,651 |
  | `refund_supply` | k16 / 35,557 | k16 / 35,630 |
  | `refund_redeem` | k16 / 35,562 | k16 / 35,635 |
  | `complete_swap` / `_supply` / `_redeem` | k16 / 45,082 / 35,576 / 35,581 | unchanged |

  `complete_withdraw` crossing k16 → k15 is the one that matters: it
  halves the proving key and the prover's RAM for the common path of a
  withdrawal. **The bench has not been re-run**; that is the main
  session's, and the prove/RSS columns for these rows will move.
- Proof sizes are identical per circuit across both sides (same proof
  system and public-input counts); verify times are milliseconds
  everywhere.

## Reproducing

From a clean checkout (nix + direnv provide the pinned toolchain):

```
nix run .#bench        # or: nix develop -c ./bench.sh
```

This re-runs the differential tests with preimage dumping on (every
preimage is corpus-verified — PI-equal under both toolchains' artifacts —
before it is benchmarked), proves all 40 cells, and writes
`target/bench/results.json`, `report.md`, and the per-region cost
profiles under `target/bench/profiles/`. Deleting
`target/bench/results.jsonl` forces a fresh run; leaving it resumes an
interrupted one. The property harness (`erc20_vault_spec.rs`,
`PROPTEST_CASES=1000000 cargo test --release` for the gating run) and the
adversarial sweeps cover the same seventeen circuits.
