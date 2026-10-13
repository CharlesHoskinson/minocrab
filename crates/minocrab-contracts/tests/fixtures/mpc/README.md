# Captured Signet respond transactions (imported from `sig-net/mpc`)

Two real, finalized Midnight transactions carrying the singleton's
`SignatureRespondedEvent` and `RespondBidirectionalEvent`. They are the
PRODUCER EVIDENCE for the event names, the Misc envelope and the Impact
program `crates/minocrab-contracts/tests/signet_ledger_apply.rs` builds:
they were emitted by compactc's artifact of the deployed singleton, not by
anything in this repo.

| file | bytes | SHA-256 |
|---|---:|---|
| `respond-tx-161.mn` | 7663 | `9444aa6304257d0ae278531a3c70ee0baa508c197369024fb14463f987b06745` |
| `respond-bidirectional-tx-181.mn` | 7676 | `5291b70cbdfe7a095828a2c6c94cf5b89f7eb2a94e22c2c4953d7706067ef17a` |

Each SHA-256 above is also the **ledger transaction hash** the source
README records for that capture, so the bytes here are pinned to the
capture's own identifier and not only to a copy operation. The test asserts
both hashes before decoding anything.

## Provenance

Copied verbatim (`cmp`-identical) from
`sig-net/mpc` `chain-signatures/chain-midnight/fixtures/` at worktree
`~/mpc` (branch `dry/midnight-publisher-ts`), imported 2026-09-05. That
directory's own `README.md` is the authoritative capture record; the facts
this repo depends on are reproduced here:

- One local `midnight-integration` capture chain at
  `c171225731f5ca07028fcd6caa6ced853ed139ef`, running
  `@sig-net/midnight-contract@0.20.0-rc.1` (compactc `0.33.0-rc.2`).
- Singleton address
  `b116cd0482b84922e761278a25d1ee2305fd6d630f0d48954d2af6537f8e214e`;
  caller address
  `e4ae041a1c3f1538902c6a8f5aedb1e791b66cef7a715114153f3bba44a87eb6`.
- Both captured events carry request id
  `1cd10eb1f4fa5c665084d24a7982b09aa321886dce77d85b5f6feee0687a414b`.

| file | finalized block | extrinsic | status | singleton call index | decoded event |
|---|---|---:|---|---:|---|
| `respond-tx-161.mn` | `4fcf501af455ebbde39bb70e6d06245a3c581239c47185cefad0f034ce4adc25` at 161 | 4 | `TxApplied` | 0 | `SignatureRespondedEvent` |
| `respond-bidirectional-tx-181.mn` | `b375f617cf94b19c0f75703dfa943da5dd9c64f97aaa5568517df57d4c8e675f` at 181 | 4 | `TxApplied` | 0 | `RespondBidirectionalEvent` |

`notify-tx-156.mn`, `caller-post-state-156.mn` and
`golden-state-caller-156.json` were NOT imported: M29 D is about the two
respond calls a publisher makes, and the notify/caller-state fixtures belong
to the reader side (`crates/signet-sim`), which pins its own.

## What these are not

Not inclusion proofs. They pin the transcript and payload half of a future
audit only — the source README is explicit that verifying them against a
chain additionally needs the block header, the ordered body and a storage
read proof, none of which the capture carries.

## Format, and the pin they double as

`midnight:transaction[v12](signature[v2],proof,pedersen-schnorr[v1])` —
a tagged-serialized
`Transaction<Signature, ProofMarker, PureGeneratorPedersen, DefaultDB>`.
mpc builds against `crate-ledger-9.1.0.0-rc.3`; this repo builds against rev
`04c9c5d`. That these files deserialize here at all is the M29 F evidence
that the two pins agree on the transaction wire format (see
`notes/mpc-publisher.org` §9).

## Since PR #127 (M43, 2026-09-24)

The singleton this crate ports moved to midnight-integration PR #127
(`align-with-protocol-spec`, `e9350c4`): `respond` and `respondBidirectional`
take ONE event struct, and `respondBidirectional`'s payload is now
`requestId(32) ‖ blockHeight LE(8) ‖ outputKind(1) ‖ serializedOutputLength
LE(8) ‖ digest(32) ‖ signature(97) ‖ zeros(78)`. Consequences for these two
captures, both taken from a chain running the PRE-#127 singleton
(`@sig-net/midnight-contract@0.20.0-rc.1`):

- `respond-tx-161.mn` still evidences all 288 bytes: `respond`'s field vector
  and payload did not change (the id moved into the struct, nothing else).
- `respond-bidirectional-tx-181.mn` evidences the entry point, the event
  name, the request id at payload offset 0 and the program's shape (`push`
  of the three-cell Misc, `log`) — NOT the payload layout, which the test
  now only checks has moved. A capture from a chain running the #127
  singleton is OWED here; when it lands, the test becomes the full 288-byte
  comparison `respond` has (`signet_ledger_apply.rs`,
  `respond_bidirectional_apply_matches_the_captured_transactions_program`).
