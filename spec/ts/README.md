<!-- GENERATED — do not edit; source: crates/minocrab-contracts/tests/serialization/ts/README.md -->

# `spec/ts` — the circuit-safe Borsh subset, in TypeScript

A reader and a writer for every type in [`../borsh-subset.md`](../borsh-subset.md),
**generated** from the same Borsh schema that produced §9's offset tables and
the vectors in [`../vectors`](../vectors). No dependencies: `borsh-subset.ts`
imports `primitives.ts` and `primitives.ts` imports nothing. There is no
`package.json`, no `node_modules`, and nothing to install.

That is possible because this format is fixed-width by construction — every
offset is a compile-time constant, so a decoder is a `DataView` at a published
offset. The generated readers say exactly that:

```ts
export function readVaultResponse(bytes: Uint8Array, offset = 0): VaultResponse {
  const view = checkedView(bytes, offset, VAULT_RESPONSE_LEN);
  return {
    kind: getU8(view, 0),
    success: getBool(view, 1),
  };
}
```

## borsh-js is the alternative, and it is a fine one

This IS Borsh, restricted to the fixed-width subset — not a dialect. Every
byte these functions produce is canonical Borsh for the declared type, so
[`borsh-js`](https://github.com/near/borsh-js) (or any other implementation)
decodes the same bytes from the same declarations, and
`../borsh-subset.md` §12 says so explicitly. Use a library if you want one.
This directory exists so that the dependency is a **choice** rather than a
requirement, and so that the offsets you decode at are *generated* from the
circuit's own layout rather than transcribed from a table by hand.

Three rules to carry across either way:

- **Integers are little-endian.** The EVM ABI words carried *inside* these
  payloads are big-endian by the EVM's own rules; they travel as `[u8; 32]`
  and Borsh does not touch their contents.
- **`Maybe` is `Flagged`, never `Option`.** `Flagged<u32>` is five bytes at
  every value; `Option<u32>` is one or five. Decode one as the other and
  every offset after it is wrong on half your inputs.
- **Read the version byte first.** A stage-7 record opens with
  `formatVersion = RECORD_FORMAT_VERSION` (`0x80`), and `readVaultEventV2` /
  `readSwapEventV2` throw `record-version: expected 0x80, got 0x…` before they
  touch a single offset a format change could have moved. A library decodes
  the same bytes but will not do this for you — `../borsh-subset.md` §6 is the
  rule, and it is the reader's job.

## What is here

| file | what it is |
|---|---|
| `borsh-subset.ts` | GENERATED: types, offset tables, readers, writers and the codec registry |
| `primitives.ts` | the `DataView` leaf layer and the reject rules |
| `vectors.test.ts` | the vector-driven conformance tests, and a GENERATED section: one version-rejection test per versioned record reader |
| `node-builtins.d.ts` | ambient declarations for the node APIs the tests use (so no `@types/node`) |
| `tsconfig.json` | strict, `erasableSyntaxOnly` — the code node can run by stripping types |

## Running the tests

From the repository root, inside `nix develop` (which supplies node and tsc):

```sh
node --test spec/ts/vectors.test.ts    # the vectors, decoded and re-encoded
tsc --noEmit -p spec/ts                # type-check
```

or, to run the node suite from cargo beside the Rust ones:

```sh
cargo test --release -p minocrab-contracts --test serialization_conformance -- \
    --ignored the_typescript_vectors_pass
```

Every vector in `../vectors/*.json` is decoded by the generated codec for its
type, checked leaf by leaf against the vector's ordered field list (path,
type, offset, width, bytes and decoded number), re-serialized to byte
equality, and — where the vector carries one — unwrapped from its 288-byte
`Misc` envelope with the zero-pad rule enforced.

## Regenerating

Everything in this directory is written by one `--ignored` Rust test, and a
checked-in file that stops being its output fails
`spec_document::the_committed_typescript_is_generated`:

```sh
cargo test --release -p minocrab-contracts --test serialization_conformance -- \
    --ignored regenerate_spec
```

The generator is `crates/minocrab-contracts/tests/serialization/ts_codegen.rs`;
the hand-written files above are edited in
`crates/minocrab-contracts/tests/serialization/ts/` and copied here by that
test — verbatim, except that this README's type table and `vectors.test.ts`'s
version-rejection tests are substituted in, both walked out of the same schema
as the decoder.

## Types the decoder covers

| spec type | TypeScript | bytes |
|---|---|---:|
| `bool` | `readBool` / `writeBool` | 1 |
| `u8` | `readU8` / `writeU8` | 1 |
| `u16` | `readU16` / `writeU16` | 2 |
| `u32` | `readU32` / `writeU32` | 4 |
| `u64` | `readU64` / `writeU64` | 8 |
| `u128` | `readU128` / `writeU128` | 16 |
| `[u8; 20]` | `readBytes20` / `writeBytes20` | 20 |
| `[u8; 32]` | `readBytes32` / `writeBytes32` | 32 |
| `[u8; 64]` | `readBytes64` / `writeBytes64` | 64 |
| `Flagged<u32>` | `readFlaggedU32` / `writeFlaggedU32` | 5 |
| `VaultEventV1` | `readVaultEventV1` / `writeVaultEventV1` | 362 |
| `ReplaceNonceEventV1` | `readReplaceNonceEventV1` / `writeReplaceNonceEventV1` | 330 |
| `SwapEventV1` | `readSwapEventV1` / `writeSwapEventV1` | 526 |
| `SupplyEventV1` | `readSupplyEventV1` / `writeSupplyEventV1` | 364 |
| `RedeemEventV1` | `readRedeemEventV1` / `writeRedeemEventV1` | 396 |
| `EmptyOutput` | `readEmptyOutput` / `writeEmptyOutput` | 0 |
| `BoolOutput` | `readBoolOutput` / `writeBoolOutput` | 1 |
| `WordOutput` | `readWordOutput` / `writeWordOutput` | 32 |
| `VaultEventV2` | `readVaultEventV2` / `writeVaultEventV2` | 338 |
| `SwapEventV2` | `readSwapEventV2` / `writeSwapEventV2` | 498 |
| `RedeemEventV2` | `readRedeemEventV2` / `writeRedeemEventV2` | 370 |
| `VaultResponse` | `readVaultResponse` / `writeVaultResponse` | 2 |
| `SwapResponse` | `readSwapResponse` / `writeSwapResponse` | 9 |
| `FailureResponse` | `readFailureResponse` / `writeFailureResponse` | 1 |
| `AttestationPreimage<VaultResponse>` | `readAttestationPreimageVaultResponse` / `writeAttestationPreimageVaultResponse` | 34 |
| `AttestationPreimage<SwapResponse>` | `readAttestationPreimageSwapResponse` / `writeAttestationPreimageSwapResponse` | 41 |
| `SupplyResponse` | `readSupplyResponse` / `writeSupplyResponse` | 9 |
| `AttestationPreimage<SupplyResponse>` | `readAttestationPreimageSupplyResponse` / `writeAttestationPreimageSupplyResponse` | 41 |
| `RedeemResponse` | `readRedeemResponse` / `writeRedeemResponse` | 9 |
| `AttestationPreimage<RedeemResponse>` | `readAttestationPreimageRedeemResponse` / `writeAttestationPreimageRedeemResponse` | 41 |
| `AttestationPreimage<FailureResponse>` | `readAttestationPreimageFailureResponse` / `writeAttestationPreimageFailureResponse` | 33 |
| `SignBidirectionalMisc` | `readSignBidirectionalMisc` / `writeSignBidirectionalMisc` | 161 |
| `RespondMisc` | `readRespondMisc` / `writeRespondMisc` | 129 |
