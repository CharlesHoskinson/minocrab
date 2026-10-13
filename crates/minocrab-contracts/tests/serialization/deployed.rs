//! The DEPLOYED bytes: how today's protocol lays each payload out, built
//! with the same code the circuits and the reference model use.
//!
//! Nothing in this module knows what Borsh is. Every function here produces
//! the bytes the deployed protocol produces:
//!
//! - [`fab_bytes`] is `parse_field_repr` + `binary_repr`, the two calls the
//!   off-circuit `persistentHash` makes on a FAB value — the byte string the
//!   ledger holds a record as, and the one the hash chips would consume. Since
//!   the V1 move (M44) neither the request id nor the attestation digest is a
//!   hash of these bytes: both are Poseidon over the FIELD limbs
//!   (`vault::prims::{request_id_v1, attestation_digest}`). The byte claims
//!   stand; the hash claims live in the vault model;
//! - [`misc_envelope`] is `serialize<Misc, 288>`: the event name, the
//!   circuit's `Serializer` segments, zero-padded;
//! - [`misc_preimage`] builds the singleton's public transcript so the
//!   CORPUS ARTIFACT itself can be asked whether it accepts those bytes. It
//!   is a THIN WRAPPER over `support::signet_call::call_preimage` — the
//!   ledger's own `ContractCallPrototype`/`construct_proof` path (M29 rung
//!   C) — not a second construction of a preimage.

use midnight_base_crypto::fab::{AlignedValue, Alignment, AlignmentAtom, AlignmentSegment};
use midnight_base_crypto::repr::BinaryHashRepr;
use midnight_transient_crypto::fab::{AlignmentExt, ValueReprAlignedValue};
use midnight_transient_crypto::proofs::ProofPreimage;
use minocrab::Fr;
use minocrab_contracts::events::MISC_SIZE;
use minocrab_zkir::v3::IrSource;

use crate::support::signet_call::{call_preimage, scalar_input};

/// The value-only FAB binary of `limbs` laid out against `atoms` — the byte
/// string the deployed hash constructions consume.
pub fn fab_bytes(atoms: &[AlignmentAtom], limbs: &[Fr]) -> Vec<u8> {
    let alignment = Alignment(
        atoms
            .iter()
            .cloned()
            .map(AlignmentSegment::Atom)
            .collect(),
    );
    let value: AlignedValue = alignment
        .parse_field_repr(limbs)
        .expect("limbs match the alignment");
    let mut bytes = Vec::new();
    ValueReprAlignedValue(value).binary_repr(&mut bytes);
    bytes
}

/// The declared binary length of an atom sequence (`Alignment::bin_len`) —
/// the deployed layout's own answer to "how wide is this record".
pub fn fab_len(atoms: &[AlignmentAtom]) -> usize {
    Alignment(atoms.iter().cloned().map(AlignmentSegment::Atom).collect()).bin_len()
}

/// The attested OUTPUT's bytes: `Bytes<LEN>`'s FAB binary over the limbs the
/// settle circuit discloses.
///
/// This replaced the old `attestation_preimage_bytes` at the V1 move (M44).
/// `calculateSignetAttestationDigestV1` has no byte preimage to build —
/// it is Poseidon over `[tag, requestId, blockHeight, outputKind, LEN,
/// ..output]` as FIELD elements — so the output is the only part of a V1
/// attestation that is a byte string, and it is the part a spec type can be
/// true of. At LEN 0 (the empty output every failed or unviable verdict
/// carries) there are no limbs and no bytes.
pub fn output_bytes(output_len: u32, output_limbs: &[Fr]) -> Vec<u8> {
    fab_bytes(&[AlignmentAtom::Bytes { length: output_len }], output_limbs)
}

// ---- the Signet singleton's Misc event ---------------------------------------

/// The 32-byte event name, `pad(32, name)`.
pub fn misc_name(name: &str) -> [u8; 32] {
    let mut padded = [0u8; 32];
    padded[..name.len()].copy_from_slice(name.as_bytes());
    padded
}

/// `serialize<Misc, 288>`: `pad(32, name)` ‖ `payload` ‖ zeros.
///
/// The padding rule the spec states and the decoder must check: bytes
/// `0..payload.len()` of the `Bytes<256>` are the payload's own layout,
/// everything after them MUST be zero.
pub fn misc_envelope(name: &str, payload: &[u8]) -> Vec<u8> {
    assert!(
        payload.len() + 32 <= MISC_SIZE,
        "payload exceeds the {MISC_SIZE}-byte Misc"
    );
    let mut bytes = vec![0u8; MISC_SIZE];
    bytes[..32].copy_from_slice(&misc_name(name));
    bytes[32..32 + payload.len()].copy_from_slice(payload);
    bytes
}

/// A `Bytes<128>`'s five FAB slots: 31-byte chunks from the front, limb 0
/// the trailing leftover.
pub fn b128_limbs(bytes: &[u8; 128]) -> Vec<Fr> {
    let mut chunks: Vec<&[u8]> = bytes.chunks(31).collect();
    chunks.reverse();
    chunks
        .into_iter()
        .map(|c| Fr::from_le_bytes(c).expect("31 bytes fit"))
        .collect()
}

/// A singleton call's proof preimage: the circuit arguments as their field
/// limbs, and the logged 288 Misc bytes as the public transcript.
///
/// THE HAND-BUILT VERSION IS GONE (M29 rung C). This delegates to
/// `support::signet_call::call_preimage`, so the preimage the corpus
/// artifact is asked about here is the very one the ledger's
/// `ContractCallPrototype` + `ContractCallExt::construct_proof` produce for
/// a real intent — the same bytes `tests/signet_construction.rs` runs its
/// call-compatibility gate on.
///
/// The limbs arrive raw rather than as a typed `AlignedValue` because this
/// module's caller is a proptest over thousands of generated payloads with
/// no typed argument value to hand. That is licensed by
/// `signet_construction::the_alignment_does_not_reach_the_preimage`, which
/// asserts a typed `[Bytes<32>, Uint<8>, ...]` argument value and the flat
/// `[Field; n]` one `scalar_input` builds give byte-identical preimages —
/// the ledger reads an argument value only through its
/// `value_only_field_repr`.
pub fn misc_preimage(inputs: Vec<Fr>, misc_bytes: &[u8]) -> ProofPreimage {
    call_preimage("respond", scalar_input(&inputs), misc_bytes)
}

/// A pinned signet-contract corpus artifact (what compactc emitted for the
/// deployed singleton).
pub fn corpus_signet_zkir(name: &str) -> IrSource {
    let path = format!(
        "{}/../../corpus/zkir/signet-midnight-integration-pr127/packages/signet-contract/src/signet-contract/zkir/{name}.zkir",
        env!("CARGO_MANIFEST_DIR")
    );
    minocrab_zkir::v3::read_zkir(&path).expect("corpus golden parses")
}
