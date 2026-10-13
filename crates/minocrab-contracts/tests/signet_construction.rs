//! M29 rung C — THE CONSTRUCTION GATE.
//!
//! `tests/signet_contract_differential.rs` already asks "does compactc's
//! artifact accept the same preimage ours does?". Until this rung, the
//! preimage it asked about was assembled by hand: a `ProofPreimage` literal
//! whose `inputs` were a `Vec<Fr>` the test wrote out and whose
//! `public_transcript_inputs` were `op.field_repr` over ops the test wrote
//! out. That is a SECOND reading of the ledger's rule, and a differential
//! against a second reading proves nothing about the first.
//!
//! Here the preimage comes from the ledger: `ContractCallPrototype` +
//! `partition_transcripts` + `Intent::add_call` →
//! `ContractCallExt::<ProofPreimage>::construct_proof`
//! (`ledger/src/construct.rs:515-573`) — the same three calls
//! `sig-net/mpc`'s sidecar makes through the ledger-v9 WASM bindings
//! (`midnight-publisher-ts/src/intent.ts`) and the same ones a Rust
//! publisher will make (M30 B). See `support/signet_call.rs`.
//!
//! What this gate proves: on the preimage PRODUCTION BUILDS, our artifact
//! and compactc's have the same input schema and the same output schema,
//! accept it, and produce identical public-input vectors and pi-skip
//! sequences — under our own simulator AND under the upstream
//! `IrSource::check`. What it does NOT prove: that a proof made from that
//! preimage verifies (rung E), that the Impact program in it is the one
//! compactc's executor emits on chain (rung D), or anything about the
//! contract's state, since these three circuits have none.

use midnight_base_crypto::fab::AlignedValue;
use midnight_transient_crypto::proofs::ProofPreimage;
use minocrab::Fr;
use minocrab_contracts::signet_contract;
use minocrab_sim::v3::{assert_call_compatible, simulate};
use minocrab_zkir::v3::IrSource;

mod support;

use support::signet_call::{
    b128_limbs, b32_slots, bytesn_value, call_preimage, respond_bidirectional_input,
    respond_bidirectional_misc, sample_attestation, scalar_input, RespondAttestation,
};

fn corpus_zkir(name: &str) -> IrSource {
    let path = format!(
        "{}/../../corpus/zkir/signet-midnight-integration-pr127/packages/signet-contract/src/signet-contract/zkir/{name}.zkir",
        env!("CARGO_MANIFEST_DIR")
    );
    minocrab_zkir::v3::read_zkir(&path).expect("corpus golden parses")
}

/// `pad(32, name)` into the first 32 misc bytes.
fn misc_with_name(name: &str) -> Vec<u8> {
    let mut bytes = vec![0u8; minocrab_contracts::events::MISC_SIZE];
    bytes[..name.len()].copy_from_slice(name.as_bytes());
    bytes
}

fn request_id() -> [u8; 32] {
    let mut rid = [0u8; 32];
    rid[..10].copy_from_slice(b"request-id");
    rid[31] = 0x9c;
    rid
}

// ---- the three calls, as the ledger builds them ----------------------------

/// `signBidirectional(requestId: Bytes<32>, notification: { version:
/// Uint<8>, payload: Bytes<128> })` — eight field inputs, in that order
/// (checked against the corpus artifact's own input schema by
/// [`input_schema_matches_the_corpus_artifact`]).
pub struct SignCall {
    request_id: [u8; 32],
    version: u8,
    payload: [u8; 128],
}

impl SignCall {
    fn new() -> SignCall {
        let mut payload = [0u8; 128];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        SignCall { request_id: request_id(), version: 1, payload }
    }

    /// name(32) ‖ version(1) ‖ requestId(32) ‖ payload(128) ‖ zeros(95).
    fn misc_bytes(&self) -> Vec<u8> {
        let mut bytes = misc_with_name(signet_contract::SIGN_BIDIRECTIONAL_EVENT);
        bytes[32] = self.version;
        bytes[33..65].copy_from_slice(&self.request_id);
        bytes[65..193].copy_from_slice(&self.payload);
        bytes
    }

    /// The arguments with their COMPACT alignment: `Bytes<32>`, `Uint<8>`
    /// (one byte), `Bytes<128>`.
    fn typed_input(&self) -> AlignedValue {
        AlignedValue::concat([
            &bytesn_value(32, &self.request_id),
            &bytesn_value(1, &[self.version]),
            &bytesn_value(128, &self.payload),
        ])
    }

    fn limbs(&self) -> Vec<Fr> {
        let (hi, lo) = b32_slots(&self.request_id);
        let mut limbs = vec![hi, lo, Fr::from(u64::from(self.version))];
        limbs.extend(b128_limbs(&self.payload));
        limbs
    }

    fn preimage(&self) -> ProofPreimage {
        call_preimage("signBidirectional", self.typed_input(), &self.misc_bytes())
    }
}

/// `respond`: `({ requestId, signature: { bigR: {x, y}, s, recoveryId } })`
/// — nine field inputs, the same nine as when the id was a separate
/// argument (PR #127 only moved it into the struct).
pub struct RespondCall {
    request_id: [u8; 32],
    big_r_x: [u8; 32],
    big_r_y: [u8; 32],
    s: [u8; 32],
    recovery_id: u8,
}

impl RespondCall {
    fn new() -> RespondCall {
        let fill = |seed: u8| {
            let mut b = [0u8; 32];
            for (i, byte) in b.iter_mut().enumerate() {
                *byte = seed.wrapping_add(i as u8).wrapping_mul(13);
            }
            b
        };
        RespondCall {
            request_id: request_id(),
            big_r_x: fill(0x11),
            big_r_y: fill(0x47),
            s: fill(0xa3),
            recovery_id: 1,
        }
    }

    /// name(32) ‖ requestId(32) ‖ x(32) ‖ y(32) ‖ s(32) ‖ recoveryId(1) ‖ zeros(127).
    fn misc_bytes(&self, name: &str) -> Vec<u8> {
        let mut bytes = misc_with_name(name);
        bytes[32..64].copy_from_slice(&self.request_id);
        bytes[64..96].copy_from_slice(&self.big_r_x);
        bytes[96..128].copy_from_slice(&self.big_r_y);
        bytes[128..160].copy_from_slice(&self.s);
        bytes[160] = self.recovery_id;
        bytes
    }

    fn typed_input(&self) -> AlignedValue {
        AlignedValue::concat([
            &bytesn_value(32, &self.request_id),
            &bytesn_value(32, &self.big_r_x),
            &bytesn_value(32, &self.big_r_y),
            &bytesn_value(32, &self.s),
            &bytesn_value(1, &[self.recovery_id]),
        ])
    }

    fn limbs(&self) -> Vec<Fr> {
        let mut limbs = Vec::new();
        for b32 in [&self.request_id, &self.big_r_x, &self.big_r_y, &self.s] {
            let (hi, lo) = b32_slots(b32);
            limbs.extend([hi, lo]);
        }
        limbs.push(Fr::from(u64::from(self.recovery_id)));
        limbs
    }

    fn preimage(&self, entry_point: &str, name: &str) -> ProofPreimage {
        call_preimage(entry_point, self.typed_input(), &self.misc_bytes(name))
    }
}

/// `respondBidirectional`: `({ requestId, blockHeight, outputKind,
/// serializedOutputLength, digest, signature })` — fourteen field inputs
/// (PR #127).
pub struct RespondBidirectionalCall {
    respond: RespondCall,
    attestation: RespondAttestation,
}

impl RespondBidirectionalCall {
    fn new() -> RespondBidirectionalCall {
        RespondBidirectionalCall { respond: RespondCall::new(), attestation: sample_attestation() }
    }

    fn misc_bytes(&self) -> Vec<u8> {
        let r = &self.respond;
        respond_bidirectional_misc(&r.request_id, &self.attestation, &r.big_r_x, &r.big_r_y, &r.s, r.recovery_id)
    }

    fn typed_input(&self) -> AlignedValue {
        let r = &self.respond;
        respond_bidirectional_input(&r.request_id, &self.attestation, &r.big_r_x, &r.big_r_y, &r.s, r.recovery_id)
    }

    /// The struct's fields in order, each at its FAB width: `Bytes<32>` is
    /// two limbs (hi, lo), a `Uint<64>` and the enum are one each.
    fn limbs(&self) -> Vec<Fr> {
        let r = &self.respond;
        let a = &self.attestation;
        let mut limbs = Vec::new();
        let (hi, lo) = b32_slots(&r.request_id);
        limbs.extend([hi, lo]);
        limbs.push(Fr::from(a.block_height));
        limbs.push(Fr::from(u64::from(a.output_kind)));
        limbs.push(Fr::from(a.serialized_output_length));
        let (hi, lo) = b32_slots(&a.digest);
        limbs.extend([hi, lo]);
        for b32 in [&r.big_r_x, &r.big_r_y, &r.s] {
            let (hi, lo) = b32_slots(b32);
            limbs.extend([hi, lo]);
        }
        limbs.push(Fr::from(u64::from(r.recovery_id)));
        limbs
    }

    fn preimage(&self) -> ProofPreimage {
        call_preimage("respondBidirectional", self.typed_input(), &self.misc_bytes())
    }
}

// ---- the gate --------------------------------------------------------------

#[test]
fn sign_bidirectional_call_is_compatible_with_the_corpus_artifact() {
    let call = SignCall::new();
    let pi = call.preimage();
    support::dump_preimage("signBidirectional", &pi);
    assert_call_compatible(&signet_contract::SignetContract::sign_bidirectional().ir, &corpus_zkir("signBidirectional"), &pi);
}

#[test]
fn respond_call_is_compatible_with_the_corpus_artifact() {
    let call = RespondCall::new();
    let pi = call.preimage("respond", signet_contract::SIGNATURE_RESPONDED_EVENT);
    support::dump_preimage("respond", &pi);
    assert_call_compatible(&signet_contract::SignetContract::respond().ir, &corpus_zkir("respond"), &pi);
}

#[test]
fn respond_bidirectional_call_is_compatible_with_the_corpus_artifact() {
    let call = RespondBidirectionalCall::new();
    let pi = call.preimage();
    support::dump_preimage("respondBidirectional", &pi);
    assert_call_compatible(
        &signet_contract::SignetContract::respond_bidirectional().ir,
        &corpus_zkir("respondBidirectional"),
        &pi,
    );
}

/// The preimage the LEDGER builds is the preimage the differential's
/// `inputs`/`public_transcript_inputs` describe — stated as an assertion
/// rather than as a comment, and stated on the FIELD VECTOR the circuit
/// actually reads.
///
/// `ContractCallExt::construct_proof` fills `inputs` from
/// `ValueReprAlignedValue(call.input).field_vec()`, i.e. the argument
/// value's `value_only_field_repr`; nothing else about the `AlignedValue`
/// reaches the transaction. So the hand-written limb lists the suite used
/// before this rung are exactly what the ledger derives from the typed
/// arguments — which is why the retired `preimage()` helper could be a thin
/// wrapper (`serialization/deployed.rs`'s `misc_preimage`) rather than a
/// second construction.
#[test]
fn the_ledgers_inputs_are_the_arguments_field_repr() {
    let sign = SignCall::new();
    assert_eq!(sign.preimage().inputs, sign.limbs(), "signBidirectional");

    let respond = RespondCall::new();
    assert_eq!(
        respond.preimage("respond", signet_contract::SIGNATURE_RESPONDED_EVENT).inputs,
        respond.limbs(),
        "respond"
    );

    let bidirectional = RespondBidirectionalCall::new();
    assert_eq!(bidirectional.preimage().inputs, bidirectional.limbs(), "respondBidirectional");
}

/// The typed alignment and a flat `[Field; n]` alignment over the same limbs
/// give the SAME preimage, byte for byte.
///
/// This is what licenses `serialization/deployed.rs`'s `misc_preimage`,
/// which takes raw limbs (its proptest generates thousands of payloads and
/// has no typed argument value to hand), to go through the very same ledger
/// path as the typed calls here.
#[test]
fn the_alignment_does_not_reach_the_preimage() {
    let ser = |pi: &ProofPreimage| {
        let mut buf = Vec::new();
        midnight_serialize::tagged_serialize(pi, &mut buf).expect("preimage serializes");
        buf
    };
    for (entry_point, typed, limbs, misc) in [
        (
            "signBidirectional",
            SignCall::new().typed_input(),
            SignCall::new().limbs(),
            SignCall::new().misc_bytes(),
        ),
        (
            "respond",
            RespondCall::new().typed_input(),
            RespondCall::new().limbs(),
            RespondCall::new().misc_bytes(signet_contract::SIGNATURE_RESPONDED_EVENT),
        ),
        (
            "respondBidirectional",
            RespondBidirectionalCall::new().typed_input(),
            RespondBidirectionalCall::new().limbs(),
            RespondBidirectionalCall::new().misc_bytes(),
        ),
    ] {
        let typed_pi = call_preimage(entry_point, typed, &misc);
        let flat_pi = call_preimage(entry_point, scalar_input(&limbs), &misc);
        assert_eq!(ser(&typed_pi), ser(&flat_pi), "{entry_point}: alignment changed the preimage");
    }
}

/// The corpus artifact's input schema is `Scalar<BLS12-381>` in every slot,
/// so the ledger's field vector is the whole of what the circuit sees — and
/// the count has to match, or `assert_call_compatible` would be comparing
/// two circuits that read different argument lists.
#[test]
fn input_schema_matches_the_corpus_artifact() {
    for (name, count) in [("signBidirectional", 8usize), ("respond", 9), ("respondBidirectional", 14)] {
        let theirs = corpus_zkir(name);
        assert_eq!(theirs.inputs.len(), count, "{name}: corpus input count");
    }
    assert_eq!(SignCall::new().preimage().inputs.len(), 8);
    assert_eq!(
        RespondCall::new().preimage("respond", signet_contract::SIGNATURE_RESPONDED_EVENT).inputs.len(),
        9
    );
    assert_eq!(RespondBidirectionalCall::new().preimage().inputs.len(), 14);
}

/// The tamper twins, on the LEDGER-BUILT preimage: a transcript whose logged
/// bytes disagree with the arguments must be rejected by BOTH artifacts.
/// `partition_transcripts` is content-blind — it runs whatever program it is
/// given — so the tamper survives the move onto the production path.
#[test]
fn a_tampered_event_is_rejected_by_both_artifacts() {
    let sign = SignCall::new();
    let mut misc = sign.misc_bytes();
    misc[40] ^= 0x01; // a requestId byte inside the logged bytes only
    let pi = call_preimage("signBidirectional", sign.typed_input(), &misc);
    assert!(simulate(&signet_contract::SignetContract::sign_bidirectional().ir, &pi).is_err(), "ours must reject");
    assert!(simulate(&corpus_zkir("signBidirectional"), &pi).is_err(), "corpus must reject");

    let respond = RespondCall::new();
    let mut misc = respond.misc_bytes(signet_contract::SIGNATURE_RESPONDED_EVENT);
    misc[130] ^= 0x01; // an s byte inside the logged bytes only
    let pi = call_preimage("respond", respond.typed_input(), &misc);
    assert!(simulate(&signet_contract::SignetContract::respond().ir, &pi).is_err(), "ours must reject");
    assert!(simulate(&corpus_zkir("respond"), &pi).is_err(), "corpus must reject");

    // The five PR #127 fields, one tamper each, at the offsets the layout
    // declares (name(32) then requestId at 32, blockHeight at 64, outputKind
    // at 72, length at 73, digest at 81).
    let bidirectional = RespondBidirectionalCall::new();
    for (offset, what) in [(64usize, "blockHeight byte 0"), (71, "blockHeight byte 7"), (72, "outputKind"), (80, "serializedOutputLength byte 7"), (81, "digest byte 0")] {
        let mut misc = bidirectional.misc_bytes();
        misc[offset] ^= 0x01;
        let pi = call_preimage("respondBidirectional", bidirectional.typed_input(), &misc);
        assert!(simulate(&signet_contract::SignetContract::respond_bidirectional().ir, &pi).is_err(), "ours must reject a tampered {what}");
        assert!(simulate(&corpus_zkir("respondBidirectional"), &pi).is_err(), "corpus must reject a tampered {what}");
    }
}

/// `outputKind` is a three-variant enum: both artifacts refuse a fourth
/// value even when the logged byte agrees with it.
#[test]
fn an_out_of_range_output_kind_is_rejected_by_both_artifacts() {
    let mut call = RespondBidirectionalCall::new();
    call.attestation.output_kind = 3;
    let pi = call.preimage();
    assert!(simulate(&signet_contract::SignetContract::respond_bidirectional().ir, &pi).is_err(), "ours must reject");
    assert!(simulate(&corpus_zkir("respondBidirectional"), &pi).is_err(), "corpus must reject");
    call.attestation.output_kind = 2;
    let pi = call.preimage();
    assert!(simulate(&signet_contract::SignetContract::respond_bidirectional().ir, &pi).is_ok(), "ours accepts `unviable`");
    assert!(simulate(&corpus_zkir("respondBidirectional"), &pi).is_ok(), "corpus accepts `unviable`");
}

/// The two respond circuits differ only by event name: each must reject the
/// other's transcript, on the ledger-built preimage too.
#[test]
fn a_swapped_event_name_is_rejected_by_both_artifacts() {
    let respond = RespondCall::new();
    let pi = respond.preimage("respond", signet_contract::RESPOND_BIDIRECTIONAL_EVENT);
    assert!(simulate(&signet_contract::SignetContract::respond().ir, &pi).is_err(), "ours must reject");
    assert!(simulate(&corpus_zkir("respond"), &pi).is_err(), "corpus must reject");
}
