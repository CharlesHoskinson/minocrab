//! M30 rung A's gates: the public surface, on its own.
//!
//! What is NOT here, deliberately: that the prototype these functions build
//! is call-compatible with compactc's artifact, that it applies to a
//! `LedgerState`, and that a proof of it verifies. Those are M29 C/D/E, they
//! run in `minocrab-contracts`, and since rung A they run THROUGH this
//! crate — so the preimages they pin are this crate's output, checked
//! against the corpus artifact and against two captured on-chain
//! transactions. Repeating them here would add a second copy, not a second
//! check.

use midnight_base_crypto::hash::HashOutput;
use midnight_coin_structure::contract::ContractAddress;
use midnight_ledger::structure::INITIAL_PARAMETERS;
use midnight_onchain_vm::ops::Op;
use midnight_storage::db::InMemoryDB;
use midnight_transient_crypto::curve::Fr;
use midnight_transient_crypto::fab::AlignedValueExt;
use minocrab_publisher::call::{
    empty_state, event_name, Attestation, ContractKeyLocation, Deployment, EcdsaSignature,
    Notification,
    SignerCall, RESPOND, RESPOND_BIDIRECTIONAL, SIGNER_CIRCUITS, SIGN_BIDIRECTIONAL,
};
use minocrab_publisher::{respond, respond_bidirectional, sign_bidirectional, PublishError};
use signet_protocol::circuits::{
    RESPOND_BIDIRECTIONAL_EVENT, SIGNATURE_RESPONDED_EVENT, SIGN_BIDIRECTIONAL_EVENT,
};
use signet_protocol::misc::MISC_SIZE;

/// The COMMITTED `expectedVk` table (M29 A/B,
/// `crates/signet-artifacts/managed/expectedVk.json`) — real hashes, so the
/// key locations these tests build are the ones a real deployment of our
/// artifacts would carry.
const EXPECTED_VK: [(&str, &str); 3] = [
    ("respond", "15954f5769161352510f237304e2cf44a74fc72403ccb07936f353a593834cd8"),
    (
        "respondBidirectional",
        "07de73c261fb0491cd1c67cf9909cbeaac8c0821f9caf7bcff649d9611d88a38",
    ),
    ("signBidirectional", "8e2042d0c6c123ab134c718f473bf6b51dd15857922f58e8102288a121a7f824"),
];

const ADDRESS_BYTES: [u8; 32] = [0x5a; 32];

fn deployment() -> Deployment {
    Deployment::new(
        ContractAddress(HashOutput(ADDRESS_BYTES)),
        EXPECTED_VK.iter().map(|(c, h)| (c.to_string(), h.to_string())),
    )
}

fn request_id() -> [u8; 32] {
    let mut rid = [0u8; 32];
    rid[..10].copy_from_slice(b"request-id");
    rid[31] = 0x9c;
    rid
}

fn fill(seed: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    for (i, byte) in b.iter_mut().enumerate() {
        *byte = seed.wrapping_add(i as u8).wrapping_mul(13);
    }
    b
}

fn signature() -> EcdsaSignature {
    EcdsaSignature { big_r_x: fill(0x11), big_r_y: fill(0x47), s: fill(0xa3), recovery_id: 1 }
}

fn attestation() -> Attestation {
    Attestation {
        block_height: 0x0102_0304_0506_0708,
        output_kind: 1,
        serialized_output_length: 32,
        digest: fill(0xd1),
    }
}

fn notification() -> Notification {
    let mut payload = [0u8; 128];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(3);
    }
    Notification { version: 1, payload }
}

// ---- the key location ------------------------------------------------------

/// `contract:<64-hex address>/<circuitId>?vk=<64-hex hash>` — the exact
/// spelling `@midnight-ntwrk/compact-js`'s `encodeContractKeyLocation`
/// produces (`dist/cjs/ContractKeyLocation.js`), written out here as a
/// literal so a change to the format is a failing assertion and not a
/// silently unroutable key request.
#[test]
fn the_encoded_key_location_is_compact_jss_spelling() {
    let loc = deployment().key_location(RESPOND).expect("respond is in the table");
    assert_eq!(
        loc.encode(),
        "contract:5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a\
         /respond?vk=15954f5769161352510f237304e2cf44a74fc72403ccb07936f353a593834cd8"
    );
    assert_eq!(ContractKeyLocation::parse(&loc.encode()).expect("round trip"), loc);
}

/// The three rejections `encodeContractKeyLocation` makes, made here at
/// construction instead of at encode time — a key location that cannot be
/// encoded should not exist.
#[test]
fn a_key_location_that_compact_js_would_refuse_is_refused_here() {
    let address = ContractAddress(HashOutput(ADDRESS_BYTES));
    let good = EXPECTED_VK[0].1;
    for (circuit, hash, why) in [
        ("", good, "empty circuit id"),
        ("resp/ond", good, "circuit id with a slash"),
        ("resp?ond", good, "circuit id with a question mark"),
        ("respond", "not hex", "a hash that is not hex"),
        ("respond", "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789", "an UPPERCASE hash"),
        ("respond", "15954f57", "a short hash"),
    ] {
        assert!(
            matches!(
                ContractKeyLocation::new(address, circuit, hash),
                Err(PublishError::KeyLocation(_))
            ),
            "{why} was accepted"
        );
    }
}

#[test]
fn a_malformed_encoded_location_does_not_parse() {
    for s in [
        "respond",
        "contract:5a/respond?vk=15954f57",
        "contract:5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a/respond",
        "contract:5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a/respond?vk=zz",
    ] {
        assert!(ContractKeyLocation::parse(s).is_err(), "'{s}' parsed");
    }
}

/// A circuit the deployment's `expectedVk` table does not carry has no key
/// location — the sidecar's own gate (`prover.ts` checks
/// `hashVerifierKey(verifierKey) !== verifierKeyHash` before it will prove),
/// kept here as "you cannot even name the key".
#[test]
fn a_circuit_outside_the_expected_vk_table_has_no_key_location() {
    assert!(matches!(
        deployment().key_location("transfer"),
        Err(PublishError::UnknownCircuit(_))
    ));
}

// ---- the arguments and the envelope ----------------------------------------

/// `pad(32, name)` ‖ requestId(32) ‖ x(32) ‖ y(32) ‖ s(32) ‖ recoveryId(1)
/// ‖ zeros(127), and the same layout `sig-net/mpc`'s reader decodes off a
/// real chain (`chain-midnight/src/emissions.rs`; `minocrab-contracts`'
/// `tests/signet_ledger_apply.rs` checks all 288 bytes against two captured
/// transactions).
#[test]
fn a_respond_call_lays_its_signature_out_where_the_singleton_says() {
    let (rid, sig) = (request_id(), signature());
    for (circuit, event, call) in [(
        RESPOND,
        SIGNATURE_RESPONDED_EVENT,
        respond::<InMemoryDB>(&deployment(), &rid, &sig).expect("respond builds"),
    )] {
        assert_eq!(call.circuit, circuit);
        assert_eq!(call.key_location.circuit_id, circuit);
        assert_eq!(call.misc.len(), MISC_SIZE);
        let mut name = [0u8; 32];
        name[..event.len()].copy_from_slice(event.as_bytes());
        assert_eq!(&call.misc[..32], &name[..], "{circuit}: the event name");
        assert_eq!(&call.misc[32..64], &rid[..], "{circuit}: the request id");
        assert_eq!(&call.misc[64..96], &sig.big_r_x[..], "{circuit}: bigR.x");
        assert_eq!(&call.misc[96..128], &sig.big_r_y[..], "{circuit}: bigR.y");
        assert_eq!(&call.misc[128..160], &sig.s[..], "{circuit}: s");
        assert_eq!(call.misc[160], sig.recovery_id, "{circuit}: recoveryId");
        assert!(call.misc[161..].iter().all(|b| *b == 0), "{circuit}: the tail is zero-padded");
        // Nine `Scalar<BLS12-381>` inputs, the count the corpus artifact
        // declares (minocrab-contracts' `input_schema_matches_the_corpus_artifact`).
        assert_eq!(field_repr_len(&call), 9, "{circuit}: argument limbs");
    }
}

/// `respondBidirectional`'s PR #127 layout: requestId(32) ‖ blockHeight
/// LE(8) ‖ outputKind(1) ‖ length LE(8) ‖ digest(32) ‖ x ‖ y ‖ s ‖
/// recoveryId ‖ zeros(78); fourteen limbs.
#[test]
fn a_respond_bidirectional_call_lays_its_attestation_out_where_the_singleton_says() {
    let (rid, att, sig) = (request_id(), attestation(), signature());
    let call = respond_bidirectional::<InMemoryDB>(&deployment(), &rid, &att, &sig)
        .expect("respondBidirectional builds");
    assert_eq!(call.circuit, RESPOND_BIDIRECTIONAL);
    assert_eq!(call.key_location.circuit_id, RESPOND_BIDIRECTIONAL);
    assert_eq!(call.misc.len(), MISC_SIZE);
    let mut name = [0u8; 32];
    name[..RESPOND_BIDIRECTIONAL_EVENT.len()].copy_from_slice(RESPOND_BIDIRECTIONAL_EVENT.as_bytes());
    assert_eq!(&call.misc[..32], &name[..], "the event name");
    assert_eq!(&call.misc[32..64], &rid[..], "the request id");
    assert_eq!(&call.misc[64..72], &att.block_height.to_le_bytes()[..], "blockHeight, little-endian");
    assert_eq!(call.misc[72], att.output_kind, "outputKind");
    assert_eq!(&call.misc[73..81], &att.serialized_output_length.to_le_bytes()[..], "serializedOutputLength, little-endian");
    assert_eq!(&call.misc[81..113], &att.digest[..], "digest");
    assert_eq!(&call.misc[113..145], &sig.big_r_x[..], "bigR.x");
    assert_eq!(&call.misc[145..177], &sig.big_r_y[..], "bigR.y");
    assert_eq!(&call.misc[177..209], &sig.s[..], "s");
    assert_eq!(call.misc[209], sig.recovery_id, "recoveryId");
    assert!(call.misc[210..].iter().all(|b| *b == 0), "the tail is zero-padded");
    assert_eq!(field_repr_len(&call), 14, "argument limbs");
}

/// `pad(32, name)` ‖ version(1) ‖ requestId(32) ‖ payload(128) ‖ zeros(95),
/// and eight argument limbs.
#[test]
fn sign_bidirectional_lays_its_notification_out_where_the_singleton_says() {
    let (rid, note) = (request_id(), notification());
    let call =
        sign_bidirectional::<InMemoryDB>(&deployment(), &rid, &note).expect("it builds");
    let mut name = [0u8; 32];
    name[..SIGN_BIDIRECTIONAL_EVENT.len()].copy_from_slice(SIGN_BIDIRECTIONAL_EVENT.as_bytes());
    assert_eq!(&call.misc[..32], &name[..]);
    assert_eq!(call.misc[32], note.version);
    assert_eq!(&call.misc[33..65], &rid[..]);
    assert_eq!(&call.misc[65..193], &note.payload[..]);
    assert!(call.misc[193..].iter().all(|b| *b == 0));
    assert_eq!(field_repr_len(&call), 8);
}

fn field_repr_len(call: &SignerCall<InMemoryDB>) -> usize {
    let mut limbs = Vec::new();
    call.input.value_only_field_repr(&mut limbs);
    limbs.len()
}

/// Every circuit the crate names has an event name and a builder — stated so
/// that a fourth signer circuit cannot appear without this file noticing.
#[test]
fn every_signer_circuit_has_an_event_name() {
    assert_eq!(SIGNER_CIRCUITS, [SIGN_BIDIRECTIONAL, RESPOND, RESPOND_BIDIRECTIONAL]);
    let mut names: Vec<&str> =
        SIGNER_CIRCUITS.iter().map(|c| event_name(c).expect("a signer circuit")).collect();
    names.sort_unstable();
    let mut expected =
        vec![SIGN_BIDIRECTIONAL_EVENT, SIGNATURE_RESPONDED_EVENT, RESPOND_BIDIRECTIONAL_EVENT];
    expected.sort_unstable();
    assert_eq!(names, expected);
    assert!(matches!(event_name("transfer"), Err(PublishError::UnknownCircuit(_))));
}

// ---- the prototype ---------------------------------------------------------

/// The prototype carries the arguments, the program and the entry point, and
/// its `key_location` is the BARE circuit id — the resolver-steering string
/// M29 C pinned and `crates/signet-artifacts/managed/` names its files by.
#[test]
fn the_prototype_carries_the_call() {
    let call =
        respond::<InMemoryDB>(&deployment(), &request_id(), &signature()).expect("respond builds");
    let proto = call
        .prototype(&empty_state(), &INITIAL_PARAMETERS, Fr::from(0x516_e37u64))
        .expect("the singleton's Push+Log program partitions");

    assert_eq!(proto.entry_point.as_ref(), RESPOND.as_bytes());
    assert_eq!(proto.address, deployment().address);
    assert_eq!(&*proto.key_location.0, RESPOND);
    assert_eq!(proto.input, call.input);
    assert!(proto.private_transcript_outputs.is_empty());

    // One guaranteed transcript, no fallible one: mpc's reader REFUSES a
    // singleton call that carries a fallible transcript
    // (`UnsupportedFallibleCall`).
    let guaranteed = proto.guaranteed_public_transcript.expect("a guaranteed transcript");
    assert!(proto.fallible_public_transcript.is_none());
    // And it declares a version — `well_formed` rejects a call against a
    // v3-keyed operation whose transcript declares none.
    assert!(guaranteed.version.is_some());
    assert_eq!(Vec::from(&guaranteed.program), call.ops);
    assert!(matches!(call.ops[0], Op::Push { storage: false, .. }));
    assert!(matches!(call.ops[1], Op::Log));
}
