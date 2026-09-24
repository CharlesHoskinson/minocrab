//! M29 rung D — THE LEDGER-APPLY GATE, against `sig-net/mpc`'s captured
//! on-chain respond transactions.
//!
//! Rung C proved the ledger's own preimage is call-compatible with
//! compactc's artifact. It said nothing about whether a respond call built
//! here would be ACCEPTED by a `LedgerState` under our verifier keys, and
//! nothing about whether the bytes it emits are the bytes `sig-net/mpc`'s
//! reader decodes off a real chain. This rung closes both, per circuit:
//!
//! 1. `ContractDeploy` a singleton whose three operations carry OUR verifier
//!    keys (`crates/signet-artifacts/managed/keys/*.verifier`, the committed
//!    artifacts of M29 A) into a fresh `LedgerState`, and apply it.
//! 2. Read the GOLDEN — a real, finalized `respond` /
//!    `respondBidirectional` transaction captured from a chain running
//!    compactc's artifact of the deployed singleton
//!    (`tests/fixtures/mpc/README.md`) — decode its singleton call's
//!    emission exactly the way `chain-midnight/src/emissions.rs` does, and
//!    take the request id and signature OUT of it.
//! 3. Build our own respond call on those same values, through the rung-C
//!    ledger path, into an `Intent` / `Transaction` under the proof-preimage
//!    marker; `well_formed` it against the deployed state, then `apply` it.
//! 4. Compare the emission THE LEDGER PRODUCED WHILE APPLYING OUR
//!    TRANSACTION (an `EventDetails::ContractLog`, not a re-run of our own
//!    program) with the golden's.
//!
//! # The transcript comparison
//!
//! COMPARED, and required equal:
//!
//! | field | why it must match |
//! |---|---|
//! | `ContractCall::entry_point` | the sidecar addresses the circuit by this name; a mismatch is an unroutable call |
//! | the guaranteed transcript's Impact program, op for op | this IS the emission: `Push` of `[Bytes<4> version, Bytes<1> tag, Bytes<288> data]`, then `Log` |
//! | `fallible_transcript` is `None` on both | mpc's reader REFUSES a singleton call that has one (`UnsupportedFallibleCall`) |
//! | `Transcript::version` is present | `well_formed` rejects a call against a v3-keyed operation whose transcript declares no version |
//! | the emitted `VersionedLogItem::version` (1) and `event_type` (`Misc`) | mpc's `emission_from_log_item` checks both before it looks at any byte |
//! | the logged cell's alignment: exactly one `Bytes<288>` atom | ditto — "emission-schema: Misc data is not one Bytes<288> atom" |
//! | all 288 logged bytes: `pad(32, name)` ‖ the 256-byte payload | the name selects mpc's `EmissionKind`; the payload is what the MPC signs over |
//!
//! NECESSARILY DIFFERENT, and why:
//!
//! | field | why |
//! |---|---|
//! | `ContractCall::address` | the golden's singleton is the capture chain's deployment (`b116cd04…`); ours is a fresh `ContractDeploy` whose address is derived from its own nonce and initial state. It cannot match without replaying their deployment, which is impossible by construction — their operations carry compactc's verifier keys and ours carry MinoCrab's, and that difference is the whole point of the swap. |
//! | `ContractCall::communication_commitment` | `transient_commit(input ‖ output, rand)` over a per-call `rand`; the sidecar sampled theirs, this suite pins ours so dumped preimages are reproducible. |
//! | `ContractCall::proof` | theirs is a real `ProofVersioned::V3`; ours is `ProofPreimageVersioned::V2`. This gate runs under the proof-preimage marker, where `ProofKind::proof_verify` is a no-op — rung E carries the proven one. |
//! | intent `binding_commitment` and `ttl`; transaction `binding_randomness` and `network_id` | per transaction and per chain. |
//! | `Transcript::gas` | the DECLARED cost, computed by `partition_transcripts` under whichever `LedgerParameters` the builder held. Both sides agree on `bytes_written`/`bytes_deleted` (678) and on a zero `read_time` — the singleton reads nothing — but the golden declares `compute_time` 2.208 ms where ours declares 1.303 ms, because theirs was partitioned by the sidecar against the capture chain's parameters at `crate-ledger-9.1.0.0-rc.3` and ours against `INITIAL_PARAMETERS` at rev `04c9c5d`. Printed by the test for the record, not asserted; the transaction applies under our pin at our figure, which is what `apply` checks. |
//! | `Transcript::effects` | same reason. |
//!
//! The payload VALUES match only because step 2 feeds the golden's own
//! request id and signature back in. That is the point of the comparison,
//! not a coincidence: a field the two toolchains lay out differently shows
//! up as a payload mismatch at a fixed offset.
//!
//! # What this gate does NOT prove
//!
//! No proof is made or verified (rung E). No fee is paid: balancing and
//! limits are off, and no DUST wallet exists anywhere in this workspace
//! (notes/mpc-publisher.org §2). The goldens are not inclusion proofs — see
//! `tests/fixtures/mpc/README.md`.

use midnight_base_crypto::fab::AlignedValue;
use midnight_base_crypto::time::Timestamp;
use midnight_ledger::events::EventDetails;
use midnight_ledger::semantics::TransactionResult;
use midnight_ledger::structure::{ProofKind, ProofMarker, Signature, Transaction};
use midnight_onchain_runtime::context::QueryContext;
use midnight_onchain_runtime::cost_model::INITIAL_COST_MODEL;
use midnight_onchain_state::state::{EntryPointBuf, StateValue};
use midnight_onchain_vm::ops::{LogEventType, VersionedLogItem};
use midnight_onchain_vm::result_mode::ResultModeVerify;
use midnight_storage::db::InMemoryDB;
use minocrab_contracts::events::{MISC_SIZE, MISC_TAG, MISC_VERSION};
use minocrab_contracts::signet_contract;
use sha2::{Digest, Sha256};

mod support;

use support::signet_call::{
    bytesn_value, call_intent, call_prototype, calls_of, deploy_singleton, empty_state, log_ops,
    managed_verifier_key, preimage_tx, respond_bidirectional_input, respond_bidirectional_misc,
    respond_input, respond_misc, sample_attestation, singleton_contract_state, tx_context, ttl,
    unbalanced_strictness, VmOp, SIGNER_CIRCUITS,
};

// ---- the goldens -----------------------------------------------------------

const RESPOND_TX_161: &[u8] = include_bytes!("fixtures/mpc/respond-tx-161.mn");
const RESPOND_BIDIRECTIONAL_TX_181: &[u8] =
    include_bytes!("fixtures/mpc/respond-bidirectional-tx-181.mn");

/// `tests/fixtures/mpc/README.md`'s table: each fixture's SHA-256 is also the
/// ledger transaction hash the capture recorded, so this one line is both the
/// import's integrity check and its provenance pin.
const RESPOND_TX_161_SHA256: &str =
    "9444aa6304257d0ae278531a3c70ee0baa508c197369024fb14463f987b06745";
const RESPOND_BIDIRECTIONAL_TX_181_SHA256: &str =
    "5291b70cbdfe7a095828a2c6c94cf5b89f7eb2a94e22c2c4953d7706067ef17a";

/// The capture chain's singleton address (`README.md`).
const CAPTURE_SINGLETON: [u8; 32] = [
    0xb1, 0x16, 0xcd, 0x04, 0x82, 0xb8, 0x49, 0x22, 0xe7, 0x61, 0x27, 0x8a, 0x25, 0xd1, 0xee, 0x23,
    0x05, 0xfd, 0x6d, 0x63, 0x0f, 0x0d, 0x48, 0x95, 0x4d, 0x2a, 0xf6, 0x53, 0x7f, 0x8e, 0x21, 0x4e,
];

/// The request id all three captured events carry (`README.md`).
const CAPTURE_REQUEST_ID: [u8; 32] = [
    0x1c, 0xd1, 0x0e, 0xb1, 0xf4, 0xfa, 0x5c, 0x66, 0x50, 0x84, 0xd2, 0x4a, 0x79, 0x82, 0xb0, 0x9a,
    0xa3, 0x21, 0x88, 0x6d, 0xce, 0x77, 0xd8, 0x5b, 0x5f, 0x6f, 0xee, 0xe0, 0x68, 0x7a, 0x41, 0x4b,
];

/// A proven transaction as finalized blocks carry it — the type
/// `chain-midnight/src/emissions.rs` calls `DecodedTransaction`.
type ProvenTx =
    Transaction<Signature, ProofMarker, <ProofMarker as ProofKind<InMemoryDB>>::Pedersen, InMemoryDB>;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn golden(bytes: &[u8], expected_sha256: &str, who: &str) -> ProvenTx {
    assert_eq!(
        hex(&Sha256::digest(bytes)),
        expected_sha256,
        "{who}: imported fixture bytes differ from the recorded capture"
    );
    // Also the M29 F evidence: mpc builds against crate-ledger-9.1.0.0-rc.3,
    // this repo against rev 04c9c5d. A transaction serialized by theirs
    // decoding here IS the two pins agreeing on the wire format.
    midnight_serialize::tagged_deserialize(&mut &bytes[..]).unwrap_or_else(|e| {
        panic!("{who}: the captured transaction must decode under our ledger pin: {e}")
    })
}

// ---- the emission decoder (mpc's, translated) ------------------------------

/// One decoded singleton emission: the 288-byte Misc split the way
/// `chain-midnight/src/emissions.rs` splits it.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Emission {
    name: [u8; 32],
    payload: [u8; 256],
}

/// MECHANICAL TRANSLATION of `emission_from_log_item` (`sig-net/mpc`
/// `chain-signatures/chain-midnight/src/emissions.rs:96-148`): version 1,
/// type `Misc`, one `Bytes<288>` cell, zero-extended, then
/// `name(32) ‖ payload(256)`. Every assertion here is one of that function's
/// `ensure!`s, so an emission our circuits produce that mpc's reader would
/// DROP fails here, under the reason mpc would print.
fn emission_from_log_item(item: &VersionedLogItem<InMemoryDB>, who: &str) -> Emission {
    assert_eq!(item.version, MISC_VERSION, "{who}: log item version");
    assert_eq!(item.event_type, LogEventType::Misc, "{who}: log item type");
    let StateValue::Cell(cell) = &item.data else {
        panic!("{who}: Misc data is not a cell");
    };
    assert_eq!(
        cell.alignment,
        bytesn_value(MISC_SIZE as u32, &[0u8]).alignment,
        "{who}: Misc data is not one Bytes<{MISC_SIZE}> atom"
    );
    assert_eq!(cell.value.0.len(), 1, "{who}: Misc data atom count");
    let stored = &cell.value.0[0].0;
    assert!(stored.len() <= MISC_SIZE, "{who}: Misc data overruns Bytes<{MISC_SIZE}>");
    let mut bytes = [0u8; MISC_SIZE];
    bytes[..stored.len()].copy_from_slice(stored);
    let mut name = [0u8; 32];
    name.copy_from_slice(&bytes[..32]);
    let mut payload = [0u8; 256];
    payload.copy_from_slice(&bytes[32..]);
    Emission { name, payload }
}

/// The golden's singleton call: entry point, guaranteed transcript program,
/// and the emission that program produces under the ledger VM —
/// `emissions_of_call`'s path (a `QueryContext` over an empty state, since
/// the singleton is stateless).
struct GoldenCall {
    entry_point: EntryPointBuf,
    program: Vec<VmOp>,
    emission: Emission,
}

fn golden_call(tx: &ProvenTx, who: &str) -> GoldenCall {
    let mut found: Option<GoldenCall> = None;
    for (_, call) in tx.calls() {
        if call.address.0 .0 != CAPTURE_SINGLETON {
            continue;
        }
        assert!(found.is_none(), "{who}: more than one singleton call");
        assert!(
            call.fallible_transcript.is_none(),
            "{who}: the singleton call carries a fallible transcript"
        );
        let transcript = call
            .guaranteed_transcript
            .as_deref()
            .unwrap_or_else(|| panic!("{who}: the singleton call has no guaranteed transcript"));
        assert!(transcript.version.is_some(), "{who}: the captured transcript declares a version");
        let program: Vec<VmOp> = Vec::from(&transcript.program);
        let results = QueryContext::new(empty_state(), call.address)
            .query::<ResultModeVerify>(&program, None, &INITIAL_COST_MODEL)
            .unwrap_or_else(|e| {
                panic!("{who}: the ledger VM rejected the captured transcript: {e}")
            });
        assert_eq!(results.events.len(), 1, "{who}: emissions in the singleton call");
        println!("{who}: captured transcript gas {:?}", transcript.gas);
        found = Some(GoldenCall {
            entry_point: call.entry_point.clone(),
            program,
            emission: emission_from_log_item(&results.events[0], who),
        });
    }
    found.unwrap_or_else(|| panic!("{who}: no singleton call in the captured transaction"))
}

// ---- our side: deploy, build, well_formed, apply ---------------------------

/// What applying our own respond transaction produced.
struct AppliedCall {
    entry_point: EntryPointBuf,
    program: Vec<VmOp>,
    emission: Emission,
}

#[allow(clippy::too_many_arguments)]
fn apply_respond_call(
    entry_point: &str,
    event_name: &str,
    request_id: &[u8; 32],
    big_r_x: &[u8; 32],
    big_r_y: &[u8; 32],
    s: &[u8; 32],
    recovery_id: u8,
) -> AppliedCall {
    apply_call(
        entry_point,
        &respond_misc(event_name, request_id, big_r_x, big_r_y, s, recovery_id),
        respond_input(request_id, big_r_x, big_r_y, s, recovery_id),
    )
}

/// Deploy the singleton under the committed keys, build ONE call of
/// `entry_point` over `misc` and `input`, `well_formed` and `apply` it, and
/// return what the chain would carry.
fn apply_call(entry_point: &str, misc: &[u8], input: AlignedValue) -> AppliedCall {
    let tblock = Timestamp::from_secs(0);
    let (ledger, address) = deploy_singleton(
        singleton_contract_state(|c| Some(managed_verifier_key(c))),
        tblock,
    );

    let proto = call_prototype(entry_point, address, input, misc);
    let intent = call_intent(vec![proto], ttl(tblock));
    let tx = preimage_tx(intent.clone());

    let vtx = tx.well_formed(&ledger, unbalanced_strictness(), tblock).unwrap_or_else(|e| {
        panic!("{entry_point}: our respond transaction is not well formed: {e:?}")
    });
    let (_after, result) = ledger.apply(&vtx, &tx_context(&ledger, tblock));
    let events = match &result {
        TransactionResult::Success(events) => events.clone(),
        other => panic!("{entry_point}: our respond transaction did not apply: {other:?}"),
    };

    let mut emission = None;
    for event in &events {
        if let EventDetails::ContractLog { address: at, entry_point: ep, logged_item } =
            &event.content
        {
            assert_eq!(*at, address, "{entry_point}: the log came from another contract");
            assert_eq!(ep.as_ref(), entry_point.as_bytes(), "{entry_point}: the log's entry point");
            assert!(emission.is_none(), "{entry_point}: more than one contract log");
            emission = Some(emission_from_log_item(logged_item, entry_point));
        }
    }
    let emission = emission
        .unwrap_or_else(|| panic!("{entry_point}: applying the call emitted no ContractLog event"));

    let calls = calls_of(&intent);
    assert_eq!(calls.len(), 1, "{entry_point}: one call in the intent");
    assert!(
        calls[0].fallible_transcript.is_none(),
        "{entry_point}: our call must have no fallible transcript — mpc's reader drops those"
    );
    let transcript = calls[0]
        .guaranteed_transcript
        .as_deref()
        .expect("our call has a guaranteed transcript")
        .clone();
    assert!(
        transcript.version.is_some(),
        "{entry_point}: our transcript declares a version (well_formed checks it \
         against the deployed operation)"
    );
    println!("{entry_point}: our transcript gas {:?}", transcript.gas);
    AppliedCall {
        entry_point: calls[0].entry_point.clone(),
        program: Vec::from(&transcript.program),
        emission,
    }
}

// ---- the two gates ---------------------------------------------------------

fn respond_matches_the_golden(
    who: &str,
    bytes: &[u8],
    sha256: &str,
    entry_point: &str,
    event_name: &str,
) {
    let theirs = golden_call(&golden(bytes, sha256, who), who);

    // The golden's own name, entry point and request id, before anything
    // here leans on them.
    let mut expected_name = [0u8; 32];
    expected_name[..event_name.len()].copy_from_slice(event_name.as_bytes());
    assert_eq!(theirs.emission.name, expected_name, "{who}: the golden's event name");
    assert_eq!(theirs.entry_point.as_ref(), entry_point.as_bytes(), "{who}: the golden's entry point");
    assert_eq!(
        theirs.emission.payload[..32],
        CAPTURE_REQUEST_ID,
        "{who}: the golden's request id at payload offset 0"
    );

    // Take the signature out of the golden's payload at the offsets the
    // singleton's layout declares — requestId(32) ‖ x(32) ‖ y(32) ‖ s(32) ‖
    // recoveryId(1) ‖ zeros(127) — and rebuild the same call here.
    let at = |from: usize| -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&theirs.emission.payload[from..from + 32]);
        out
    };
    let (request_id, big_r_x, big_r_y, s) = (at(0), at(32), at(64), at(96));
    let recovery_id = theirs.emission.payload[128];
    assert!(
        theirs.emission.payload[129..].iter().all(|b| *b == 0),
        "{who}: the golden's payload tail is not zero-padded as the layout declares"
    );

    let ours = apply_respond_call(
        entry_point,
        event_name,
        &request_id,
        &big_r_x,
        &big_r_y,
        &s,
        recovery_id,
    );

    assert_eq!(ours.entry_point, theirs.entry_point, "{who}: entry point");
    assert_eq!(ours.program, theirs.program, "{who}: Impact program");
    assert_eq!(ours.emission, theirs.emission, "{who}: the 288 emitted Misc bytes");
}

#[test]
fn respond_apply_matches_the_captured_transaction() {
    respond_matches_the_golden(
        "respond-tx-161",
        RESPOND_TX_161,
        RESPOND_TX_161_SHA256,
        "respond",
        signet_contract::SIGNATURE_RESPONDED_EVENT,
    );
}

/// The captured `respondBidirectional` transaction predates PR #127: its
/// payload is the OLD layout (requestId ‖ signature ‖ zeros), and the
/// singleton this crate ports now emits requestId ‖ blockHeight ‖ outputKind
/// ‖ serializedOutputLength ‖ digest ‖ signature ‖ zeros. So this capture no
/// longer evidences the payload bytes; what it still evidences — and what
/// this test holds it to — is everything that did not change: the entry
/// point, the event name, the request id at offset 0, and the SHAPE of the
/// Impact program (`push` of the three-cell Misc — version, tag, 288 bytes
/// — then `log`; the pushed literal itself carries the payload, so it
/// differs exactly where the payload does). A capture from a chain running the #127 singleton
/// is owed (`tests/fixtures/mpc/README.md`); when it arrives, this becomes
/// the full 288-byte comparison `respond` has.
#[test]
fn respond_bidirectional_apply_matches_the_captured_transactions_program() {
    let who = "respond-bidirectional-tx-181";
    let theirs = golden_call(
        &golden(RESPOND_BIDIRECTIONAL_TX_181, RESPOND_BIDIRECTIONAL_TX_181_SHA256, who),
        who,
    );
    let event_name = signet_contract::RESPOND_BIDIRECTIONAL_EVENT;
    let mut expected_name = [0u8; 32];
    expected_name[..event_name.len()].copy_from_slice(event_name.as_bytes());
    assert_eq!(theirs.emission.name, expected_name, "{who}: the golden's event name");
    assert_eq!(theirs.entry_point.as_ref(), b"respondBidirectional", "{who}: the golden's entry point");
    assert_eq!(theirs.emission.payload[..32], CAPTURE_REQUEST_ID, "{who}: the golden's request id");

    // The golden's signature, at the OLD offsets, re-emitted through the
    // NEW layout with a sample attestation.
    let at = |from: usize| -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&theirs.emission.payload[from..from + 32]);
        out
    };
    let (request_id, big_r_x, big_r_y, s) = (at(0), at(32), at(64), at(96));
    let recovery_id = theirs.emission.payload[128];
    let attestation = sample_attestation();
    let ours = apply_call(
        "respondBidirectional",
        &respond_bidirectional_misc(&request_id, &attestation, &big_r_x, &big_r_y, &s, recovery_id),
        respond_bidirectional_input(&request_id, &attestation, &big_r_x, &big_r_y, &s, recovery_id),
    );

    assert_eq!(ours.entry_point, theirs.entry_point, "{who}: entry point");
    // The program, with the pushed Misc literal's payload masked: op for op
    // the same, and the same version and tag cells.
    let shape = |program: &[VmOp]| -> String {
        let s = format!("{program:?}");
        let (head, tail) = s.split_once(", <[").expect("the push carries a third cell");
        let (_payload, rest) = tail.split_once("]: b288>").expect("a 288-byte cell");
        format!("{head}, <[…]: b288>{rest}")
    };
    assert_eq!(shape(&ours.program), shape(&theirs.program), "{who}: Impact program shape");
    assert_eq!(ours.program.len(), 2, "{who}: push + log");
    assert_eq!(ours.emission.name, theirs.emission.name, "{who}: event name");
    assert_eq!(ours.emission.payload[..32], theirs.emission.payload[..32], "{who}: request id");
    // And the layout really did move: the signature sits after the
    // attestation now (payload offset 81, i.e. Misc offset 113), not where
    // the capture had it (payload offset 32).
    assert_eq!(ours.emission.payload[81..113], big_r_x, "{who}: bigR.x at the #127 offset");
    assert_eq!(theirs.emission.payload[32..64], big_r_x, "{who}: bigR.x at the capture's offset");
    assert_ne!(ours.emission.payload[32..64], big_r_x, "{who}: bigR.x is no longer at the old offset");
}

/// The deployed operations really do carry the COMMITTED verifier keys under
/// the Compact entry-point names. Without this, the apply gates above would
/// pass just as well against a contract that declares no keys at all — the
/// proof-preimage marker never looks at one.
#[test]
fn the_deployed_operations_are_our_committed_verifier_keys() {
    let (ledger, address) = deploy_singleton(
        singleton_contract_state(|c| Some(managed_verifier_key(c))),
        Timestamp::from_secs(0),
    );
    let state = ledger.index(address).expect("the singleton is deployed");
    for circuit in SIGNER_CIRCUITS {
        let ep: EntryPointBuf = circuit.as_bytes().into();
        let op = state
            .operations
            .get(&ep)
            .unwrap_or_else(|| panic!("{circuit}: no operation at that entry point"));
        assert_eq!(
            op.latest().expect("a v3 verifier key"),
            &managed_verifier_key(circuit),
            "{circuit}: the deployed key is not the committed managed key"
        );
        assert!(op.v2.is_none(), "{circuit}: no legacy verifier key is deployed");
    }
}

/// The Impact program `support::signet_call::log_ops` writes out is the
/// program a real chain carried. Stated on its own so a change to `log_ops`
/// fails HERE, naming the golden, rather than somewhere downstream.
#[test]
fn log_ops_is_the_program_the_captured_transactions_carry() {
    for (who, bytes, sha256, event_name) in [
        (
            "respond-tx-161",
            RESPOND_TX_161,
            RESPOND_TX_161_SHA256,
            signet_contract::SIGNATURE_RESPONDED_EVENT,
        ),
        (
            "respond-bidirectional-tx-181",
            RESPOND_BIDIRECTIONAL_TX_181,
            RESPOND_BIDIRECTIONAL_TX_181_SHA256,
            signet_contract::RESPOND_BIDIRECTIONAL_EVENT,
        ),
    ] {
        let theirs = golden_call(&golden(bytes, sha256, who), who);
        let mut misc = vec![0u8; MISC_SIZE];
        misc[..event_name.len()].copy_from_slice(event_name.as_bytes());
        misc[32..].copy_from_slice(&theirs.emission.payload);
        assert_eq!(log_ops(&misc), theirs.program, "{who}");
    }
    // And the three constants those ops carry are the ones mpc's reader
    // checks by name.
    assert_eq!(MISC_VERSION, 1, "log item version");
    assert_eq!(MISC_TAG, LogEventType::Misc as u8, "log event type");
    assert_eq!(MISC_SIZE, 288, "name(32) + payload(256)");
}
