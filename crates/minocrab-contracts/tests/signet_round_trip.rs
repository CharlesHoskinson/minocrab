//! M35 rung D, THE STATE-DRIVING HALF: request → post → respond, chained on
//! a real `StateValue` through the Impact VM under plain `cargo test`.
//!
//! Rung D built the responder (`crates/signet-sim`) but could not chain it,
//! because nothing produced a circuit's transcript from ledger state. The
//! executor (`minocrab_sim::v3::exec`) does, so this file closes the loop as
//! far as it goes:
//!
//! 1. a request circuit runs against a real pre-state; the executor derives
//!    its transcript FROM that state and the Impact VM applies it;
//! 2. the singleton's notification is built from the slot's OWN declared
//!    path (`Pending::record_path`, the one the artifact-agreement gate pins
//!    against the compiled contract-info);
//! 3. `SigNetSim` — the MPC's own reader, translated — walks the POST state
//!    by that path, finds the record the circuit filed, recomputes its id
//!    from the bytes it decoded, and signs. Nothing is handed to it: every
//!    byte it reads was written by the circuit into a `StateValue`.
//!
//! It also chains the pairs THROUGH state: a request circuit's post-state is
//! the state its settle circuit reads, with nothing carried between them but
//! a `StateValue`. That is what M35 D's `cargo test` speed asks for, and it
//! is the first time a settle in this workspace has read a record it was not
//! handed.
//!
//! The adversarial responders live here too, each hitting the reader's own
//! drop reason by name.
//!
//! The last link, `respond → settle`, closed on 2026-09-07 (decisions.org
//! T1): the typed settle's digest now packs the output the way the MPC's
//! `compute_response_hash` does — `the_typed_settle_digest_is_the_digest_the_
//! mpc_signs` pins the agreement, and the chained pairs below settle against
//! the sim's own attestation. See notes/signet-async.org §10.

use midnight_onchain_state::state::StateValue;
use midnight_transient_crypto::proofs::Zkir;
use minocrab::Fr;
use minocrab_contracts::erc20_vault_pending::{self as pending};
use minocrab_contracts::signet_v1::ETHEREUM_CAIP2_ID;
use minocrab_sim::v3::exec::{self, Call};
use signet_sim::reader::MISC_PAYLOAD_LEN;
use signet_sim::{EvmOutcome, Refusal, SigNetSim};

mod vault_pending;
use vault_pending::model::*;
use vault_pending::prims::{attestation_digest, b32_slots, pad32};

/// The height the simulated MPC attests. One constant, because what the
/// tests here are about is the record and the signature — the height's own
/// gate is `Outbox::raise_seen`'s, and the model varies it under proptest.
const HEIGHT: u64 = 21_000_000;

/// The singleton's `Misc` payload for a request: `version(1) ‖
/// requestId(32) ‖ callerAddress(32) ‖ pathDepth(1) ‖ path(4) ‖ zeros`.
///
/// Built from the SLOT's declared path, not from a constant — the same
/// bytes `Pending::request` derives, so a layout change moves both.
fn notification(request_id: &[u8; 32], caller: &[u8; 32], path: &[u8]) -> [u8; MISC_PAYLOAD_LEN] {
    let mut out = [0u8; MISC_PAYLOAD_LEN];
    out[0] = 1;
    out[1..33].copy_from_slice(request_id);
    out[33..65].copy_from_slice(caller);
    out[65] = path.len() as u8;
    out[66..66 + path.len()].copy_from_slice(path);
    out
}

/// Run a request circuit against `pre` and return the state it leaves.
fn post_state_of(
    ir: &minocrab_zkir::v3::IrSource,
    scenario_inputs: &[Fr],
    scenario_witnesses: &[Fr],
    comm_rand: Fr,
    pre: &vault_pending::exec::PreState,
    self_addr: &[u8; 32],
) -> StateValue<midnight_storage::db::InMemoryDB> {
    let ctx = exec::context(pre.state(), *self_addr);
    let call = Call::new(scenario_inputs, scenario_witnesses).with_comm_rand(comm_rand);
    let run = exec::execute(ir, &call, &ctx).expect("the request circuit runs against the state");
    run.post
}

/// A deposit filed by the circuit, and the state it left behind.
fn filed_deposit() -> (StartDepositScenario, StateValue<midnight_storage::db::InMemoryDB>) {
    let s = StartDepositScenario::new();
    let pi = s.preimage();
    let comm_rand = pi.communications_commitment.expect("a request commits").1;
    let post = post_state_of(
        &pending::Vault::deposit().ir,
        &pi.inputs,
        &pi.private_transcript,
        comm_rand,
        &s.pre_state(),
        &s.env.self_addr,
    );
    (s, post)
}

fn deposits_path() -> Vec<u8> {
    pending::VAULT.deposits.record_path().as_slice().to_vec()
}

// ---- the chain -------------------------------------------------------------

/// THE ROUND TRIP, as far as it goes: the record the MPC signs over was
/// written into the ledger by the circuit, found by the MPC's own path walk,
/// and its id recomputed from the bytes as filed.
#[test]
fn the_mpc_resolves_the_record_the_request_circuit_filed() {
    let (s, post) = filed_deposit();
    let rid = s.request_id();
    let mut sim = SigNetSim::from_seed(b"minocrab round trip", 0);
    let payload = notification(&rid, &s.env.self_addr, &deposits_path());

    let attestation = sim
        .respond_v1(&payload, &post, EvmOutcome::Executed { body: vec![1u8] }, HEIGHT)
        .expect("the MPC resolves the filed record");

    assert_eq!(attestation.request_id, rid, "the id the MPC signs is the filed one");
    assert_eq!(
        attestation.output,
        vec![1u8],
        "the output is the EVM body ALONE — V1 glues no kind byte to its front"
    );
    assert_eq!(attestation.output_kind, signet_sim::hashing::v1::output_kind::EXECUTED);
    assert_eq!(attestation.block_height, HEIGHT, "the height is attested, not inferred");
    // The record the reader decoded is the one the circuit's arguments
    // describe — the drift gate of signet_flow.rs, now driven by STATE
    // rather than by a hand-built cell.
    assert_eq!(attestation.record.key_version, s.env.key_version);
    assert_eq!(attestation.record.execution_dest, pad32(ETHEREUM_CAIP2_ID));
    assert_eq!(
        attestation.record.output_deserialization_schema,
        SUCCESS_SCHEMA,
        "the schema in the record is the one the Deposit filing names"
    );
}

/// A failed destination-chain call: `OutputKind::failed` and an EMPTY
/// output, where the Borsh lineage attested one failure-kind byte.
#[test]
fn a_never_executed_call_attests_the_failed_verdict() {
    let (s, post) = filed_deposit();
    let mut sim = SigNetSim::from_seed(b"minocrab round trip", 0);
    let payload = notification(&s.request_id(), &s.env.self_addr, &deposits_path());
    let attestation = sim
        .respond_v1(&payload, &post, EvmOutcome::NeverExecuted, HEIGHT)
        .expect("a failure is still an attestation");
    assert!(attestation.output.is_empty(), "a non-execution decodes nothing");
    assert_eq!(attestation.output_kind, signet_sim::hashing::v1::output_kind::FAILED);
}

// ---- the adversarial responders --------------------------------------------

/// An id that was never filed: the reader drops it, and no signature exists
/// for it at all. This is the "unfiled id" responder — it cannot even reach
/// the settle circuit.
#[test]
fn an_unfiled_id_is_refused_by_the_reader() {
    let (s, post) = filed_deposit();
    let mut sim = SigNetSim::from_seed(b"minocrab round trip", 0);
    let payload = notification(&[0xabu8; 32], &s.env.self_addr, &deposits_path());
    assert!(matches!(
        sim.respond_v1(&payload, &post, EvmOutcome::Executed { body: vec![1] }, HEIGHT),
        Err(Refusal::Absent)
    ));
}

/// The notification points at the ENV map rather than the record map: the
/// walk lands on a map whose values are not records.
#[test]
fn a_wrong_path_is_refused_by_the_reader() {
    let (s, post) = filed_deposit();
    let mut sim = SigNetSim::from_seed(b"minocrab round trip", 0);
    let mut path = deposits_path();
    *path.last_mut().expect("a non-empty path") += 1;
    let payload = notification(&s.request_id(), &s.env.self_addr, &path);
    assert!(
        sim.respond_v1(&payload, &post, EvmOutcome::Executed { body: vec![1] }, HEIGHT)
            .is_err(),
        "the neighbouring field is not the request index"
    );
}

/// A depth outside 1..=4, and an unsupported version: the reader fails
/// closed on the notification before it touches state.
#[test]
fn a_malformed_notification_is_refused_by_the_reader() {
    let (s, post) = filed_deposit();
    let mut sim = SigNetSim::from_seed(b"minocrab round trip", 0);

    let mut bad_depth = notification(&s.request_id(), &s.env.self_addr, &deposits_path());
    bad_depth[65] = 9;
    assert!(matches!(
        sim.respond_v1(&bad_depth, &post, EvmOutcome::Executed { body: vec![1] }, HEIGHT),
        Err(Refusal::Notification(_))
    ));

    let mut bad_version = notification(&s.request_id(), &s.env.self_addr, &deposits_path());
    bad_version[0] = 2;
    assert!(matches!(
        sim.respond_v1(&bad_version, &post, EvmOutcome::Executed { body: vec![1] }, HEIGHT),
        Err(Refusal::Notification(_))
    ));
}

/// A responder with a DIFFERENT root: it resolves the record and signs, but
/// under a key the vault's `mpcResponseKey` is not. The two attestations
/// differ in the signature and in nothing else, which is the property the
/// settle circuit's verification rests on.
#[test]
fn a_wrong_key_attests_the_same_bytes_under_a_different_signature() {
    let (s, post) = filed_deposit();
    let payload = notification(&s.request_id(), &s.env.self_addr, &deposits_path());
    let outcome = EvmOutcome::Executed { body: vec![1u8] };

    let mut honest = SigNetSim::from_seed(b"minocrab round trip", 0);
    let mut rogue = SigNetSim::from_seed(b"a different cluster", 0);
    let a = honest.respond_v1(&payload, &post, outcome.clone(), HEIGHT).expect("honest");
    let b = rogue.respond_v1(&payload, &post, outcome, HEIGHT).expect("rogue");

    assert_eq!(a.request_id, b.request_id);
    assert_eq!(a.output, b.output);
    assert_ne!(a.signature, b.signature, "a different root signs differently");
    assert_ne!(
        honest.response_key(u32::from(a.record.key_version), &s.env.self_addr),
        rogue.response_key(u32::from(b.record.key_version), &s.env.self_addr),
        "and the key the vault stored is not the rogue's"
    );
}

/// Replay and double response are the same thing at this boundary: the
/// responder is PURE, so the second call returns the identical attestation.
/// Nothing in the MPC stops a replay — the settle circuit's `remove` does,
/// which is why `consume` is not idempotent.
#[test]
fn a_replay_produces_the_identical_attestation() {
    let (s, post) = filed_deposit();
    let mut sim = SigNetSim::from_seed(b"minocrab round trip", 0);
    let payload = notification(&s.request_id(), &s.env.self_addr, &deposits_path());
    let once = sim
        .respond_v1(&payload, &post, EvmOutcome::Executed { body: vec![1] }, HEIGHT)
        .expect("first");
    let twice = sim
        .respond_v1(&payload, &post, EvmOutcome::Executed { body: vec![1] }, HEIGHT)
        .expect("second");
    assert_eq!(once, twice, "the responder is a function of its inputs");
}

// ---- the link that does not close -------------------------------------------

/// THE LAST LINK, CLOSED (2026-09-07, decisions.org T1): the digest a typed
/// `Pending` settle verifies IS the digest the MPC signs.
///
/// `signet::calculate_attestation_digest_borsh` — what `Pending::complete`
/// and `refund` use — hashes `[requestId.hi, requestId.lo]` then the
/// serialized output `kind ‖ borsh(output)` PACKED as one byte string in
/// FAB's 31-byte limbing. The MPC's `compact-hashing::compute_response_hash`
/// (translated verbatim in `signet_sim::hashing`, pinned by the MPC's own
/// golden vectors) hashes exactly that.
///
/// Until 2026-09-07 the typed digest hashed ONE FIELD ELEMENT PER BORSH LEAF
/// (the kind byte one limb, the payload another) — which agreed with the MPC
/// under keccak / persistentHash, where the hash is over BYTES, and stopped
/// agreeing when M28 moved the protocol to `transientHash`. That
/// disagreement, and the packing that fixed it, belonged to the Borsh
/// `serializedOutput`: `kind ‖ borsh(output)` as one byte string.
///
/// V1 (M44 rung D) has no packing problem to get wrong. The digest names the
/// id, the HEIGHT, the VERDICT and the attested WIDTH as separate field
/// elements and then the output's own FAB limbs — so the agreement to pin is
/// that the hand model, the MPC's rule and the width the filing implies all
/// say the same thing, at each of the vault's three output shapes.
#[test]
fn the_typed_settle_digest_is_the_digest_the_mpc_signs() {
    use signet_sim::hashing::v1 as mpc;
    let rid = [0x5au8; 32];

    // A `Bool` output: one byte, one limb.
    let model = attestation_digest(&rid, HEIGHT, mpc::output_kind::EXECUTED, FLAG_WIDTH, &[Fr::from(1u64)]);
    let theirs = mpc::attestation_digest(&rid, HEIGHT, mpc::output_kind::EXECUTED, &[1u8]);
    assert_eq!(model, theirs, "the hand model limbs a Bytes<1> the way the MPC does");

    // A `uint256` output: thirty-two bytes, TWO limbs (byte 31 above the
    // low thirty-one), which is the shape a packed byte string could not
    // express and the width the digest now commits to.
    let amount_in = 0x0102_0304_0506_0708u64;
    let mut word = [0u8; 32];
    word[..8].copy_from_slice(&amount_in.to_le_bytes());
    let model = attestation_digest(
        &rid,
        HEIGHT,
        mpc::output_kind::EXECUTED,
        WORD_WIDTH,
        &word_output_limbs(amount_in),
    );
    let theirs = mpc::attestation_digest(&rid, HEIGHT, mpc::output_kind::EXECUTED, &word);
    assert_eq!(model, theirs, "a uint256 limbs as [byte 31, bytes 0..31]");

    // A non-execution: width zero, no limbs. Under the Borsh rule this was
    // the failure KIND byte alone; now the verdict carries it and the
    // output is genuinely empty.
    let model = attestation_digest(&rid, HEIGHT, mpc::output_kind::FAILED, 0, &[]);
    let theirs = mpc::attestation_digest(&rid, HEIGHT, mpc::output_kind::FAILED, &[]);
    assert_eq!(model, theirs, "a failure attests nothing at width zero");

    // AND THE WIDTH IS LOAD-BEARING: the same bytes at a width the filing
    // does not imply is a different digest, which is what makes a
    // wrong-width output unverifiable rather than merely wrong.
    assert_ne!(
        attestation_digest(&rid, HEIGHT, mpc::output_kind::EXECUTED, FLAG_WIDTH, &[Fr::from(1u64)]),
        attestation_digest(&rid, HEIGHT, mpc::output_kind::EXECUTED, WORD_WIDTH, &[Fr::from(1u64)]),
    );

    // And what the CIRCUIT hashes is the model's: `tests/vault_pending`'s
    // spec harness holds the two together on every settle, and
    // `deposit_then_claim_settles_the_sims_attestation` below settles
    // against the sim's own attestation.
}

// ---- the pairs, chained through state ---------------------------------------

/// Run `request_ir` against `pre`, then `settle_ir` against the state that
/// left behind, and check the settle's transcript against the model's.
///
/// Nothing crosses between the halves but a `StateValue`: the settle's
/// reads — the record, the environment, the response key — are answered out
/// of what the request wrote, not out of a scenario the test built.
fn chain(
    request_ir: &minocrab_zkir::v3::IrSource,
    request_pi: &midnight_transient_crypto::proofs::ProofPreimage,
    request_pre: &vault_pending::exec::PreState,
    settle_ir: &minocrab_zkir::v3::IrSource,
    settle_pi: &midnight_transient_crypto::proofs::ProofPreimage,
    settle_ops: &[vault_pending::prims::VmOp],
    self_addr: &[u8; 32],
) {
    let post = post_state_of(
        request_ir,
        &request_pi.inputs,
        &request_pi.private_transcript,
        request_pi
            .communications_commitment
            .expect("a request commits")
            .1,
        request_pre,
        self_addr,
    );

    let ctx = exec::context(post, *self_addr);
    let mut call = Call::new(&settle_pi.inputs, &settle_pi.private_transcript);
    if let Some((_, rand)) = settle_pi.communications_commitment {
        call = call.with_comm_rand(rand);
    }
    let settled = exec::execute(settle_ir, &call, &ctx)
        .expect("the settle circuit accepts the state its request left");

    assert_eq!(
        settled.ops, settle_ops,
        "the settle's transcript against the REQUEST's post-state is the model's"
    );
    assert_eq!(
        settled.preimage.public_transcript_outputs, settle_pi.public_transcript_outputs,
        "and every value it read came out of that state"
    );
    settle_ir
        .check(&settled.preimage)
        .expect("the reference VM accepts the chained settle");
}

/// THE LAST LINK: `request → post → respond → settle`, with NOTHING supplied
/// by the model but the scenario. The vault's stored response key is the
/// sim's derived one, the deposit files into real state, the sim reads that
/// state and signs, and the claim circuit — run by the executor against the
/// same state — accepts the sim's signature. The model's own signature
/// (under a key the sim does not hold) is replaced slot for slot.
#[test]
fn deposit_then_claim_settles_the_sims_attestation() {
    let mut sim = SigNetSim::from_seed(b"minocrab round trip", 0);
    let mut c = ClaimScenario::new();
    let self_addr = c.d.env.self_addr;
    let key = sim.response_key(u32::from(c.d.env.key_version), &self_addr);
    c.d.env.mpc_key_xy = Some(SigNetSim::point_coordinates(&key).expect("a derived key is not the identity"));

    let post = {
        let pi = c.d.preimage();
        post_state_of(
            &pending::Vault::deposit().ir,
            &pi.inputs,
            &pi.private_transcript,
            pi.communications_commitment.expect("a request commits").1,
            &c.d.pre_state(),
            &self_addr,
        )
    };
    let payload = notification(&c.d.request_id(), &self_addr, &deposits_path());
    let attestation = sim
        .respond_v1(&payload, &post, EvmOutcome::Executed { body: vec![1u8] }, HEIGHT)
        .expect("the MPC resolves the filed record");
    assert_eq!(attestation.output, vec![1u8]);

    let settle = |signature: &signet_sim::sign::Signature| {
        let sig = signature.circuit_input();
        let (rx_hi, rx_lo) = b32_slots(&sig.big_r_x);
        let (s_hi, s_lo) = b32_slots(&sig.s);
        // `settle_head_inputs`' V1 slot order: requestId (two),
        // blockHeight, outputKind, serializedOutputLength, digest (two),
        // bigR.x (two), bigR.y (two), s (two), recoveryId, then the
        // attested output. The DIGEST slot is replaced too: it is the
        // sim's, and the model's own value was computed under the model's
        // key.
        let mut inputs = c.inputs();
        let (d_hi, d_lo) = b32_slots(&attestation.digest);
        inputs[5] = d_hi;
        inputs[6] = d_lo;
        inputs[7] = rx_hi;
        inputs[8] = rx_lo;
        inputs[11] = s_hi;
        inputs[12] = s_lo;
        let witnesses = c.witnesses();
        let mut call = Call::new(&inputs, &witnesses);
        if let Some((_, rand)) = c.preimage().communications_commitment {
            call = call.with_comm_rand(rand);
        }
        let ctx = exec::context(post.clone(), self_addr);
        exec::execute(&pending::Vault::claim().ir, &call, &ctx).map(|_| ())
    };

    settle(&attestation.signature).expect("the claim circuit accepts the sim's attestation");

    // A cluster with a different root signs the same bytes under a key the
    // vault did not store: refused at the signature check, nothing else.
    let mut rogue = SigNetSim::from_seed(b"a different cluster", 0);
    let forged = rogue
        .respond_v1(&payload, &post, EvmOutcome::Executed { body: vec![1u8] }, HEIGHT)
        .expect("the rogue reads the same record");
    assert_eq!(forged.output, attestation.output);
    assert!(
        matches!(settle(&forged.signature), Err(exec::ExecError::Rejected { .. })),
        "a signature under another root is rejected"
    );
}

#[test]
fn deposit_then_claim_chains_through_state() {
    let c = ClaimScenario::new();
    chain(
        &pending::Vault::deposit().ir,
        &c.d.preimage(),
        &c.d.pre_state(),
        &pending::Vault::claim().ir,
        &c.preimage(),
        &c.ops(),
        &c.d.env.self_addr,
    );
}

#[test]
fn withdraw_then_complete_chains_through_state() {
    let c = CompleteWithdrawScenario::new();
    chain(
        &pending::Vault::withdraw().ir,
        &c.w.preimage(),
        &c.w.pre_state(),
        &pending::Vault::complete_withdraw().ir,
        &c.preimage(),
        &c.ops(),
        &c.w.env.self_addr,
    );
}

#[test]
fn swap_then_complete_chains_through_state() {
    let c = CompleteSwapScenario::new();
    chain(
        &pending::Vault::swap().ir,
        &c.s.preimage(),
        &c.s.pre_state(),
        &pending::Vault::complete_swap().ir,
        &c.preimage(),
        &c.ops(),
        &c.s.env.self_addr,
    );
}

#[test]
fn supply_then_complete_chains_through_state() {
    let c = CompleteSupplyScenario::new();
    chain(
        &pending::Vault::supply().ir,
        &c.s.preimage(),
        &c.s.pre_state(),
        &pending::Vault::complete_supply().ir,
        &c.preimage(),
        &c.ops(),
        &c.s.env.self_addr,
    );
}

#[test]
fn redeem_then_complete_chains_through_state() {
    let c = CompleteRedeemScenario::new();
    chain(
        &pending::Vault::redeem().ir,
        &c.s.preimage(),
        &c.s.pre_state(),
        &pending::Vault::complete_redeem().ir,
        &c.preimage(),
        &c.ops(),
        &c.s.env.self_addr,
    );
}

/// The refund half of the same pair: an attested failure consumes the very
/// record the withdrawal filed, out of the same post-state.
#[test]
fn withdraw_then_refund_chains_through_state() {
    let c = RefundWithdrawalScenario::new();
    chain(
        &pending::Vault::withdraw().ir,
        &c.w.preimage(),
        &c.w.pre_state(),
        &pending::Vault::refund_withdrawal().ir,
        &c.preimage(),
        &c.ops(),
        &c.w.env.self_addr,
    );
}
