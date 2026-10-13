//! `treasury` — the README's cross-chain example, run (M37 rung C).
//!
//! The contract is notes/evm-calls.org §0's target shape as real code; this
//! file is the evidence that it is not just a shape. Every case below builds
//! a `ProofPreimage` BY HAND — the ledger op stream, the argument slots, the
//! witnesses, and a real secp256k1 signature over a real Poseidon
//! attestation digest — and hands it to the simulator, the way
//! `tests/vault_pending` does for the vault's seventeen circuits.
//!
//! What the round trips pin (notes/evm-calls.org §3, the SYMMETRIC tickets):
//!
//! | attestation                  | `complete` | `refund`, owner | `refund`, stranger |
//! |------------------------------|-----------:|----------------:|-------------------:|
//! | `executed`, flag `true`      |     ACCEPT |          reject |             reject |
//! | `executed`, flag `false`     |     reject |          ACCEPT |             reject |
//! | `failed` (the empty output)  |     reject |          ACCEPT |             reject |
//!
//! The middle row is the one the deployed vault gets wrong: its
//! `completeWithdraw` accepts an attested `false` and refunds inside the
//! completion, so a transfer that moved nothing can be marked done. Here a
//! `false` cannot complete, whoever presents it, because
//! `Erc20Transfer`'s return is `Bool`, whose `AbiType::success` IS the
//! flag, and `complete` asserts `EvmCall::succeeded`.
//!
//! The third column is `Owned`: the environment carries a commitment to the
//! SENDER's secret, and `refund_to_owner` opens it against a fresh witness.

use minocrab_contracts::treasury::Treasury;
use minocrab_sim::v3::{cost, simulate};

#[path = "vault/prims.rs"]
#[allow(dead_code)]
mod prims;

#[path = "treasury/model.rs"]
mod model;
#[path = "treasury/ops.rs"]
mod ops;

use model::{Attestation, SendScenario, SettleScenario};

// ---- the layout the derive computes ------------------------------------------

/// Six fields from two declarations — FOUR of `Signet` since V1, where the
/// `fff3421c` block had five — under the fifteen-field segment length, so
/// the notification the MPC follows is one element deep and
/// `#[derive(Ledger)]` found the `Signet` block at offset 0 without anyone
/// naming it in `Pending`'s constructor.
#[test]
fn the_block_is_laid_out_by_slot_width() {
    let t = &minocrab_contracts::treasury::TREASURY;
    assert_eq!(t.signet.signer.index(), 0);
    assert_eq!(t.signet.mpc_key_version.index(), 2);
    assert_eq!(t.signet.evm_chain_id.index(), 3);
    assert_eq!(t.transfers.record_path().as_slice(), &[4]);
    assert_eq!(t.transfers.record_path().depth(), 1);
}

// ---- send ---------------------------------------------------------------------

/// The request half: a `transfer(to, amount)` filed against a callee, with
/// the caller committed into the environment. Nothing in `send`'s source
/// names the selector, the words, the gas or the path — and the model here
/// spells all four out independently, so agreement is a check.
#[test]
fn send_files_the_transfer() {
    let s = SendScenario::new();
    let ir = Treasury::send().ir;
    simulate(&ir, &s.preimage()).expect("send accepts a well-formed request");
}

/// The freshness assert: an id already in the map is rejected.
#[test]
fn send_rejects_a_request_that_already_exists() {
    let mut s = SendScenario::new();
    s.request_exists = true;
    let ir = Treasury::send().ir;
    assert!(simulate(&ir, &s.preimage()).is_err());
}

// ---- send -> complete ---------------------------------------------------------

/// The happy path, end to end: file, then settle the attested `true`.
#[test]
fn send_then_complete() {
    let s = SettleScenario::new(Attestation::ExecutedTrue);
    simulate(&Treasury::send().ir, &s.send.preimage()).expect("the request files");
    simulate(&Treasury::complete().ir, &s.complete_preimage())
        .expect("an attested success completes");
}

/// ANYONE MAY COMPLETE. The completion witnesses nothing at all — there is
/// no secret in the circuit to present — so a stranger's proof is the same
/// proof. Pinned as the private transcript being EMPTY rather than as a
/// second accepted run, which would be the same run.
#[test]
fn anyone_can_complete() {
    let s = SettleScenario::new(Attestation::ExecutedTrue);
    assert!(
        s.complete_preimage().private_transcript.is_empty(),
        "complete witnesses something: {:?}",
        s.complete_preimage().private_transcript
    );
    simulate(&Treasury::complete().ir, &s.complete_preimage()).expect("accepts");
}

/// THE HOLE THIS API CLOSES. A mined `transfer` that returned `false` is a
/// perfectly valid `executed` attestation, correctly signed — and it cannot
/// complete, because a `Bool` return's `success` is the flag and `complete`
/// asserts it.
#[test]
fn a_false_attestation_cannot_complete() {
    let s = SettleScenario::new(Attestation::ExecutedFalse);
    assert!(
        simulate(&Treasury::complete().ir, &s.complete_preimage()).is_err(),
        "an attested `false` completed"
    );
}

/// A `failed` verdict is not `executed`, so `complete`'s verdict assert
/// rejects it before anything else does.
#[test]
fn a_failure_attestation_cannot_complete() {
    let s = SettleScenario::new(Attestation::NeverExecuted);
    assert!(simulate(&Treasury::complete().ir, &s.complete_preimage()).is_err());
}

/// A completion of an entry that is not in the map: the membership assert.
#[test]
fn complete_rejects_an_unfiled_request() {
    let mut s = SettleScenario::new(Attestation::ExecutedTrue);
    s.pending = false;
    assert!(simulate(&Treasury::complete().ir, &s.complete_preimage()).is_err());
}

// ---- send -> refund -----------------------------------------------------------

/// A NEVER-EXECUTED request refunds — the `failed` verdict, whose signed
/// preimage has width ZERO and no output limbs.
#[test]
fn send_then_refund_a_never_executed_call() {
    let s = SettleScenario::new(Attestation::NeverExecuted);
    simulate(&Treasury::send().ir, &s.send.preimage()).expect("the request files");
    simulate(&Treasury::refund().ir, &s.refund_preimage())
        .expect("an attested failure refunds");
}

/// AND SO DOES AN EXECUTED `false` — the second disjunct, over the OTHER
/// preimage width. That both are accepted by one circuit is what the
/// two-digest selection in `Pending::refund` buys.
#[test]
fn a_false_attestation_can_refund() {
    let s = SettleScenario::new(Attestation::ExecutedFalse);
    simulate(&Treasury::refund().ir, &s.refund_preimage())
        .expect("an attested `false` refunds");
}

/// A SUCCESS DOES NOT REFUND: the verdict is `executed`, the signature
/// verifies, and the disjunction still fails because the flag is set.
#[test]
fn a_true_attestation_cannot_refund() {
    let s = SettleScenario::new(Attestation::ExecutedTrue);
    assert!(
        simulate(&Treasury::refund().ir, &s.refund_preimage()).is_err(),
        "an attested success refunded"
    );
}

/// ONLY THE OWNER. A stranger with a valid failure attestation cannot open
/// the environment's commitment, so the refund does not prove.
#[test]
fn a_stranger_cannot_refund() {
    for attestation in [Attestation::NeverExecuted, Attestation::ExecutedFalse] {
        let mut s = SettleScenario::new(attestation);
        s.presented_sk = Some(model::tagged32(b"not-the-sender", 0x99));
        assert!(
            simulate(&Treasury::refund().ir, &s.refund_preimage()).is_err(),
            "{attestation:?}: a stranger refunded"
        );
    }
}

/// The failure attestation's signature is over the ZERO-WIDTH preimage;
/// presenting it under the `executed` verdict selects the one-byte digest
/// instead, which it does not verify against. The negative control for the
/// digest selection: without it, one of the two branches would be verifying
/// the wrong preimage and this test would pass for the wrong reason.
#[test]
fn a_failure_signature_does_not_verify_under_the_executed_verdict() {
    let s = SettleScenario::new(Attestation::NeverExecuted);
    let mut pi = s.refund_preimage();
    // Relabel the verdict as `executed`, leaving the signature (and
    // therefore the preimage it was made over) alone.
    pi.inputs[model::OUTPUT_KIND_SLOT] =
        minocrab::Fr::from(minocrab_contracts::signet_v1::output_kind::EXECUTED);
    assert!(simulate(&Treasury::refund().ir, &pi).is_err());
}

// ---- what the two settle circuits cost ----------------------------------------

/// WHAT `Failed<Call>` COSTS, measured. `refund` does everything `complete`
/// does plus: a second Poseidon digest and a `cond_select` (the two
/// preimage widths), the verdict disjunction, the owner commitment's
/// opening, and `own_public_key`. The whole difference is a few hundred rows against
/// the ~25k the one shared ECDSA verification costs, and `k` does not move.
#[test]
fn the_refund_pays_one_extra_digest() {
    let (k_complete, rows_complete) = cost(&Treasury::complete().ir);
    let (k_refund, rows_refund) = cost(&Treasury::refund().ir);
    eprintln!("complete: k={k_complete} rows={rows_complete}");
    eprintln!("refund:   k={k_refund} rows={rows_refund}");
    assert_eq!(k_complete, k_refund, "the extra digest moved k");
    let extra = rows_refund - rows_complete;
    eprintln!("refund - complete = {extra} rows");
    assert!(
        extra < rows_complete / 20,
        "the refund's extra work is {extra} rows, over 5% of {rows_complete}"
    );
}

/// The request circuit is CHEAP — no signature verification, no hash of a
/// witness beyond the one commitment.
#[test]
fn the_circuits_build_at_a_finite_cost() {
    let (k_send, rows_send) = cost(&Treasury::send().ir);
    let (k_complete, rows_complete) = cost(&Treasury::complete().ir);
    eprintln!("send: k={k_send} rows={rows_send}");
    assert!(rows_send < rows_complete, "{rows_send} {rows_complete}");
    assert!(k_send <= 14 && k_complete <= 16, "{k_send} {k_complete}");
}
