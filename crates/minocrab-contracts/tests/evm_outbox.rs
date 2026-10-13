//! THE OUTBOX, AS A CONTRACT — `Outbox<Filing, Env, WORDS>` (M41 B/C,
//! notes/stream-design.org, "emit restored"): the contention-free replacement
//! of M39's `Queued` batch, and the reference PRIMITIVE stream.
//!
//! What this file is the witness for:
//!
//! 1. A request that CHOOSES NO NONCE, NO FEE AND NO KEY VERSION, and READS
//!    NO SHARED STATE. `call` takes the callee and the arguments; the nonce
//!    is assigned by a blind `add` on the accumulator and snapshotted into
//!    the handle's entry, never read by the circuit.
//! 2. `emit`, one request per transaction, permissionless: two stable reads
//!    of the handle's entries, then exactly what `Pending::request` files —
//!    one record, one id, one notification.
//! 3. The settle side is `Pending`'s, followed by the spec's C3 check and a
//!    blind max on last seen.
//! 4. THE CONTENTION AUDIT (the milestone's gate): across the three
//!    circuits, no `popeq` reads either accumulator cell — checked on the
//!    emitted Impact stream, not on prose. Since M44 rung D there is no
//!    shared COUNTER left to admit either: the Signet request nonce
//!    (notes/nonce-admin.org §10.1) went with the V1 vocabulary, and what
//!    `file_request` reads of the block is two write-once config cells,
//!    counted here so their presence is a number and not a surprise.
//!
//! IT IS A TEST-ONLY CONTRACT, like `tests/evm_no_return.rs`'s: it exercises
//! the API without adding circuits to the crate's frozen snapshots.

use minocrab::v3::Circuit3;
use minocrab::{Fr, Public};
use minocrab_contracts::evm::{erc20, Filed};
use minocrab_contracts::evm_flow::{
    Contract, Emitted, Failed, Handle, HandleOwned, Inserted, Outbox, Succeeded,
};
use minocrab_contracts::signet_flow::{Settled, Signet};
use minocrab_contracts::signet_v1::schema;
use minocrab_ledger::{idx_path, ImpactElem, LedgerKey};
use minocrab_sim::v3::cost;
use minocrab_std::v3::{
    circuit, label, Bytes, Disclose, Discloses, Ledger, LedgerRepr, LedgerWidth, Uint,
};
use minocrab_zkir::v3::{Instruction as I, Operand};

mod leakage;

/// The outbox's one filing: a plain `erc20::Transfer` under the `success`
/// schema.
///
/// IT USED TO BE A CONTRIVANCE. Before the V1 vocabulary the attested
/// payload carried no block height, so this file declared a
/// `HeightedTransfer` — the same selector and calldata as `erc20::Transfer`,
/// but decoding the return word as the height the MPC observed — purely so
/// that C3's last-seen check had a height to raise against. V1 attests the
/// height itself (spec M2), [`Outcome::block_height`] carries it, and
/// [`Outbox::raise_seen`] reads it off the outcome: the contrivance is gone
/// and the slot files the real library call.
type Heighted = Filed<erc20::Transfer, schema::Success>;

/// What a settle needs back.
#[derive(LedgerRepr)]
struct Amount {
    amount: Uint<64, Public>,
}

/// Eleven fields: the four of `Signet`, then the outbox's seven — records,
/// outstanding, bodies, the nonce cell, the last-seen cell, and the two
/// snapshot maps.
#[derive(Ledger)]
struct Block {
    signet: Signet,
    calls: Outbox<Heighted, HandleOwned<Amount>, 2>,
}

const BLOCK: Block = Block::new();

/// Field indices, by the layout above. There is no third accumulator any
/// more: the Signet request-nonce counter went with the V1 vocabulary (M44
/// rung D), so the outbox's own two cells are the whole audit.
const NONCE_CELL: u8 = 7;
const SEEN_CELL: u8 = 8;
/// The two Signet CONFIG cells `file_request` reads — written once by
/// `initialize`, never again.
const KEY_VERSION: u8 = 2;
const CHAIN_ID: u8 = 3;

label! {
    Sent = "the amount sent";
    Owner = "the requester's refund commitment";
    Recipient = "own public key as refund recipient";
}

// ---- the circuits -------------------------------------------------------------

/// CALL: no nonce argument, no fee argument, no shared read. The transaction
/// this files is complete except for the number the ledger assigns blind.
#[circuit]
fn call(
    c: &mut Circuit3,
    token: Contract<erc20::Erc20>,
    to: Bytes<20>,
    amount: Uint<64>,
) -> Discloses<(Sent, Owner, Inserted)> {
    let sent = amount.field().disclose_as::<Sent>(c);
    BLOCK.calls.call_owned::<Owner>(
        c,
        token,
        (to, amount.widen::<128>()),
        |_, _| Amount {
            amount: Uint::from_field_unchecked(sent),
        },
    );
    Discloses::of(())
}

/// EMIT: one request, one record, one notification; anyone may prove it.
#[circuit]
fn emit(c: &mut Circuit3, handle: Handle) -> Discloses<Emitted> {
    BLOCK.calls.emit(c, handle);
    Discloses::of(())
}

/// SETTLE A SUCCESS, then C3 and the blind max on last seen.
///
/// The height `raise_seen` consumes is the ATTESTATION'S, disclosed by the
/// settle itself (`Settled` carries `BlockHeightSettled`), which is why
/// neither circuit here declares a height label of its own any more.
#[circuit]
fn complete(c: &mut Circuit3, ticket: Succeeded<Heighted>) -> Discloses<Settled> {
    let outcome = BLOCK.calls.complete(c, ticket);
    let _amount = outcome.env.env.inner.amount;
    BLOCK.calls.raise_seen(c, &outcome);
    Discloses::of(())
}

/// REFUND TO THE REQUESTER — the commitment opens against the HANDLE the
/// requester kept, not against the request id the emit minted — then C3.
#[circuit]
fn refund(c: &mut Circuit3, ticket: Failed<Heighted>) -> Discloses<(Settled, Recipient)> {
    let (_owner, outcome) = BLOCK.calls.refund_to_owner::<Recipient>(c, ticket);
    let Amount { amount: _amount } = outcome.env.env.inner;
    BLOCK.calls.raise_seen(c, &outcome);
    Discloses::of(())
}

// ---- the audit --------------------------------------------------------------------

/// Every Impact instruction's elements, immediates decoded, wires as `None`.
fn impact_ops(ir: &minocrab_zkir::v3::IrSource) -> Vec<Vec<Option<Fr>>> {
    ir.instructions
        .iter()
        .filter_map(|i| match i {
            I::Impact { inputs, .. } => Some(
                inputs
                    .iter()
                    .map(|op| match op {
                        Operand::Immediate(v) => Some(*v),
                        Operand::Variable(_) => None,
                    })
                    .collect(),
            ),
            _ => None,
        })
        .collect()
}

/// `popeq` / `popeqc` opcodes.
fn is_popeq(op: &[Option<Fr>]) -> bool {
    matches!(op.first(), Some(Some(v)) if *v == Fr::from(0x0cu64) || *v == Fr::from(0x0du64))
}

/// The `idx [field]` a `dup 0; idx [field]; popeq` read carries, as the
/// ledger crate spells it.
fn field_read(field: u8) -> Vec<Option<Fr>> {
    idx_path(false, false, &[LedgerKey::Field(field)])
        .0
        .into_iter()
        .map(|e| match e {
            ImpactElem::Imm(v) => Some(v),
            ImpactElem::Wire(_) => None,
        })
        .collect()
}

/// How many CHECKED reads of `field`: an `idx [field]` immediately followed
/// by a `popeq`. A bare `idx [field]` with no `popeq` after it is the blind
/// snapshot's fetch, which is the point.
fn reads_of(ir: &minocrab_zkir::v3::IrSource, field: u8) -> usize {
    let pattern = field_read(field);
    let ops = impact_ops(ir);
    ops.windows(2)
        .filter(|w| w[0] == pattern && is_popeq(&w[1]))
        .count()
}

fn popeqs(ir: &minocrab_zkir::v3::IrSource) -> usize {
    impact_ops(ir).iter().filter(|op| is_popeq(op)).count()
}

fn asserts_saying(compiled: &minocrab::v3::Compiled3, message: &str) -> usize {
    compiled
        .assert_messages
        .iter()
        .filter(|m| m.message == message)
        .count()
}

fn disclosures_labelled(compiled: &minocrab::v3::Compiled3, label: &str) -> usize {
    compiled
        .disclosures
        .iter()
        .filter(|d| d.label == label)
        .count()
}

/// The block's layout: four Signet fields, then the slot's seven.
#[test]
fn the_block_is_laid_out_by_slot_width() {
    assert_eq!(BLOCK.signet.signer.index(), 0);
    assert_eq!(BLOCK.calls.record_path().as_slice(), &[4]);
    assert_eq!(<Outbox<Heighted, HandleOwned<Amount>, 2> as LedgerWidth>::WIDTH, 7);
}

/// THE CONTENTION AUDIT. Neither accumulator cell is ever CHECKED-read by
/// any of the four circuits: no `idx [nonce]; popeq` and no `idx [seen];
/// popeq`. The blind snapshot does `idx [cell]` — a fetch — and inserts it
/// without a `popeq`, and the blind combines reach the cells with `idxp`.
#[test]
fn no_circuit_reads_the_accumulator() {
    for (name, compiled) in [
        ("call", call()),
        ("emit", emit()),
        ("complete", complete()),
        ("refund", refund()),
    ] {
        assert_eq!(reads_of(&compiled.ir, NONCE_CELL), 0, "{name} reads the nonce cell");
        assert_eq!(reads_of(&compiled.ir, SEEN_CELL), 0, "{name} reads the last-seen cell");
    }
}

/// WHAT IS READ, counted: call = one per-key member check; emit = the two
/// stream reads plus `file_request`'s plus the member check on the body; the
/// settles are `Pending`'s.
///
/// SINCE M44 RUNG D THERE IS NO SHARED COUNTER LEFT in the lineage. The
/// Signet request nonce — the one read every request used to make, and the
/// one number this audit had to admit as contention
/// (notes/nonce-admin.org §10.1) — went with the V1 vocabulary. What
/// `file_request` still reads of the block are two CONFIG cells,
/// `mpcKeyVersion` and `evmChainId`, which nothing writes after
/// `initialize`: two emits in one transaction read the same value and do not
/// contend. That is the stronger claim, so it is the one asserted here.
#[test]
fn the_reads_are_per_key_and_the_config_cells() {
    let call = call();
    assert_eq!(popeqs(&call.ir), 1, "call: the handle's not-member check");
    assert_eq!(reads_of(&call.ir, KEY_VERSION), 0, "a call files nothing, so reads no config");
    assert_eq!(reads_of(&call.ir, CHAIN_ID), 0);
    assert_eq!(asserts_saying(&call, "Stream key already present"), 1);

    let emit = emit();
    assert_eq!(reads_of(&emit.ir, KEY_VERSION), 1, "emit files one record");
    assert_eq!(reads_of(&emit.ir, CHAIN_ID), 1);
    // The stream's four (member and lookup of the body, the two snapshot
    // lookups — all under the handle) plus `file_request`'s five (the
    // contract's own address, the chain id, the key version, the record's
    // not-member check, the signer address for the notification).
    assert_eq!(popeqs(&emit.ir), 4 + 5);
    assert_eq!(asserts_saying(&emit, "Stream key not present"), 1);
    assert_eq!(asserts_saying(&emit, "Request already exists"), 1);

    for compiled in [complete(), refund()] {
        assert_eq!(reads_of(&compiled.ir, KEY_VERSION), 0);
        assert_eq!(reads_of(&compiled.ir, CHAIN_ID), 0);
        assert_eq!(asserts_saying(&compiled, "Request not found"), 1);
        assert_eq!(asserts_saying(&compiled, "Response not after the call"), 1);
    }
}

/// ONE EMIT, ONE FILING, ONE NOTIFICATION — and a call files nothing.
#[test]
fn an_emit_files_one_record_and_a_call_files_none() {
    let emit = emit();
    assert_eq!(disclosures_labelled(&emit, "xcall communications commitment"), 1);
    assert_eq!(disclosures_labelled(&emit, "xcall entry-point hash"), 1);
    assert_eq!(disclosures_labelled(&emit, "request id"), 1);
    assert_eq!(disclosures_labelled(&emit, "request record"), 1);
    assert_eq!(disclosures_labelled(&emit, "emitted handle"), 1);

    let call = call();
    assert_eq!(disclosures_labelled(&call, "xcall communications commitment"), 0);
    assert_eq!(disclosures_labelled(&call, "request record"), 0);
    assert_eq!(disclosures_labelled(&call, "queued pre-record"), 1);
}

/// THE REFUND OPENS AGAINST THE HANDLE; the completion has no owner gate.
#[test]
fn a_refund_opens_the_requesters_commitment() {
    assert_eq!(asserts_saying(&refund(), "Not the owner"), 1);
    assert_eq!(asserts_saying(&complete(), "Not the owner"), 0);
}

/// THE ROW TABLE, printed for the record (a test-only contract has no
/// snapshot).
#[test]
fn the_circuits_build_at_a_finite_cost() {
    println!("| circuit | k | rows | popeqs |");
    println!("|---|---|---|---|");
    for (name, compiled) in [
        ("call", call()),
        ("emit", emit()),
        ("complete", complete()),
        ("refund", refund()),
    ] {
        let (k, rows) = cost(&compiled.ir);
        println!("| {name} | {k} | {rows} | {} |", popeqs(&compiled.ir));
    }
    let (k_call, rows_call) = cost(&call().ir);
    let (_, rows_emit) = cost(&emit().ir);
    // A call is a hash and a few ledger ops; the emit carries the record.
    assert!(rows_call < rows_emit, "{rows_call} {rows_emit}");
    assert!(k_call <= 11, "call k = {k_call}");
}

/// The library pads this lineage spells as immediates: the MPC signing path
/// and the owner commitment's tag pad. The contract names neither.
const LITERALS: &[&str] = &["vault", "vault:refund:"];

/// THE LEAKAGE INVENTORY over the four circuits — the emit line is M41's
/// new one. Printed rather than frozen (test-only contract); the gate is
/// the tables' own: nothing witness-dependent reaches the ledger unlabelled.
#[test]
fn the_leakage_walk_runs_over_the_outbox() {
    for (name, compiled) in [
        ("call", call()),
        ("emit", emit()),
        ("complete", complete()),
        ("refund", refund()),
    ] {
        let lines = leakage::inventory(name, &compiled, None, LITERALS);
        for line in &lines {
            if line.starts_with("== ") || line.contains("unlabelled witness-dependent") {
                println!("{line}");
            }
            if !line.starts_with("impact #") {
                continue;
            }
            if let Some(rest) = line.split("unlabelled witness-dependent ").nth(1) {
                let n: usize = rest
                    .split_whitespace()
                    .next()
                    .expect("a count follows")
                    .parse()
                    .expect("the count is a number");
                assert_eq!(n, 0, "{name}: {line}");
            }
        }
    }
}

/// A handle is one field slot: the emit argument declares one wire.
#[test]
fn a_handle_is_one_field_slot() {
    assert_eq!(<Handle as minocrab_std::v3::CircuitAbi>::SLOTS, 1);
}
