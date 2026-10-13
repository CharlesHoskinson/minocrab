//! The `erc20_vault_pending` reference model's Impact op builders, over the
//! Pending lineage's SEGMENTED 22-field ledger.
//!
//! A byte-for-byte copy of `tests/vault/ops.rs` (M35 rung C's harness
//! extension) with one number changed: `FIELDS`. Every builder here is
//! generic in the field index, and `segment_of`'s formula (the remainder
//! segment LEADS) is the same compactc-style rule the twenty-two-field
//! `Vault` block is segmented by (notes/signet-async.org "Rung C, lending
//! extension": `22 = 15 + 7`, remainder leads, so field `i` is `[0, i]`
//! for `i < 7` and `[1, i − 7]` otherwise) — confirmed instruction-for-
//! instruction against the dumped `.zkir` for `initialize`, `withdraw`,
//! `claim`, `approve_router` and `complete_swap`.
//!
//! Independent of `minocrab-ledger` on purpose: this is the ORACLE the
//! eDSL's `LedgerMap` / `LedgerCell` / `LedgerCounter` / `Pending` methods
//! are checked against, so it must not be built from them.

use midnight_base_crypto::fab::{
    Alignment, AlignmentAtom, AlignmentSegment, AlignedValue, Value, ValueAtom,
};
use midnight_onchain_state::state::StateValue;
use midnight_onchain_vm::ops::{Key, Op};
use midnight_transient_crypto::fab::ValueReprAlignedValue;
use midnight_transient_crypto::repr::FieldRepr;
use minocrab::Fr;

use super::prims::{atom, bytesn_value, cell, VmOp};

/// The Pending lineage's field count, and compactc's segment length.
///
/// TWENTY-ONE SINCE M44 RUNG D, where it was twenty-two: `Signet` lost its
/// request-nonce counter and its caip2 cell and gained `mpcKeyVersion`. The
/// count is not cosmetic — it sets the SEGMENTATION BOUNDARY below, so one
/// field fewer moves every path in the block.
pub const FIELDS: u8 = 21;
const SEGMENT: u8 = 15;

/// A field's two-element path: `[segment, offset]`. The remainder segment
/// LEADS (`batch` in determine-ledger-paths.ss), so the first `21 mod 15 =
/// 6` fields sit in segment 0.
pub fn segment_of(field: u8) -> (u8, u8) {
    assert!(field < FIELDS, "field {field} is not one of the vault's {FIELDS}");
    let lead = FIELDS % SEGMENT;
    if field < lead {
        (0, field)
    } else {
        (1 + (field - lead) / SEGMENT, (field - lead) % SEGMENT)
    }
}

fn key(i: u8) -> Key {
    Key::Value(bytesn_value(1, &[i]))
}

pub fn field_path(field: u8) -> Vec<Key> {
    let (seg, off) = segment_of(field);
    vec![key(seg), key(off)]
}

fn key32(k: &[u8; 32]) -> StateValue {
    cell(bytesn_value(32, k))
}

/// `field.read()` — `dup 0; idx f; popeq[c]`. Counters read cached
/// (`popeqc`), cells uncached (`popeq`).
pub fn read(field: u8, cached: bool, result: AlignedValue) -> Vec<VmOp> {
    vec![
        Op::Dup { n: 0 },
        Op::Idx {
            cached: false,
            push_path: false,
            path: field_path(field).into(),
        },
        Op::Popeq { cached, result },
    ]
}

/// `kernel.self()` — `dup 2; idxc [0]; popeqc` against the context.
pub fn kernel_self(addr: &[u8; 32]) -> Vec<VmOp> {
    vec![
        Op::Dup { n: 2 },
        Op::Idx {
            cached: true,
            push_path: false,
            path: vec![key(0)].into(),
        },
        Op::Popeq {
            cached: true,
            result: bytesn_value(32, addr),
        },
    ]
}

/// `map.member(key)` — `dup 0; idx f; push key; member; popeqc`.
pub fn member(field: u8, k: &[u8; 32], result: bool) -> Vec<VmOp> {
    vec![
        Op::Dup { n: 0 },
        Op::Idx {
            cached: false,
            push_path: false,
            path: field_path(field).into(),
        },
        Op::Push {
            storage: false,
            value: key32(k),
        },
        Op::Member,
        Op::Popeq {
            cached: true,
            result: bytesn_value(1, &[u8::from(result)]),
        },
    ]
}

/// `map.lookup(key)` — `dup 0; idx f; idx [key]; popeq`.
pub fn lookup(field: u8, k: &[u8; 32], result: AlignedValue) -> Vec<VmOp> {
    vec![
        Op::Dup { n: 0 },
        Op::Idx {
            cached: false,
            push_path: false,
            path: field_path(field).into(),
        },
        Op::Idx {
            cached: false,
            push_path: false,
            path: vec![Key::Value(bytesn_value(32, k))].into(),
        },
        Op::Popeq {
            cached: false,
            result,
        },
    ]
}

/// `map.insert(key, value)` — `idxp f; push key; pushs value; ins 1; insc 2`.
pub fn insert(field: u8, k: &[u8; 32], value: AlignedValue) -> Vec<VmOp> {
    vec![
        Op::Idx {
            cached: false,
            push_path: true,
            path: field_path(field).into(),
        },
        Op::Push {
            storage: false,
            value: key32(k),
        },
        Op::Push {
            storage: true,
            value: cell(value),
        },
        Op::Ins {
            cached: false,
            n: 1,
        },
        Op::Ins { cached: true, n: 2 },
    ]
}

/// `map.remove(key)` — `idxp f; push key; rem; insc 2`.
pub fn remove(field: u8, k: &[u8; 32]) -> Vec<VmOp> {
    vec![
        Op::Idx {
            cached: false,
            push_path: true,
            path: field_path(field).into(),
        },
        Op::Push {
            storage: false,
            value: key32(k),
        },
        Op::Rem { cached: false },
        Op::Ins { cached: true, n: 2 },
    ]
}

/// `counter.increment(1)` — `idxp f; addi 1; insc 2`.
pub fn counter_inc(field: u8) -> Vec<VmOp> {
    vec![
        Op::Idx {
            cached: false,
            push_path: true,
            path: field_path(field).into(),
        },
        Op::Addi { immediate: 1 },
        Op::Ins { cached: true, n: 2 },
    ]
}

/// `cell = value` — the NESTED whole-field write: `idxp [segment]; push
/// offset; pushs value; ins 1; insc 1`.
pub fn cell_write(field: u8, value: AlignedValue) -> Vec<VmOp> {
    let (seg, off) = segment_of(field);
    vec![
        Op::Idx {
            cached: false,
            push_path: true,
            path: vec![key(seg)].into(),
        },
        Op::Push {
            storage: false,
            value: cell(bytesn_value(1, &[off])),
        },
        Op::Push {
            storage: true,
            value: cell(value),
        },
        Op::Ins {
            cached: false,
            n: 1,
        },
        Op::Ins { cached: true, n: 1 },
    ]
}

/// One kernel claim into effects map `effect` (0 nullifiers, 1 receives, 2
/// spends): `swap 0; idxpc [effect]; push note; push null; insc 2; swap 0`.
pub fn claim(effect: u8, note: &[u8; 32]) -> Vec<VmOp> {
    vec![
        Op::Swap { n: 0 },
        Op::Idx {
            cached: true,
            push_path: true,
            path: vec![key(effect)].into(),
        },
        Op::Push {
            storage: false,
            value: key32(note),
        },
        Op::Push {
            storage: false,
            value: StateValue::Null,
        },
        Op::Ins { cached: true, n: 2 },
        Op::Swap { n: 0 },
    ]
}

/// `kernel.mintShielded(domainSep, amount)` — effects map 4, the
/// add-or-insert on the colour's running total.
pub fn mint_shielded(domain_sep: &[u8; 32], amount: u64) -> Vec<VmOp> {
    vec![
        Op::Swap { n: 0 },
        Op::Idx {
            cached: true,
            push_path: true,
            path: vec![key(4)].into(),
        },
        Op::Push {
            storage: false,
            value: key32(domain_sep),
        },
        Op::Dup { n: 1 },
        Op::Dup { n: 1 },
        Op::Member,
        Op::Push {
            storage: false,
            value: cell(bytesn_value(8, &amount.to_le_bytes())),
        },
        Op::Swap { n: 0 },
        Op::Neg,
        Op::Branch { skip: 4 },
        Op::Dup { n: 2 },
        Op::Dup { n: 2 },
        Op::Idx {
            cached: true,
            push_path: false,
            path: vec![Key::Stack].into(),
        },
        Op::Add,
        Op::Ins { cached: true, n: 2 },
        Op::Swap { n: 0 },
    ]
}

/// The whole `mintShieldedToken` tail after its `kernel.self()` read:
/// the mint and the spend claim of the new coin's commitment.
pub fn mint_and_spend(domain_sep: &[u8; 32], amount: u64, cm: &[u8; 32]) -> Vec<VmOp> {
    let mut ops = mint_shielded(domain_sep, amount);
    ops.extend(claim(2, cm));
    ops
}

/// `kernel.claimContractCall(addr, ep, comm)` — effects map 3, appended
/// with its sequence number: `swap 0; idxpc [3]; dup 0; size; push (addr,
/// ep, comm); concatc 160; push null; insc 2; swap 0`.
pub fn claim_contract_call(addr: &[u8; 32], ep: &[u8; 32], comm: Fr) -> Vec<VmOp> {
    let mut comm_bytes = comm.as_le_bytes();
    while comm_bytes.last() == Some(&0) {
        comm_bytes.pop();
    }
    let addr_ep_comm = AlignedValue::new(
        Value(vec![
            ValueAtom(addr.to_vec()).normalize(),
            ValueAtom(ep.to_vec()).normalize(),
            ValueAtom(comm_bytes).normalize(),
        ]),
        Alignment(vec![
            atom(32),
            atom(32),
            AlignmentSegment::Atom(AlignmentAtom::Field),
        ]),
    )
    .unwrap();
    vec![
        Op::Swap { n: 0 },
        Op::Idx {
            cached: true,
            push_path: true,
            path: vec![key(3)].into(),
        },
        Op::Dup { n: 0 },
        Op::Size,
        Op::Push {
            storage: false,
            value: cell(addr_ep_comm),
        },
        Op::Concat {
            cached: true,
            n: 160,
        },
        Op::Push {
            storage: false,
            value: StateValue::Null,
        },
        Op::Ins { cached: true, n: 2 },
        Op::Swap { n: 0 },
    ]
}

/// The popeq results of an op stream, value-only, in read order — the
/// preimage's `public_transcript_outputs`. Derived from the ops rather than
/// listed beside them, so the two cannot disagree.
pub fn outputs_of(ops: &[VmOp]) -> Vec<Fr> {
    let mut out = Vec::new();
    for op in ops {
        if let Op::Popeq { result, .. } = op {
            ValueReprAlignedValue(result.clone()).field_repr(&mut out);
        }
    }
    out
}

/// `field_repr` of an op stream — the preimage's `public_transcript_inputs`.
pub fn transcript_of(ops: &[VmOp]) -> Vec<Fr> {
    let mut out = Vec::new();
    for op in ops {
        op.field_repr(&mut out);
    }
    out
}
