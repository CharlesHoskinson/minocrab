//! The treasury's Impact op builders — `tests/vault_pending/ops.rs` over a
//! NARROW block.
//!
//! The treasury declares seven ledger fields (`Signet`'s five, then the
//! transfer slot's record and environment maps), which is under compactc's
//! fifteen-field segment length, so every path is ONE element and no write
//! is nested. That is the whole difference from the vault harness's copy;
//! every builder below is otherwise the same instruction sequence.
//!
//! Independent of `minocrab-ledger` on purpose: this is the ORACLE the
//! eDSL's `LedgerMap` / `LedgerCell` / `LedgerCounter` / `Pending` methods
//! are checked against, so it must not be built from them.

use midnight_base_crypto::fab::{
    AlignedValue, Alignment, AlignmentAtom, AlignmentSegment, Value, ValueAtom,
};
use midnight_onchain_state::state::StateValue;
use midnight_onchain_vm::ops::{Key, Op};
use midnight_transient_crypto::fab::ValueReprAlignedValue;
use midnight_transient_crypto::repr::FieldRepr;
use minocrab::Fr;

use super::prims::{atom, bytesn_value, cell, VmOp};

/// The treasury's field count — seven, so one segment and one-element paths.
pub const FIELDS: u8 = 7;
const SEGMENT: u8 = 15;

fn key(i: u8) -> Key {
    Key::Value(bytesn_value(1, &[i]))
}

/// A field's path. Under the segment length there is no segmentation at
/// all, so this is the bare declaration index — asserted, rather than
/// assumed, so a widened block fails here instead of silently diverging.
pub fn field_path(field: u8) -> Vec<Key> {
    assert!(field < FIELDS, "field {field} is not one of the treasury's {FIELDS}");
    const {
        assert!(
            FIELDS <= SEGMENT,
            "a block past compactc's segment length is segmented and every path \
             is two elements — this builder emits one"
        )
    };
    vec![key(field)]
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

/// `map.insert(key, value)` — `idxp f; push key; pushs value; ins 1; insc 1`.
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
        // `insc len(path)` (minocrab-ledger `ops::map_insert`): the closing
        // insert re-seats the container at every path element, and this
        // block's paths are one element long.
        Op::Ins { cached: true, n: 1 },
    ]
}

/// `map.remove(key)` — `idxp f; push key; rem; insc 1`.
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
        Op::Ins { cached: true, n: 1 },
    ]
}

/// `counter.increment(1)` — `idxp f; addi 1; insc 1`.
///
/// UNUSED since M44 rung D: the treasury's only counter was the Signet
/// request nonce, which went with the V1 vocabulary. Kept because the next
/// contract with a counter needs it and the op encoding is the thing worth
/// not re-deriving.
#[allow(dead_code)]
pub fn counter_inc(field: u8) -> Vec<VmOp> {
    vec![
        Op::Idx {
            cached: false,
            push_path: true,
            path: field_path(field).into(),
        },
        Op::Addi { immediate: 1 },
        Op::Ins { cached: true, n: 1 },
    ]
}

/// `kernel.claimContractCall(addr, ep, comm)` — effects map 3, appended
/// with its sequence number.
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
/// preimage's `public_transcript_outputs`.
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
