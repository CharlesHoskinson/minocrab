//! Impact element/op encoding: [`ImpactOp`], [`ImpactElem`], [`LedgerValue`],
//! [`LedgerKey`], the header/alignment helpers, [`idx_path`], [`push_cell`],
//! [`dup`], [`swap`].

use midnight_base_crypto::fab::{
    Alignment, AlignmentAtom, AlignmentSegment, AlignedValue, Value, ValueAtom,
};
use midnight_onchain_vm::ops::{Key, Op};
use midnight_onchain_vm::result_mode::ResultModeVerify;
use midnight_storage::db::InMemoryDB;
use midnight_transient_crypto::repr::FieldRepr;
use minocrab::v3::ImpactElem;
use minocrab::Fr;

/// The concrete op type whose `field_repr` defines the PI encoding.
pub type VmOp = Op<ResultModeVerify, InMemoryDB>;

/// One Impact instruction: the element stream of a single Impact-VM op.
#[derive(Clone)]
pub struct ImpactOp(pub Vec<ImpactElem>);

impl ImpactOp {
    /// A fully-constant op, encoded by the real `Op::field_repr`.
    pub fn constant(op: &VmOp) -> ImpactOp {
        let mut elems = Vec::new();
        op.field_repr(&mut elems);
        ImpactOp(elems.into_iter().map(ImpactElem::Imm).collect())
    }
}

/// A FAB-aligned value whose limbs may be circuit-computed: the alignment
/// atoms plus one element per FAB limb, in slot order (`Bytes<32>` =
/// `[hi, lo]` — notes/builtin-lowering.org §1).
#[derive(Clone)]
pub struct LedgerValue {
    pub(crate) atoms: Vec<AlignmentAtom>,
    pub(crate) elems: Vec<ImpactElem>,
}

/// How many FAB limbs one alignment atom occupies: a `bytes<n>` is limbed in
/// 31-byte chunks (at least one, so `bytes<0>` is one zero limb), a `field`
/// and a `compress` are one each.
///
/// Public because it is the FAB rule and it should be stated once — the
/// stdlib needs it to build a default value's zeros
/// (notes/ledger-adts.org finding (c)).
pub fn atom_limbs(atom: &AlignmentAtom) -> usize {
    match atom {
        // A `Bytes<0>` atom is in the alignment but holds NO limb (compactc's
        // V1 Signet record: 23 atoms, 30 limbs — M44).
        AlignmentAtom::Bytes { length } => (*length as usize).div_ceil(31),
        AlignmentAtom::Field | AlignmentAtom::Compress => 1,
    }
}

impl LedgerValue {
    /// A value of one or more atoms; `elems` are the concatenated limbs.
    pub fn new(atoms: Vec<AlignmentAtom>, elems: Vec<ImpactElem>) -> LedgerValue {
        let expected: usize = atoms.iter().map(atom_limbs).sum();
        assert_eq!(
            elems.len(),
            expected,
            "LedgerValue: {} limbs for atoms {atoms:?}",
            elems.len()
        );
        LedgerValue { atoms, elems }
    }

    /// A single `bytes<n>` atom.
    pub fn bytes(n: u32, elems: Vec<ImpactElem>) -> LedgerValue {
        Self::new(vec![AlignmentAtom::Bytes { length: n }], elems)
    }

    /// The alignment atoms, in slot order.
    pub fn atoms(&self) -> &[AlignmentAtom] {
        &self.atoms
    }

    /// The limbs, in slot order.
    pub fn elems(&self) -> &[ImpactElem] {
        &self.elems
    }
}

/// `Fr` for an alignment atom, per `AlignmentAtom::field_repr`
/// (transient-crypto fab.rs:596-608): `bytes n` → n, compress → −1,
/// field → −2.
fn atom_elem(atom: &AlignmentAtom) -> Fr {
    match atom {
        AlignmentAtom::Bytes { length } => Fr::from(u64::from(*length)),
        AlignmentAtom::Compress => Fr::from(0u64) - Fr::from(1u64),
        AlignmentAtom::Field => Fr::from(0u64) - Fr::from(2u64),
    }
}

/// The alignment header of an `AlignedValue::field_repr`: atom count, then
/// one element per atom (fab.rs:364-374).
pub(crate) fn alignment_header(atoms: &[AlignmentAtom]) -> Vec<ImpactElem> {
    let mut out = vec![ImpactElem::Imm(Fr::from(atoms.len() as u64))];
    out.extend(atoms.iter().map(|a| ImpactElem::Imm(atom_elem(a))));
    out
}

/// `push` / `pushs` of a `Cell` holding `value`:
/// `[0x10 + storage, 1 (Cell tag), alignment header…, limbs…]`
/// (ops.rs:488-491 + StateValue::field_repr state.rs:171-179 +
/// AlignedValue::field_repr).
pub fn push_cell(storage: bool, value: &LedgerValue) -> ImpactOp {
    let mut elems = vec![
        ImpactElem::Imm(Fr::from(0x10u64 + u64::from(storage))),
        ImpactElem::Imm(Fr::from(1u64)), // StateValue::Cell tag
    ];
    elems.extend(alignment_header(&value.atoms));
    elems.extend(value.elems.iter().copied());
    ImpactOp(elems)
}

/// One element of a pushed `StateValue::Array` whose cells may be
/// circuit-computed — see [`push_array`].
#[derive(Clone)]
pub enum LedgerElem {
    /// `StateValue::Null`.
    Null,
    /// `StateValue::Cell(..)`, possibly carrying wires.
    Cell(LedgerValue),
}

/// `push` / `pushs` of a `StateValue::Array`:
/// `[0x10 + storage, 3 | len << 4, element reprs…]` (`StateValue::field_repr`,
/// onchain-state state.rs:171-205).
///
/// The ONE mixed push in the ADT layer: `List.pushFront` pushes
/// `[Cell(value), Null, Null]` whose first element carries the pushed value's
/// wires (notes/ledger-adts.org §2). Every other ADT constant — the empty
/// map, the blank tree, a `List`'s initial value — is fully constant and goes
/// through [`ImpactOp::constant`] with a real `StateValue`, per the crate's
/// standing rule; `push_array_matches_field_repr` pins that the two agree on
/// the constant case.
pub fn push_array(storage: bool, elems: &[LedgerElem]) -> ImpactOp {
    let mut out = vec![
        ImpactElem::Imm(Fr::from(0x10u64 + u64::from(storage))),
        ImpactElem::Imm(Fr::from(3u64 | ((elems.len() as u64) << 4))),
    ];
    for elem in elems {
        match elem {
            LedgerElem::Null => out.push(ImpactElem::Imm(Fr::from(0u64))),
            LedgerElem::Cell(value) => {
                out.push(ImpactElem::Imm(Fr::from(1u64)));
                out.extend(alignment_header(&value.atoms));
                out.extend(value.elems.iter().copied());
            }
        }
    }
    ImpactOp(out)
}

/// The DEFAULT value of a type with these atoms: one zero limb per FAB limb.
///
/// True for every Compact type, not just the scalar ones — compactc's `VMnull`
/// reduction is `(make-list count 0)` over the limb count
/// (reduce-to-zkir.ss:350-355, notes/ledger-adts.org finding (c)) — which is
/// why no per-type default table exists anywhere below this line.
pub fn default_value(atoms: Vec<AlignmentAtom>) -> LedgerValue {
    let limbs: usize = atoms.iter().map(atom_limbs).sum();
    LedgerValue::new(atoms, vec![ImpactElem::Imm(Fr::from(0u64)); limbs])
}

/// The `AlignedValue` key of ledger field `index`: one `bytes<1>` atom.
pub fn field_key(index: u8) -> AlignedValue {
    AlignedValue::new(
        Value(vec![ValueAtom(vec![index]).normalize()]),
        Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes {
            length: 1,
        })]),
    )
    .expect("a byte fits a bytes<1> atom")
}

/// `idx` by ONE constant `bytes<1>` key.
///
/// Two things are spelled this way, and they are the same instruction: a
/// top-level ledger FIELD (`idx_one(false, false, field)` to read, uncached
/// and not remembering the path; `idx_one(false, true, field)` to reach one
/// that will be written back) and a POSITION inside an ADT's `Array` —
/// `List` is `[head, tail, length]`, `MerkleTree` is `[tree, next-index]`,
/// `HistoricMerkleTree` adds `[.., history]`, and every descent into one is
/// `(align i 1)` in compactc's vm-code (notes/ledger-adts.org §1). The one
/// spelling for both, per crate: production call sites (this crate's own
/// `ops.rs`/`reads.rs`, and `minocrab-std`'s one `cached = true` site) all
/// write the three arguments out rather than reach for a named wrapper —
/// see notes/edsl-trim.org §D, finding 2, which removed the two this
/// crate used to carry (`idx_field`, `idxp_field`).
pub fn idx_one(cached: bool, push_path: bool, index: u8) -> ImpactOp {
    ImpactOp::constant(&Op::Idx {
        cached,
        push_path,
        path: vec![Key::Value(field_key(index))].into(),
    })
}

/// `dup n`.
pub fn dup(n: u8) -> ImpactOp {
    assert!(
        n <= 15,
        "dup {n}: the reach does not fit the opcode's low nibble — a coin arm \
         at this path depth would miscompile in compactc too \
         (midnight-ledger.ss:576-577)"
    );
    ImpactOp::constant(&Op::Dup { n })
}

/// `idx` by a single dynamic (possibly circuit-computed) key, uncached,
/// path not remembered — the Map.lookup descent step:
/// `[0x50, key alignment header…, key limbs…]` (`Key::Value(av)` is encoded
/// as `AlignedValue::field_repr`, ops.rs:67-73).
pub fn idx_key(key: &LedgerValue) -> ImpactOp {
    let mut elems = vec![ImpactElem::Imm(Fr::from(0x50u64))];
    elems.extend(alignment_header(&key.atoms));
    elems.extend(key.elems.iter().copied());
    ImpactOp(elems)
}

// --- the ledger PATH (`f`) --------------------------------------------------
//
// Every ledger operation's vm-code is written against `f`, "the path to the
// field being operated on" (midnight-ledger.ss:133-138), and `f` is "a list of
// either aligned value instances, or the symbol 'stack". For a top-level
// field it is one `bytes<1>` key; nesting appends map keys.
//
// A NESTED ACCESS IS NOT A NEW INSTRUCTION. compactc's
// `propagate-ledger-paths.ss` walks a chain of accessors, folds every
// intermediate `Map.lookup(k)` into `f` as one more path element, and emits
// nothing for it; only the LAST accessor's vm-code runs, with a longer `f`.
// So `m.lookup(k).insert(k2, v)` is `map_insert`'s five instructions with a
// two-element path — `idxp` gains a low nibble and the closing `insc` a
// bigger `n`. See notes/coin-arms-nested-adts.org "AS BUILT — STAGE B1".

/// One element of a ledger path — compactc's `f` entry.
///
/// [`LedgerKey::Field`] and [`LedgerKey::Value`] are the two halves of
/// upstream's `Key::Value(AlignedValue)`, split because a field index is
/// const-known and a map key generally is not; [`LedgerKey::Stack`] is
/// upstream's `Key::Stack` (`'stack` in the vm-code). All three encode
/// exactly as `Key::field_repr` does — `key_encoding_matches_field_repr`
/// pins it.
#[derive(Clone)]
pub enum LedgerKey {
    /// A constant `bytes<1>` key — a ledger field index, or a position inside
    /// an ADT's `Array` (compactc's `(align i 1)`). Encodes as `[1, 1, i]`.
    Field(u8),
    /// A FAB-aligned key whose limbs may be circuit-computed: a `Map` key.
    /// Encodes as its alignment header followed by its limbs.
    Value(LedgerValue),
    /// The top of the Impact stack, `-1` — the coin arms' `idxc [(1), stack]`
    /// and nothing else.
    Stack,
}

impl LedgerKey {
    /// This element's `Key::field_repr` elements, appended to `out`.
    pub(crate) fn push_elems(&self, out: &mut Vec<ImpactElem>) {
        match self {
            LedgerKey::Field(index) => {
                out.extend(alignment_header(&[AlignmentAtom::Bytes { length: 1 }]));
                out.push(ImpactElem::Imm(Fr::from(u64::from(*index))));
            }
            LedgerKey::Value(value) => {
                out.extend(alignment_header(&value.atoms));
                out.extend(value.elems.iter().copied());
            }
            LedgerKey::Stack => out.push(ImpactElem::Imm(Fr::from(0u64) - Fr::from(1u64))),
        }
    }

    /// This element pushed as a `Cell` — compactc's
    /// `(push [storage #f] [value (state-value 'cell (car (reverse f)))])`,
    /// the key the whole-field-replace ops write the new value under.
    pub(crate) fn push_as_cell(&self) -> ImpactOp {
        match self {
            LedgerKey::Field(index) => push_cell(false, &field_index_value(*index)),
            LedgerKey::Value(value) => push_cell(false, value),
            LedgerKey::Stack => panic!("a whole-field replace cannot write under a stack key"),
        }
    }
}

/// The encoder of `idx` over a whole path.
///
/// `[0x50 | hi | (path.len() − 1)]` then each element's encoding, which is
/// `assemble1`'s `idx` case (reduce-to-zkir.ss:586-601) and upstream's
/// `Op::Idx` field_repr (ops.rs:510-524) at once. The low nibble is the
/// ONLY thing depth changes.
pub fn idx_path(cached: bool, push_path: bool, path: &[LedgerKey]) -> ImpactOp {
    assert!(
        !path.is_empty(),
        "idx_path: an empty path emits no instruction — the callers that can \
         produce one go through the suppression helpers"
    );
    assert!(
        path.len() <= 16,
        "idx_path: a {}-element path does not fit the opcode's low nibble \
         (compactc has the same bound, unchecked)",
        path.len()
    );
    let hi = match (cached, push_path) {
        (false, false) => 0x50u8,
        (true, false) => 0x60,
        (false, true) => 0x70,
        (true, true) => 0x80,
    };
    let mut elems = vec![ImpactElem::Imm(Fr::from(u64::from(
        hi | (path.len() as u8 - 1),
    )))];
    for key in path {
        key.push_elems(&mut elems);
    }
    ImpactOp(elems)
}

/// The one-element path of a top-level ledger field — what every `u8`
/// builder widens into, and the reason the widening is purely ADDITIVE.
pub(crate) fn field_path(index: u8) -> [LedgerKey; 1] {
    [LedgerKey::Field(index)]
}

/// The field index as a pushable `bytes<1>` value — the key half of
/// [`field_key`], for the ops that push it rather than index by it.
pub(crate) fn field_index_value(index: u8) -> LedgerValue {
    LedgerValue::bytes(1, vec![ImpactElem::Imm(Fr::from(u64::from(index)))])
}

/// `swap n`.
pub fn swap(n: u8) -> ImpactOp {
    ImpactOp::constant(&Op::Swap { n })
}

/// `idx` by a single dynamic key, CACHED — [`idx_key`]'s twin, and the shape
/// the balance lookup descends with.
pub fn idx_key_cached(key: &LedgerValue) -> ImpactOp {
    let mut elems = vec![ImpactElem::Imm(Fr::from(0x60u64))];
    elems.extend(alignment_header(&key.atoms));
    elems.extend(key.elems.iter().copied());
    ImpactOp(elems)
}

/// A path in words, for the stale-read backstop's refusal to name a read:
/// `field 3`, `field 3 / key`, `stack`.
pub fn render_path(path: &[LedgerKey]) -> String {
    path.iter()
        .map(|key| match key {
            LedgerKey::Field(i) => format!("field {i}"),
            LedgerKey::Value(_) => "key".to_string(),
            LedgerKey::Stack => "stack".to_string(),
        })
        .collect::<Vec<_>>()
        .join(" / ")
}
