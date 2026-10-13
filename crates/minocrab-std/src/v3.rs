//! ZKIR v3-only stdlib: the `zkir-v3-library.compact` ports.
//!
//! Built against the typed v3 frontend (`minocrab::v3`). Lowering follows
//! compactc exactly (notes/builtin-lowering.org §13, verified against the
//! library's compiled output): Compact-level `Bytes<32>` values live as
//! `[hi, lo]` native slot pairs ([`B32`]); typed `Bytes<32>` values appear
//! only at instruction boundaries; byte surgery is div_mod / reconstitute
//! chains over the low limb.

use minocrab::v3::{
    AnyWire3, Bytes32T, Circuit3, FieldT, IrTy, JubjubPointT, Secp256k1PointT, Secp256k1ScalarT,
    Wire3,
};
use minocrab::{Alignment, AlignmentAtom, AlignmentSegment, Fr, Meet, Private, Public, Visibility};

/// What the derives in `minocrab-macros` name: re-exports only, so an
/// expansion depends on nothing a user must import.
#[doc(hidden)]
pub mod __derive {
    pub use super::{repr_limbs, LedgerRepr, ProofWires};
    pub use minocrab::v3::{Circuit3, FieldT, Val, Wire3};
    pub use minocrab::{AlignmentAtom, Public};
}

mod call;
mod disclose;
mod entry;
mod ledger;

/// Blind accumulators (M40): the steps the ledger applies itself — `Add`,
/// `Max`, `Min`, `And`, `Or`, `Last`, `First` and tuples of them — with a
/// blind snapshot into a per-key map. Written module-qualified
/// (`blind::Max`) except for the two traits.
mod assumed;
pub mod blind;
mod hook;
mod stream;
mod vector;

/// Compact's `kernel` ADT and the token stdlib built on it (M17) — always
/// written module-qualified (`kernel::balance(c, &t)`), because a kernel
/// operation is an EFFECT on the transaction and the call site should say so.
pub mod kernel;
mod predicate;

/// Canonical Borsh, restricted to the fixed-width subset a circuit can emit
/// — the serialization layer (M11, notes/borsh-format.org). Read its module
/// docs first: **this is Borsh, not a format of ours**, and the subset exists
/// because a circuit cannot have data-dependent layout.
pub mod borsh;

/// The two hash FLAVORS — `persistent_hash`/`transient_hash` over a value's
/// Borsh encoding (the default) and the `_compact` pair over Compact's FAB
/// representation (Compact-interop digest agreement only). Always written
/// module-qualified (`hash::persistent_hash(c, &v)`), never re-exported bare:
/// which bytes get hashed is a decision, and it should be visible at the call
/// site.
pub mod hash;

pub use assumed::{Assumed, ProofWires};
pub use blind::{Monoid, Primitive};
pub use hook::{CellArith, Hook, HookValue, Reachable};
pub use stream::{ContentionFree, Fold, Serial, Step, Stream, StreamSpec};
pub use vector::{Bounded, NonEmpty};
pub use entry::{entry, entry_out, ArgPath, CircuitArg, CircuitArgs, CircuitOut};

/// The ledger block as types: `#[derive(Ledger)]`'s declaration-order
/// indices and the typed slots ([`LedgerMap`] and [`LedgerSet`] with Compact's
/// method names, [`LedgerList`], [`LedgerMerkleTree`],
/// [`LedgerHistoricMerkleTree`], [`LedgerCell`], [`LedgerCounter`],
/// [`LedgerField`]) over `minocrab_ledger`'s ops — one Impact operation per
/// method, `c` and the guard visible at every call site.
/// Nesting (M22 stage B2) adds [`LedgerMap::at_key`] and the types it needs:
/// [`FieldPath`] (a declared slot's const path — one element, or the segment
/// path a block of sixteen fields or more forces), [`KeyPath`] (the runtime
/// path an `at_key` chain builds), and the sealed pair [`LedgerSlot`] /
/// [`LedgerAdt`] that splits the value position into plain values and ADT
/// handles.
pub use ledger::{
    Fresh,
    assert_distinct_kinds, leaf_hash, repr_limbs, CoinArm, FieldPath, KeyPath, KeyedPath, LedgerAdt,
    LedgerCell, LedgerCounter, LedgerField, LedgerHistoricMerkleTree, LedgerList, LedgerMap,
    LedgerMerkleTree, LedgerPath, LedgerRepr, LedgerSet, LedgerSlot, LedgerWidth,
    MAX_FIELD_PATH, MAX_LEDGER_PATH, MAX_NESTING,
};

/// Assertion predicates: `c.assert(less_than(0u64, amount))` — deferred,
/// `#[must_use]` descriptors whose widths come from the operand types (see
/// the module docs). The same comparisons are methods on the typed leaves
/// (`amount.gt(0u64)`), delegating to these.
pub use predicate::{
    eq, ge, greater_than, is_true, le, less_than, ne, not, Check, CheckOperand,
};

/// Typed disclosure declarations: `label!` types, `.disclose_as::<L>(c)`,
/// and the `Discloses<D, R>` a circuit returns. The vocabulary lives in the
/// frontend (`minocrab::v3::disclose`, whose docs explain the
/// rustc-checks-symbols / generated-test-checks-the-set split) because
/// minocrab-ledger discloses too; `v3::disclose` here holds the [`Disclose`]
/// impls for this crate's value types. Re-exported so one
/// `use minocrab_std::v3::…` brings the whole vocabulary in.
pub use minocrab::label;
pub use minocrab::v3::{
    assert_declared_disclosures, assert_discloses_nothing, disclosed_labels, Declared, Disclose, DisclosureLabel, Discloses,
    LabelSet,
};

/// The ABI vocabulary, which lives in the frontend (`minocrab::v3::abi` —
/// the port of `emit-constraints-for` plus the traits `minocrab_ledger::call`
/// has to name) and is re-exported here because this is where argument types
/// are WRITTEN: a [`CircuitAbi`] impl names [`Prim`]s, `contract_call` takes
/// [`LimbConstraint`]s, and [`CircuitArg`] / [`CallArg`] are the two
/// visibility-specific halves of one schema.
pub use minocrab::v3::{CallArg, CallArgs, CallResult, CircuitAbi, LimbConstraint, Prim};

/// The if / else-if / else chain (`c.when(..).else_when(..).otherwise(..)`)
/// and the trait that lets its arms be written as wires or as [`Check`]s.
pub use minocrab::v3::{Branches, GuardCond, Select, Selected, ValueBranches};

/// The result of a guarded read — the value, or the type's DEFAULT where the
/// guard was off. Re-exported here because this is where guarded reads are
/// WRITTEN: every `_guarded` method on [`LedgerMap`], [`LedgerCell`] and
/// [`LedgerCounter`] returns one.
pub use minocrab::v3::Guarded;

/// `#[derive(CircuitArg)]` — the struct impls of [`CircuitArg`] and
/// [`CircuitArgs`], generated from the fields (field order is the wire
/// contract). Named the same as the trait it implements, the way
/// `serde::Serialize` is; one `use minocrab_std::v3::CircuitArg;` brings
/// both.
#[cfg(feature = "macros")]
pub use minocrab_macros::CircuitArg;

/// `#[circuit]` — a plain typed function becomes an entry point: the
/// parameters after `c: &mut Circuit3` are the arguments (declaration order
/// is the wire contract), and the function itself becomes
/// `fn name() -> Compiled3` built through [`entry`] / [`entry_out`].
/// `#[circuit(max_k = N)]` additionally declares a cost budget, checked by a
/// generated test against minocrab-sim's cost model.
#[cfg(feature = "macros")]
pub use minocrab_macros::circuit;
pub use minocrab_macros::contract;

/// `#[derive(Ledger)]` — a struct mirroring Compact's `export ledger` block
/// becomes the contract's ledger handle, each field at its declaration-order
/// index. Named the same as nothing else here: the slot TYPES are what the
/// fields are written in.
#[cfg(feature = "macros")]
pub use minocrab_macros::Ledger;

/// `#[derive(LedgerRepr)]` — a struct of `Public` ledger leaves becomes a
/// storable value (a `Map` value, a `Cell` type), atoms and limbs in
/// declaration order. The derive and the trait share the name, as
/// serde's do. A `Private` field has no `LedgerRepr` impl, so it fails to
/// type-check rather than leaking into state:
///
/// ```compile_fail
/// use minocrab::{Private, Public};
/// use minocrab_std::v3::{LedgerRepr, Uint, B32};
///
/// #[derive(LedgerRepr)]
/// struct Env {
///     id: B32<Public>,
///     secret: B32<Private>,
/// }
/// ```
///
/// while the all-`Public` form compiles and stores:
///
/// ```
/// use minocrab::Public;
/// use minocrab_std::v3::{LedgerMap, LedgerRepr, Uint, B32};
///
/// #[derive(LedgerRepr)]
/// struct Env {
///     id: B32<Public>,
///     amount: Uint<64, Public>,
/// }
///
/// const ENVS: LedgerMap<B32<Public>, Env> = LedgerMap::at(0);
/// assert_eq!(Env::atoms().len(), B32::<Public>::atoms().len() + 1);
/// ```
#[cfg(feature = "macros")]
pub use minocrab_macros::LedgerRepr;

/// `#[interface]` — a bodyless trait declaring another contract's circuits
/// becomes a typed calling handle over `minocrab_ledger::call`. The
/// expansion names `::minocrab_ledger` paths, so a crate using it depends on
/// minocrab-ledger as well as minocrab-std.
#[cfg(feature = "macros")]
pub use minocrab_macros::interface;

/// Implementation detail of `#[derive(CircuitArg)]` and `#[circuit]`: the
/// upstream types their expansions have to name, re-exported so the
/// generated code needs only `minocrab_std` in scope and the macro crate
/// needs no dependency of ours. Not a stable API.
#[doc(hidden)]
pub mod __private {
    pub use minocrab::v3::{Circuit3, Compiled3, FieldT, Wire3};
    pub use minocrab::{AlignmentAtom, OnChainGuard, Private, Public, Visibility};

    /// The bodies of the disclosure tests `#[circuit]` generates: the
    /// set-equality one for a `Discloses<..>` return, the discloses-nothing
    /// one for every other.
    pub use super::{assert_declared_disclosures, assert_discloses_nothing};
}

/// Visibility usable by v3 stdlib gadgets (closed under [`Meet`], reachable
/// from [`Public`]).
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a visibility a v3 gadget can be generic over",
    label = "expected `Public` or `Private`",
    note = "`Vis3` has exactly two impls — `minocrab::Public` and \
            `minocrab::Private` — and every typed leaf (`Uint<BITS, V>`, \
            `B32<V>`, `Bytes<N, V>`, …) is generic over it. If this is your \
            own type parameter, bound it `V: Vis3`; if it is a concrete type, \
            it is a VALUE type in the visibility position — the leaves take \
            visibility last (`Uint<64, Private>`), and `B32`/`BytesN` take it \
            first (`B32<Public>`, `BytesN<Public, 20>`)"
)]
pub trait Vis3: Visibility + Meet<Self, Out = Self> + Meet<Public, Out = Self> + Sized + Copy {
    fn from_public<T: IrTy>(w: Wire3<T, Public>) -> Wire3<T, Self>;
}

impl Vis3 for Public {
    fn from_public<T: IrTy>(w: Wire3<T, Public>) -> Wire3<T, Public> {
        w
    }
}

impl Vis3 for Private {
    fn from_public<T: IrTy>(w: Wire3<T, Public>) -> Wire3<T, Private> {
        w.private()
    }
}

// ---- typed leaves -----------------------------------------------------------
//
// Compact's scalar leaves as single-wire newtypes, so a circuit argument
// carries its width in its type: the input constraint compactc emits for a
// leaf (`assert_bits(BITS)` / `assert_boolean` / `assert_bits(8N)`) is then
// derived from the argument type instead of hand-written in a block
// parallel to the argument list, where an omission is invisible to PI
// equality on honest preimages (notes/contract-api.org §Survey).
//
// Parameter order is const-first with the visibility defaulted to Private
// (`Uint<64>`, `Bytes<20>`), deliberately unlike `B32<V>` / `BytesN<V, N>`:
// these are the types circuit signatures are written in, and reading
// side-by-side with the Compact source wins (DECIDED, notes/contract-api.org).
//
// All three are `#[repr(transparent)]` around one wire, and `.field()`
// unwraps to it without emitting an instruction.
//
// The bound arithmetic these leaves encode (the add/mul const-assert
// thresholds, the subtraction guard, the free widen/to_uint retypes, the
// guard's comparison width) is machine-checked in `lean/MinocrabStdProofs/
// Numeric.lean`, shipped with this crate; tests/lean_claims.rs is the
// drift gate. Model proofs — the transcription gap is stated in the file's
// header (M25, notes/lean-port.org).

/// Compact's `Uint<0..2^BITS - 1>`: one native slot, `assert_bits(BITS)` on
/// entry, alignment atom `bytes ceil(BITS/8)`.
///
/// `BITS` must satisfy `0 < BITS < 255`: at or above the native field's
/// width upstream's `ConstrainBits` constrains nothing, so a wider `Uint`
/// would silently be no `Uint` at all.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Uint<const BITS: u32, V: Vis3 = Private>(Wire3<FieldT, V>);

impl<const BITS: u32, V: Vis3> Uint<BITS, V> {
    /// An ASSERTION, not a check: the caller is CLAIMING `w` already holds a
    /// value below `2^BITS`, and this emits nothing to verify it
    /// (notes/api-safety-survey.org §A1). Typical justification is a
    /// constrained circuit argument about to receive [`Self::constrain_input`],
    /// or the result of an operation this module already range-checked
    /// (`sub`, `narrow`, a `BoundedUint::to_uint` bridge). Getting the claim
    /// wrong is silent — `CheckOperand::BITS`/`MAX`, the comparison widths,
    /// [`Self::widen`]'s soundness argument, and the Borsh packing all rest on
    /// it holding.
    ///
    /// When the wire is NOT already known to satisfy the bound, use
    /// [`Self::from_field_checked`] instead.
    pub fn from_field_unchecked(w: Wire3<FieldT, V>) -> Self {
        const {
            assert!(
                BITS > 0 && BITS < 255,
                "Uint<BITS> needs 0 < BITS < 255 — the native field is 255 bits \
                 wide, and a range constraint at or above that is vacuous"
            )
        };
        Uint(w)
    }

    /// [`Self::from_field_unchecked`] immediately followed by
    /// [`Self::constrain_input`] — the CHECKED twin, for a wire that is not
    /// already known to hold a `Uint<BITS>`.
    ///
    /// Cost: exactly `constrain_input`'s constraint (~`BITS`/4 rows, one
    /// `assert_boolean` at `BITS = 1`). With
    /// `Circuit3::dedup_range_constraints` enabled, a redundant call is free —
    /// the pass drops a later constraint no tighter than one already proven.
    pub fn from_field_checked(c: &mut Circuit3, w: Wire3<FieldT, V>) -> Self {
        // The CONSTRAINED value comes back, not `w`: inside a `when` the two
        // differ (`select(guard, w, 0)` is what was checked, and what the
        // branch computes), and a checked leaf must carry the checked wire.
        Self::from_field_unchecked(w).constrain_input(c)
    }

    /// `x as Field` — the same slot, no instructions.
    pub fn field(self) -> Wire3<FieldT, V> {
        self.0
    }

    /// Range-constrain a `Uint<BITS>` entering the circuit, exactly as
    /// compactc constrains its `Uint<BITS>` arguments — through the ONE
    /// table (`Prim::constraint`), so this and `CircuitArg::constrain`
    /// cannot say different things. Note `Uint<1>` is `constrain_to_boolean`
    /// there, as it is in compactc.
    pub fn constrain_input(self, c: &mut Circuit3) -> Self {
        Self(Prim::Uint { bits: BITS }.constraint().emit(c, self.0))
    }


    /// `self - other`, with COMPACT'S UNDERFLOW GUARD — the whole reason this
    /// method exists rather than leaving callers to `c.add(a, c.neg(b))`.
    ///
    /// compactc inserts a guard BEFORE every subtraction
    /// (`infer-types.ss`, decoded in notes/builtin-lowering.org §9):
    ///
    /// ```text
    /// assert(a >= b, "result of subtraction would be negative")
    /// neg(b); add(a, neg)
    /// ```
    ///
    /// and this is exactly that, in that order, at compactc's own width — the
    /// comparison's `bits` comes from `BITS` through the predicate layer, not
    /// from a number typed here.
    ///
    /// WHY IT IS NOT OPTIONAL, and why the raw spelling is a footgun
    /// (notes/api-safety-survey.org §B1): field arithmetic has no sign. For
    /// `a < b` the raw form yields `a - b + p` — a value near 2^255, not −1.
    /// Downstream that is a coin worth 2^255, or a `Uint<64>` ledger write of
    /// a 255-bit number. It is the balance-underflow bug, and no differential
    /// on an honest preimage can see it, because an honest preimage does not
    /// underflow.
    ///
    /// The result keeps `BITS`, which is compactc's rule (result type
    /// `Uint<maxa>`) and is sound because `a - b <= a < 2^BITS`.
    ///
    /// Cost: identical to compactc's, because it IS compactc's — one
    /// `less_than`, one `not` for the negation (verified against the port's
    /// own completeSwap, which mirrors compactc's artifact), one `assert`,
    /// one `neg`, one `add`.
    /// Both operands at the same visibility — a subtraction mixing them is
    /// spelled by moving one with `.private()` first, which is where the
    /// visibility join belongs and is free.
    pub fn sub(self, c: &mut Circuit3, other: Uint<BITS, V>) -> Uint<BITS, V>
    where
        V: Meet<V, Out = V>,
    {
        self.sub_with(c, other, "result of subtraction would be negative")
    }

    /// [`Uint::sub`] with the caller's own message on the underflow guard.
    ///
    /// The message is METADATA — no instruction, no row — so this is the SAME
    /// lowering as [`Uint::sub`], and a contract that already had a
    /// domain-specific message for its hand-written guard keeps it. That is
    /// not a convenience: a good message is what makes a failed proof
    /// diagnosable, and losing it would be a reason not to adopt the guarded
    /// form at all.
    pub fn sub_with(self, c: &mut Circuit3, other: Uint<BITS, V>, message: &'static str) -> Uint<BITS, V>
    where
        V: Meet<V, Out = V>,
    {
        c.assert(crate::v3::predicate::ge(self, other).message(message));
        let negated = c.neg(other.field());
        Uint::from_field_unchecked(c.add(self.field(), negated))
    }

    /// `x as Uint<WIDER>` — the LOSSLESS widening, and the explicit escape
    /// from a mixed-width comparison (dmd 2026-08-15, decision A: no implicit
    /// widening, Rust-style).
    ///
    /// FREE, in both senses. No instruction: it is the same wire, retyped.
    /// And no new CONSTRAINT, which is the part worth arguing: a wire already
    /// constrained to `BITS` bits holds a value `< 2^BITS ≤ 2^WIDER`, so it
    /// satisfies the wider range by construction — `constrain_bits(WIDER)`
    /// would be a tautology costing ~WIDER/4 rows. (The soundness of that
    /// argument rests on the leaf's invariant, which is the type's whole
    /// point: a `Uint<BITS>` is a wire something has constrained — an
    /// argument by `CircuitArg::constrain`, a computed value by whoever
    /// called `from_field_unchecked`. Widening PROPAGATES that obligation, it
    /// does not discharge one.)
    ///
    /// Narrowing is not offered and is not an oversight: it needs a real
    /// range check, so it is `Uint::<N>::from_field_checked` — visibly a
    /// cost.
    pub fn widen<const WIDER: u32>(self) -> Uint<WIDER, V> {
        const {
            assert!(
                WIDER >= BITS,
                "`.widen::<W>()` only widens: W must be at least the source's \
                 BITS. Narrowing needs a range check, so spell it out — \
                 `Uint::<W>::from_field_checked(c, x.field())`, which is the \
                 cost made visible"
            )
        };
        Uint::from_field_unchecked(self.0)
    }
}

impl<const BITS: u32> Uint<BITS, Public> {
    /// A `Uint<BITS>` constant from a native Rust value; panics at
    /// circuit-build time if `v` does not fit in `BITS` bits.
    ///
    /// `#[track_caller]` because the magnitude of a runtime integer is not a
    /// type, so this is one of the value-dependent checks that could not
    /// become a compile error (notes/contract-api.org §Panics): the least it
    /// can do is blame the line that wrote the literal.
    #[track_caller]
    pub fn constant(c: &mut Circuit3, v: u64) -> Self {
        assert!(
            BITS >= 64 || v >> BITS == 0,
            "{v} does not fit in Uint<{BITS}>"
        );
        Uint::from_field_unchecked(c.constant(v))
    }
}

/// Compact's `Uint<0..BOUND>` for an ARBITRARY bound: one native slot
/// holding a value strictly BELOW `BOUND`.
///
/// **`BOUND` IS EXCLUSIVE**, exactly as the Compact spelling is —
/// `BoundedUint<70000>` is `Uint<0..70000>`, the digits unchanged, so a port
/// cannot introduce an off-by-one and a reviewer reading side by side does
/// not have to do arithmetic. compactc says the same thing in its own words
/// when the bound is zero: "range end for Uint type is 0 but must be at
/// least 1 (the range end is exclusive)". The largest legal value is
/// therefore `BOUND - 1`, which is the `maxval` `contract-info.json`
/// publishes and the number [`Prim::unsigned`] takes
/// (notes/bounded-integers.org §0).
///
/// Why this is a SECOND leaf rather than a generalization of [`Uint`]:
/// `generic_const_exprs` is not available on this toolchain, so neither can
/// be an alias of the other, and `Uint<128>`'s bound (2^128) does not fit a
/// `u128` const parameter anyway. They coexist over the same wire, and the
/// two free conversions ([`BoundedUint::to_uint`], [`BoundedUint::widen`])
/// bridge them. Nothing in `Uint`'s code path changed to make room.
///
/// The lowering is NOT this type's opinion — [`Self::constrain_input`] hands
/// the maxval to compactc's own table, which answers `constrain_eq 0` /
/// `constrain_to_boolean` / `constrain_bits k` / `less_than + assert`
/// depending on the bound. `BoundedUint<256>` is therefore exactly
/// `constrain_bits 8`, the same as `Uint<8>`, because that is what compactc
/// emits for `Uint<0..256>`.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct BoundedUint<const BOUND: u128, V: Vis3 = Private>(Wire3<FieldT, V>);

impl<const BOUND: u128, V: Vis3> BoundedUint<BOUND, V> {
    /// The largest legal value: `BOUND - 1`, compactc's `maxval`.
    pub const MAX: u128 = BOUND - 1;

    /// An ASSERTION, not a check: the caller is CLAIMING `w` already holds a
    /// value below `BOUND`, and this emits nothing to verify it
    /// (notes/api-safety-survey.org §A1). Typical justification is a
    /// constrained circuit argument about to receive [`Self::constrain_input`],
    /// or the result of an operation this module already range-checked
    /// (`sub`, `narrow`, [`Uint::widen`]'s bridge). Getting the claim wrong is
    /// silent — everything built on this leaf's invariant rests on it holding.
    ///
    /// When the wire is NOT already known to satisfy the bound, use
    /// [`Self::from_field_checked`] instead.
    pub fn from_field_unchecked(w: Wire3<FieldT, V>) -> Self {
        const {
            assert!(
                BOUND >= 1,
                "range end for Uint type is 0 but must be at least 1 (the range end is \
                 exclusive) — compactc's own rule: `BoundedUint<BOUND>` is Compact's \
                 `Uint<0..BOUND>`, whose largest legal value is BOUND - 1"
            )
        };
        BoundedUint(w)
    }

    /// [`Self::from_field_unchecked`] immediately followed by
    /// [`Self::constrain_input`] — the CHECKED twin, for a wire that is not
    /// already known to hold a value below `BOUND`.
    ///
    /// Cost: exactly `constrain_input`'s constraint (whichever of its four
    /// cases the bound lands on). With `Circuit3::dedup_range_constraints`
    /// enabled, a redundant call is free.
    pub fn from_field_checked(c: &mut Circuit3, w: Wire3<FieldT, V>) -> Self {
        // The CONSTRAINED value comes back, not `w`: inside a `when` the two
        // differ (`select(guard, w, 0)` is what was checked, and what the
        // branch computes), and a checked leaf must carry the checked wire.
        Self::from_field_unchecked(w).constrain_input(c)
    }

    /// `x as Field` — the same slot, no instructions.
    pub fn field(self) -> Wire3<FieldT, V> {
        self.0
    }

    /// Range-constrain a `Uint<0..BOUND>` entering the circuit, exactly as
    /// compactc constrains its own — through the ONE table
    /// ([`Prim::constraint`]), so this and `CircuitArg::constrain` cannot
    /// say different things.
    ///
    /// What comes out depends on the bound, and every case is compactc's:
    /// `BOUND = 1` is `constrain_eq 0`, `BOUND = 2` is
    /// `constrain_to_boolean`, a `BOUND` of `2^k` is `constrain_bits k`,
    /// and anything else is `less_than v BOUND bits` + `assert` with
    /// compactc's even-rounded `bits`.
    pub fn constrain_input(self, c: &mut Circuit3) -> Self {
        Self(Prim::unsigned(Self::MAX).constraint().emit(c, self.0))
    }

    /// `x as Uint<0..BIGGER>` — the LOSSLESS widening, free in both senses
    /// ([`Uint::widen`]'s argument verbatim: a value below `BOUND` is below
    /// any larger bound by construction, so no instruction and no second
    /// range constraint).
    pub fn widen<const BIGGER: u128>(self) -> BoundedUint<BIGGER, V> {
        const {
            assert!(
                BIGGER >= BOUND,
                "`.widen::<B>()` only widens: B must be at least the source's BOUND. \
                 Narrowing needs a range check, so spell it out — \
                 `BoundedUint::<B>::from_field_checked(c, x.field())`, which is the \
                 cost made visible"
            )
        };
        BoundedUint::from_field_unchecked(self.0)
    }

    /// `x as Uint<BITS>` — the free bridge to the sized leaf, and with it to
    /// everything written against [`Uint`] (Borsh at a Borsh width, a
    /// comparison at `BITS`, a `LedgerCell<Uint<BITS>>`).
    ///
    /// Free for the same reason [`Self::widen`] is: a value below `BOUND` is
    /// below `2^BITS` when `2^BITS >= BOUND`, so the wider range is
    /// satisfied by construction and `constrain_bits(BITS)` would be a
    /// tautology costing ~BITS/4 rows.
    pub fn to_uint<const BITS: u32>(self) -> Uint<BITS, V> {
        const {
            assert!(
                BITS < 128 && (1u128 << BITS) >= BOUND,
                "`.to_uint::<BITS>()` needs 2^BITS >= BOUND, so that every value the \
                 bound allows is a BITS-bit value. A narrower BITS is a REAL narrowing: \
                 `.narrow::<BITS>(c)`, which emits the range check"
            )
        };
        Uint::from_field_unchecked(self.0)
    }

    /// `self + other`, with COMPACT'S MAX TRACKING — the bound of the result
    /// is a fact about the types, not a promise the author makes
    /// (notes/api-safety-survey.org §B2).
    ///
    /// compactc's rule (`infer-types.ss`, decoded in
    /// notes/builtin-lowering.org §9) is that `+` is a plain field `add`
    /// whose result type is `Uint<maxa + maxb>`, with **no overflow check at
    /// the op itself** — the check happens later, at the downcast. This is
    /// exactly that: ONE `add` instruction, no constraint, and the widened
    /// bound in the type where compactc keeps its `maxval`. The downcast is
    /// then [`Self::to_uint`] (free, when the bound fits) or
    /// [`Self::narrow`] (checked, when it does not).
    ///
    /// `OUT` IS NAMED BY THE CALLER because `generic_const_exprs` is not
    /// available on this toolchain — the compiler cannot write
    /// `BoundedUint<BOUND + BOUND2 - 1>` for us. What it can do is REJECT a
    /// bound that is too small, which is an inline-`const` assert here and so
    /// an `error[E0080]` at the call site:
    ///
    /// ```compile_fail
    /// # use minocrab::v3::{Circuit3, FieldT};
    /// # use minocrab_std::v3::BoundedUint;
    /// let mut c = Circuit3::new();
    /// let a = BoundedUint::<300>::from_field_unchecked(c.arg::<FieldT>("a"));
    /// let b = BoundedUint::<200>::from_field_unchecked(c.arg::<FieldT>("b"));
    /// // error[E0080]: `.add::<OUT>()` needs OUT >= BOUND + BOUND2 - 1 …
    /// let _ = a.add::<498, 200>(&mut c, b);
    /// ```
    ///
    /// `499` is accepted, and is the narrowest bound that is: the largest sum
    /// is `299 + 199 = 498`, and the bound is exclusive.
    ///
    /// The two bounds may DIFFER — an addition needs no common width, unlike
    /// [`Self::sub`], whose guard is a comparison.
    /// Both operands at the same visibility, as [`Uint::sub`]: mixing them is
    /// spelled by moving one with `.private()` first.
    pub fn add<const OUT: u128, const BOUND2: u128>(
        self,
        c: &mut Circuit3,
        other: BoundedUint<BOUND2, V>,
    ) -> BoundedUint<OUT, V>
    where
        V: Meet<V, Out = V>,
    {
        const {
            assert!(
                OUT >= sum_bound(BOUND, BOUND2),
                "`.add::<OUT>()` needs OUT >= BOUND + BOUND2 - 1: the largest sum is \
                 (BOUND - 1) + (BOUND2 - 1), and the bound is EXCLUSIVE, so one more \
                 than that is the narrowest type holding it. Name that bound at the \
                 call site — the addition emits no check, exactly as compactc's does \
                 not, so the type is the only thing tracking the max"
            )
        };
        BoundedUint::from_field_unchecked(c.add(self.field(), other.field()))
    }

    /// `self * other`, the same rule as [`Self::add`] with compactc's
    /// multiplicative max: result type `Uint<maxa · maxb>`, one `mul`
    /// instruction, no check at the op.
    ///
    /// `OUT` must be at least `(BOUND - 1) * (BOUND2 - 1) + 1`, and an
    /// `error[E0080]` says so otherwise:
    ///
    /// ```compile_fail
    /// # use minocrab::v3::{Circuit3, FieldT};
    /// # use minocrab_std::v3::BoundedUint;
    /// let mut c = Circuit3::new();
    /// let a = BoundedUint::<300>::from_field_unchecked(c.arg::<FieldT>("a"));
    /// let b = BoundedUint::<200>::from_field_unchecked(c.arg::<FieldT>("b"));
    /// // error[E0080]: `.mul::<OUT>()` needs OUT >= (BOUND - 1) * (BOUND2 - 1) + 1 …
    /// let _ = a.mul::<59_400, 200>(&mut c, b);
    /// ```
    ///
    /// (`299 * 199 = 59_501`, so `59_502` is the narrowest legal `OUT`.)
    ///
    /// A bound computation that OVERFLOWS a `u128` is itself a compile error
    /// (`bound_or_overflow`), not a wrap: a wrapped bound would accept an
    /// `OUT` the product cannot fit, which is the max tracking silently
    /// telling a lie. Compact refuses the analogous case in its own units —
    /// "error if result max > 2^248 − 1 (cast to Field)". Here that is:
    ///
    /// ```compile_fail
    /// # use minocrab::v3::{Circuit3, FieldT};
    /// # use minocrab_std::v3::BoundedUint;
    /// let mut c = Circuit3::new();
    /// let a = BoundedUint::<{ u128::MAX }>::from_field_unchecked(c.arg::<FieldT>("a"));
    /// let b = BoundedUint::<{ u128::MAX }>::from_field_unchecked(c.arg::<FieldT>("b"));
    /// // error[E0080]: the result's bound does not fit a u128 const parameter …
    /// let _ = a.mul::<{ u128::MAX }, { u128::MAX }>(&mut c, b);
    /// ```
    pub fn mul<const OUT: u128, const BOUND2: u128>(
        self,
        c: &mut Circuit3,
        other: BoundedUint<BOUND2, V>,
    ) -> BoundedUint<OUT, V>
    where
        V: Meet<V, Out = V>,
    {
        const {
            assert!(
                OUT >= product_bound(BOUND, BOUND2),
                "`.mul::<OUT>()` needs OUT >= (BOUND - 1) * (BOUND2 - 1) + 1: the \
                 largest product is of the two largest values, and the bound is \
                 EXCLUSIVE, so one more than that is the narrowest type holding it. \
                 Name that bound at the call site — the multiplication emits no \
                 check, exactly as compactc's does not"
            )
        };
        BoundedUint::from_field_unchecked(c.mul(self.field(), other.field()))
    }

    /// `self - other`, with COMPACT'S UNDERFLOW GUARD — [`Uint::sub`]'s
    /// method for a bounded operand, and the same lowering:
    /// `assert(a >= b)`, `neg(b)`, `add(a, neg)`, in that order, with the
    /// comparison at the BOUND's own width (`max(1, intlen(BOUND - 1))`,
    /// which is what the predicate layer reads off the type — not the
    /// even-rounded width the range constraint runs at).
    ///
    /// Why the underflow matters, in one line (notes/api-safety-survey.org
    /// §B1): field arithmetic has no sign, so `a - b` for `a < b` is
    /// `a - b + p`, a value near 2^255 — the balance-underflow bug, invisible
    /// to any differential on an honest preimage.
    ///
    /// BOTH BOUNDS ARE THE SAME, deliberately (dmd 2026-08-16, decision A
    /// reaffirmed): the guard is a COMPARISON, and a comparison needs one
    /// width, so a mixed-bound subtraction is spelled by widening the narrow
    /// side first — `a.sub(c, b.widen::<BOUND>())`, free for a value already
    /// range-constrained.
    ///
    /// The result keeps `BOUND`, which is compactc's rule (`Uint<maxa>`) and
    /// is sound because the guard has established `a - b <= a < BOUND`.
    pub fn sub(self, c: &mut Circuit3, other: BoundedUint<BOUND, V>) -> BoundedUint<BOUND, V>
    where
        V: Meet<V, Out = V>,
    {
        self.sub_with(c, other, "result of subtraction would be negative")
    }

    /// [`Self::sub`] with the caller's own message on the underflow guard.
    ///
    /// The message is METADATA — no instruction, no row — so this is the SAME
    /// lowering as [`Self::sub`], and a contract with a domain-specific
    /// message for its hand-written guard keeps it ([`Uint::sub_with`]'s
    /// argument verbatim).
    pub fn sub_with(
        self,
        c: &mut Circuit3,
        other: BoundedUint<BOUND, V>,
        message: &'static str,
    ) -> BoundedUint<BOUND, V>
    where
        V: Meet<V, Out = V>,
    {
        c.assert(crate::v3::predicate::ge(self, other).message(message));
        let negated = c.neg(other.field());
        BoundedUint::from_field_unchecked(c.add(self.field(), negated))
    }

    /// `x as Uint<BITS>` when the bound does NOT fit — the CHECKED
    /// narrowing.
    ///
    /// Emits exactly the range constraint compactc emits for a `Uint<BITS>`
    /// argument (`Prim::Uint { bits }`, so `constrain_bits BITS`, or
    /// `constrain_to_boolean` at `BITS = 1` — the ONE table, as
    /// [`Self::constrain_input`] uses), and nothing else. That is the whole
    /// cost, and it is visible: ~BITS/4 rows.
    ///
    /// This matches Compact's own downcast, which checks in EVERY position —
    /// `constrain_bits` straight-line, and a guarded
    /// `cond_select`/`less_than`/`assert` chain inside conditional branches
    /// (probe-verified under the pinned compactc and 0.34.0;
    /// notes/builtin-lowering.org §9, corrected 2026-08-28 — an earlier
    /// claim here that compactc omits the check in argument position was a
    /// mis-read of the artifacts, withdrawn in notes/compact-findings.org
    /// §1). What Compact's surface language CANNOT spell, and this API can,
    /// is the unchecked narrowing (`from_field_unchecked`): the value of
    /// `narrow`/`to_uint` is making the checked/free split an explicit
    /// choice a reviewer can read off the call site.
    ///
    /// For the FREE direction (`2^BITS >= BOUND`, where every legal value
    /// already fits and a constraint would be a tautology) this is an
    /// `error[E0080]` pointing at [`Self::to_uint`]:
    ///
    /// ```compile_fail
    /// # use minocrab::v3::{Circuit3, FieldT};
    /// # use minocrab_std::v3::BoundedUint;
    /// let mut c = Circuit3::new();
    /// let x = BoundedUint::<300>::from_field_unchecked(c.arg::<FieldT>("x"));
    /// // error[E0080]: `.narrow::<BITS>()` is the CHECKED narrowing … use `.to_uint`
    /// let _ = x.narrow::<9>(&mut c);
    /// ```
    ///
    /// so the two spellings partition the cases, and which one a call site
    /// uses says whether it paid.
    pub fn narrow<const BITS: u32>(self, c: &mut Circuit3) -> Uint<BITS, V> {
        const {
            assert!(
                BITS < 128 && (1u128 << BITS) < BOUND,
                "`.narrow::<BITS>()` is the CHECKED narrowing, for 2^BITS < BOUND — \
                 the case that needs a range check. Here every value the bound allows \
                 already fits BITS bits, so the check would be a tautology: use \
                 `.to_uint::<BITS>()`, which is free"
            )
        };
        let narrowed = Uint::<BITS, V>::from_field_unchecked(self.0);
        narrowed.constrain_input(c);
        narrowed
    }
}

/// The result bound of a tracked operation, or a COMPILE ERROR if it does not
/// fit a `u128` const parameter.
///
/// Wrapping would be the worst possible answer: a wrapped bound is a small
/// number, so it would accept an `OUT` the result cannot hold and the max
/// tracking would be quietly lying. compactc refuses the analogous case in
/// its own units — "error if result max > 2^248 − 1 (cast to Field)".
const fn bound_or_overflow(bound: Option<u128>) -> u128 {
    match bound {
        Some(bound) => bound,
        None => panic!(
            "the result's bound does not fit a u128 const parameter, so no OUT can be \
             wide enough: narrow an operand first with `.narrow::<BITS>(c)` (which \
             range-checks), or leave the tracked world with `.field()` and raw field \
             arithmetic"
        ),
    }
}

/// The narrowest bound holding every sum of a `Uint<0..A>` and a
/// `Uint<0..B>`: the largest sum is `(A - 1) + (B - 1)` and the bound is
/// exclusive, so `A + B - 1`.
const fn sum_bound(a: u128, b: u128) -> u128 {
    assert!(
        a >= 1 && b >= 1,
        "a bound of 0 admits no values at all (the range end is exclusive) — every \
         operand's BOUND must be at least 1"
    );
    bound_or_overflow(match (a - 1).checked_add(b - 1) {
        Some(max) => max.checked_add(1),
        None => None,
    })
}

/// The narrowest bound holding every product: `(A - 1) * (B - 1) + 1`.
const fn product_bound(a: u128, b: u128) -> u128 {
    assert!(
        a >= 1 && b >= 1,
        "a bound of 0 admits no values at all (the range end is exclusive) — every \
         operand's BOUND must be at least 1"
    );
    bound_or_overflow(match (a - 1).checked_mul(b - 1) {
        Some(max) => max.checked_add(1),
        None => None,
    })
}

impl<const BOUND: u128> BoundedUint<BOUND, Public> {
    /// A `Uint<0..BOUND>` constant from a native Rust value; panics at
    /// circuit-build time if `v` is not below `BOUND`.
    ///
    /// A PANIC and not a compile error, for the reason recorded in
    /// notes/contract-api.org §"Panics that could NOT become compile
    /// errors": the magnitude of a runtime integer is not in the type
    /// system. `#[track_caller]` so it at least names the line that wrote
    /// the literal rather than this function.
    #[track_caller]
    pub fn constant(c: &mut Circuit3, v: u128) -> Self {
        assert!(
            v < BOUND,
            "{v} is not a value of Uint<0..{BOUND}> (the range end is exclusive, so the \
             largest legal value is {})",
            BOUND - 1
        );
        let fr = Fr::from_le_bytes(&v.to_le_bytes()).expect("16 bytes fit the native field");
        BoundedUint::from_field_unchecked(c.constant(fr))
    }
}

/// Compact's `Boolean`: one native slot holding 0 or 1, `assert_boolean` on
/// entry, alignment atom `bytes 1`.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Bool<V: Vis3 = Private>(Wire3<FieldT, V>);

impl<V: Vis3> Bool<V> {
    /// An ASSERTION, not a check: the caller is CLAIMING `w` already holds 0
    /// or 1, and this emits nothing to verify it (notes/api-safety-survey.org
    /// §A1). Typical justification is a constrained circuit argument about to
    /// receive [`Self::constrain_input`], or the result of an operation this
    /// module already produced as boolean (`cond_select` of two booleans, a
    /// comparison's own output). Getting the claim wrong is silent.
    ///
    /// When the wire is NOT already known to be 0 or 1, use
    /// [`Self::from_field_checked`] instead.
    pub fn from_field_unchecked(w: Wire3<FieldT, V>) -> Self {
        Bool(w)
    }

    /// [`Self::from_field_unchecked`] immediately followed by
    /// [`Self::constrain_input`] — the CHECKED twin, for a wire that is not
    /// already known to be boolean.
    ///
    /// Cost: exactly `constrain_input`'s constraint (one `assert_boolean`).
    /// With `Circuit3::dedup_range_constraints` enabled, a redundant call is
    /// free.
    pub fn from_field_checked(c: &mut Circuit3, w: Wire3<FieldT, V>) -> Self {
        // The CONSTRAINED value comes back, not `w`: inside a `when` the two
        // differ (`select(guard, w, 0)` is what was checked, and what the
        // branch computes), and a checked leaf must carry the checked wire.
        Self::from_field_unchecked(w).constrain_input(c)
    }

    /// The underlying 0/1 wire — the same slot, no instructions.
    pub fn field(self) -> Wire3<FieldT, V> {
        self.0
    }

    /// Constrain a `Boolean` entering the circuit, as compactc does for
    /// every `tunsigned 1` slot.
    pub fn constrain_input(self, c: &mut Circuit3) -> Self {
        Self(Prim::Uint { bits: 1 }.constraint().emit(c, self.0))
    }
}

impl Bool<Public> {
    /// A `Boolean` constant from a native Rust `bool`.
    pub fn constant(c: &mut Circuit3, v: bool) -> Self {
        Bool(c.constant(u64::from(v)))
    }
}

/// Compact's `Bytes<N>` for `N <= 31`: one native slot holding the bytes
/// little-endian, `assert_bits(8N)` on entry, alignment atom `bytes N`.
/// Above 31 bytes a `Bytes<N>` no longer fits a slot — use [`B32`] at 32
/// and [`BytesN`] beyond.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Bytes<const N: usize, V: Vis3 = Private>(Wire3<FieldT, V>);

impl<const N: usize, V: Vis3> Bytes<N, V> {
    /// An ASSERTION, not a check: the caller is CLAIMING `w` already holds
    /// `N` little-endian bytes (`< 2^(8N)`), and this emits nothing to verify
    /// it (notes/api-safety-survey.org §A1). Typical justification is a
    /// constrained circuit argument about to receive
    /// [`Self::constrain_input`], or the result of an operation this module
    /// already range-checked. Getting the claim wrong is silent — the Borsh
    /// packing's injectivity rests on it holding.
    ///
    /// When the wire is NOT already known to satisfy the bound, use
    /// [`Self::from_field_checked`] instead.
    pub fn from_field_unchecked(w: Wire3<FieldT, V>) -> Self {
        const {
            assert!(
                N > 0 && N <= 31,
                "Bytes<N> here needs 0 < N <= 31 — use B32 at 32, BytesN above"
            )
        };
        Bytes(w)
    }

    /// [`Self::from_field_unchecked`] immediately followed by
    /// [`Self::constrain_input`] — the CHECKED twin, for a wire that is not
    /// already known to hold `N` in-range bytes.
    ///
    /// Cost: exactly `constrain_input`'s constraint (~`8N`/4 rows). With
    /// `Circuit3::dedup_range_constraints` enabled, a redundant call is free.
    pub fn from_field_checked(c: &mut Circuit3, w: Wire3<FieldT, V>) -> Self {
        // The CONSTRAINED value comes back, not `w`: inside a `when` the two
        // differ (`select(guard, w, 0)` is what was checked, and what the
        // branch computes), and a checked leaf must carry the checked wire.
        Self::from_field_unchecked(w).constrain_input(c)
    }

    /// The packed little-endian limb — the same slot, no instructions.
    pub fn field(self) -> Wire3<FieldT, V> {
        self.0
    }

    /// Constrain a `Bytes<N>` entering the circuit (`8N` bits), as compactc
    /// constrains a short byte-string argument.
    pub fn constrain_input(self, c: &mut Circuit3) -> Self {
        Self(Prim::Uint { bits: 8 * N as u32 }.constraint().emit(c, self.0))
    }
}

impl<const N: usize> Bytes<N, Public> {
    /// A `Bytes<N>` constant from native Rust bytes, `bytes[0]` least
    /// significant (the in-slot order of [`B32`]'s low limb).
    pub fn constant(c: &mut Circuit3, bytes: &[u8; N]) -> Self {
        Bytes::from_field_unchecked(c.constant(Fr::from_le_bytes(bytes).expect("N <= 31 bytes fit")))
    }
}

/// Compact's `Bytes<0>`: a value with NO slots and one zero-length FAB atom.
///
/// It exists because the Signet V1 vocabulary (`@sig-net/midnight` 0.24)
/// pins a record field to it (`respondSerializationSchema: Bytes<0>`) and a
/// circuit argument may be one (`serializedOutput: Bytes<0>`, the empty
/// output of a failed or unviable attestation). compactc gives it zero input
/// slots and zero limbs — the atom is in the alignment, nothing is in the
/// value — so a one-limb [`Bytes<N>`] cannot stand for it: it is its own type.
#[derive(Clone, Copy)]
pub struct Bytes0<V: Vis3 = Private>(std::marker::PhantomData<fn() -> V>);

impl<V: Vis3> Default for Bytes0<V> {
    fn default() -> Self {
        Bytes0(std::marker::PhantomData)
    }
}

impl<V: Vis3> Bytes0<V> {
    /// The one value there is.
    pub fn new() -> Self {
        Self::default()
    }

    /// The same (absent) value at the other visibility.
    pub fn private(self) -> Bytes0<Private> {
        Bytes0::default()
    }
}

/// A Compact-level `Bytes<32>`: the `[hi, lo]` native slot pair (hi = byte
/// 31, lo = bytes 0..30 little-endian).
#[derive(Clone, Copy)]
pub struct B32<V: Vis3> {
    pub hi: Wire3<FieldT, V>,
    pub lo: Wire3<FieldT, V>,
}

impl B32<Public> {
    /// `pad(32, s)` as a constant pair: the string's bytes occupy bytes
    /// 0.., the rest is zero (the stdlib pad builtin's layout, confirmed
    /// against compactc's inline literals, e.g. test-caller-contract
    /// initialise's `"signet-caller:deployer:"`).
    pub fn pad(c: &mut Circuit3, s: &str) -> B32<Public> {
        assert!(s.len() <= 32, "pad(32, ..) literal longer than 32 bytes");
        let mut bytes = [0u8; 32];
        bytes[..s.len()].copy_from_slice(s.as_bytes());
        B32 {
            hi: c.constant(Fr::from(u64::from(bytes[31]))),
            lo: c.constant(Fr::from_le_bytes(&bytes[..31]).expect("31 bytes fit")),
        }
    }
}

impl<V: Vis3> B32<V> {
    /// `bit ? a : b`, limbwise.
    pub fn cond_select(
        c: &mut Circuit3,
        bit: Wire3<FieldT, V>,
        a: &B32<V>,
        b: &B32<V>,
    ) -> B32<V> {
        B32 {
            hi: c.cond_select(bit, a.hi, b.hi),
            lo: c.cond_select(bit, a.lo, b.lo),
        }
    }
}

impl<V: Vis3> B32<V> {
    /// Forget that both limbs are public — [`Wire3::private`] for the pair,
    /// so a `Bytes<32>` crossing INTO a private computation (a hash preimage,
    /// a comparison against a witnessed value) need not be taken apart and
    /// rebuilt limb by limb at the call site. Zero instructions.
    pub fn private(self) -> B32<Private> {
        B32 {
            hi: self.hi.private(),
            lo: self.lo.private(),
        }
    }

    /// Constrain a `Bytes<32>` entering the circuit (8/248 bits).
    pub fn constrain_input(self, c: &mut Circuit3) -> Self {
        B32 {
            hi: Prim::Uint { bits: 8 }.constraint().emit(c, self.hi),
            lo: Prim::Uint { bits: 248 }.constraint().emit(c, self.lo),
        }
    }

    /// To the typed `Bytes<32>` value (instruction-boundary form).
    pub fn to_typed(self, c: &mut Circuit3) -> Wire3<Bytes32T, V> {
        c.bytes32_from_low_high(self.lo, self.hi)
    }

    /// From the typed `Bytes<32>` value.
    pub fn from_typed(c: &mut Circuit3, typed: Wire3<Bytes32T, V>) -> Self {
        let (lo, hi) = c.bytes32_into_low_high(typed);
        B32 { hi, lo }
    }
}

/// Declare a `Bytes<32>`-shaped newtype and its whole impl set — the M23 R2
/// sweep's machinery (notes/newtype-survey.org).
///
/// The problem it solves is stated there in one line: **every real
/// cross-assignment hazard in this codebase is a positional argument to an
/// ordinary `fn`, or a same-typed pair handed to a `LedgerMap` op**, and a
/// `Bytes<32>` is the shape that hazard keeps taking — a request id, a
/// secret key, an identity commitment, a refund commitment, a coin nonce, a
/// token domain separator and a coin colour are all `[hi, lo]` pairs, so
/// today they all type-check for each other.
///
/// **A newtype declared this way is provably zero-instruction and
/// snapshot-neutral**, because every impl DELEGATES:
///
/// - [`CircuitArg::declare`] reuses **the caller's [`ArgPath`] verbatim** —
///   no extra segment — so the declared labels stay `foo_hi`/`foo_lo` and
///   `interface_snapshot` cannot see the change. Modelling the newtype as
///   Compact's *struct* shape (`declare(c, &path.field("bytes"))`) would add
///   a `_bytes` segment and move that snapshot; this deliberately does not.
/// - No impl adds a `constrain_input` the site did not already have.
///   `CircuitArg::constrain` is a provided body over `push_prims`/
///   `push_slots`, so delegation gives the identical constraint sequence.
///
/// The precedent is [`ContractAddress`] below, hand-written in exactly this
/// shape; this macro is that impl set, once, in the idiom `select_via_field!`
/// and `ledger_repr_via_abi!` already use in this crate.
///
/// Exported (`minocrab_std::v3::b32_newtype`) because generated interface
/// crates invoke it: `minocrab-interface-gen` emits it for any Compact
/// `Alias` whose target is `Bytes<32>`, which is how `RequestId` stopped
/// being a `pub type` — a newtype with the safety removed.
///
/// ```
/// use minocrab_std::v3::b32_newtype;
///
/// b32_newtype! {
///     /// A protocol-meaningful 32-byte value.
///     Widget,
/// }
/// ```
#[macro_export]
macro_rules! b32_newtype {
    ($( $(#[$m:meta])* $name:ident ),* $(,)?) => {$(
        $(#[$m])*
        #[derive(Clone, Copy)]
        #[repr(transparent)]
        pub struct $name<V: $crate::v3::Vis3>(pub $crate::v3::B32<V>);

        impl<V: $crate::v3::Vis3> $name<V> {
            /// The underlying `Bytes<32>` — the same two slots, no
            /// instructions. The one way OUT of the newtype, so a `grep`
            /// for `.bytes()` finds every place the distinction is dropped.
            pub fn bytes(self) -> $crate::v3::B32<V> {
                self.0
            }

            /// The FAB limbs, `[hi, lo]`.
            pub fn limbs(self) -> [::minocrab::v3::Wire3<::minocrab::v3::FieldT, V>; 2] {
                [self.0.hi, self.0.lo]
            }

            /// From the `[hi, lo]` limbs a ledger read hands back.
            pub fn from_limbs(limbs: [::minocrab::v3::Wire3<::minocrab::v3::FieldT, V>; 2]) -> Self {
                $name($crate::v3::B32 { hi: limbs[0], lo: limbs[1] })
            }

            /// Forget that both limbs are public — [`B32::private`] for the
            /// pair. Zero instructions.
            pub fn private(self) -> $name<::minocrab::Private> {
                $name(self.0.private())
            }

            /// Constrain this value entering the circuit (8/248 bits) —
            /// [`B32::constrain_input`], delegated, so the emitted sequence
            /// is identical to the bare `Bytes<32>`'s.
            pub fn constrain_input(self, c: &mut ::minocrab::v3::Circuit3) -> Self {
                $name(self.0.constrain_input(c))
            }

            /// `bit ? a : b`, limbwise.
            pub fn cond_select(
                c: &mut ::minocrab::v3::Circuit3,
                bit: ::minocrab::v3::Wire3<::minocrab::v3::FieldT, V>,
                a: &Self,
                b: &Self,
            ) -> Self {
                $name($crate::v3::B32::cond_select(c, bit, &a.0, &b.0))
            }

            /// To the typed `Bytes<32>` value (instruction-boundary form).
            pub fn to_typed(
                self,
                c: &mut ::minocrab::v3::Circuit3,
            ) -> ::minocrab::v3::Wire3<::minocrab::v3::Bytes32T, V> {
                self.0.to_typed(c)
            }

            /// From the typed `Bytes<32>` value — what a hash result is
            /// wrapped with, and the point at which a digest becomes THIS
            /// protocol value rather than any other 32-byte one.
            pub fn from_typed(
                c: &mut ::minocrab::v3::Circuit3,
                typed: ::minocrab::v3::Wire3<::minocrab::v3::Bytes32T, V>,
            ) -> Self {
                $name($crate::v3::B32::from_typed(c, typed))
            }
        }

        /// A struct of one `Bytes<32>`, which flattens to exactly that
        /// `Bytes<32>`'s slots.
        impl<V: $crate::v3::Vis3> ::minocrab::v3::CircuitAbi for $name<V> {
            const SLOTS: usize = <$crate::v3::B32<V> as ::minocrab::v3::CircuitAbi>::SLOTS;

            fn push_atoms(atoms: &mut Vec<::minocrab::AlignmentAtom>) {
                <$crate::v3::B32<V> as ::minocrab::v3::CircuitAbi>::push_atoms(atoms);
            }

            fn push_prims(prims: &mut Vec<::minocrab::v3::Prim>) {
                <$crate::v3::B32<V> as ::minocrab::v3::CircuitAbi>::push_prims(prims);
            }
        }

        impl $crate::v3::CircuitArg for $name<::minocrab::Private> {
            fn declare(c: &mut ::minocrab::v3::Circuit3, path: &$crate::v3::ArgPath) -> Self {
                // THE CALLER'S PATH, VERBATIM — see the macro's docs.
                $name(<$crate::v3::B32<::minocrab::Private> as $crate::v3::CircuitArg>::declare(c, path))
            }

            fn push_slots(
                &self,
                slots: &mut Vec<::minocrab::v3::Wire3<::minocrab::v3::FieldT, ::minocrab::Private>>,
            ) {
                $crate::v3::CircuitArg::push_slots(&self.0, slots)
            }
        }

        impl ::minocrab::v3::CallArg for $name<::minocrab::Public> {
            fn push_call_slots(
                &self,
                slots: &mut Vec<::minocrab::v3::Wire3<::minocrab::v3::FieldT, ::minocrab::Public>>,
            ) {
                ::minocrab::v3::CallArg::push_call_slots(&self.0, slots)
            }
        }

        impl ::minocrab::v3::CallResult for $name<::minocrab::Public> {
            fn from_call_slots(
                slots: &[::minocrab::v3::Wire3<::minocrab::v3::FieldT, ::minocrab::Public>],
            ) -> Self {
                $name(<$crate::v3::B32<::minocrab::Public> as ::minocrab::v3::CallResult>::from_call_slots(slots))
            }
        }

        impl $crate::v3::CircuitOut for $name<::minocrab::Public> {
            const SLOTS: usize = <$crate::v3::B32<::minocrab::Public> as $crate::v3::CircuitOut>::SLOTS;

            fn emit(self, c: &mut ::minocrab::v3::Circuit3, label: &str) {
                $crate::v3::CircuitOut::emit(self.0, c, label)
            }
        }

        impl ::minocrab::v3::Disclose for $name<::minocrab::Private> {
            type Public = $name<::minocrab::Public>;

            fn disclose_as<L: ::minocrab::v3::DisclosureLabel>(
                self,
                c: &mut ::minocrab::v3::Circuit3,
            ) -> $name<::minocrab::Public> {
                $name(::minocrab::v3::Disclose::disclose_as::<L>(self.0, c))
            }
        }

        /// Two slots — the `[hi, lo]` pair, the same cost the bare
        /// `Bytes<32>` has.
        impl<V: $crate::v3::Vis3> ::minocrab::v3::Select<V> for $name<V> {
            fn select(
                c: &mut ::minocrab::v3::Circuit3,
                bit: ::minocrab::v3::Wire3<::minocrab::v3::FieldT, V>,
                a: Self,
                b: Self,
            ) -> Self {
                $name(::minocrab::v3::Select::select(c, bit, a.0, b.0))
            }
        }

        impl $crate::v3::ProofWires for $name<::minocrab::Public> {
            fn push_wires(&self, out: &mut Vec<::minocrab::v3::Val>) {
                $crate::v3::ProofWires::push_wires(&self.0, out)
            }
        }

        /// In a ledger slot: pure delegation to the ABI traits, the same
        /// path `ledger_repr_via_abi!` takes for every leaf.
        impl $crate::v3::LedgerRepr for $name<::minocrab::Public> {
            fn atoms() -> Vec<::minocrab::AlignmentAtom> {
                <Self as ::minocrab::v3::CircuitAbi>::atoms()
            }

            fn push_limbs(
                &self,
                _c: &mut ::minocrab::v3::Circuit3,
                limbs: &mut Vec<::minocrab::v3::Wire3<::minocrab::v3::FieldT, ::minocrab::Public>>,
            ) {
                ::minocrab::v3::CallArg::push_call_slots(self, limbs)
            }

            #[track_caller]
            fn from_limbs(
                limbs: Vec<::minocrab::v3::Wire3<::minocrab::v3::FieldT, ::minocrab::Public>>,
            ) -> Self {
                debug_assert_eq!(
                    limbs.len(),
                    <Self as ::minocrab::v3::CircuitAbi>::SLOTS,
                    "ledger read handed back the wrong number of limbs"
                );
                <Self as ::minocrab::v3::CallResult>::from_call_slots(&limbs)
            }
        }

        /// Borsh: one 32-byte atom over the `[hi, lo]` slot pair —
        /// [`B32`]'s encoding, delegated, so a newtype in a preimage hashes
        /// exactly the bytes the bare `Bytes<32>` did.
        impl<V: $crate::v3::Vis3> $crate::v3::borsh::CircuitBorsh<V> for $name<V> {
            const LEN: usize = <$crate::v3::B32<V> as $crate::v3::borsh::CircuitBorsh<V>>::LEN;

            fn push_limbs(&self, limbs: &mut $crate::v3::borsh::Limbs<V>) {
                $crate::v3::borsh::CircuitBorsh::push_limbs(&self.0, limbs)
            }

            fn push_segments(&self, out: &mut $crate::v3::Serializer<V>) {
                $crate::v3::borsh::CircuitBorsh::push_segments(&self.0, out)
            }

            fn constrain_canonical(&self, c: &mut ::minocrab::v3::Circuit3) {
                $crate::v3::borsh::CircuitBorsh::constrain_canonical(&self.0, c)
            }

            fn read<R: $crate::v3::borsh::BorshReader<V>>(
                c: &mut ::minocrab::v3::Circuit3,
                r: &mut R,
            ) -> Self {
                $name(<$crate::v3::B32<V> as $crate::v3::borsh::CircuitBorsh<V>>::read(c, r))
            }

            fn push_layout(
                path: &$crate::v3::borsh::LayoutPath,
                offset: &mut usize,
                out: &mut Vec<$crate::v3::borsh::FieldSpec>,
            ) {
                <$crate::v3::B32<V> as $crate::v3::borsh::CircuitBorsh<V>>::push_layout(path, offset, out)
            }
        }
    )*};
}

/// The R2 sweep's declarative newtype constructor — see its own docs.
/// Re-exported under `v3` so a generated interface crate's single
/// `use minocrab_std::v3::…` line brings it in with everything else.
pub use crate::b32_newtype;

/// Compact's `ContractAddress` — a struct of one `Bytes<32>`, and the type
/// every cross-contract call names its target with (164 occurrences in the
/// corpus). A newtype rather than a bare [`B32`] because a contract address
/// and a hash are not interchangeable, and the interface layer's whole job
/// is to stop them being passed for each other.
///
/// Its FAB shape IS the inner `Bytes<32>`'s: Compact structs flatten, so a
/// `ContractAddress` argument is the same two slots a `Bytes<32>` argument
/// is (which is why the ported circuits' hand-written `B32` reads are
/// unchanged by its introduction).
#[derive(Clone, Copy)]
pub struct ContractAddress<V: Vis3>(pub B32<V>);

impl<V: Vis3> ContractAddress<V> {
    /// The address's FAB limbs, `[hi, lo]`.
    pub fn limbs(self) -> [Wire3<FieldT, V>; 2] {
        [self.0.hi, self.0.lo]
    }

    /// From the `[hi, lo]` limbs a ledger read or `kernel.self()` hands back.
    pub fn from_limbs(limbs: [Wire3<FieldT, V>; 2]) -> Self {
        ContractAddress(B32 {
            hi: limbs[0],
            lo: limbs[1],
        })
    }

    /// The underlying `Bytes<32>`.
    pub fn bytes(self) -> B32<V> {
        self.0
    }

    /// Forget that both limbs are public — [`B32::private`] for the pair.
    /// Zero instructions.
    pub fn private(self) -> ContractAddress<Private> {
        ContractAddress(self.0.private())
    }
}

/// Compact's `UserAddress` — a struct of one `Bytes<32>`, and the non-contract
/// half of an [`UnshieldedRecipient`](kernel::UnshieldedRecipient).
///
/// The twin of [`ContractAddress`] in every respect including its FAB shape,
/// and a separate type for the same reason: a user and a contract are not
/// interchangeable recipients, and `Either<ContractAddress, UserAddress>`
/// would say nothing if both arms were the same type.
#[derive(Clone, Copy)]
pub struct UserAddress<V: Vis3>(pub B32<V>);

impl<V: Vis3> UserAddress<V> {
    /// The address's FAB limbs, `[hi, lo]`.
    pub fn limbs(self) -> [Wire3<FieldT, V>; 2] {
        [self.0.hi, self.0.lo]
    }

    /// From the `[hi, lo]` limbs a ledger read hands back.
    pub fn from_limbs(limbs: [Wire3<FieldT, V>; 2]) -> Self {
        UserAddress(B32 {
            hi: limbs[0],
            lo: limbs[1],
        })
    }

    /// The underlying `Bytes<32>`.
    pub fn bytes(self) -> B32<V> {
        self.0
    }
}

b32_newtype! {
    /// Compact's `ZswapCoinPublicKey` — a struct of one `Bytes<32>`, and the
    /// SHIELDED half of a coin recipient (`Either<ZswapCoinPublicKey,
    /// ContractAddress>`, [`CoinRecipient`]).
    ///
    /// The third leaf of this shape after [`ContractAddress`] and
    /// [`UserAddress`], and separate from both for the reason they are
    /// separate from each other: a zswap public key is a user's spending
    /// key, not an address, and an `Either` whose arms were the same type
    /// would say nothing. Adopted THROUGH the recipient plumbing by
    /// newtype-survey A8: [`own_public_key`] returns one and
    /// [`CoinRecipient`]'s arms carry their own types, so a recipient built
    /// with a contract address in the key arm — a coin minted to a wallet
    /// key nobody holds — no longer compiles.
    ZswapCoinPublicKey,
}

/// Compact's `MerkleTreeDigest` — a struct of one `Field`, and the argument
/// of [`LedgerMerkleTree::check_root`](crate::v3::LedgerMerkleTree::check_root).
///
/// The one type in the stdlib whose ABI is `Prim::Field`: an UNCONSTRAINED
/// native slot (the fixture's `mtCheckRoot` takes `%r.0` with no
/// `constrain_bits`, and pushes it under a `field` atom). `Prim::Field` is in
/// the ABI table and this is the one typed leaf that reaches it.
///
/// Deliberately a NAMED type rather than a bare `Field` leaf. A digest is the
/// only unconstrained-field value a contract has a reason to accept from
/// outside — a root it is about to compare against the tree's — and naming it
/// keeps "an unconstrained field argument" from becoming an idiom
/// (notes/ledger-adts.org §3).
///
/// Compact's `merkleTreePathRoot` family is the proof side of Merkle
/// membership (a root computed from a path); this is the LEDGER side, which
/// asks the tree whether a root is one it has had.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct MerkleTreeDigest<V: Vis3 = Private>(Wire3<FieldT, V>);

impl<V: Vis3> MerkleTreeDigest<V> {
    /// Wrap a wire holding a digest (a circuit argument, a computed root).
    ///
    /// Named `_unchecked` for the same reason every other leaf's
    /// constructor is (notes/api-safety-survey.org §A1): it is the caller
    /// CLAIMING the wire holds a digest, not a check. Unlike the other v3
    /// leaves there is no `from_field_checked` twin, because there is
    /// nothing to constrain — this type's whole point is that it is the ONE
    /// leaf with an unconstrained native slot (see the type's docs,
    /// `Prim::Field`), so `constrain_input` does not exist here to delegate
    /// to.
    pub fn from_field_unchecked(w: Wire3<FieldT, V>) -> Self {
        MerkleTreeDigest(w)
    }

    /// The digest wire — the same slot, no instructions.
    pub fn field(self) -> Wire3<FieldT, V> {
        self.0
    }
}

/// [`Select`] for the typed leaves, so a value-producing conditional works on
/// whatever a branch actually returns.
///
/// Each is one `cond_select` per NATIVE SLOT — one for a scalar leaf, two for
/// a `Bytes<32>`, and a `Maybe` selects its tag as well as its payload. The
/// per-slot cost is the honest one: there is no cheaper way to choose between
/// two values in a circuit that does not branch.
macro_rules! select_via_field {
    ($( $(#[$m:meta])* [$($gen:tt)*] $ty:ty => |$c:ident, $bit:ident, $a:ident, $b:ident| $body:expr ),* $(,)?) => {$(
        $(#[$m])*
        impl<$($gen)*> Select<V> for $ty {
            fn select($c: &mut Circuit3, $bit: Wire3<FieldT, V>, $a: Self, $b: Self) -> Self {
                $body
            }
        }
    )*};
}

select_via_field! {
    [V: Vis3] Bool<V> => |c, bit, a, b| Bool::from_field_unchecked(c.cond_select(bit, a.field(), b.field())),
    [const BITS: u32, V: Vis3] Uint<BITS, V> =>
        |c, bit, a, b| Uint::from_field_unchecked(c.cond_select(bit, a.field(), b.field())),
    [const N: usize, V: Vis3] Bytes<N, V> =>
        |c, bit, a, b| Bytes::from_field_unchecked(c.cond_select(bit, a.field(), b.field())),
    /// Two slots — the `[hi, lo]` pair.
    [V: Vis3] B32<V> => |c, bit, a, b| B32 {
        hi: c.cond_select(bit, a.hi, b.hi),
        lo: c.cond_select(bit, a.lo, b.lo),
    },
    /// The address's inner `Bytes<32>`.
    [V: Vis3] ContractAddress<V> =>
        |c, bit, a, b| ContractAddress(Select::select(c, bit, a.0, b.0)),
    [V: Vis3] UserAddress<V> => |c, bit, a, b| UserAddress(Select::select(c, bit, a.0, b.0)),
    /// The TAG is selected too — a `Maybe` chosen from two branches takes the
    /// chosen branch's `is_some`, not either one's.
    [T: Select<V>, V: Vis3] Maybe<T, V> => |c, bit, a, b| Maybe {
        is_some: Select::select(c, bit, a.is_some, b.is_some),
        value: Select::select(c, bit, a.value, b.value),
    },
}

/// [`Select`] with a PUBLIC bit over PRIVATE leaves — what a `when_value`
/// over private data is, since a scope's condition must be an
/// `OnChainGuard`. Each delegates to the leaf's own `Select<Private>` with
/// the bit demoted, so the instruction is the same `cond_select`; the
/// result stays private. See `Select<Public> for Wire3<FieldT, Private>`.
macro_rules! select_public_over_private {
    ($( [$($gen:tt)*] $ty:ty ),* $(,)?) => {$(
        impl<$($gen)*> Select<Public> for $ty {
            fn select(c: &mut Circuit3, bit: Wire3<FieldT, Public>, a: Self, b: Self) -> Self {
                <Self as Select<Private>>::select(c, bit.private(), a, b)
            }
        }
    )*};
}

select_public_over_private! {
    [] Bool<Private>,
    [const BITS: u32] Uint<BITS, Private>,
    [const N: usize] Bytes<N, Private>,
    [] B32<Private>,
    [] ContractAddress<Private>,
    [] UserAddress<Private>,
    [T: Select<Private>] Maybe<T, Private>,
}

/// Explode a limb into `nbytes` byte wires, least-significant first: a
/// chain of `div_mod_power_of_two(_, 8)` where each remainder is a byte and
/// the final quotient is the last byte (compactc's `bytes->vector` shape).
pub fn explode_limb<V: Vis3>(
    c: &mut Circuit3,
    limb: Wire3<FieldT, V>,
    nbytes: usize,
) -> Vec<Wire3<FieldT, V>> {
    let mut bytes = Vec::with_capacity(nbytes);
    let mut acc = limb;
    for _ in 0..nbytes - 1 {
        let (quotient, byte) = c.div_mod_power_of_two(acc, 8);
        bytes.push(byte);
        acc = quotient;
    }
    bytes.push(acc);
    bytes
}

/// Rebuild a limb from byte wires (least-significant first): a right-fold
/// of `reconstitute_field(rest, byte, 8)` (compactc's `vector->bytes`).
pub fn rebuild_limb<V: Vis3>(c: &mut Circuit3, bytes: &[Wire3<FieldT, V>]) -> Wire3<FieldT, V> {
    let mut acc = *bytes.last().expect("at least one byte");
    for &byte in bytes[..bytes.len() - 1].iter().rev() {
        acc = c.reconstitute_field(acc, byte, 8);
    }
    acc
}

/// `Bytes<32> as Vector<32, Uint<8>>`: bytes 0..30 from the low limb, byte
/// 31 is the high limb directly.
pub fn b32_to_bytes<V: Vis3>(c: &mut Circuit3, b: &B32<V>) -> Vec<Wire3<FieldT, V>> {
    let mut bytes = explode_limb(c, b.lo, 31);
    bytes.push(b.hi);
    bytes
}

/// `Vector<32, Uint<8>> as Bytes<32>` (`v[0]` least significant).
pub fn bytes_to_b32<V: Vis3>(c: &mut Circuit3, bytes: &[Wire3<FieldT, V>]) -> B32<V> {
    assert_eq!(bytes.len(), 32);
    B32 {
        lo: rebuild_limb(c, &bytes[..31]),
        hi: bytes[31],
    }
}

// ---- Bytes<N>, N > 31 -------------------------------------------------------
//
// FAB slot order for a `Bytes<len>`: a leftover limb of `len mod 31` bytes
// (the most significant bytes) followed by 31-byte limbs down to the least
// significant. Confirmed against the attest corpus artifact: `Bytes<128>` =
// 5 limbs of 4+31+31+31+31 bytes, input-constrained 32/248/248/248/248 bits.
//
// The limbing rule lives in exactly one place — [`limb_len`] — which both
// the const-generic [`BytesN`] and the runtime-sized [`BytesNDyn`] use.

/// Bytes in limb `i` of a `Bytes<len>`, slot order: limb 0 is the leftover
/// (most significant) chunk, every other limb is a full 31 bytes.
const fn limb_len(len: usize, i: usize) -> usize {
    if i == 0 {
        match len % 31 {
            0 => 31,
            leftover => leftover,
        }
    } else {
        31
    }
}

/// The FAB limb count of a `Bytes<len>` — the limbing rule as a `const fn`,
/// so layouts that embed a `Bytes<len>` field ([`BytesN::LIMBS`], the Signet
/// event record) derive their widths from it instead of counting by hand.
pub const fn bytes_limbs(len: usize) -> usize {
    len.div_ceil(31)
}

/// Bytes per limb of a `Bytes<len>`, slot order.
fn limb_lens(len: usize) -> Vec<usize> {
    assert!(len > 31, "use B32 / a single limb for short byte strings");
    (0..len.div_ceil(31)).map(|i| limb_len(len, i)).collect()
}

/// A Compact-level `Bytes<N>` for `N > 31`, its size in the type.
///
/// Vec-backed rather than `[_; N.div_ceil(31)]` because that array length
/// needs `generic_const_exprs`; [`Self::LIMBS`] is the const width and
/// every constructor asserts the invariant `limbs.len() == LIMBS`.
#[derive(Clone)]
pub struct BytesN<V: Vis3, const N: usize> {
    /// Invariant: `limbs.len() == Self::LIMBS`; `limbs[0]` is the leftover
    /// (most significant) chunk.
    limbs: Vec<Wire3<FieldT, V>>,
}

impl<V: Vis3, const N: usize> BytesN<V, N> {
    /// The FAB limb count.
    pub const LIMBS: usize = bytes_limbs(N);

    /// Bytes in limb `i`, slot order (limb 0 is the leftover chunk).
    pub const fn limb_len(i: usize) -> usize {
        limb_len(N, i)
    }

    /// Wrap existing limb wires (leftover chunk first).
    pub fn from_limbs(limbs: Vec<Wire3<FieldT, V>>) -> Self {
        const { assert!(N > 31, "Bytes<N> here needs N > 31 — use B32 below that") };
        assert_eq!(limbs.len(), Self::LIMBS, "Bytes<{N}> takes {} limbs", Self::LIMBS);
        BytesN { limbs }
    }

    /// Slot order: `limbs()[0]` = the leftover (most significant) bytes.
    pub fn limbs(&self) -> &[Wire3<FieldT, V>] {
        &self.limbs
    }

    /// Rebuild the same `Bytes<N>` from a per-limb wire transform (the
    /// disclose loops) — limbs visited in slot order.
    pub fn map_limbs<W: Vis3>(
        &self,
        mut f: impl FnMut(usize, Wire3<FieldT, V>) -> Wire3<FieldT, W>,
    ) -> BytesN<W, N> {
        BytesN::from_limbs(self.limbs.iter().enumerate().map(|(i, &w)| f(i, w)).collect())
    }

    /// The FAB atoms of a `Bytes<N>` field.
    pub fn atoms() -> Vec<AlignmentAtom> {
        vec![AlignmentAtom::Bytes { length: N as u32 }]
    }

    /// The alignment of a lone `Bytes<N>` value.
    pub fn alignment() -> Alignment {
        Alignment(Self::atoms().into_iter().map(AlignmentSegment::Atom).collect())
    }

    /// A `Bytes<N>` literal as constant limbs — bytes given in string
    /// order (byte 0 first), packed into FAB slot order.
    pub fn literal(c: &mut Circuit3, bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), N, "Bytes<{N}> literal length");
        Self::from_limbs(bytes_literal_limbs(c, bytes))
    }

    /// Constrain a `Bytes<N>` entering the circuit (8·leftover bits, then
    /// 248 per full limb).
    pub fn constrain_input(&self, c: &mut Circuit3) {
        for (limb, nbytes) in self.limbs.iter().zip(limb_lens(N)) {
            Prim::Uint { bits: 8 * nbytes as u32 }.constraint().emit(c, *limb);
        }
    }

    /// All `N` bytes as wires, least-significant first (byte 0 first) —
    /// the limbs exploded in reverse slot order.
    pub fn to_le_bytes(&self, c: &mut Circuit3) -> Vec<Wire3<FieldT, V>> {
        let mut bytes = Vec::with_capacity(N);
        for (limb, nbytes) in self.limbs.iter().zip(limb_lens(N)).rev() {
            bytes.extend(explode_limb(c, *limb, nbytes));
        }
        bytes
    }

    /// Rebuild from byte wires (byte 0 first): 31-byte chunks from the
    /// front, the leftover chunk becoming limb 0.
    pub fn from_le_bytes(c: &mut Circuit3, bytes: &[Wire3<FieldT, V>]) -> Self {
        assert_eq!(bytes.len(), N, "Bytes<{N}> takes {N} bytes");
        let mut limbs: Vec<Wire3<FieldT, V>> = bytes
            .chunks(31)
            .map(|chunk| rebuild_limb(c, chunk))
            .collect();
        limbs.reverse();
        Self::from_limbs(limbs)
    }
}

impl<const N: usize> BytesN<Private, N> {
    /// Declare a `Bytes<N>` circuit argument as the limb arguments
    /// `{label}_0 ..= {label}_{LIMBS-1}`, in slot order.
    pub fn arg(c: &mut Circuit3, label: &str) -> Self {
        Self::from_limbs((0..Self::LIMBS).map(|i| c.arg(&format!("{label}_{i}"))).collect())
    }
}

impl<V: Vis3> From<B32<V>> for BytesN<V, 32> {
    /// `Bytes<32>` limbed as a `Bytes<N>`: the leftover chunk is byte 31
    /// (`hi`), the full limb is bytes 0..30 (`lo`).
    fn from(b: B32<V>) -> Self {
        BytesN::from_limbs(vec![b.hi, b.lo])
    }
}

impl<V: Vis3> BytesN<V, 32> {
    pub fn to_b32(&self) -> B32<V> {
        B32 { hi: self.limbs[0], lo: self.limbs[1] }
    }
}

/// A `Bytes<len>` whose length is only known at runtime — the hash-cost
/// experiments sweep `len` as test-harness data, and the Signet event's
/// deserialization schemas differ in length per instantiation. Everything
/// with a compile-time size uses [`BytesN`] instead.
#[derive(Clone)]
pub struct BytesNDyn<V: Vis3> {
    len: usize,
    /// Slot order: `limbs[0]` = the leftover (most significant) bytes.
    pub limbs: Vec<Wire3<FieldT, V>>,
}

impl<V: Vis3> BytesNDyn<V> {
    pub fn new(len: usize, limbs: Vec<Wire3<FieldT, V>>) -> BytesNDyn<V> {
        assert_eq!(limbs.len(), limb_lens(len).len(), "Bytes<{len}> limb count");
        BytesNDyn { len, limbs }
    }

    /// A `Bytes<len>` literal as constant limbs — bytes given in string
    /// order (byte 0 first), packed into FAB slot order; `len` is the
    /// literal's own length.
    pub fn literal(c: &mut Circuit3, bytes: &[u8]) -> BytesNDyn<V> {
        BytesNDyn::new(bytes.len(), bytes_literal_limbs(c, bytes))
    }

    /// Constrain a `Bytes<len>` entering the circuit (8·leftover bits,
    /// then 248 per full limb).
    pub fn constrain_input(&self, c: &mut Circuit3) {
        for (limb, nbytes) in self.limbs.iter().zip(limb_lens(self.len)) {
            Prim::Uint { bits: 8 * nbytes as u32 }.constraint().emit(c, *limb);
        }
    }
}

/// The constant limbs of a byte-string literal (byte 0 first in), FAB slot
/// order out.
///
/// Public because the limbing rule has to live in ONE place and a
/// `Bytes<N>`-shaped type outside this module needs it: the Signet record's
/// output-deserialization schema is a byte literal of any width at all
/// (`signet_v1::SchemaLiteral`), below and above the 31-byte limb.
pub fn bytes_literal_limbs<V: Vis3>(c: &mut Circuit3, bytes: &[u8]) -> Vec<Wire3<FieldT, V>> {
    let mut limbs: Vec<Wire3<FieldT, V>> = bytes
        .chunks(31)
        .map(|chunk| V::from_public(c.constant(Fr::from_le_bytes(chunk).expect("≤31 bytes fit"))))
        .collect();
    limbs.reverse();
    limbs
}

/// `serialize<T, N>` (compiler/analysis-passes/expand-serialize.ss):
/// value-only FAB binary, fields concatenated in declaration order,
/// zero-padded to N.
///
/// Fields are kept as `(wire, byte-length)` segments in string order and
/// re-limbed at [`Serializer::finish`]: a segment straddling an output
/// 31-byte limb boundary is split with ONE `div_mod` at the boundary,
/// everything else is constant-weight mul/add packing — instead of the
/// Compact-stdlib shape (explode every field to bytes, reconstitute every
/// output limb), which costs ~150 rows per exploded byte.
///
/// PRECONDITION, on [`Serializer::new`]: every pushed wire must already be
/// constrained to its byte length (circuit arguments via
/// `constrain_input`/`assert_bits`, typed-conversion limbs by their
/// instruction, literals by construction) — the limb packing is only
/// injective for in-range segments, and a packing that is not injective is
/// a digest that binds nothing.
///
/// [`Serializer::constrained`] DISCHARGES that obligation instead of stating
/// it: it emits each segment's own `constrain_bits` at `8·len` before
/// packing, so the caller can no longer forget. It is the entry point to
/// reach for; `new` stays because the shipped circuits' segments are
/// arguments already constrained at entry, and because the constraints only
/// become free with `Circuit3::dedup_range_constraints` on — which no
/// shipped artifact turns on (notes/ir-passes.org §11, api-safety-survey
/// §B3).
pub struct Serializer<V: Vis3> {
    /// Fields in string order; each wire packs its bytes LE.
    segments: Vec<Segment<V>>,
    /// Set by [`Serializer::constrained`]: emit the segments' range
    /// constraints at `finish` rather than trusting the caller for them.
    constrained: bool,
}

/// One pushed field: the wire, its byte length, and whether this
/// [`Serializer`] built it itself as a constant.
struct Segment<V: Vis3> {
    wire: Wire3<FieldT, V>,
    len: usize,
    /// A literal limb is in range BY CONSTRUCTION (it is `Fr::from_le_bytes`
    /// of its own `len` bytes), so the constrained mode does not re-prove
    /// it — and must not: after the immediate-copy fold the constraint's
    /// operand is an immediate, which no pass can dedup away again.
    literal: bool,
}

impl<V: Vis3> Serializer<V> {
    pub fn new() -> Serializer<V> {
        Serializer { segments: Vec::new(), constrained: false }
    }

    /// A [`Serializer`] that PROVES its own precondition: `finish` emits
    /// `constrain_bits(wire, 8·len)` for every pushed field before packing
    /// it, so the injectivity of the packing does not rest on the caller.
    ///
    /// It is a mode of the whole serializer rather than a checked twin of
    /// each `push_*`, for two reasons. The precondition is about EVERY
    /// segment — a packing with three of four fields constrained is as
    /// non-injective as one with none — so partial checking would discharge
    /// nothing while looking like it did. And the pushes come from
    /// `CircuitBorsh::push_segments`, including the derived ones, which
    /// cannot pass a checked spelling through: as a mode, every existing
    /// impl becomes checked without changing a line of it.
    ///
    /// THE COST IS ZERO WHERE THE WIRES WERE ALREADY CONSTRAINED, and only
    /// there: the added constraints are exact duplicates of the caller's, so
    /// `Circuit3::dedup_range_constraints` removes precisely them
    /// (`tests/v3_dedup.rs` proves the two circuits are byte-identical
    /// ZKIR). With the flag off they are two rows each — real, and the
    /// price of the check.
    pub fn constrained() -> Serializer<V> {
        Serializer { segments: Vec::new(), constrained: true }
    }

    /// A `Uint` field: `nbytes` LE bytes (Boolean = 1 byte).
    pub fn push_uint(&mut self, value: Wire3<FieldT, V>, nbytes: usize) {
        assert!(nbytes <= 31, "Uint fields fit one limb");
        self.push(value, nbytes);
    }

    /// A `Bytes<32>` field.
    pub fn push_b32(&mut self, value: &B32<V>) {
        self.push(value.lo, 31);
        self.push(value.hi, 1);
    }

    /// A `Bytes<M>` field (M > 31), limbs taken as segments directly.
    pub fn push_bytes_n<const M: usize>(&mut self, value: &BytesN<V, M>) {
        for (limb, nbytes) in value.limbs().iter().zip(limb_lens(M)).rev() {
            self.push(*limb, nbytes);
        }
    }

    /// A literal byte string, packed into constant segments.
    pub fn push_literal(&mut self, c: &mut Circuit3, bytes: &[u8]) {
        for chunk in bytes.chunks(31) {
            let limb = V::from_public(
                c.constant(Fr::from_le_bytes(chunk).expect("≤31 bytes fit")),
            );
            self.segments.push(Segment { wire: limb, len: chunk.len(), literal: true });
        }
    }

    /// A caller-supplied field, whose range is the caller's claim (or, in
    /// the constrained mode, this serializer's obligation).
    fn push(&mut self, wire: Wire3<FieldT, V>, len: usize) {
        self.segments.push(Segment { wire, len, literal: false });
    }

    /// Zero-pad to `N` and re-limb as `Bytes<N>`.
    pub fn finish<const N: usize>(self, c: &mut Circuit3) -> BytesN<V, N> {
        BytesN::from_limbs(self.finish_dyn(c, N).limbs)
    }

    /// The shared body of [`Self::finish`], for a `len` that need not be a
    /// constant. Public because [`hash::transient_hash`] has exactly that:
    /// its length is `T::LEN`, an associated const of a generic parameter,
    /// which Rust cannot pass as a const-generic argument.
    ///
    /// `len > 31`, as [`BytesNDyn`] requires; a short string is one limb,
    /// which [`Self::finish_limbs`] hands back without the `Bytes<N>`
    /// envelope.
    pub fn finish_dyn(self, c: &mut Circuit3, len: usize) -> BytesNDyn<V> {
        let limbs = self.finish_limbs(c, len);
        BytesNDyn::new(len, limbs)
    }

    /// Zero-pad to `len` bytes and re-limb, handing back the limbs in FAB
    /// SLOT ORDER (`limbs[0]` the leftover, most-significant chunk) for ANY
    /// `len`: one limb of `len` bytes when `len <= 31` — the `Bytes<N>`
    /// envelope does not exist below 32 (`B32` and a single limb do), so
    /// this is the form a short packed string takes — and
    /// [`bytes_limbs`]`(len)` limbs above. Empty for `len == 0`.
    ///
    /// The Signet attestation digest is the caller: the serialized output
    /// (a kind byte and the attested value) is a few bytes, and the MPC
    /// hashes it as one packed limb.
    pub fn finish_limbs(self, c: &mut Circuit3, len: usize) -> Vec<Wire3<FieldT, V>> {
        let total: usize = self.segments.iter().map(|s| s.len).sum();
        assert!(total <= len, "serialized size exceeds Bytes<{len}>");
        let lens: Vec<usize> = match len {
            0 => Vec::new(),
            1..=31 => vec![len],
            _ => limb_lens(len),
        };
        // The constrained mode's whole content: the precondition, emitted —
        // in string order, before anything consumes a segment.
        if self.constrained {
            for segment in self.segments.iter().filter(|s| !s.literal) {
                Prim::Uint { bits: 8 * segment.len as u32 }
                    .constraint()
                    .emit(c, segment.wire);
            }
        }
        let zero = V::from_public(c.constant(0u64));
        let mut segments: std::collections::VecDeque<(Wire3<FieldT, V>, usize)> = self
            .segments
            .into_iter()
            .map(|s| (s.wire, s.len))
            .collect();

        // Fill output limbs least-significant first; missing tail
        // segments mean the remaining limbs are the zero pad.
        let le_lens: Vec<usize> = lens.into_iter().rev().collect();
        let mut le_limbs = Vec::with_capacity(le_lens.len());
        for out_len in le_lens {
            let mut acc: Option<Wire3<FieldT, V>> = None;
            let mut filled = 0usize;
            while filled < out_len {
                let Some((wire, seg_len)) = segments.pop_front() else {
                    break;
                };
                let (piece, piece_len) = if seg_len > out_len - filled {
                    // Split at the limb boundary; the high rest opens
                    // the next limb.
                    let take = out_len - filled;
                    let (rest, low) = c.div_mod_power_of_two(wire, (8 * take) as u32);
                    segments.push_front((rest, seg_len - take));
                    (low, take)
                } else {
                    (wire, seg_len)
                };
                let weighted = if filled == 0 {
                    piece
                } else {
                    let shift = V::from_public(pow2_const(c, filled));
                    c.mul(piece, shift)
                };
                acc = Some(match acc {
                    None => weighted,
                    Some(a) => c.add(a, weighted),
                });
                filled += piece_len;
            }
            le_limbs.push(acc.unwrap_or(zero));
        }
        let mut limbs = le_limbs;
        limbs.reverse();
        limbs
    }
}

/// The constant `2^(8·byte_shift)`.
pub fn pow2_const(c: &mut Circuit3, byte_shift: usize) -> Wire3<FieldT, minocrab::Public> {
    let mut bytes = [0u8; 31];
    bytes[byte_shift] = 1;
    c.constant(Fr::from_le_bytes(&bytes[..=byte_shift]).expect("≤31 bytes fit"))
}

impl<V: Vis3> Default for Serializer<V> {
    fn default() -> Self {
        Self::new()
    }
}

/// Compact's `Secp256k1Point` as a circuit ARGUMENT: one slot, of ZKIR type
/// `Point<Secp256k1>` rather than the native field.
///
/// It is the odd one out among the typed leaves in exactly one way, and the
/// way matters: its slot is not a `Wire3<FieldT, _>`, so it carries no range
/// constraint at all (`Prim::Point` → `LimbConstraint::None`, which is
/// compactc's own `[(tpoint ,ctype) instr*]` line) and
/// [`CircuitArg::push_slots`] hands back nothing for it. Everything else — a
/// slot in the argument list, an entry in the FAB alignment — is as usual.
///
/// The FAB atoms are `encode()`'s five limbs (x as bytes 24+8, y as bytes
/// 24+8, then the infinity flag as a field), notes/ledger-abi.org §3: one
/// slot, five atoms, the same way a `Bytes<32>` is two slots and one atom.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Secp256k1Point<V: Vis3 = Private>(Wire3<Secp256k1PointT, V>);

impl<V: Vis3> Secp256k1Point<V> {
    /// Wrap a point wire (a circuit argument, or a ledger read's result).
    pub fn from_point(w: Wire3<Secp256k1PointT, V>) -> Self {
        Secp256k1Point(w)
    }

    /// The point wire — the same slot, no instructions.
    pub fn point(self) -> Wire3<Secp256k1PointT, V> {
        self.0
    }
}

/// Compact's `Secp256k1Scalar`: ONE slot of ZKIR type `Scalar<Secp256k1>`,
/// the same non-native-slot story as [`Secp256k1Point`] — no range
/// constraint (`reduce-to-zkir.ss` has nothing to say about a scalar slot),
/// no entry in a native slot list, an ordinary argument slot otherwise.
///
/// The FAB atoms are `b24 + b8` (`circuit-alignment-for`,
/// reduce-to-zkir.ss:34-91: "Secp256k1 Base/Scalar → b24+b8" —
/// notes/ledger-abi.org §3): one slot, two atoms, the way a point is one
/// slot and five.
///
/// First needed by the AA manager's `execute`, whose
/// `Secp256k1EcdsaSignature { r, s }` argument is two of these — the
/// corpus's only scalar-typed circuit arguments.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Secp256k1Scalar<V: Vis3 = Private>(Wire3<Secp256k1ScalarT, V>);

impl<V: Vis3> Secp256k1Scalar<V> {
    /// Wrap a scalar wire (a circuit argument, or a conversion's result).
    pub fn from_scalar(w: Wire3<Secp256k1ScalarT, V>) -> Self {
        Secp256k1Scalar(w)
    }

    /// The scalar wire — the same slot, no instructions.
    pub fn scalar(self) -> Wire3<Secp256k1ScalarT, V> {
        self.0
    }
}

/// Compact's `JubjubPoint`: one slot of ZKIR type `Point<Jubjub>`, exactly as
/// [`Secp256k1Point`] is one `Point<Secp256k1>` — same story about carrying no
/// range constraint and contributing no native slot, a shorter alignment.
///
/// The FAB atoms are `encode()`'s two limbs, both `field` (notes/ledger-abi.org
/// §3; the fixture's `opJubjub` pushes `[-0x02, -0x02]`), where a
/// `Secp256k1Point`'s five are `b24, b8, b24, b8, field`.
///
/// compactc's ABI publishes this type as `Alias { name: "JubjubPoint", type:
/// Opaque { tsType: "JubjubPoint" } }`, which is why it lives beside [`Opaque`]
/// in the reader (notes/opaque-bridging.org §0b) and nowhere near it here: a
/// curve point is not an opaque value, it just shares a spelling in one JSON
/// file.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct JubjubPoint<V: Vis3 = Private>(Wire3<JubjubPointT, V>);

impl<V: Vis3> JubjubPoint<V> {
    /// Wrap a point wire (a circuit argument, or a ledger read's result).
    pub fn from_point(w: Wire3<JubjubPointT, V>) -> Self {
        JubjubPoint(w)
    }

    /// The point wire — the same slot, no instructions.
    pub fn point(self) -> Wire3<JubjubPointT, V> {
        self.0
    }
}

/// The TypeScript type name a Compact `Opaque<'ts-type'>` carries — a MARKER
/// TYPE, not a const string.
///
/// `const TS_NAME: &'static str` cannot be a const-generic ARGUMENT on stable
/// (`adt_const_params`), so the name has to be carried by a type either way.
/// That turns out to be the shape worth wanting: [`Opaque<Str>`](Opaque) and
/// `Opaque<Uint8Array>` are then distinct types that do not unify, so mixing
/// them is a type error with no lowering consequence — CLAUDE.md's
/// second-preference rejection mechanism, and Compact's own rule (the pinned
/// compiler: `expected right-hand side of = to have type Opaque<"string"> but
/// received Opaque<"Uint8Array">`).
///
/// Declare your own with [`crate::ts_type!`].
pub trait TsType {
    /// The name as it appears inside Compact's `Opaque<"…">` and as
    /// `contract-info.json`'s `tsType`.
    const TS_NAME: &'static str;
}

/// Declare a [`TsType`] marker: `ts_type!(MyType = "MyType");`
///
/// One line per distinct `tsType` a contract mentions. `minocrab-interface-gen`
/// emits these into a generated interface crate, so the mapping from a Compact
/// `Opaque<"…">` to a Rust type is something a reader can see rather than
/// something the generator knows.
#[macro_export]
macro_rules! ts_type {
    ($( $(#[$m:meta])* $name:ident = $ts:literal );* $(;)?) => {$(
        $(#[$m])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum $name {}
        impl $crate::v3::TsType for $name {
            const TS_NAME: &'static str = $ts;
        }
    )*};
}

/// The [`TsType`] markers for the two names the corpus uses.
pub mod ts {
    crate::ts_type! {
        /// Compact's `Opaque<"string">` — 55 of the corpus's 74 `Opaque`
        /// nodes. Named `Str` and not `String` deliberately: a generated
        /// crate that shadows `std::string::String` is a nasty import, and
        /// [`TsType::TS_NAME`](super::TsType::TS_NAME) still carries
        /// `"string"` verbatim.
        Str = "string";
        /// Compact's `Opaque<"Uint8Array">`.
        Uint8Array = "Uint8Array"
    }
}

/// Compact's `Opaque<'ts-type'>`: a value that lives on the TypeScript side,
/// which a circuit can hold, compare, store and pass on — and nothing else.
///
/// # What the wire actually holds
///
/// One native slot with NO range constraint (compactc's `[(topaque
/// ,opaque-type) instr*]`, i.e. [`Prim::Opaque`] → [`LimbConstraint::None`])
/// under a FAB `compress` atom. The value in that slot is not a handle or an
/// index — it is a BINDING COMMITMENT to the underlying bytes
/// (`transient-crypto/src/fab.rs`, `ValueAtom::field_repr_unchecked`):
///
/// ```text
/// AlignmentAtom::Compress => transient_commit(bytes, len)   // 0 if bytes is empty
/// ```
///
/// Three consequences, and they are the whole API:
///
/// - **[`Opaque::eq`] is sound.** Comparing two opaques compares their
///   commitments, so it decides equality of the TS-side values up to Poseidon
///   collision resistance. It is not pointer identity.
/// - **[`Opaque::default_value`] is the field element zero**, because the empty byte
///   string is special-cased upstream — which is why compactc lowers
///   `default<Opaque<"string">>` to the immediate `0x00` with no ceremony.
/// - **There is nothing else to offer.** The commitment is one-way
///   (`AlignmentAtom::parse_field_repr` returns `None` for `Compress`), so
///   there is no byte view, no length, no way to build one in circuit, and no
///   hash: [`hash::persistent_hash`] is bounded on
///   [`CircuitBorsh`](borsh::CircuitBorsh), which this type deliberately does
///   not implement (§5 of notes/opaque-bridging.org). compactc refuses the same
///   thing in almost the same words — *"persistentHash cannot be applied to a
///   first argument containing opaque JavaScript values"*.
///
/// # Where it can appear
///
/// Everywhere a Compact `Opaque` can: circuit argument, circuit result,
/// witness result, ledger `Cell` / `Map` key / `Map` value / `Set` element,
/// struct field, and either side of a cross-contract call. The fixture
/// `tests/fixtures/opaque/opaque.compact` in `minocrab-contracts` has one
/// circuit per position.
///
/// # The ts-type is part of the type
///
/// Two opaques of different TS types have the same LAYOUT — one `compress`
/// atom each — so nothing in the ABI keeps them apart. The Rust type parameter
/// does, and it is a compile error rather than a lint:
///
/// ```compile_fail
/// use minocrab::v3::Circuit3;
/// use minocrab_std::v3::{ts, Opaque};
///
/// let mut c = Circuit3::new();
/// let name: Opaque<ts::Str> = Opaque::from_field_unchecked(c.witness());
/// let blob: Opaque<ts::Uint8Array> = Opaque::from_field_unchecked(c.witness());
/// // ERROR: expected `Opaque<Str>`, found `Opaque<Uint8Array>`
/// let _ = name.eq(&mut c, blob);
/// ```
///
/// which is the rejection compactc makes for the same mistake: *"expected
/// right-hand side of = to have type `Opaque<"string">` but received
/// `Opaque<"Uint8Array">`"*. Two opaques of the SAME ts-type compare fine:
///
/// ```
/// use minocrab::v3::Circuit3;
/// use minocrab_std::v3::{ts, Opaque};
///
/// let mut c = Circuit3::new();
/// let a: Opaque<ts::Str> = Opaque::from_field_unchecked(c.witness());
/// let b: Opaque<ts::Str> = Opaque::from_field_unchecked(c.witness());
/// let _same = a.eq(&mut c, b);
/// ```
#[repr(transparent)]
pub struct Opaque<T: TsType, V: Vis3 = Private>(Wire3<FieldT, V>, std::marker::PhantomData<T>);

// `Copy` like every other leaf (there is no resource discipline to protect —
// an opaque is not spendable or consumed), but HAND-WRITTEN: `#[derive(Copy)]`
// on a struct with a `PhantomData<T>` field adds an implicit `T: Copy` bound,
// and `T` here is an uninhabited marker that has no reason to carry one. The
// derive would then make `self.field()` fail to compile behind a `&self`.
impl<T: TsType, V: Vis3> Clone for Opaque<T, V> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: TsType, V: Vis3> Copy for Opaque<T, V> {}

impl<T: TsType, V: Vis3> Opaque<T, V> {
    /// Wrap a wire holding an opaque's commitment (a circuit argument, a
    /// witnessed value, a ledger read).
    ///
    /// Named `_unchecked` for the same reason every other leaf's
    /// constructor is (notes/api-safety-survey.org §A1): it is the caller
    /// CLAIMING the wire holds a commitment, not a check. There is no
    /// `from_field_checked` twin — `Prim::Opaque` is compactc's own
    /// no-constraint primitive (see the type's docs), so there is no
    /// `constrain_input` here to delegate to.
    pub fn from_field_unchecked(w: Wire3<FieldT, V>) -> Self {
        Opaque(w, std::marker::PhantomData)
    }

    /// The commitment wire — the same slot, no instructions.
    ///
    /// Named `field` like every other leaf's unwrap, but worth reading twice:
    /// what comes out is `transient_commit(bytes, len)`, not the value. There
    /// is no operation on it that means anything except equality.
    pub fn field(self) -> Wire3<FieldT, V> {
        self.0
    }
}

impl<T: TsType> Opaque<T, Public> {
    /// Compact's `default<Opaque<…>>` — the empty value, whose commitment is
    /// the field element zero (see the type's docs). One `Circuit3::constant`,
    /// which inlines as an immediate wherever it is used.
    pub fn default_value(c: &mut Circuit3) -> Self {
        Opaque::from_field_unchecked(c.constant(Fr::from(0u64)))
    }
}

impl<T: TsType, V: Vis3> Opaque<T, V> {
    /// `a == b` — one `test_eq` over the two commitments, so this decides
    /// equality of the TS-side values (see the type's docs on why that is
    /// sound and not handle identity).
    pub fn eq<W: Vis3>(
        self,
        c: &mut Circuit3,
        other: Opaque<T, W>,
    ) -> Wire3<FieldT, <V as Meet<W>>::Out>
    where
        V: Meet<W>,
        <V as Meet<W>>::Out: Vis3,
    {
        c.test_eq(self.0, other.0)
    }
}

/// `struct Secp256k1EcdsaSignature { r: Secp256k1Scalar, s: Secp256k1Scalar }`
#[derive(Clone, Copy)]
pub struct Secp256k1EcdsaSignature<V: Vis3> {
    pub r: Wire3<Secp256k1ScalarT, V>,
    pub s: Wire3<Secp256k1ScalarT, V>,
}

/// `circuit hashToSecp256k1Scalar(digest: Bytes<32>): Secp256k1Scalar` —
/// the digest is a big-endian integer (RFC 6979), so reverse the bytes and
/// reduce mod the scalar-field order.
pub fn hash_to_secp256k1_scalar<V: Vis3>(
    c: &mut Circuit3,
    digest: &B32<V>,
) -> Wire3<Secp256k1ScalarT, V> {
    let typed = digest.to_typed(c);
    let reversed = c.reverse_bytes(typed);
    c.from_bytes32(reversed)
}

/// `circuit secp256k1EcdsaVerify(msgHash, sig, pk): Boolean`
///
/// Standard ECDSA: `w = s⁻¹`, `u1 = z·w`, `u2 = r·w`,
/// `P = u1·G + u2·pk`, valid iff `P.x == r` as 32-byte big-endian
/// integers. Accepts both low-s and high-s signatures (as the library
/// does); `msgHash` is taken as given and must be bound to the real
/// message by the caller.
pub fn secp256k1_ecdsa_verify<V: Vis3>(
    c: &mut Circuit3,
    msg_hash: &B32<V>,
    sig: &Secp256k1EcdsaSignature<V>,
    pk: Wire3<Secp256k1PointT, V>,
) -> Wire3<FieldT, V> {
    let z = hash_to_secp256k1_scalar(c, msg_hash);
    let w = c.inv(sig.s);
    let u1 = c.mul(z, w);
    let u2 = c.mul(sig.r, w);
    let g_u1 = c.ec_mul_generator(u1);
    let pk_u2 = c.ec_mul(pk, u2);
    let point = c.add(g_u1, pk_u2);

    // (secp256k1PointX(point) as Bytes<32>) as Secp256k1Scalar == r —
    // compactc emits the into/from round-trip as-is.
    let (x, _y) = c.into_coordinates(point);
    let x_bytes = c.into_bytes32(x);
    let x_pair = B32::from_typed(c, x_bytes);
    let x_typed = x_pair.to_typed(c);
    let x_scalar: Wire3<Secp256k1ScalarT, V> = c.from_bytes32(x_typed);
    c.test_eq(x_scalar, sig.r)
}

/// A secp256k1 base-field element as 32 big-endian byte wires
/// (`secp256k1BaseBigEndian`: canonical LE bytes, reversed).
fn base_big_endian<V: Vis3>(
    c: &mut Circuit3,
    base: Wire3<minocrab::v3::Secp256k1BaseT, V>,
) -> Vec<Wire3<FieldT, V>> {
    let typed = c.into_bytes32(base);
    let pair = B32::from_typed(c, typed);
    let le = b32_to_bytes(c, &pair);
    le.into_iter().rev().collect()
}

/// `circuit secp256k1EthereumAddress(pk): Bytes<20>` — keccak256 of the
/// point's big-endian coordinates, bytes 12..31. `Bytes<20>` is a single
/// native slot. The point at infinity is rejected
/// (`pk != default<Secp256k1Point>`).
pub fn secp256k1_ethereum_address<V: Vis3>(
    c: &mut Circuit3,
    pk: Wire3<Secp256k1PointT, V>,
) -> Wire3<FieldT, V> {
    // default<Secp256k1Point> = generator · 0, built as compactc does
    // (into_bytes32(0) → from_bytes32 scalar → ec_mul_generator).
    let zero = c.constant(0u64);
    let zero_bytes = c.into_bytes32(zero);
    let zero_scalar: Wire3<Secp256k1ScalarT, Public> = c.from_bytes32(zero_bytes);
    let identity = c.ec_mul_generator(zero_scalar);
    let is_identity = c.test_eq(pk, V::from_public(identity));
    let not_identity = c.not(is_identity);
    c.assert(not_identity);

    // keccak256 over the 64 big-endian coordinate bytes (alignment =
    // 64 × bytes 1, per the verified library dump).
    let (x, y) = c.into_coordinates(pk);
    let mut bytes = base_big_endian(c, x);
    bytes.extend(base_big_endian(c, y));
    let alignment = minocrab::Alignment(
        (0..64)
            .map(|_| AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 1 }))
            .collect(),
    );
    let erased: Vec<_> = bytes.iter().map(|w| w.erase()).collect();
    let hash = c.keccak256(alignment, &erased);

    // slice<20>(hash, 12): bytes 12..31 of the digest, rebuilt as the
    // single Bytes<20> limb.
    let pair = B32::from_typed(c, hash);
    let hash_bytes = b32_to_bytes(c, &pair);
    rebuild_limb(c, &hash_bytes[12..32])
}

// --- coins (the zswap stdlib circuits, v3) -----------------------------------

/// `circuit ownPublicKey(): ZswapCoinPublicKey` — witness-backed: the
/// local secret key never enters the circuit, the runtime supplies the
/// derived key as a witness, input-constrained like any `Bytes<32>`
/// (confirmed against the mint-tokens corpus artifact).
pub fn own_public_key(c: &mut Circuit3) -> ZswapCoinPublicKey<Private> {
    let pk = B32 {
        hi: c.witness::<FieldT>(),
        lo: c.witness::<FieldT>(),
    };
    pk.constrain_input(c);
    ZswapCoinPublicKey(pk)
}

/// A `bytes<n>` (n ≤ 31) literal as a single constant limb — always an INLINE
/// hash operand, since compactc puts a constant preimage element straight into
/// the instruction (`AnyWire3::immediate`), so there is no wire-producing
/// twin.
fn short_literal_imm(bytes: &[u8]) -> Fr {
    assert!(bytes.len() <= 31);
    Fr::from_le_bytes(bytes).expect("≤31 bytes fit")
}

fn b32_atom() -> AlignmentSegment {
    AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 })
}

/// `circuit tokenType(domain_sep: Bytes<32>, contract: ContractAddress):
/// Bytes<32>` — `persistentHash([pad(32, "midnight:derive_token"),
/// domain_sep, contract])` (input order confirmed against the mint-tokens
/// corpus artifact).
pub fn token_type<V: Vis3>(
    c: &mut Circuit3,
    domain_sep: &TokenDomainSeparator<V>,
    contract: &B32<V>,
) -> CoinColor<V> {
    let domain_sep = domain_sep.bytes();
    // The domain prefix is CONSTANT, so it is inlined into the hash operand
    // list rather than named by two `copy`s — compactc emits
    // `["0x00", "0x6d69646e696768743a6465726976655f746f6b656e", …]` with no
    // `copy` in sight (the M17 fixture's `sMintUnshieldedToken`). This is
    // M16's `AnyWire3::immediate` applied to the last hash operand in the
    // stdlib that still named its constants; it removes one `copy` pair from
    // every `token_type` call site and is zero rows (M9 phase 7 measured that
    // class).
    let (p_hi, p_lo) = b32_pad_limbs("midnight:derive_token");
    let alignment = Alignment(vec![b32_atom(), b32_atom(), b32_atom()]);
    CoinColor(hash::persistent_hash_compact(
        c,
        alignment,
        &[
            AnyWire3::immediate(p_hi),
            AnyWire3::immediate(p_lo),
            domain_sep.hi.erase(),
            domain_sep.lo.erase(),
            contract.hi.erase(),
            contract.lo.erase(),
        ],
    ))
}

/// The `[hi, lo]` field elements of `pad(32, s)`, as constants — the
/// value half of [`B32::pad`], for the call sites that inline it.
fn b32_pad_limbs(s: &str) -> (Fr, Fr) {
    assert!(s.len() <= 32, "pad(32, ..) literal longer than 32 bytes");
    let mut bytes = [0u8; 32];
    bytes[..s.len()].copy_from_slice(s.as_bytes());
    (
        Fr::from(u64::from(bytes[31])),
        Fr::from_le_bytes(&bytes[..31]).expect("31 bytes fit"),
    )
}

b32_newtype! {
    /// A shielded-coin nonce — one type for a mint nonce, a change nonce,
    /// `ShieldedCoinInfo.nonce` and the kernel's evolved nonces, which are
    /// the same protocol object at different points in its life. The mint
    /// signatures carry three same-shaped 32-byte values (domain separator,
    /// nonce, recipient key); this type makes the nonce position
    /// unswappable — newtype-survey hazard A5, the sweep's most
    /// consequential (a swapped nonce/recipient mints a coin to a key
    /// nobody holds and silently destroys the value).
    CoinNonce,
    /// A token DOMAIN SEPARATOR — the pre-token [`token_type`] derives a
    /// colour from. Distinct from [`CoinColor`] on purpose: a separator
    /// handed where a colour goes (or vice versa) derives a coherent but
    /// wrong token family that every mint and burn would agree on —
    /// newtype-survey hazard A6.
    TokenDomainSeparator,
    /// A token type ("colour") — [`token_type`]'s output, the coin field
    /// and every unshielded balance/send/receive key. See
    /// [`TokenDomainSeparator`] for why the two do not unify.
    CoinColor,
}

/// `struct ShieldedCoinInfo { nonce: Bytes<32>, color: Bytes<32>,
/// value: Uint<128> }`.
#[derive(Clone, Copy)]
pub struct ShieldedCoinInfo3<V: Vis3> {
    pub nonce: CoinNonce<V>,
    pub color: CoinColor<V>,
    pub value: Wire3<FieldT, V>,
}

/// The ABI of Compact's `ShieldedCoinInfo`, in declaration order.
///
/// Written out rather than derived because `value` is a bare wire here, not
/// a `Uint<128, V>` — the coin gadgets do field arithmetic on it. The width
/// the Compact struct declares is therefore stated once, here, instead of
/// being carried by the field's type.
impl<V: Vis3> CircuitAbi for ShieldedCoinInfo3<V> {
    const SLOTS: usize = <B32<V> as CircuitAbi>::SLOTS * 2 + 1;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        <B32<V> as CircuitAbi>::push_atoms(atoms);
        <B32<V> as CircuitAbi>::push_atoms(atoms);
        <Uint<128, V> as CircuitAbi>::push_atoms(atoms);
    }

    fn push_prims(prims: &mut Vec<Prim>) {
        <B32<V> as CircuitAbi>::push_prims(prims);
        <B32<V> as CircuitAbi>::push_prims(prims);
        <Uint<128, V> as CircuitAbi>::push_prims(prims);
    }
}

/// `struct QualifiedShieldedCoinInfo { nonce: Bytes<32>, color: Bytes<32>,
/// value: Uint<128>, mt_index: Uint<64> }` — a coin the contract can SPEND,
/// which is [`ShieldedCoinInfo3`] plus its position in the coin commitment
/// tree.
#[derive(Clone, Copy)]
pub struct QualifiedShieldedCoinInfo3<V: Vis3> {
    pub nonce: CoinNonce<V>,
    pub color: CoinColor<V>,
    pub value: Wire3<FieldT, V>,
    pub mt_index: Wire3<FieldT, V>,
}

impl<V: Vis3> QualifiedShieldedCoinInfo3<V> {
    /// `downcastQualifiedCoin(coin)` — forget the tree index. Zero
    /// instructions; the index is the ledger's business, not the
    /// commitment's.
    pub fn downcast(&self) -> ShieldedCoinInfo3<V> {
        ShieldedCoinInfo3 {
            nonce: self.nonce,
            color: self.color,
            value: self.value,
        }
    }
}

/// The ABI of Compact's `QualifiedShieldedCoinInfo`, in declaration order —
/// [`ShieldedCoinInfo3`]'s three fields then the `Uint<64>` index.
impl<V: Vis3> CircuitAbi for QualifiedShieldedCoinInfo3<V> {
    const SLOTS: usize = <ShieldedCoinInfo3<V> as CircuitAbi>::SLOTS + 1;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        <ShieldedCoinInfo3<V> as CircuitAbi>::push_atoms(atoms);
        <Uint<64, V> as CircuitAbi>::push_atoms(atoms);
    }

    fn push_prims(prims: &mut Vec<Prim>) {
        <ShieldedCoinInfo3<V> as CircuitAbi>::push_prims(prims);
        <Uint<64, V> as CircuitAbi>::push_prims(prims);
    }
}

/// `struct ShieldedSendResult { change: Maybe<ShieldedCoinInfo>, sent:
/// ShieldedCoinInfo }` — what [`kernel::send_shielded`]
/// hands back: the coin that went to the recipient, and the change coin the
/// contract paid back to itself, if there was any.
#[derive(Clone, Copy)]
pub struct ShieldedSendResult<V: Vis3> {
    pub change: Maybe<ShieldedCoinInfo3<V>, V>,
    pub sent: ShieldedCoinInfo3<V>,
}

/// `Either<ZswapCoinPublicKey, ContractAddress>` — a coin recipient. Both
/// arms are `Bytes<32>` on the wire; `is_left` = 1 selects the public key.
#[derive(Clone, Copy)]
pub struct CoinRecipient<V: Vis3> {
    pub is_left: Wire3<FieldT, V>,
    pub left: ZswapCoinPublicKey<V>,
    pub right: ContractAddress<V>,
}

// ---- Compact's generic sum shapes -------------------------------------------
//
// Both are plain structs in Compact — the tag is a `Boolean` field and BOTH
// arms are always present on the wire, so they flatten like any other struct
// and a `Maybe`/`Either` argument costs its tag plus every arm (see the
// `CircuitArg` impls for the slot layout). Parameter order is the argument
// convention: the payload types first, the visibility last and defaulted, so
// a signature reads like its Compact source.

/// `struct Maybe<T> { is_some: Boolean; value: T; }` — the v3 twin of
/// Compact's `Maybe<T>`. `value` is meaningful only when `is_some` is 1,
/// but it occupies its slots either way.
#[derive(Clone, Copy)]
pub struct Maybe<T, V: Vis3 = Private> {
    pub is_some: Bool<V>,
    pub value: T,
}

/// `struct Either<A, B> { is_left: Boolean; left: A; right: B; }` — the v3
/// twin of Compact's `Either<A, B>`. Both arms occupy their slots; `is_left`
/// says which one is meaningful.
#[derive(Clone, Copy)]
pub struct Either<A, B, V: Vis3 = Private> {
    pub is_left: Bool<V>,
    pub left: A,
    pub right: B,
}

/// `circuit coinNullifier(coin, addr): Bytes<32>` — the CoinPreimage hash
/// with the `midnight:zswap-cn[v1]` domain and a ContractAddress
/// (`dataType` = 0), as `sendShielded` computes for the spender
/// (withdraw.zkir:190).
pub fn coin_nullifier_contract<V: Vis3>(
    c: &mut Circuit3,
    coin: &ShieldedCoinInfo3<V>,
    addr: &B32<V>,
) -> B32<V> {
    // The domain prefix and the `dataType` byte are CONSTANT, so both are
    // inlined into the hash operand list rather than named by a `copy` —
    // compactc emits `["0x6d69…", …, "0x00", %self.hi, %self.lo]` with no
    // `copy` in sight (`kernel.compact`'s `sMergeCoin`). Same rule, same
    // mechanism and the same zero rows as `token_type`'s (M17).
    hash::persistent_hash_compact(
        c,
        coin_preimage_alignment(),
        &[
            AnyWire3::immediate(short_literal_imm(b"midnight:zswap-cn[v1]")),
            coin.nonce.bytes().hi.erase(),
            coin.nonce.bytes().lo.erase(),
            coin.color.bytes().hi.erase(),
            coin.color.bytes().lo.erase(),
            coin.value.erase(),
            AnyWire3::immediate(0u64),
            addr.hi.erase(),
            addr.lo.erase(),
        ],
    )
}

/// The `CoinPreimage` alignment both coin digests hash under:
/// `[domain_sep: Bytes<21>, coin: ShieldedCoinInfo, dataType: Boolean,
/// data: Bytes<32>]`.
fn coin_preimage_alignment() -> Alignment {
    Alignment(vec![
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 21 }),
        b32_atom(),
        b32_atom(),
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 16 }),
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 1 }),
        b32_atom(),
    ])
}

/// `circuit coinCommitment(coin, recipient): Bytes<32>` —
/// `persistentHash` over the coin preimage `["midnight:zswap-cc[v1]"
/// (Bytes<21>), nonce, color, value (Uint<128>), is_left (Boolean),
/// recipient bytes]`, mirroring Compact's `coin_commitment` and the
/// mint-tokens corpus artifact.
pub fn coin_commitment<V: Vis3>(
    c: &mut Circuit3,
    coin: &ShieldedCoinInfo3<V>,
    recipient: &CoinRecipient<V>,
) -> B32<V> {
    let data = B32::cond_select(c, recipient.is_left, &recipient.left.bytes(), &recipient.right.bytes());
    coin_commitment_to(c, coin, recipient.is_left.erase(), &data)
}

/// [`coin_commitment`] against a recipient whose tag and address are already
/// to hand — the two things the preimage actually contains.
///
/// It is separate for two reasons, both visible in the artifacts. A recipient
/// that is a STATIC `right(addr)` has no select to do at all, and compactc
/// emits none ([`coin_commitment_to_contract`]). And a circuit that commits to
/// the same coin TWICE — `sendShielded` claims the spend and then, on the
/// self-send path, the receive — selects once and hashes twice, which is
/// exactly what compactc's `sSendShielded` does (the `cond_select` pair is
/// shared, the `persistent_hash` is not).
pub fn coin_commitment_to<V: Vis3>(
    c: &mut Circuit3,
    coin: &ShieldedCoinInfo3<V>,
    is_left: AnyWire3<V>,
    data: &B32<V>,
) -> B32<V> {
    // The domain prefix is constant — inlined, per `coin_nullifier_contract`.
    hash::persistent_hash_compact(
        c,
        coin_preimage_alignment(),
        &[
            AnyWire3::immediate(short_literal_imm(b"midnight:zswap-cc[v1]")),
            coin.nonce.bytes().hi.erase(),
            coin.nonce.bytes().lo.erase(),
            coin.color.bytes().hi.erase(),
            coin.color.bytes().lo.erase(),
            coin.value.erase(),
            is_left,
            data.hi.erase(),
            data.lo.erase(),
        ],
    )
}

/// [`coin_commitment`] against `right<ZswapCoinPublicKey, ContractAddress>(addr)`
/// — a contract recipient written as a literal, which is what every stdlib
/// circuit that pays a contract (`receiveShielded`, `mergeCoin`, the change
/// coin of `sendShielded`) constructs.
///
/// The tag is the inline immediate `0` and the address is the data, so there
/// is no select: the arm that is not taken is `default<ZswapCoinPublicKey>`
/// and never reaches the preimage. compactc folds it the same way.
pub fn coin_commitment_to_contract<V: Vis3>(
    c: &mut Circuit3,
    coin: &ShieldedCoinInfo3<V>,
    addr: &B32<V>,
) -> B32<V> {
    coin_commitment_to(c, coin, AnyWire3::immediate(0u64), addr)
}
