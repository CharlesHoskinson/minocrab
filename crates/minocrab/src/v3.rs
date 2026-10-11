//! L2 for ZKIR v3 — the typed eDSL frontend.
//!
//! Visibility in the type and `disclose` as the single Private→Public gate
//! (the crate docs), and wires also carry their ZKIR v3 *value type*
//! ([`IrTy`] markers for [`IrType`]), so the
//! per-instruction supported-type lists that [`Builder3`] checks at circuit
//! build time become Rust compile errors here: `ec_mul` of a secp256k1
//! point by a Jubjub scalar simply does not type-check.
//!
//! v3 circuits have one `Output` terminator; [`Circuit3::output`] queues
//! wires and [`Circuit3::finish`] emits the terminator.

use std::marker::PhantomData;

use minocrab_ir::v3::{Arg, Builder3, IrSource, IrType};
pub use minocrab_ir::v3::{Alignment, Identifier, Val};
use minocrab_ir::Fr;

use crate::{DisclosureKind, Meet, OnChainGuard, Private, Public, Region, Visibility};

mod abi;
mod disclose;
mod effects;

pub use abi::{
    uint_atom_bytes, uint_compare_bits, CallArg, CallArgs, CallResult, CircuitAbi, LimbConstraint,
    Prim,
};

/// Typed disclosure declarations — `label!` types, `.disclose_as::<L>(c)`,
/// and the `Discloses<D, R>` a circuit returns (see the module docs).
pub use disclose::{
    assert_declared_disclosures, assert_discloses_nothing, disclosed_labels, Declared, Disclose, DisclosureLabel, Discloses,
    LabelSet,
};

// --- value-type markers -------------------------------------------------------

/// Type-level tag for a ZKIR v3 [`IrType`].
pub trait IrTy: 'static {
    fn ir_type() -> IrType;
}

macro_rules! ir_ty {
    ($($(#[$doc:meta])* $name:ident => $variant:ident),* $(,)?) => {$(
        $(#[$doc])*
        #[derive(Clone, Copy)]
        pub enum $name {}
        impl IrTy for $name {
            fn ir_type() -> IrType {
                IrType::$variant
            }
        }
    )*};
}

ir_ty! {
    /// The native BLS12-381 scalar field (Compact `Field`, `Uint`, `Boolean`).
    FieldT => Native,
    /// `Bytes<32>` as a single typed value.
    Bytes32T => Bytes32,
    /// A point on Jubjub, the native embedded curve.
    JubjubPointT => JubjubPoint,
    /// A scalar of Jubjub's scalar field.
    JubjubScalarT => JubjubScalar,
    /// A point on secp256k1.
    Secp256k1PointT => Secp256k1Point,
    /// A base-field element of secp256k1.
    Secp256k1BaseT => Secp256k1Base,
    /// A scalar-field element of secp256k1.
    Secp256k1ScalarT => Secp256k1Scalar,
    /// A point on secp256r1.
    Secp256r1PointT => Secp256r1Point,
    /// A base-field element of secp256r1.
    Secp256r1BaseT => Secp256r1Base,
    /// A scalar-field element of secp256r1.
    Secp256r1ScalarT => Secp256r1Scalar,
    /// A point on Curve25519.
    Curve25519PointT => Curve25519Point,
    /// A base-field element of Curve25519.
    Curve25519BaseT => Curve25519Base,
    /// A scalar-field element of Curve25519.
    Curve25519ScalarT => Curve25519Scalar,
}

/// Types supported by TestEq/Add/Neg/CondSelect/ConstrainEq (everything but
/// `Bytes<32>` and `Scalar<Jubjub>`).
pub trait EqAddTy: IrTy {}
impl EqAddTy for FieldT {}
impl EqAddTy for JubjubPointT {}
impl EqAddTy for Secp256k1PointT {}
impl EqAddTy for Secp256k1BaseT {}
impl EqAddTy for Secp256k1ScalarT {}
impl EqAddTy for Secp256r1PointT {}
impl EqAddTy for Secp256r1BaseT {}
impl EqAddTy for Secp256r1ScalarT {}
impl EqAddTy for Curve25519PointT {}
impl EqAddTy for Curve25519BaseT {}
impl EqAddTy for Curve25519ScalarT {}

/// Field elements supporting Mul/Inv (no points).
pub trait MulTy: EqAddTy {}
impl MulTy for FieldT {}
impl MulTy for Secp256k1BaseT {}
impl MulTy for Secp256k1ScalarT {}
impl MulTy for Secp256r1BaseT {}
impl MulTy for Secp256r1ScalarT {}
impl MulTy for Curve25519BaseT {}
impl MulTy for Curve25519ScalarT {}

/// Prime fields with a canonical 32-byte form (IntoBytes32/FromBytes32).
pub trait Bytes32ConvTy: IrTy {}
impl Bytes32ConvTy for FieldT {}
impl Bytes32ConvTy for Secp256k1BaseT {}
impl Bytes32ConvTy for Secp256k1ScalarT {}
impl Bytes32ConvTy for Secp256r1BaseT {}
impl Bytes32ConvTy for Secp256r1ScalarT {}
impl Bytes32ConvTy for Curve25519BaseT {}
impl Bytes32ConvTy for Curve25519ScalarT {}

/// Scalars whose curve generator `EcMulGenerator` can multiply (the VM
/// dispatches on the scalar type; Jubjub and secp256k1 are supported).
pub trait GeneratorScalarTy: IrTy {
    type Point: PointTy;
}
impl GeneratorScalarTy for JubjubScalarT {
    type Point = JubjubPointT;
}
impl GeneratorScalarTy for Secp256k1ScalarT {
    type Point = Secp256k1PointT;
}

/// Curve points: their coordinate (base-field) and scalar types.
pub trait PointTy: EqAddTy {
    type Coord: IrTy;
    type Scalar: IrTy;
}
impl PointTy for JubjubPointT {
    type Coord = FieldT;
    type Scalar = JubjubScalarT;
}
impl PointTy for Secp256k1PointT {
    type Coord = Secp256k1BaseT;
    type Scalar = Secp256k1ScalarT;
}
impl PointTy for Secp256r1PointT {
    type Coord = Secp256r1BaseT;
    type Scalar = Secp256r1ScalarT;
}
impl PointTy for Curve25519PointT {
    type Coord = Curve25519BaseT;
    type Scalar = Curve25519ScalarT;
}

// --- wires ---------------------------------------------------------------------

/// One v3 circuit value, tagged with its ZKIR type and its visibility.
pub struct Wire3<T: IrTy, V: Visibility> {
    val: Val,
    _marker: PhantomData<(T, V)>,
}

impl<T: IrTy, V: Visibility> Clone for Wire3<T, V> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T: IrTy, V: Visibility> Copy for Wire3<T, V> {}

impl<T: IrTy, V: Visibility> Wire3<T, V> {
    fn new(val: Val) -> Self {
        Wire3 {
            val,
            _marker: PhantomData,
        }
    }

    /// The underlying L1 value handle.
    pub fn val(self) -> Val {
        self.val
    }

    /// Forget that this wire is public (safe: private is the restrictive
    /// end of the disclosure lattice).
    pub fn private(self) -> Wire3<T, Private> {
        Wire3::new(self.val)
    }

    /// Erase the value type for heterogeneous operand lists (hash inputs),
    /// keeping visibility.
    pub fn erase(self) -> AnyWire3<V> {
        AnyWire3 {
            arg: Arg::Val(self.val),
            _vis: PhantomData,
        }
    }
}

/// [`Wire3::erase`] as a conversion, so a hash operand list may be written as
/// plain wires where none of them is constant.
impl<T: IrTy, V: Visibility> From<Wire3<T, V>> for AnyWire3<V> {
    fn from(w: Wire3<T, V>) -> AnyWire3<V> {
        w.erase()
    }
}

/// A type-erased hash OPERAND: a wire of any value type, or an INLINE
/// IMMEDIATE ([`AnyWire3::immediate`]).
///
/// The immediate arm is M9 phase 8's rule applied to preimages: compactc puts
/// a constant preimage element straight into the instruction's operand list
/// (a domain separator is always one), and naming it with a `copy` first is a
/// zero-row but visible difference. `AnyWire3` therefore carries an [`Arg`]
/// rather than a [`Val`], and every hash instruction inlines what is constant.
pub struct AnyWire3<V: Visibility> {
    arg: Arg,
    _vis: PhantomData<V>,
}

impl<V: Visibility> AnyWire3<V> {
    /// A constant preimage element, inlined into the instruction rather than
    /// named by a `copy` — the shape compactc emits for a domain separator.
    ///
    /// The visibility parameter is the LIST's, not the value's: a constant is
    /// public, and it takes whatever visibility its neighbours have.
    pub fn immediate(imm: impl Into<Fr>) -> AnyWire3<V> {
        AnyWire3 {
            arg: Arg::Imm(imm.into()),
            _vis: PhantomData,
        }
    }
}

/// A condition usable as a GUARD: a wire, or (in `minocrab-std`) a `Check`
/// from the predicate vocabulary.
///
/// The trait exists so that [`Circuit3::when`] and [`Branches`] read the same
/// whether the condition is already a wire or is written as
/// `eq(a, b).and(..)` — a condition is a condition, and where it lands should
/// not change how it is spelled.
pub trait GuardCond<V: Visibility> {
    /// Lower to the wire the guard operand takes.
    fn into_guard(self, c: &mut Circuit3) -> Wire3<FieldT, V>;
}

impl<V: Visibility> GuardCond<V> for Wire3<FieldT, V> {
    fn into_guard(self, _c: &mut Circuit3) -> Wire3<FieldT, V> {
        self
    }
}

/// A value that came out of a conditional — [`ValueBranches::otherwise`]'s
/// result, wrapped.
///
/// `#[repr(transparent)]` around the value and carrying nothing at run time,
/// so it costs no instruction and no byte. What it carries is a
/// `#[must_use]` that TRAVELS: a function-level attribute fires only where
/// the call is written, but a must-use TYPE fires wherever a value of it is
/// dropped — including one step removed, which is where the waste actually
/// happens:
///
/// ```compile_fail
/// # #![deny(unused_must_use)]
/// # use minocrab::v3::{Circuit3, FieldT, Selected, Wire3};
/// # use minocrab::Private;
/// fn fee(c: &mut Circuit3, g: Wire3<FieldT, Private>, x: Wire3<FieldT, Private>)
///     -> Selected<Wire3<FieldT, Private>> {
///     c.when_value(g, |_c| x).otherwise(|_c| x)   // fine: it is returned
/// }
/// # let mut c = Circuit3::new();
/// # let g = c.arg::<FieldT>("g");
/// # let x = c.arg::<FieldT>("x");
/// fee(&mut c, g, x);   // …and THIS is the mistake the wrapper catches
/// ```
///
/// It is deliberately thin: [`Deref`](std::ops::Deref) to the value, `Copy`
/// where the value is, and [`Selected::into_inner`] to be rid of it. Field
/// access needs no ceremony — a `Selected<B32>` still has `.hi` and `.lo`.
///
/// THE TENSION, stated because it decides how much the wrapper is worth: the
/// more eagerly it is unwrapped, the less it propagates. Kept in a helper's
/// SIGNATURE it catches the dropped-result mistake a caller away; unwrapped
/// at the first opportunity it degrades to exactly the function-level
/// `#[must_use]` it replaced. Both are fine — the type also reads as
/// documentation ("this came from a branch, so every arm was paid for") — but
/// the lint only pays if signatures keep it.
#[repr(transparent)]
#[must_use = "this value came from a conditional; dropping it means every arm was emitted \
              for nothing"]
pub struct Selected<T>(T);

impl<T> Selected<T> {
    /// Unwrap. No instruction, no cost — the wrapper is compile-time only.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> std::ops::Deref for Selected<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Clone> Clone for Selected<T> {
    fn clone(&self) -> Self {
        Selected(self.0.clone())
    }
}

impl<T: Copy> Copy for Selected<T> {}

/// A selected value guards as the value does, so a conditional's result can
/// be the condition of the next one without ceremony.
impl<V: Visibility> GuardCond<V> for Selected<Wire3<FieldT, V>> {
    fn into_guard(self, c: &mut Circuit3) -> Wire3<FieldT, V> {
        self.0.into_guard(c)
    }
}

/// …and it can itself be selected between, so chains nest.
impl<V: Visibility, T: Select<V>> Select<V> for Selected<T> {
    fn select(c: &mut Circuit3, bit: Wire3<FieldT, V>, taken: Self, fallback: Self) -> Self {
        Selected(T::select(c, bit, taken.0, fallback.0))
    }
}

/// The result of a GUARDED READ: the value the transcript carried if the
/// guard held, and the type's DEFAULT if it did not.
///
/// The default is not this library's choice. A guarded-off `public_input` /
/// `private_input` gate yields the type's default and does not consume the
/// transcript — upstream's own VM semantics (`ir_vm.rs:348-366`), and the
/// whole reason a read can sit inside a branch at all. What this type adds is
/// that the caller has to SAY which they mean, instead of receiving a value
/// that is silently zero on a path they were not thinking about.
///
/// It is deliberately NOT [`Deref`](std::ops::Deref), and that is the
/// difference from [`Selected`]. `Selected` guards against DROPPING a value,
/// so deref coercion is harmless and saves ceremony. `Guarded` guards against
/// CONFUSING two values — the read one and the default one — and a coercion
/// that silently produced the value would undo exactly the thing the type is
/// for.
///
/// Three ways out, and the costs are the honest ones:
///
/// | | means | cost |
/// |---+---+---|
/// | [`or_default`](Guarded::or_default) | "the default is the right answer here" | *nothing* — the gate already did it |
/// | [`or`](Guarded::or) | "use this instead when the guard was off" | one `cond_select` per native slot |
/// | [`assert_read`](Guarded::assert_read) | "the guard must have held" | one `Assert` |
///
/// `or_default` being free is worth stating plainly, because the instinct is
/// to expect a type-system win to cost rows: the wire already IS the default
/// when the guard is off, so naming that fact emits nothing at all.
#[must_use = "a guarded read is the type's DEFAULT when its guard was off — say which you \
              mean with `.or_default()`, `.or(..)` or `.assert_read(c)`"]
pub struct Guarded<T, V: Visibility> {
    value: T,
    guard: Wire3<FieldT, V>,
}

impl<T, V: Visibility> Guarded<T, V> {
    /// Wrap a value read under `guard`.
    ///
    /// Crate-private: only [`Circuit3::when`] / [`Circuit3::when_private`]
    /// (via [`Branches::guarded`]) may mint one, so holding a `Guarded` is
    /// proof it came from the scope — the one spelling of a conditional read
    /// (notes/edsl-trim.org §B). Contract code never calls this directly.
    pub(crate) fn new(value: T, guard: Wire3<FieldT, V>) -> Self {
        Guarded { value, guard }
    }

    /// Take the value, accepting the type's default where the guard was off.
    ///
    /// ZERO INSTRUCTIONS. The gate already yielded the default; this only
    /// records that the caller meant it.
    pub fn or_default(self) -> T {
        self.value
    }

    /// The guard the read carried, for a caller doing its own selection.
    pub fn guard(&self) -> Wire3<FieldT, V> {
        self.guard
    }
}

impl<T: Select<V>, V: Visibility> Guarded<T, V> {
    /// Take the value, substituting `fallback` where the guard was off.
    ///
    /// One `cond_select` per native slot of `T` — the same instructions the
    /// caller would write by hand, on the same guard.
    pub fn or(self, c: &mut Circuit3, fallback: T) -> T {
        T::select(c, self.guard, self.value, fallback)
    }
}

impl<T, V: Visibility> Guarded<T, V> {
    /// Take the value and REQUIRE that the guard held: `assert(guard)`.
    ///
    /// One `Assert`. Turns "may not have been read" into "was read", at the
    /// price of making the circuit unsatisfiable on the path where it was
    /// not — which is a statement about the protocol, so it is spelled out
    /// rather than defaulted to.
    pub fn assert_read(self, c: &mut Circuit3) -> T {
        c.assert_with(self.guard, Some("guarded read: the guard must hold"));
        self.value
    }
}

impl<T: Clone, V: Visibility> Clone for Guarded<T, V> {
    fn clone(&self) -> Self {
        Guarded { value: self.value.clone(), guard: self.guard }
    }
}

impl<T: Copy, V: Visibility> Copy for Guarded<T, V> {}

/// A value that a conditional can SELECT between: one `cond_select` per
/// native slot.
///
/// Implemented in the frontend for a bare wire and in `minocrab-std` for the
/// typed leaves, so [`Circuit3::when_value`] works on whatever a branch
/// actually produces rather than only on field elements.
pub trait Select<V: Visibility>: Sized {
    /// `bit ? taken : fallback`, slotwise.
    fn select(c: &mut Circuit3, bit: Wire3<FieldT, V>, taken: Self, fallback: Self) -> Self;
}

impl<V: Visibility> Select<V> for Wire3<FieldT, V> {
    fn select(c: &mut Circuit3, bit: Wire3<FieldT, V>, taken: Self, fallback: Self) -> Self {
        Wire3::new(c.b.cond_select(bit.val, taken.val, fallback.val))
    }
}

/// A PUBLIC condition choosing between PRIVATE values — the shape every
/// `when_value` over private data has, now that a scope's condition must be
/// [`OnChainGuard`]. The result is private (the values are); the selection
/// itself is the same `cond_select`. The other mixed case — a private bit
/// over public values — is deliberately absent: the selected value would
/// reveal the bit, so it has no `Select<Private>` for a public `Self`.
impl Select<Public> for Wire3<FieldT, Private> {
    fn select(c: &mut Circuit3, bit: Wire3<FieldT, Public>, taken: Self, fallback: Self) -> Self {
        Wire3::new(c.b.cond_select(bit.val, taken.val, fallback.val))
    }
}

/// Arrays select elementwise — a bounded vector's slots.
impl<V: Visibility, T: Select<V>, const N: usize> Select<V> for [T; N] {
    fn select(c: &mut Circuit3, bit: Wire3<FieldT, V>, taken: Self, fallback: Self) -> Self {
        let mut out = Vec::with_capacity(N);
        for (a, b) in taken.into_iter().zip(fallback) {
            out.push(T::select(c, bit, a, b));
        }
        match <[T; N]>::try_from(out) {
            Ok(array) => array,
            Err(_) => unreachable!("one selection per element"),
        }
    }
}

/// Tuples select componentwise — a fold's carried state is often a pair.
macro_rules! select_tuples {
    ($( ($($t:ident $i:tt),+) ),* $(,)?) => {$(
        impl<V: Visibility, $($t: Select<V>),+> Select<V> for ($($t,)+) {
            fn select(c: &mut Circuit3, bit: Wire3<FieldT, V>, a: Self, b: Self) -> Self {
                ($( $t::select(c, bit, a.$i, b.$i), )+)
            }
        }
    )*};
}

select_tuples! {
    (A 0, B 1),
    (A 0, B 1, C 2),
    (A 0, B 1, C 2, D 3),
}

/// An if / else-if / else chain that produces a VALUE — see
/// [`Circuit3::when_value`].
/// Unfinished, it produces nothing — so leaving off `otherwise` is a warning
/// rather than a chain that silently emitted its arms and discarded them:
///
/// ```compile_fail
/// # #![deny(unused_must_use)]
/// # use minocrab::v3::{Circuit3, FieldT};
/// # let mut c = Circuit3::new();
/// # let g = c.arg::<FieldT>("g");
/// # let x = c.arg::<FieldT>("x");
/// c.when_value(g, |_c| x);
/// ```
#[must_use = "a value chain produces nothing until `otherwise` supplies the fallback"]
pub struct ValueBranches<'a, V: Visibility, T> {
    c: &'a mut Circuit3,
    last: Wire3<FieldT, V>,
    prior: Option<Wire3<FieldT, V>>,
    /// The value chosen by the arms so far.
    chosen: T,
}

impl<V: Visibility, T: Select<V>> ValueBranches<'_, V, T> {
    /// The next arm: its value wins where `cond` holds and no earlier arm
    /// matched. Costs one `cond_select` per slot of `T`, plus two to thread
    /// the guard — see [`Circuit3::when_value`] for the whole table.
    pub fn else_when(
        self,
        cond: impl GuardCond<V>,
        body: impl FnOnce(&mut Circuit3) -> T,
    ) -> Self {
        let ValueBranches {
            c,
            last,
            prior,
            chosen,
        } = self;
        let prior = unmatched_after(c, last, prior);
        let cond = cond.into_guard(c);
        let guard = arm_guard(c, cond, Some(prior));
        let value = c.guarded(guard, body);
        let chosen = T::select(c, guard, value, chosen);
        ValueBranches {
            c,
            last: cond,
            prior: Some(prior),
            chosen,
        }
    }

    /// The fallback, and the only way to get the value out — so a value chain
    /// is EXHAUSTIVE by construction. Costs one `cond_select` per slot of
    /// `T`, plus one to thread the guard.
    ///
    /// Dropping the result is a warning, because it means every arm was
    /// emitted for nothing:
    ///
    /// ```compile_fail
    /// # #![deny(unused_must_use)]
    /// # use minocrab::v3::{Circuit3, FieldT};
    /// # let mut c = Circuit3::new();
    /// # let g = c.arg::<FieldT>("g");
    /// # let g = c.disclose(g, "g");
    /// # let x = c.arg::<FieldT>("x");
    /// c.when_value(g, |_c| x).otherwise(|_c| x);
    /// ```
    ///
    /// ```
    /// # #![deny(unused_must_use)]
    /// # use minocrab::v3::{Circuit3, FieldT};
    /// # let mut c = Circuit3::new();
    /// # let g = c.arg::<FieldT>("g");
    /// # let g = c.disclose(g, "g");
    /// # let x = c.arg::<FieldT>("x");
    /// let chosen = c.when_value(g, |_c| x).otherwise(|_c| x);
    /// c.assert(chosen.into_inner());
    /// ```
    pub fn otherwise(self, body: impl FnOnce(&mut Circuit3) -> T) -> Selected<T> {
        let ValueBranches {
            c,
            last,
            prior,
            chosen,
        } = self;
        let guard = unmatched_after(c, last, prior);
        let value = c.guarded(guard, body);
        Selected(T::select(c, guard, value, chosen))
    }
}

/// An if / else-if / else chain in progress — see [`Circuit3::when`].
///
/// Holds the condition of the arm just run and the "nothing had matched"
/// accumulator from BEFORE it. The new accumulator is computed only when
/// another arm actually arrives, so a bare `c.when(cond, ..)` — a plain `if`
/// with no `else` — emits nothing beyond the arm itself. (An unused
/// instruction is a real row; `tests/backend_folding.rs` measures it.)
pub struct Branches<'a, V: Visibility, R = ()> {
    c: &'a mut Circuit3,
    last: Wire3<FieldT, V>,
    /// `None` is the constant 1 — no arm before this one.
    prior: Option<Wire3<FieldT, V>>,
    /// What the first arm's body returned — a read made inside the scope,
    /// or `()` for an effect-only arm.
    value: R,
    /// A [`Circuit3::when_private`] chain: every further arm is a private
    /// scope too, so the on-chain emitters keep refusing inside it.
    private: bool,
}

/// `prior && !last`, the accumulator after an arm. Split out because both
/// chain kinds need it and neither should compute it early.
fn unmatched_after<V: Visibility>(
    c: &mut Circuit3,
    last: Wire3<FieldT, V>,
    prior: Option<Wire3<FieldT, V>>,
) -> Wire3<FieldT, V> {
    let fallback = match prior {
        Some(p) => Arg::Val(p.val),
        None => Arg::Imm(Fr::from(1u64)),
    };
    Wire3::new(c.b.cond_select(last.val, Fr::from(0u64), fallback))
}

/// `prior && cond`, the guard of an arm.
fn arm_guard<V: Visibility>(
    c: &mut Circuit3,
    cond: Wire3<FieldT, V>,
    prior: Option<Wire3<FieldT, V>>,
) -> Wire3<FieldT, V> {
    match prior {
        None => cond,
        Some(p) => Wire3::new(c.b.cond_select(p.val, cond.val, Fr::from(0u64))),
    }
}

impl<V: Visibility> Branches<'_, V, ()> {
    /// The next arm: runs where `cond` holds and no earlier arm matched.
    pub fn else_when(self, cond: impl GuardCond<V>, body: impl FnOnce(&mut Circuit3)) -> Self {
        let Branches { c, last, prior, private, .. } = self;
        let prior = unmatched_after(c, last, prior);
        let cond = cond.into_guard(c);
        let guard = arm_guard(c, cond, Some(prior));
        c.scoped(private, guard, body);
        Branches {
            c,
            last: cond,
            prior: Some(prior),
            value: (),
            private,
        }
    }

    /// The final arm: runs where NO earlier arm matched.
    pub fn otherwise(self, body: impl FnOnce(&mut Circuit3)) {
        let Branches { c, last, prior, private, .. } = self;
        let guard = unmatched_after(c, last, prior);
        c.scoped(private, guard, body);
    }
}

/// A value read inside a scope: the body of [`Circuit3::when`] /
/// [`Circuit3::when_private`] returned it, and it is the type's DEFAULT
/// wherever the guard was off (a skipped read's wires hold zero, a skipped
/// witness yields the default). These are the three ways to take it out,
/// and the [`Guarded`] they go through says so in its `#[must_use]`.
impl<V: Visibility, R> Branches<'_, V, R> {
    /// The body's value as a [`Guarded`], to hand on or decide about later.
    pub fn guarded(self) -> Guarded<R, V> {
        Guarded::new(self.value, self.last)
    }

    /// The value, accepting the default where the guard was off. ZERO
    /// instructions.
    pub fn or_default(self) -> R {
        self.value
    }

    /// The value, with `fallback` where the guard was off: one `cond_select`
    /// per slot of `R`.
    pub fn or(self, fallback: R) -> R
    where
        R: Select<V>,
    {
        let Branches { c, last, value, .. } = self;
        R::select(c, last, value, fallback)
    }

    /// The value, and an `assert(guard)`: the read MUST have happened.
    pub fn assert_read(self) -> R {
        let Branches { c, last, value, .. } = self;
        c.assert_with(last, Some("guarded read: the guard must hold"));
        value
    }
}

/// One element of an Impact public-input block: an inline constant or a
/// circuit-computed (necessarily public) native value.
#[derive(Clone, Copy)]
pub enum ImpactElem {
    Imm(Fr),
    Wire(Wire3<FieldT, Public>),
}

// --- operands -------------------------------------------------------------------

/// What an instruction takes: a wire, or an INLINE IMMEDIATE.
///
/// v3 has no `LoadImm` — an immediate is an operand of the instruction that
/// uses it (`{"op": "less_than", "a": {"immediate": "0"}, …}`), so a native
/// Rust value in an operand position costs NOTHING. Naming one first
/// (`let zero = c.constant(0u64); c.less_than(zero, x, 64)`) emits a `Copy`
/// whose only purpose is the name.
///
/// The type parameters are the ones a wire carries, so an operand cannot
/// launder either of them:
/// - `T` is the ZKIR value type. An immediate is a native field element, so
///   only `Operand<FieldT, _>` has literal conversions — `c.test_eq(point,
///   1u64)` does not compile, and never reaches [`Builder3`]'s type check.
/// - `V` is the visibility, and immediates are [`Public`] because a
///   constant is part of the circuit. Mixing follows the usual [`Meet`]: a
///   comparison of a private wire against a literal is private, since
///   `Private ⊓ Public = Private`.
///
/// Construction is `From`, so call sites write the value itself: a wire, a
/// `u64`, a `bool`, or an [`Fr`] for a wider constant.
pub struct Operand<T: IrTy, V: Visibility> {
    arg: Arg,
    _marker: PhantomData<(T, V)>,
}

impl<T: IrTy, V: Visibility> Clone for Operand<T, V> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T: IrTy, V: Visibility> Copy for Operand<T, V> {}

impl<T: IrTy, V: Visibility> Operand<T, V> {
    fn arg(self) -> Arg {
        self.arg
    }

    /// This operand seen at the meet of its visibility with `W` — which is
    /// either its own visibility or [`Private`], never the other way round.
    ///
    /// It is `Wire3::private` generalized to the lattice, and it exists so
    /// that a MIXED comparison can be assembled: both sides of
    /// `less_than(0u64, secret)` become operands at `Public ⊓ Private`
    /// before the instruction is built.
    pub fn meet<W: Visibility>(self) -> Operand<T, <V as Meet<W>>::Out>
    where
        V: Meet<W>,
    {
        Operand {
            arg: self.arg,
            _marker: PhantomData,
        }
    }
}

impl<T: IrTy, V: Visibility> From<Wire3<T, V>> for Operand<T, V> {
    fn from(w: Wire3<T, V>) -> Self {
        Operand {
            arg: Arg::Val(w.val),
            _marker: PhantomData,
        }
    }
}

/// Immediates: native only, and [`Public`] — the visibility an inline
/// constant has.
macro_rules! immediate_operand {
    ($($ty:ty => |$v:ident| $conv:expr),* $(,)?) => {$(
        impl From<$ty> for Operand<FieldT, Public> {
            fn from($v: $ty) -> Self {
                Operand {
                    arg: Arg::Imm($conv),
                    _marker: PhantomData,
                }
            }
        }
    )*};
}

immediate_operand! {
    Fr => |v| v,
    u64 => |v| Fr::from(v),
    u32 => |v| Fr::from(u64::from(v)),
    u8 => |v| Fr::from(u64::from(v)),
    bool => |v| Fr::from(u64::from(v)),
}

impl<V: Visibility> Clone for AnyWire3<V> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<V: Visibility> Copy for AnyWire3<V> {}

// --- disclosure records ----------------------------------------------------------

/// What a v3 circuit reveals, recorded at build time — the v3 twin of
/// [`Disclosure`](crate::Disclosure).
///
/// It differs from the v2 record in the one way v3 differs from v2 about
/// values: v2 names a disclosed value by its ZKIR *memory index*, and v3
/// values have no index — they are [`Identifier`]s (`%label.N`), which is
/// what the instruction stream refers to and what the simulator keys its
/// value memory by. So the record carries identifiers, and a v3 report can
/// resolve a disclosure to the value it actually took in a run (the v3
/// record used to store a hard-coded `index: 0`, which resolved to
/// nothing).
///
/// One record is one *logical* value, so `values` is a list: a
/// `Bytes<32>` disclosed under one label contributes both of its limbs
/// here rather than two records named `"… (hi)"` and `"… (lo)"`. That is
/// what makes a declared label set comparable to the disclosed one — labels
/// are per value, not per wire (notes/contract-api.org §Disclosure
/// declaration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disclosure3 {
    /// What is being disclosed and why — the label type's
    /// `DisclosureLabel::LABEL` for a declared disclosure, the call site's
    /// string otherwise.
    pub label: String,
    /// How it leaves the circuit.
    pub kind: DisclosureKind,
    /// The disclosed value's wires, in wire order.
    pub values: Vec<DisclosedWire>,
}

/// One wire of a [`Disclosure3`] — a name the run's memory can be keyed by,
/// or the CONSTANT it holds.
///
/// The constant arm is what keeps the valued report whole under the
/// constant-folding pass (notes/ir-passes.org §2 ii): a `Copy` of an immediate
/// is inlined into its consumers and dropped, so a disclosed constant has no
/// identifier left to look up — but its value was never in doubt, and saying
/// so is strictly more informative than a name would have been.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisclosedWire {
    /// A computed wire, resolved through the run's memory.
    Named(Identifier),
    /// A constant, known without running anything.
    Constant(Fr),
}

// --- circuit ---------------------------------------------------------------------

/// What [`Circuit3::assert`] accepts.
///
/// A boolean wire is the base case. The other implementor is
/// `minocrab_std::v3::Check`, the deferred predicate — an inert descriptor
/// that emits its comparison HERE, at the assert, and nothing anywhere else
/// (an unasserted predicate emits nothing at all, and warns, being
/// `#[must_use]`).
pub trait Assertion {
    /// Emit this assertion into `c`.
    fn assert_in(self, c: &mut Circuit3);
}

impl<V: Visibility> Assertion for Wire3<FieldT, V> {
    fn assert_in(self, c: &mut Circuit3) {
        c.assert_with(self, None);
    }
}

/// Compact's `assert(cond, "message")` second argument, kept beside the
/// instruction stream: the message and the position of the `Assert` it
/// belongs to. Metadata only — ZKIR has no room for it, and a simulator
/// uses it to name a failed check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertMessage {
    /// Index of the `Assert` instruction this message belongs to — in the
    /// FINISHED stream (`Compiled3::ir`) once [`Circuit3::finish`] has run,
    /// which moves it across the instructions the passes delete.
    pub instruction: usize,
    /// What the check means, in the contract author's words.
    pub message: String,
}

/// A ZKIR v3 circuit under construction.
pub struct Circuit3 {
    b: Builder3,
    disclosures: Vec<Disclosure3>,
    witnesses: u32,
    regions: Vec<Region>,
    queued_outputs: Vec<(Val, IrType)>,
    assert_messages: Vec<AssertMessage>,
    /// The AMBIENT GUARD stack — see [`Circuit3::guarded`]. Each entry is
    /// already the conjunction of itself and everything below it, so the top
    /// is the effective guard and reading it costs nothing.
    guards: Vec<Val>,
    /// How many [`Circuit3::when_private`] scopes are open. Inside one, the
    /// on-chain emitters (`v3/effects.rs`) refuse at build time.
    private_scopes: u32,
    /// Gadget scratch state — see [`Circuit3::ext_insert`].
    ext: std::collections::BTreeMap<std::any::TypeId, Box<dyn std::any::Any>>,
    /// The DEFERRED Impact programs — see [`Circuit3::then`]. Each was
    /// lowered at attachment and is emitted, in this order, when the body
    /// ends, under the guard captured at attachment.
    deferred: Vec<DeferredImpact>,
    /// Transcript reads the programmer has NAMED AS STALE-ABLE
    /// (`Assumed::stale`, notes/hooks-design.org): a value descending from
    /// one of these may re-enter the ledger; one descending from any other
    /// read is refused at the ledger boundary — see
    /// [`Circuit3::refuse_stale`].
    acknowledged_reads: std::collections::HashSet<Val>,
    /// What each transcript read was, in the ledger layer's words (`cell
    /// read at field 3`), for the refusal to name it.
    read_labels: std::collections::BTreeMap<Val, String>,
}

/// One attached [`Deferred`] program: its instructions and the ambient
/// guard at attachment (`None` for straight-line code).
pub(crate) struct DeferredImpact {
    pub(crate) guard: Option<Val>,
    pub(crate) ops: Vec<Vec<ImpactElem>>,
}

/// A program the circuit EMITS AFTER ITS BODY — the ledger hook of
/// notes/hooks-design.org, at the level this crate sees it: a list of Impact
/// instructions, lowered once at attachment.
///
/// [`Circuit3::then`] lowers the value on the spot (so its wires are the
/// values they are at the `then`), records the ambient guard, and holds
/// the instructions until the body has emitted everything else; then every
/// attached program is emitted in attachment order, each under its own
/// captured guard. The transcript therefore runs the body's inline effects
/// first — including writes that appear textually after the `then` — and
/// the hooks after them, which is the order the design states and the
/// order a reader of the circuit should assume.
pub trait Deferred {
    /// The instructions, one `Vec<ImpactElem>` per Impact op, with every
    /// circuit-computed element a [`Public`] wire.
    fn lower(self, c: &mut Circuit3) -> Vec<Vec<ImpactElem>>;
}

/// A finished v3 circuit: the lowered ZKIR plus its disclosure record.
pub struct Compiled3 {
    pub ir: IrSource,
    pub disclosures: Vec<Disclosure3>,
    pub witnesses: u32,
    pub regions: Vec<Region>,
    /// The messages of the asserts that carry one (see [`AssertMessage`]).
    pub assert_messages: Vec<AssertMessage>,
}

impl Compiled3 {
    /// The message of the assert at instruction `index`, if it has one.
    pub fn assert_message(&self, index: usize) -> Option<&str> {
        self.assert_messages
            .iter()
            .find(|m| m.instruction == index)
            .map(|m| m.message.as_str())
    }
}

impl Default for Circuit3 {
    fn default() -> Self {
        Self::new()
    }
}

impl Circuit3 {
    pub fn new() -> Self {
        Circuit3 {
            b: Builder3::new(),
            disclosures: Vec::new(),
            witnesses: 0,
            regions: Vec::new(),
            queued_outputs: Vec::new(),
            assert_messages: Vec::new(),
            guards: Vec::new(),
            private_scopes: 0,
            ext: std::collections::BTreeMap::new(),
            deferred: Vec::new(),
            acknowledged_reads: std::collections::HashSet::new(),
            read_labels: std::collections::BTreeMap::new(),
        }
    }

    // --- the stale-read backstop --------------------------------------------------

    /// Name a transcript read's wires, so a refusal can say which read a
    /// value descends from. The ledger layer calls this after minting.
    pub fn label_reads(&mut self, wires: &[Wire3<FieldT, Public>], label: &str) {
        let vals: Vec<Val> = wires.iter().map(|w| w.val).collect();
        self.label_read_vals(&vals, label);
    }

    /// [`Circuit3::label_reads`] on raw values — for a typed gate (a point
    /// cell's read) that is not a `FieldT` wire.
    pub fn label_read_vals(&mut self, vals: &[Val], label: &str) {
        for &v in vals {
            self.read_labels.insert(v, label.to_string());
        }
    }

    /// Mark every transcript read behind `wires` as ACKNOWLEDGED: the
    /// programmer has said, by writing `.stale()`, that the transaction
    /// assumes those values are still current at landing. Values derived
    /// from them may then re-enter the ledger.
    pub fn acknowledge_stale(&mut self, wires: &[Val]) {
        for &w in wires {
            let reads = self.b.transcript_reads_behind(w, &|_| false);
            self.acknowledged_reads.extend(reads);
        }
    }

    /// The BACKSTOP at the ledger boundary (notes/hooks-design.org, "Stale
    /// values must be named"): refuse a value that descends from a
    /// transcript read the programmer has not acknowledged with `.stale()`,
    /// naming the read. The types catch a read result used directly (an
    /// `Assumed<T>` has no ledger representation); this catches what was
    /// COMPUTED from one, which Rust's types do not carry. A build-time
    /// error, the last rung of the rejection ladder, recorded for review.
    #[track_caller]
    pub fn refuse_stale(&self, wires: &[Val], what: &str) {
        for &w in wires {
            let acknowledged = &self.acknowledged_reads;
            let reads = self.b.transcript_reads_behind(w, &|v| acknowledged.contains(&v));
            if let Some(read) = reads.first() {
                let label = self
                    .read_labels
                    .get(read)
                    .cloned()
                    .unwrap_or_else(|| "a transcript read".to_string());
                let at = self
                    .b
                    .instruction_index_of(*read)
                    .map(|i| format!(" (instruction {i})"))
                    .unwrap_or_default();
                panic!(
                    "{what} descends from {label}{at}, an inline ledger read the transaction \
                     ASSUMES is still current at landing, and nothing names that assumption. \
                     Write `.stale(c)` on the value you read (`let x = SLOT.read(c).stale(c);`) \
                     to record it — or, if the write must not go stale, move it into a hook \
                     (`c.then(Hook::new()…)`) that computes it on the ledger instead."
                );
            }
        }
    }

    // --- gadget scratch state ---------------------------------------------------

    /// Store one value of type `T` on the circuit, replacing any previous
    /// one — GADGET SCRATCH STATE, keyed by type.
    ///
    /// A gadget that wants per-circuit memoisation (the kernel.self cache
    /// is the in-tree example; a third-party gadget crate has the same
    /// need and no fork to put a field in) parks its state here under its
    /// own private type, so two gadgets can never collide and nothing here
    /// is nameable from outside the module that owns the type. This is
    /// metadata for CONSTRUCTION only: nothing in the extension map
    /// reaches the lowered [`Compiled3`].
    pub fn ext_insert<T: std::any::Any>(&mut self, value: T) {
        self.ext
            .insert(std::any::TypeId::of::<T>(), Box::new(value));
    }

    /// The stored `T`, if [`Circuit3::ext_insert`] has run for it.
    pub fn ext_get<T: std::any::Any>(&self) -> Option<&T> {
        self.ext
            .get(&std::any::TypeId::of::<T>())
            .and_then(|b| b.downcast_ref())
    }

    // --- circuit arguments (witness data, like v2 args) -------------------------

    /// Declare the next circuit argument. Must precede all instructions.
    pub fn arg<T: IrTy>(&mut self, label: &str) -> Wire3<T, Private> {
        Wire3::new(self.b.input(label, T::ir_type()))
    }

    /// Argument slots declared so far — the entry-point core checks it
    /// against the argument list's declared width.
    pub fn arg_count(&self) -> usize {
        self.b.input_count()
    }

    /// Instructions built so far — the entry-point core checks that
    /// argument declaration emitted none.
    pub fn instruction_count(&self) -> usize {
        self.b.len()
    }

    // --- inputs ------------------------------------------------------------------

    /// Read the next witness value from the private transcript.
    pub fn witness<T: IrTy>(&mut self) -> Wire3<T, Private> {
        // THE AMBIENT GUARD REACHES WITNESSES, and it has to: a guarded
        // private input yields the default and does NOT consume the private
        // transcript when its guard is false, so a witness read unguarded
        // inside a branch would consume a value on the path that was not
        // taken. That is a semantic difference, not a framing one — the
        // witness stream itself moves — and it is invisible to a differential
        // on an honest preimage, which is the failure mode guard scoping
        // exists to close (`Circuit3::guarded`'s third bullet).
        let guard = self.effect_guard(None);
        Wire3::new(self.emit_private_input(T::ir_type(), guard))
    }

    /// Read the next witness value under a guard (false ⇒ default value,
    /// transcript not consumed).
    ///
    /// The explicit guard RESOLVES AGAINST THE AMBIENT SCOPE, like every
    /// effect's does (`Circuit3::effect_guard`): inside a
    /// [`Circuit3::when`], the witness is consumed only where BOTH hold.
    /// Passed through verbatim, as it once was, a `_guarded` witness under
    /// a scope consumed the private transcript on the path not taken
    /// whenever its own guard was true — shifting every later witness, and
    /// invisible to a differential on an honest preimage.
    /// Contract code should reach for [`Circuit3::when`] /
    /// [`Circuit3::when_private`] instead — the scope resolves the guard
    /// automatically, so a plain [`Circuit3::witness`] inside one IS this.
    /// This is the primitive the scope lowers to, kept as the twin
    /// `minocrab-std/tests/v3_guard_scope.rs` compares the scoped form
    /// against, byte for byte.
    pub fn witness_guarded<T: IrTy, V: Visibility>(
        &mut self,
        guard: Wire3<FieldT, V>,
    ) -> Wire3<T, Private> {
        let guard = self.effect_guard(Some(Arg::Val(guard.val)));
        Wire3::new(self.emit_private_input(T::ir_type(), guard))
    }

    /// Read the next value from the public transcript (visible on-chain).
    #[track_caller]
    pub fn public_transcript_input<T: IrTy>(&mut self) -> Wire3<T, Public> {
        // Picks up the ambient guard, so a read inside `guarded` needs no
        // `_guarded` variant at the call site.
        let guard = self.effect_guard(None);
        Wire3::new(self.emit_public_input(T::ir_type(), guard))
    }

    /// Guarded public-transcript read.
    ///
    /// The explicit guard RESOLVES AGAINST THE AMBIENT SCOPE, exactly as an
    /// emitted op's does — without this, a `_guarded` read inside
    /// [`Circuit3::when`] would fire its gates on the raw condition while
    /// its op embed (which goes through `Circuit3::effect_guard`) stays
    /// correctly skipped, shifting every later read's public inputs by the
    /// orphaned gates. Found by the AA manager port: `sendUnshielded`'s
    /// auto-receive `kernel.self` read is guarded by `recipient.is_left`,
    /// and the manager is the first contract to run it inside a branch
    /// (`custodyDispatch`'s `isWithdrawUnshielded` arm), where a named-swap
    /// call has `is_left` true while the arm is off. Straight-line callers
    /// are untouched — with no ambient guard the operand passes through
    /// unchanged.
    /// Contract code should reach for [`Circuit3::when`] instead — the scope
    /// resolves the guard automatically, so a plain
    /// [`Circuit3::public_transcript_input`] inside one IS this. This is the
    /// primitive the scope lowers to, kept as the twin
    /// `minocrab-std/tests/v3_guard_scope.rs` compares the scoped form
    /// against, byte for byte.
    #[track_caller]
    pub fn public_transcript_input_guarded<T: IrTy, V: OnChainGuard>(
        &mut self,
        guard: Wire3<FieldT, V>,
    ) -> Wire3<T, Public> {
        let guard = self.effect_guard(Some(Arg::Val(guard.val)));
        Wire3::new(self.emit_public_input(T::ir_type(), guard))
    }

    /// A native-field constant, NAMED: `Copy imm` into a reusable wire.
    ///
    /// Only worth it when the value is used as a wire — a hash preimage
    /// element, a record limb, an Impact guard. In an operand position, pass
    /// the native Rust value itself ([`Operand`]): `c.less_than(0u64, x, 64)`
    /// inlines the immediate and emits no instruction at all, while
    /// `c.less_than(c.constant(0u64), x, 64)` emits this `Copy` first.
    pub fn constant(&mut self, imm: impl Into<Fr>) -> Wire3<FieldT, Public> {
        Wire3::new(self.b.imm(imm))
    }

    /// Name a value that already exists: `Copy val` into a fresh wire.
    ///
    /// Zero rows — a `Copy` is a rename, which is why M9 phase 7's literals
    /// work removed 47 of them without moving a single row, and why this
    /// session's 42 removed the same way (`opcost`: 100 `Copy`s cost 0 rows,
    /// 100 `cond_select`s cost 101). It is NOT a way to make a value cheaper,
    /// and there is no reason to reach for it in ordinary circuit code.
    ///
    /// It exists because compactc's own lowering emits it, and a stdlib
    /// circuit that claims to BE compactc's lowering has to be able to say so:
    /// an `x as Uint<N>` cast names its range-checked result, and
    /// `degradeToTransient` names the limb it degrades
    /// (`minocrab_std::v3::kernel`'s shielded compositions, M17).
    pub fn copy<T: IrTy, V: Visibility>(&mut self, val: Wire3<T, V>) -> Wire3<T, V> {
        Wire3::new(self.b.copy(val.val))
    }

    // --- arithmetic and logic (visibility joins via Meet) --------------------------
    //
    // Every operand position takes an `impl Into<Operand<T, V>>`: a wire, or
    // a native Rust value that becomes an inline immediate (see `Operand`).

    pub fn add<T: EqAddTy, A, B>(
        &mut self,
        a: impl Into<Operand<T, A>>,
        b: impl Into<Operand<T, B>>,
    ) -> Wire3<T, A::Out>
    where
        A: Visibility + Meet<B>,
        B: Visibility,
    {
        Wire3::new(self.b.add(a.into().arg(), b.into().arg()))
    }

    pub fn mul<T: MulTy, A, B>(
        &mut self,
        a: impl Into<Operand<T, A>>,
        b: impl Into<Operand<T, B>>,
    ) -> Wire3<T, A::Out>
    where
        A: Visibility + Meet<B>,
        B: Visibility,
    {
        Wire3::new(self.b.mul(a.into().arg(), b.into().arg()))
    }

    pub fn neg<T: EqAddTy, V: Visibility>(&mut self, a: impl Into<Operand<T, V>>) -> Wire3<T, V> {
        Wire3::new(self.b.neg(a.into().arg()))
    }

    /// `a^(-1)`; unsatisfiable at proving time if `a` is zero.
    pub fn inv<T: MulTy, V: Visibility>(&mut self, a: impl Into<Operand<T, V>>) -> Wire3<T, V> {
        Wire3::new(self.b.inv(a.into().arg()))
    }

    /// Boolean not; the operand must hold 0 or 1.
    pub fn not<V: Visibility>(&mut self, a: impl Into<Operand<FieldT, V>>) -> Wire3<FieldT, V> {
        Wire3::new(self.b.not(a.into().arg()))
    }

    /// Boolean (native) `a == b`.
    pub fn test_eq<T: EqAddTy, A, B>(
        &mut self,
        a: impl Into<Operand<T, A>>,
        b: impl Into<Operand<T, B>>,
    ) -> Wire3<FieldT, A::Out>
    where
        A: Visibility + Meet<B>,
        B: Visibility,
    {
        Wire3::new(self.b.test_eq(a.into().arg(), b.into().arg()))
    }

    /// `a < b` over `bits`-bit native values.
    pub fn less_than<A, B>(
        &mut self,
        a: impl Into<Operand<FieldT, A>>,
        b: impl Into<Operand<FieldT, B>>,
        bits: u32,
    ) -> Wire3<FieldT, A::Out>
    where
        A: Visibility + Meet<B>,
        B: Visibility,
    {
        Wire3::new(self.b.less_than(a.into().arg(), b.into().arg(), bits))
    }

    /// `bit ? a : b`.
    pub fn cond_select<T: EqAddTy, C, A, B>(
        &mut self,
        bit: impl Into<Operand<FieldT, C>>,
        a: impl Into<Operand<T, A>>,
        b: impl Into<Operand<T, B>>,
    ) -> Wire3<T, <C::Out as Meet<B>>::Out>
    where
        C: Visibility + Meet<A>,
        A: Visibility,
        B: Visibility,
        C::Out: Meet<B>,
    {
        Wire3::new(
            self.b
                .cond_select(bit.into().arg(), a.into().arg(), b.into().arg()),
        )
    }

    /// Split into `(w >> bits, w mod 2^bits)`.
    pub fn div_mod_power_of_two<V: Visibility>(
        &mut self,
        w: Wire3<FieldT, V>,
        bits: u32,
    ) -> (Wire3<FieldT, V>, Wire3<FieldT, V>) {
        let (d, m) = self.b.div_mod_power_of_two(w.val, bits);
        (Wire3::new(d), Wire3::new(m))
    }

    /// `divisor * 2^bits + modulus`, checked against field overflow.
    pub fn reconstitute_field<A, B>(
        &mut self,
        divisor: Wire3<FieldT, A>,
        modulus: Wire3<FieldT, B>,
        bits: u32,
    ) -> Wire3<FieldT, A::Out>
    where
        A: Visibility + Meet<B>,
        B: Visibility,
    {
        Wire3::new(self.b.reconstitute_field(divisor.val, modulus.val, bits))
    }

    // --- hashes -----------------------------------------------------------------

    /// Poseidon-family hash of native field elements.
    ///
    /// The operands are wires or, like [`persistent_hash`](Self::persistent_hash)'s,
    /// [`AnyWire3`]s — so a constant element (a domain separator always is one)
    /// can be INLINED into the instruction rather than named by a `Copy` first,
    /// which is the shape compactc emits (the nonce evolution's
    /// `"midnight:kernel:nonce_evolve"`).
    pub fn transient_hash<V: Visibility, O: Copy + Into<AnyWire3<V>>>(
        &mut self,
        inputs: &[O],
    ) -> Wire3<FieldT, V> {
        let args: Vec<Arg> = inputs.iter().map(|&w| w.into().arg).collect();
        Wire3::new(self.b.transient_hash(&args))
    }

    /// SHA-256 persistent hash of `inputs` laid out per `alignment`.
    pub fn persistent_hash<V: Visibility>(
        &mut self,
        alignment: Alignment,
        inputs: &[AnyWire3<V>],
    ) -> Wire3<Bytes32T, V> {
        let args: Vec<Arg> = inputs.iter().map(|w| w.arg).collect();
        Wire3::new(self.b.persistent_hash(alignment, &args))
    }

    /// Keccak-256 of `inputs` laid out per `alignment`.
    pub fn keccak256<V: Visibility>(
        &mut self,
        alignment: Alignment,
        inputs: &[AnyWire3<V>],
    ) -> Wire3<Bytes32T, V> {
        let args: Vec<Arg> = inputs.iter().map(|w| w.arg).collect();
        Wire3::new(self.b.keccak256(alignment, &args))
    }

    /// Hash native field elements to a Jubjub point.
    pub fn hash_to_curve<V: Visibility>(
        &mut self,
        inputs: &[Wire3<FieldT, V>],
    ) -> Wire3<JubjubPointT, V> {
        let args: Vec<Arg> = inputs.iter().map(|w| Arg::Val(w.val)).collect();
        Wire3::new(self.b.hash_to_curve(&args))
    }

    // --- elliptic curves -----------------------------------------------------------

    /// Multiply a point by a scalar of its curve.
    pub fn ec_mul<P: PointTy, A, B>(
        &mut self,
        point: Wire3<P, A>,
        scalar: Wire3<P::Scalar, B>,
    ) -> Wire3<P, A::Out>
    where
        A: Visibility + Meet<B>,
        B: Visibility,
    {
        Wire3::new(self.b.ec_mul(point.val, scalar.val))
    }

    /// Multiply the curve generator matching the scalar's type (Jubjub or
    /// secp256k1).
    pub fn ec_mul_generator<S: GeneratorScalarTy, V: Visibility>(
        &mut self,
        scalar: Wire3<S, V>,
    ) -> Wire3<S::Point, V> {
        Wire3::new(self.b.ec_mul_generator(scalar.val))
    }

    /// The affine coordinates `(x, y)` of a point (unsatisfiable for the
    /// Weierstrass identity).
    pub fn into_coordinates<P: PointTy, V: Visibility>(
        &mut self,
        point: Wire3<P, V>,
    ) -> (Wire3<P::Coord, V>, Wire3<P::Coord, V>) {
        let (x, y) = self.b.into_coordinates(point.val);
        (Wire3::new(x), Wire3::new(y))
    }

    /// Reconstruct a point from affine coordinates (cannot build the
    /// Weierstrass identity).
    pub fn from_coordinates<P: PointTy, A, B>(
        &mut self,
        x: Wire3<P::Coord, A>,
        y: Wire3<P::Coord, B>,
    ) -> Wire3<P, A::Out>
    where
        A: Visibility + Meet<B>,
        B: Visibility,
    {
        Wire3::new(self.b.from_coordinates(P::ir_type(), x.val, y.val))
    }

    // --- Bytes<32> conversions --------------------------------------------------------

    /// The canonical little-endian 32-byte form of a prime-field element.
    pub fn into_bytes32<T: Bytes32ConvTy, V: Visibility>(
        &mut self,
        input: Wire3<T, V>,
    ) -> Wire3<Bytes32T, V> {
        Wire3::new(self.b.into_bytes32(input.val))
    }

    /// A prime-field element from its 32-byte form (non-canonical bytes are
    /// reduced mod the field order).
    pub fn from_bytes32<T: Bytes32ConvTy, V: Visibility>(
        &mut self,
        bytes: Wire3<Bytes32T, V>,
    ) -> Wire3<T, V> {
        Wire3::new(self.b.from_bytes32(bytes.val, T::ir_type()))
    }

    /// Reverse the byte order of a `Bytes<32>` value.
    pub fn reverse_bytes<V: Visibility>(
        &mut self,
        bytes: Wire3<Bytes32T, V>,
    ) -> Wire3<Bytes32T, V> {
        Wire3::new(self.b.reverse_bytes(bytes.val))
    }

    /// Decompose `Bytes<32>` into `(low, high)` native elements (low = bytes
    /// 0..30 LE, high = byte 31) — Compact's field-slot view.
    pub fn bytes32_into_low_high<V: Visibility>(
        &mut self,
        bytes: Wire3<Bytes32T, V>,
    ) -> (Wire3<FieldT, V>, Wire3<FieldT, V>) {
        let (low, high) = self.b.bytes32_into_low_high(bytes.val);
        (Wire3::new(low), Wire3::new(high))
    }

    /// Compose `Bytes<32>` from `(low, high)` native elements.
    pub fn bytes32_from_low_high<A, B>(
        &mut self,
        low: Wire3<FieldT, A>,
        high: Wire3<FieldT, B>,
    ) -> Wire3<Bytes32T, A::Out>
    where
        A: Visibility + Meet<B>,
        B: Visibility,
    {
        Wire3::new(self.b.bytes32_from_low_high(low.val, high.val))
    }

    /// A `JubjubScalar` from a native element (reduces mod the Jubjub
    /// scalar-field order — unlike v2's plain copy).
    pub fn jubjub_scalar_from_native<V: Visibility>(
        &mut self,
        native: Wire3<FieldT, V>,
    ) -> Wire3<JubjubScalarT, V> {
        Wire3::new(self.b.jubjub_scalar_from_native(native.val))
    }

    /// Encode a value as its raw native-element representation.
    pub fn encode<T: IrTy, V: Visibility>(&mut self, input: Wire3<T, V>) -> Vec<Wire3<FieldT, V>> {
        self.b
            .encode(input.val)
            .into_iter()
            .map(Wire3::new)
            .collect()
    }

    // --- constraints -----------------------------------------------------------------

    /// Constrain a condition to be true (constraining private data is the
    /// point of ZK — this discloses nothing).
    ///
    /// Takes anything [`Assertion`]: a boolean wire, or a deferred PREDICATE
    /// that lowers itself here (`minocrab_std::v3::Check` —
    /// `c.assert(less_than(0u64, amount))`). A predicate lowers to exactly
    /// the comparison instruction the hand-written form emits, at this call
    /// site.
    pub fn assert(&mut self, cond: impl Assertion) {
        cond.assert_in(self);
    }

    /// [`Circuit3::assert`] with Compact's second `assert(cond, "message")`
    /// argument.
    ///
    /// The message is METADATA — no instruction, no slot, no row, exactly
    /// like a disclosure record — recorded against the position of the
    /// `Assert` about to be emitted, so a simulator can name the failed
    /// check instead of printing an instruction index. ZKIR has nowhere to
    /// put it, which is why it lives beside the stream rather than in it.
    pub fn assert_with<V: Visibility>(&mut self, cond: Wire3<FieldT, V>, message: Option<&str>) {
        // An assertion inside a guarded scope holds only where the guard
        // does: `assert(select(guard, cond, 1))`. See [`Circuit3::guarded`].
        let guard = self.effect_guard(None);
        self.emit_assert(cond.val, message, guard);
    }

    /// `constrain_eq a b` — either side may be an inline immediate, which is
    /// compactc's own `(constrain_eq ,var-name ,0)` shape: `c.assert_eq(w,
    /// 0u64)` names no constant and so emits no `Copy`.
    ///
    /// Inside a [`Circuit3::when`] it holds only where the guard does, like
    /// every check: `constrain_eq` has no value to select on, so the scoped
    /// form is `test_eq` + `assert(select(guard, eq, 1))` — compactc's own
    /// lowering of `assert(a == b)` in a branch. Straight-line code emits
    /// the direct instruction as before.
    pub fn assert_eq<T: EqAddTy, A: Visibility, B: Visibility>(
        &mut self,
        a: impl Into<Operand<T, A>>,
        b: impl Into<Operand<T, B>>,
    ) {
        let guard = self.effect_guard(None);
        self.emit_constrain_eq(a.into().arg(), b.into().arg(), guard);
    }

    /// `constrain_bits w bits`. Inside a [`Circuit3::when`] the value checked
    /// is `select(guard, w, 0)`, so the constraint holds trivially where the
    /// guard is off — a range check on a value that is only meaningful in
    /// the branch cannot brick the proof outside it.
    ///
    /// RETURNS THE WIRE IT CONSTRAINED: `w` in straight-line code, the
    /// selected wire inside a scope. That selected wire is the branch's
    /// value in compactc's semantics, and it is the one a checked
    /// constructor must hand on — `w` itself is not covered by the check on
    /// the path not taken. Statement-position callers (an entry constraint
    /// on an argument or a guarded read, where the two coincide) may drop it.
    pub fn assert_bits<V: Visibility>(&mut self, w: Wire3<FieldT, V>, bits: u32) -> Wire3<FieldT, V> {
        let guard = self.effect_guard(None);
        Wire3::new(self.emit_constrain_bits(w.val, bits, guard))
    }

    /// `constrain_to_boolean w`; guarded, and returning the constrained wire,
    /// exactly as [`Circuit3::assert_bits`].
    pub fn assert_boolean<V: Visibility>(&mut self, w: Wire3<FieldT, V>) -> Wire3<FieldT, V> {
        let guard = self.effect_guard(None);
        Wire3::new(self.emit_constrain_boolean(w.val, guard))
    }

    // --- disclosure: the only Private → Public gate --------------------------------------

    /// Explicitly make a private value public — the greppable audit point,
    /// as in the v2 frontend.
    ///
    /// The typed form is `minocrab_std::v3::Disclose::disclose_as::<L>`,
    /// which names the disclosure with a label TYPE that the circuit's
    /// `Discloses<..>` declaration also names, so the two cannot drift; this
    /// is its one-wire, free-string base case.
    pub fn disclose<T: IrTy>(&mut self, w: Wire3<T, Private>, label: &str) -> Wire3<T, Public> {
        let [out] = self.disclose_all(label, [w]);
        out
    }

    /// [`Circuit3::disclose`] under a LABEL TYPE — the record every
    /// `Discloses<..>` declaration is checked against. The bare-string form
    /// records [`DisclosureKind::DisclosedUntyped`], which no declaration
    /// accepts (external review §4.5: a string that spells a declared label
    /// must not pass for it); this one records [`DisclosureKind::Disclosed`].
    ///
    /// Crate-private: the public spelling for a single wire is
    /// [`Disclose::disclose_as`] (the value is the receiver, not this
    /// method's argument — see that trait's doc for why). This is the
    /// primitive it delegates to, kept
    /// around because [`Circuit3::disclose_all_as`] and
    /// [`Circuit3::disclose_slice_as`] — the multi-wire primitives
    /// `minocrab-std`'s composite `Disclose` impls call directly — need a
    /// one-wire base case too (notes/edsl-trim.org §D, finding 1).
    pub(crate) fn disclose_as<L: DisclosureLabel, T: IrTy>(
        &mut self,
        w: Wire3<T, Private>,
    ) -> Wire3<T, Public> {
        let [out] = self.disclose_all_as::<L, T, 1>([w]);
        out
    }

    /// [`Circuit3::disclose_all`] under a label type — see
    /// `Circuit3::disclose_as` (crate-private: the public spelling for one
    /// wire is [`Disclose::disclose_as`]).
    pub fn disclose_all_as<L: DisclosureLabel, T: IrTy, const N: usize>(
        &mut self,
        wires: [Wire3<T, Private>; N],
    ) -> [Wire3<T, Public>; N] {
        self.record_disclosure(L::LABEL, DisclosureKind::Disclosed, &wires);
        wires.map(|w| Wire3::new(w.val))
    }

    /// [`Circuit3::disclose_slice`] under a label type — see
    /// `Circuit3::disclose_as` (crate-private: the public spelling for one
    /// wire is [`Disclose::disclose_as`]).
    pub fn disclose_slice_as<L: DisclosureLabel, T: IrTy>(
        &mut self,
        wires: &[Wire3<T, Private>],
    ) -> Vec<Wire3<T, Public>> {
        self.record_disclosure(L::LABEL, DisclosureKind::Disclosed, wires);
        wires.iter().map(|w| Wire3::new(w.val)).collect()
    }

    /// Disclose the wires of ONE logical value under ONE label — a
    /// `Bytes<32>`'s `[hi, lo]` pair becomes a single record rather than a
    /// `"… (hi)"` / `"… (lo)"` pair (see [`Disclosure3`]).
    ///
    /// The BARE-STRING form: its record is [`DisclosureKind::DisclosedUntyped`],
    /// which satisfies no `Discloses<..>` declaration. Call sites that
    /// declare use [`Circuit3::disclose_all_as`] (the typed layer,
    /// `minocrab_std::v3::Disclose`, fans out through it); this one is for
    /// hand-built circuits and tests that declare nothing.
    pub fn disclose_all<T: IrTy, const N: usize>(
        &mut self,
        label: &str,
        wires: [Wire3<T, Private>; N],
    ) -> [Wire3<T, Public>; N] {
        self.record_disclosure(label, DisclosureKind::DisclosedUntyped, &wires);
        wires.map(|w| Wire3::new(w.val))
    }

    /// [`Circuit3::disclose_all`] for a run-time number of wires (a
    /// `Bytes<N>`'s limbs, an event record's fields): still one record.
    pub fn disclose_slice<T: IrTy>(
        &mut self,
        label: &str,
        wires: &[Wire3<T, Private>],
    ) -> Vec<Wire3<T, Public>> {
        self.record_disclosure(label, DisclosureKind::DisclosedUntyped, wires);
        wires.iter().map(|w| Wire3::new(w.val)).collect()
    }

    /// How a disclosure record names one wire: by identifier, or — when the
    /// wire is a named constant the folding pass will inline away — by the
    /// constant itself.
    fn disclosed_wire(&self, val: Val) -> DisclosedWire {
        match self.b.immediate_of(val) {
            Some(imm) => DisclosedWire::Constant(imm),
            None => DisclosedWire::Named(self.b.identifier(val)),
        }
    }

    /// One `Disclosed` record over `wires` — or NONE, if there are no wires.
    /// A value with no wires discloses nothing (a cross-contract call to a
    /// `[]`-returning circuit has an empty result list), and recording it
    /// anyway would put a label in the disclosed set that no value backs.
    fn record_disclosure<T: IrTy>(
        &mut self,
        label: &str,
        kind: DisclosureKind,
        wires: &[Wire3<T, Private>],
    ) {
        if wires.is_empty() {
            return;
        }
        let values = wires.iter().map(|&w| self.disclosed_wire(w.val)).collect();
        self.disclosures.push(Disclosure3 {
            label: label.to_string(),
            kind,
            values,
        });
    }

    // --- public-input blocks and outputs (public only) --------------------------------------

    /// Declare a guarded block of native public inputs (one Impact
    /// instruction). The full ledger-op encoding layer sits above this.
    ///
    /// Contract code should reach for [`Circuit3::when`] instead — the scope
    /// resolves the guard automatically, so an Impact op emitted through the
    /// ledger layer inside one already carries it. This is a primitive the
    /// scope lowers to.
    #[track_caller]
    pub fn impact<V: OnChainGuard>(
        &mut self,
        guard: impl Into<Operand<FieldT, V>>,
        inputs: &[Wire3<FieldT, Public>],
    ) {
        let elems: Vec<ImpactElem> = inputs.iter().map(|&w| ImpactElem::Wire(w)).collect();
        self.impact_mixed(guard, &elems);
    }

    /// [`Circuit3::impact`] with mixed operands: constants go inline as
    /// immediates (as compactc emits opcode/alignment elements), computed
    /// values as wires.
    ///
    /// The GUARD is an operand too (M9 phase 8): a wire for a branch
    /// condition, or the native `true`/`1u64` for a straight-line operation,
    /// which inlines as an immediate instead of naming a `Copy`. compactc
    /// always names one (it threads a `1` wire through every op of a
    /// straight-line circuit), so the immediate form is a deliberate
    /// departure — zero rows, one fewer instruction, and no longer
    /// byte-identical to compactc's stream.
    ///
    /// Contract code should reach for [`Circuit3::when`] instead — the scope
    /// resolves the guard automatically. This is the primitive the scope
    /// lowers to.
    #[track_caller]
    pub fn impact_mixed<V: OnChainGuard>(
        &mut self,
        guard: impl Into<Operand<FieldT, V>>,
        elems: &[ImpactElem],
    ) {
        let args = self.impact_args(elems);
        let guard = self.effect_guard(Some(guard.into().arg()));
        self.emit_impact(guard, &args);
    }

    /// The operands of one Impact instruction, recording each wire among
    /// them as a disclosure — shared by the inline and the deferred
    /// emitters so both keep the same record.
    pub(crate) fn impact_args(&mut self, elems: &[ImpactElem]) -> Vec<Arg> {
        elems
            .iter()
            .map(|e| match e {
                ImpactElem::Imm(imm) => Arg::Imm(*imm),
                ImpactElem::Wire(w) => {
                    let value = self.disclosed_wire(w.val);
                    self.disclosures.push(Disclosure3 {
                        label: "impact public input".to_string(),
                        kind: DisclosureKind::Statement,
                        values: vec![value],
                    });
                    Arg::Val(w.val)
                }
            })
            .collect()
    }

    /// ATTACH a deferred program (a ledger hook): lower it now, capture the
    /// ambient guard, and emit it after the body — see [`Deferred`].
    ///
    /// Inside [`Circuit3::when`] the hook is emitted under that scope's
    /// guard, so it is absent from the transcript where the guard is off.
    /// Inside [`Circuit3::when_private`] it is refused at build time, as
    /// every on-chain effect there is: emitting it later would disclose
    /// the private condition just the same.
    #[track_caller]
    pub fn then<D: Deferred>(&mut self, program: D) {
        let ops = program.lower(self);
        let wires: Vec<Val> = ops
            .iter()
            .flat_map(|op| op.iter())
            .filter_map(|e| match e {
                ImpactElem::Wire(w) => Some(w.val),
                ImpactElem::Imm(_) => None,
            })
            .collect();
        self.refuse_stale(&wires, "a hook argument");
        self.defer_impact(ops);
    }

    /// How many attached programs are waiting to be emitted. Zero after
    /// [`Circuit3::flush_deferred`] / [`Circuit3::finish`].
    pub fn deferred_count(&self) -> usize {
        self.deferred.len()
    }

    /// Queue a wire as a circuit output (the single v3 Output terminator is
    /// emitted by [`Circuit3::finish`]).
    pub fn output<T: IrTy>(&mut self, w: Wire3<T, Public>, label: &str) {
        let value = self.disclosed_wire(w.val);
        self.disclosures.push(Disclosure3 {
            label: label.to_string(),
            kind: DisclosureKind::Output,
            values: vec![value],
        });
        self.queued_outputs.push((w.val, T::ir_type()));
    }

    // --- guard scoping ---------------------------------------------------------------------

    /// THE MECHANISM behind [`Circuit3::when`]: run `body` with `cond` as the
    /// AMBIENT GUARD, so every ledger operation, transcript read and
    /// assertion inside it is guarded by `cond` without naming it.
    ///
    /// Private on purpose. `when` is the one public spelling of a guard —
    /// this returned the body's VALUE, which invites the reading that the
    /// value came from a conditional when in fact it was computed
    /// unconditionally and only its EFFECTS were guarded. A value that
    /// depends on a branch has to be selected, which is
    /// [`Circuit3::when_value`].
    ///
    /// This is the scoped form of the `_under` / `_guarded` argument every
    /// ledger and kernel method carries, and it exists because that argument
    /// does not COMPOSE. A helper called under a branch has to thread the
    /// guard through its whole call graph by hand, and a helper that performs
    /// a transcript read has to know to reach for the `_guarded` variant —
    /// knowledge that lives in no type and is checked by nothing.
    ///
    /// THREE THINGS ARE GUARDED, and the third is the one that makes this a
    /// safety feature rather than a convenience:
    ///
    /// 1. Impact instructions ([`Circuit3::impact_mixed`]).
    /// 2. Public-transcript reads ([`Circuit3::public_transcript_input`]),
    ///    which yield the type's default when the guard is off.
    /// 3. **Checks — every one of them.** `assert(x)` inside a guarded scope
    ///    lowers as `assert(select(guard, x, 1))`; `assert_bits` and
    ///    `assert_boolean` check `select(guard, w, 0)`; `assert_eq` becomes
    ///    `test_eq` + a guarded assert. Each holds only where the guard
    ///    does. Written by hand this is the caller's job and nothing checks
    ///    it, so a check placed inside a conditional fires unconditionally
    ///    and no differential test on an honest preimage can see the
    ///    mistake. There is no unguarded spelling: every effect resolves its
    ///    guard through one private choke point (`v3/effects.rs`), and a
    ///    test pins that nothing bypasses it.
    ///
    /// NESTING is Compact's `&&`: the inner scope's guard is `select(outer,
    /// inner, 0)`, computed ONCE on entry rather than per operation. So
    ///
    /// ```ignore
    /// c.guarded(a, |c| c.guarded(b, |c| { .. }))
    /// ```
    ///
    /// reproduces exactly the shape compactc emits for `if (a && b)`: the
    /// reads between the two scopes are guarded by `a` alone, and everything
    /// in the inner scope by the conjunction.
    fn guarded<V: Visibility, R>(
        &mut self,
        cond: Wire3<FieldT, V>,
        body: impl FnOnce(&mut Self) -> R,
    ) -> R {
        self.push_guard(cond.val);
        let result = body(self);
        self.pop_guard();
        result
    }

    /// Start an if / else-if / else CHAIN — arms are mutually exclusive, and
    /// each one runs where its condition holds and no earlier one matched.
    ///
    /// ```ignore
    /// c.when(a, |c| { .. })
    ///  .else_when(b, |c| { .. })
    ///  .otherwise(|c| { .. });
    /// ```
    ///
    /// `otherwise` is optional: a chain without it is a plain `if / else if`,
    /// and dropping the builder just ends it.
    ///
    /// COST is two `cond_select`s per arm after the first — one to and the
    /// condition with "nothing matched yet", one to update it — and the first
    /// arm and the `otherwise` arm are free, because their guards are already
    /// to hand. A two-arm `when(..).otherwise(..)` is therefore exactly
    /// [`Circuit3::cond_select`], one negation and no more.
    ///
    /// Arms return `()`. A circuit does not branch, so every arm's
    /// instructions are emitted regardless and "the value of the branch that
    /// ran" is not a thing the stream can express — build it with
    /// [`Circuit3::cond_select`] on the arms' results instead, where the
    /// selection is visible.
    ///
    /// The body may RETURN what it read: `c.when(g, |c| map.lookup(c, &k))`
    /// hands the value back through [`Branches::or_default`] /
    /// [`Branches::or`] / [`Branches::assert_read`] (or [`Branches::guarded`]
    /// to pass it on), which is the ONE way a conditional read is spelled —
    /// there is no per-operation guard parameter. A skipped read already
    /// holds the type's default, so `or_default` costs nothing.
    pub fn when<V: OnChainGuard, R>(
        &mut self,
        cond: impl GuardCond<V>,
        body: impl FnOnce(&mut Self) -> R,
    ) -> Branches<'_, V, R> {
        let cond = cond.into_guard(self);
        let value = self.guarded(cond, body);
        Branches {
            c: self,
            last: cond,
            prior: None,
            value,
            private: false,
        }
    }

    /// A scope on a PRIVATE condition, for bodies with no on-chain effect —
    /// Compact's `if (privateBit) { assert(...) }` without a `disclose`.
    ///
    /// [`Circuit3::when`] requires an [`OnChainGuard`]: whether an Impact op
    /// or a public-transcript read ran is visible on chain, so a private
    /// condition guarding one is a disclosure (the external review's §4.1).
    /// But a body that only WITNESSES and CHECKS reveals nothing — a guarded
    /// witness read yields the default and consumes no transcript, a guarded
    /// assert becomes `assert(select(g, x, 1))` — and compactc allows it
    /// without disclosure. This is that scope: the condition may be
    /// `Private`, the body may read witnesses and assert, and the two
    /// on-chain emitters REFUSE inside it at build time with the
    /// disclose-first message. The ladder's last rung, because the scope
    /// stack is dynamic and the type system cannot reach it without a
    /// type-state `Circuit3` (M26).
    ///
    /// Byte-identical to the hand-threaded form (`assert(select(g, x, 1))`,
    /// `witness_guarded(g)`), as `minocrab-std/tests/v3_guard_scope.rs`
    /// pins. Nesting follows [`Circuit3::when`]'s rule (a conjunction); a
    /// public [`Circuit3::when`] INSIDE a private scope is still inside it,
    /// so its on-chain effects are refused too. An `else_when` /
    /// `otherwise` arm of a private chain is a private scope as well.
    ///
    /// Like [`Circuit3::when`], the body may return what it witnessed:
    /// `c.when_private(g, |c| c.witness::<T>()).or_default()` is the guarded
    /// witness read, and the only spelling of one.
    pub fn when_private<V: Visibility, R>(
        &mut self,
        cond: impl GuardCond<V>,
        body: impl FnOnce(&mut Self) -> R,
    ) -> Branches<'_, V, R> {
        let cond = cond.into_guard(self);
        let value = self.scoped(true, cond, body);
        Branches {
            c: self,
            last: cond,
            prior: None,
            value,
            private: true,
        }
    }

    /// [`Circuit3::guarded`], as a private scope when `private` — the arm
    /// runner the two chains share.
    fn scoped<V: Visibility, R>(
        &mut self,
        private: bool,
        cond: Wire3<FieldT, V>,
        body: impl FnOnce(&mut Self) -> R,
    ) -> R {
        if private {
            self.private_scopes += 1;
        }
        let result = self.guarded(cond, body);
        if private {
            self.private_scopes -= 1;
        }
        result
    }

    /// The chain that produces a VALUE — Compact's `if`-as-an-expression.
    ///
    /// ```ignore
    /// let fee = c.when_value(is_premium, |c| tier_a(c))
    ///            .else_when(is_member, |c| tier_b(c))
    ///            .otherwise(|c| standard(c));
    /// ```
    ///
    /// EXHAUSTIVE BY CONSTRUCTION: `otherwise` is the only method that
    /// returns the value, so a chain without a fallback does not type-check.
    /// The effectful [`Circuit3::when`] needs no such rule — an arm that does
    /// not run simply has its effects guarded off — but a value has to come
    /// from somewhere.
    ///
    /// # What it costs
    ///
    /// **Every arm's instructions are emitted, whatever the conditions turn
    /// out to be.** A circuit does not branch, so an `if` costs the SUM of
    /// its arms and never the maximum. That is the setting rather than
    /// anything this API chose, and it is the dominant term whenever the arms
    /// do real work.
    ///
    /// On top of the arms, for `n` arms over a `T` of `s` native slots:
    ///
    /// | | `cond_select`s |
    /// |---|---|
    /// | threading the guards | `2(n − 2) + 3`, and none at all for `n = 1` |
    /// | choosing the value | `s(n − 1)` |
    ///
    /// So a three-arm chain returning a `Bytes<32>` (two slots) is **seven**
    /// selects over the three bodies —
    /// `a_three_arm_value_chain_costs_what_the_docs_say` in
    /// `minocrab-std/tests/v3_guard_scope.rs` pins that number so this table
    /// cannot rot. A `Maybe<T>` counts its tag as a slot; see [`Select`].
    ///
    /// # What it does not cost
    ///
    /// Anything over the hand-written form. The selects are the ones a
    /// careful author writes anyway
    /// (`a_value_chain_is_the_hand_written_select` pins the equality). What
    /// the chain removes is selecting on the wrong guard, and the temptation
    /// to skip guarding the arms' EFFECTS because only the value looked
    /// conditional.
    ///
    /// # When to reach for something else
    ///
    /// The advice is not "avoid it". It is: use it when the branches
    /// genuinely produce a value. Prefer straight-line code with a single
    /// [`Circuit3::cond_select`] at the end when one arm is much dearer than
    /// the others and you would rather pay for that work once,
    /// unconditionally — because the chain will pay for it regardless of
    /// which way the condition goes.
    pub fn when_value<V: OnChainGuard, T: Select<V>>(
        &mut self,
        cond: impl GuardCond<V>,
        body: impl FnOnce(&mut Self) -> T,
    ) -> ValueBranches<'_, V, T> {
        let cond = cond.into_guard(self);
        let chosen = self.guarded(cond, body);
        ValueBranches {
            c: self,
            last: cond,
            prior: None,
            chosen,
        }
    }

    // --- profiling regions ---------------------------------------------------------------

    /// Attribute the instructions built inside `f` to a named region.
    pub fn region<R>(&mut self, label: &str, f: impl FnOnce(&mut Self) -> R) -> R {
        let start = self.b.len();
        let result = f(self);
        self.regions.push(Region {
            label: label.to_string(),
            start,
            end: self.b.len(),
        });
        result
    }

    // --- passes -----------------------------------------------------------------------------

    /// Turn on constraint deduplication for this circuit — THE OPT PROFILE,
    /// and the one pass that is not free.
    ///
    /// With it on, a later range constraint on a wire that an earlier one
    /// already proved at least as tight is dropped at [`Circuit3::finish`]
    /// (`minocrab_ir::v3::passes::dedup_range_constraints`, which states the
    /// soundness argument). A repeated `constrain_bits` is two rows — the
    /// most expensive redundancy in `tests/backend_folding.rs` — so this is
    /// what lets a gadget CHECK the preconditions it currently documents:
    /// `Serializer::constrained` and the checked Borsh readers emit the
    /// range constraints their packing needs, and where the caller already
    /// constrained those wires the pass removes exactly what was added.
    ///
    /// WHY IT IS NOT ON EVERYWHERE. Our primary correctness warrant is
    /// differential equality with compactc, instruction for instruction, and
    /// compactc RE-EMITS: this pass makes us strictly more deduplicated than
    /// the artifact we are checked against. So a circuit that must stay
    /// instruction-comparable to compactc leaves it off, and the M10
    /// lineage — spec-anchored, warranted by symbolic-effect equivalence
    /// rather than PI-equality — is where it may go on. No shipped artifact
    /// flips it today (notes/ir-passes.org §1, §11).
    pub fn dedup_range_constraints(&mut self, on: bool) {
        self.b.dedup_range_constraints(on);
    }

    // --- finish ------------------------------------------------------------------------------

    pub fn finish(mut self, communications_commitment: bool) -> Compiled3 {
        self.flush_deferred();
        if !self.queued_outputs.is_empty() {
            let vals: Vec<Arg> = self
                .queued_outputs
                .iter()
                .map(|(v, _)| Arg::Val(*v))
                .collect();
            self.b.output(&vals);
        }
        // Regions and assert messages hold BUILD-time indices; the passes in
        // `finish` delete instructions, so move both onto the finished stream
        // (notes/ir-passes.org §13). A message whose assert was deleted goes
        // with it; a region whose instructions were all deleted is empty.
        let (ir, kept) = self.b.finish_kept(communications_commitment);
        #[cfg(debug_assertions)]
        let built = (self.regions.clone(), self.assert_messages.clone());
        let regions: Vec<Region> = self
            .regions
            .into_iter()
            .map(|r| Region {
                start: kept.boundary(r.start),
                end: kept.boundary(r.end),
                label: r.label,
            })
            .collect();
        let assert_messages: Vec<AssertMessage> = self
            .assert_messages
            .into_iter()
            .filter_map(|m| {
                kept.position(m.instruction).map(|instruction| AssertMessage {
                    instruction,
                    message: m.message,
                })
            })
            .collect();
        #[cfg(debug_assertions)]
        moved_onto_the_finished_stream(&kept, &built.0, &built.1, &regions, &assert_messages);
        Compiled3 {
            ir,
            disclosures: self.disclosures,
            witnesses: self.witnesses,
            regions,
            assert_messages,
        }
    }
}

/// The metadata `Circuit3::finish` moved, checked one instruction at a time
/// rather than through `Kept::boundary` (debug builds; `Builder3::finish_kept`
/// has already checked each kept instruction against the one it became):
/// every message whose assert survived sits at that assert's finished
/// position, in build order, and every region is exactly the run of finished
/// positions its surviving instructions landed on.
#[cfg(debug_assertions)]
fn moved_onto_the_finished_stream(
    kept: &minocrab_ir::v3::passes::Kept,
    built_regions: &[Region],
    built_messages: &[AssertMessage],
    regions: &[Region],
    messages: &[AssertMessage],
) {
    let survivors: Vec<(usize, &str)> = built_messages
        .iter()
        .filter_map(|m| kept.position(m.instruction).map(|at| (at, m.message.as_str())))
        .collect();
    let moved: Vec<(usize, &str)> = messages.iter().map(|m| (m.instruction, m.message.as_str())).collect();
    assert_eq!(moved, survivors, "Circuit3::finish: a message left its assert");
    for (built, region) in built_regions.iter().zip(regions) {
        let landed: Vec<usize> = (built.start..built.end).filter_map(|i| kept.position(i)).collect();
        let span: Vec<usize> = (region.start..region.end).collect();
        assert_eq!(landed, span, "Circuit3::finish: region {:?} left its instructions", region.label);
        // An emptied region sits where its instructions were: after the
        // survivors in front of it.
        assert_eq!(region.start, kept.boundary(built.start), "region {:?}", region.label);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_wires_track_visibility_and_type() {
        let mut c = Circuit3::new();
        let x = c.witness::<FieldT>();
        let k = c.constant(3u64);
        let s = c.add(x, k.private());
        // s is private: no path to output without disclose.
        let s_pub = c.disclose(s, "witness plus three");
        c.output(s_pub, "sum");

        let pk = c.witness::<Secp256k1PointT>();
        let (px, _py) = c.into_coordinates(pk);
        let px_bytes = c.into_bytes32(px);
        let (lo, _hi) = c.bytes32_into_low_high(px_bytes);
        c.assert_bits(lo, 248);

        let compiled = c.finish(false);
        assert_eq!(compiled.witnesses, 2);
        assert_eq!(compiled.ir.outputs.len(), 1);
    }

    /// The final-stream index of every `Assert`, in order.
    fn assert_positions(compiled: &Compiled3) -> Vec<usize> {
        use minocrab_ir::v3::Instruction;
        compiled
            .ir
            .instructions
            .iter()
            .enumerate()
            .filter(|(_, i)| matches!(i, Instruction::Assert { .. }))
            .map(|(at, _)| at)
            .collect()
    }

    /// `finish` drops instructions (the copy fold, the true-assert rule),
    /// and every message must still name the assert it was written on. Here
    /// `c.assert_with(c.constant(1), ..)` is `copy %k = 1; assert %k`: the
    /// fold removes the copy and the true-assert rule removes the assert, so
    /// two instructions vanish in front of the three real asserts. A message
    /// recorded at its build-time index then lands two asserts late — "x
    /// must hold" on the `z` check — and the dropped assert's message must
    /// go with it.
    #[test]
    fn assert_messages_survive_the_passes_that_drop_instructions() {
        let mut c = Circuit3::new();
        let x = c.arg::<FieldT>("x");
        let y = c.arg::<FieldT>("y");
        let z = c.arg::<FieldT>("z");
        let one = c.constant(1u64);
        c.assert_with(one, Some("cannot fail"));
        c.assert_with(x, Some("x must hold"));
        c.assert_with(y, Some("y must hold"));
        c.assert_with(z, Some("z must hold"));
        let compiled = c.finish(false);

        let asserts = assert_positions(&compiled);
        assert_eq!(asserts.len(), 3, "the constant-true assert is dropped");
        let named: Vec<Option<&str>> = asserts
            .iter()
            .map(|&at| compiled.assert_message(at))
            .collect();
        assert_eq!(
            named,
            [Some("x must hold"), Some("y must hold"), Some("z must hold")]
        );
        assert_eq!(
            compiled.assert_messages.len(),
            3,
            "the dropped assert's message is dropped with it"
        );
        for m in &compiled.assert_messages {
            assert!(asserts.contains(&m.instruction), "{m:?} names no assert");
        }
    }

    /// A region's `[start, end)` is the same build-time position, and moves
    /// the same way: a folded copy in front of a region shifts the span one
    /// instruction late, so the region labelled for the `x` check covered
    /// the `y` check instead. A region whose only instructions were dropped
    /// is empty, and a region around both keeps both.
    #[test]
    fn regions_survive_the_passes_that_drop_instructions() {
        let mut c = Circuit3::new();
        let x = c.arg::<FieldT>("x");
        let y = c.arg::<FieldT>("y");
        c.region("outer", |c| {
            c.region("folded away", |c| {
                let one = c.constant(1u64);
                c.assert(one);
            });
            c.region("x check", |c| c.assert(x));
        });
        c.region("y check", |c| c.assert(y));
        let compiled = c.finish(false);

        let asserts = assert_positions(&compiled);
        assert_eq!(asserts.len(), 2);
        let span = |label: &str| {
            let r = compiled
                .regions
                .iter()
                .find(|r| r.label == label)
                .expect("region recorded");
            (r.start, r.end)
        };
        assert_eq!(span("folded away"), (asserts[0], asserts[0]));
        assert_eq!(span("x check"), (asserts[0], asserts[0] + 1));
        assert_eq!(span("outer"), (asserts[0], asserts[0] + 1));
        assert_eq!(span("y check"), (asserts[1], asserts[1] + 1));
        let len = compiled.ir.instructions.len();
        for r in &compiled.regions {
            assert!(r.start <= r.end && r.end <= len, "{r:?} out of range");
        }
    }
}
