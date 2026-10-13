//! The circuit entry-point core: one trait per argument type that is at
//! once its schema, its declaration and its input constraints, and an
//! [`entry`] that owns the fixed build order every v3 circuit follows.
//!
//! The problem it solves (notes/contract-api.org §Survey): a hand-written
//! circuit declares its arguments in one block and range-constrains them in
//! a second, parallel block, and nothing but the author's eye ties the two
//! together — a missing `assert_bits` is invisible to the differential
//! tests, because an honest preimage satisfies the circuit either way. Here
//! both blocks are generated from the argument's type, so they cannot
//! disagree.
//!
//! The three laws every [`CircuitArg`] impl must satisfy:
//!
//! 1. `declare` touches exactly [`CircuitAbi::SLOTS`] argument slots and
//!    calls nothing but [`Circuit3::arg`] — ZKIR requires every input to
//!    precede every instruction, so declaration cannot compute.
//! 2. `push_atoms` describes exactly those slots, in the same order (the
//!    FAB atoms of the Compact type the argument stands for), and
//!    `push_prims` gives the flattened primitive type of each one.
//! 3. `push_slots` hands back exactly those slots' wires, in the same
//!    order — every slot except the curve-point ones, whose wires are not
//!    field elements (see [`CircuitArg::push_slots`]).
//!
//! Law 3 used to read "`constrain` emits exactly the input constraints
//! compactc emits for that Compact type" — every impl carried its own copy
//! of a rule that lives in one place in compactc (`emit-constraints-for`,
//! reduce-to-zkir.ss:640-667). Since M12 stage 1 it does not:
//! [`CircuitArg::constrain`] is a provided method that zips `push_prims`
//! against `push_slots` and runs [`minocrab::v3::Prim::constraint`], so an
//! impl only says WHAT its slots are, never how they are constrained. The
//! same table is what `minocrab_ledger::contract_call` runs over a
//! cross-contract call's result limbs.
//!
//! [`entry`] enforces the parts of law 1 that are checkable — the slot
//! count and the emptiness of the instruction stream after declaration —
//! and orders the two phases so law 3's "in slot order" is all an impl has
//! to get right.

use minocrab::v3::{
    uint_atom_bytes, Circuit3, CircuitAbi, Compiled3, FieldT, JubjubPointT, Prim,
    Secp256k1PointT, Secp256k1ScalarT, Wire3,
};
use minocrab::{AlignmentAtom, Private, Public};

use super::{
    Bool, BoundedUint, Bytes, Bytes0, BytesN, ContractAddress, Either, JubjubPoint, Maybe,
    MerkleTreeDigest, Opaque, Secp256k1Point, Secp256k1Scalar, ShieldedCoinInfo3,
    ShieldedSendResult, TsType, Uint, UserAddress, Vis3, B32,
};

// ---- argument paths ---------------------------------------------------------

/// The label of one argument slot, built from the argument's name and the
/// path to the slot inside it: segments joined with `_`.
///
/// The rule, stated once for every impl below:
/// - a struct field appends its Compact field name ([`ArgPath::field`]) —
///   `depositRequest` + `erc20Address` = `depositRequest_erc20Address`;
/// - an element of a vector or a limb of a multi-slot leaf appends its
///   index ([`ArgPath::index`]) — `notification_payload_0`;
/// - a structural slot appends the suffix its shape owns
///   ([`ArgPath::suffix`]): `_hi`/`_lo` for a `Bytes<32>` pair, `_is_some`
///   for a `Maybe` tag, `_is_left` for an `Either` tag.
///
/// compactc itself does not flatten struct arguments this way (it repeats
/// the base name: `%depositRequest.5`, `%depositRequest.6`); the joined
/// path is ours and is strictly more informative. Argument names are
/// cosmetic to the ledger ABI — order and type are the contract — so this
/// is a free improvement (notes/contract-api.org §Survey).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArgPath(String);

impl ArgPath {
    /// The argument itself: the Compact parameter name, verbatim.
    pub fn root(name: &str) -> ArgPath {
        ArgPath(name.to_string())
    }

    /// A struct field of this value.
    pub fn field(&self, name: &str) -> ArgPath {
        self.join(name)
    }

    /// Element / limb `i` of this value.
    pub fn index(&self, i: usize) -> ArgPath {
        self.join(&i.to_string())
    }

    /// A structural slot of this value (`hi`, `lo`, `is_some`, `is_left`).
    pub fn suffix(&self, suffix: &str) -> ArgPath {
        self.join(suffix)
    }

    /// The label as `Circuit3::arg` takes it.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn join(&self, segment: &str) -> ArgPath {
        ArgPath(format!("{}_{segment}", self.0))
    }
}

impl std::fmt::Display for ArgPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ---- CircuitArg -------------------------------------------------------------

/// A type usable as (part of) a circuit argument: its ABI ([`CircuitAbi`]),
/// how it is declared, and which wires its slots are — one trait, so a
/// schema and its materialization cannot drift apart (the `CandidType`
/// lesson, notes/contract-api.org §Survey).
///
/// Implemented for [`Private`] leaves only: circuit arguments are witness
/// data, so [`Circuit3::arg`] can only hand back private wires.
///
/// See the module docs for the three laws an impl must satisfy.
#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot be a circuit argument",
    label = "not an argument type",
    note = "circuit arguments are witness data, so the leaves are implemented \
            at `Private` ONLY: write `Uint<64>` / `B32<Private>` / \
            `Bytes<20>`, not their `Public` spellings (`Uint<64>`'s \
            visibility already defaults to `Private`)",
    note = "a struct becomes an argument type with `#[derive(CircuitArg)]`, \
            which needs every field to be one in turn — field order is the \
            wire contract"
)]
pub trait CircuitArg: CircuitAbi + Sized {
    /// Declare the slots — `Circuit3::arg` calls and nothing else.
    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self;

    /// This value's NATIVE slots, in slot order — matching
    /// [`CircuitAbi::push_prims`] one for one, skipping the slots whose
    /// primitive type is [`Prim::Point`].
    ///
    /// The skip is not an exception to law 3, it is the only way to state
    /// it: a curve-point slot holds a `Wire3<Secp256k1PointT, _>`, not a
    /// field element, and compactc's constraint table has nothing to say
    /// about it (`(tpoint …) → no constraint`). Everything a slot list is
    /// used for — emitting constraints, hashing a value's FAB
    /// representation — is native-field work, so a point contributes no
    /// entry. `Prim::Point` marks exactly those positions, which is what
    /// [`CircuitArg::constrain`] filters on.
    fn push_slots(&self, slots: &mut Vec<Wire3<FieldT, Private>>);

    /// Emit compactc's input constraints for this type, in slot order.
    ///
    /// NEVER OVERRIDDEN: the body is the ABI table applied to this type's
    /// own slots, so there is one statement of the rule in the whole
    /// system (see the module docs). An impl that overrode it would be
    /// re-introducing exactly the hand-written parallel copy M12 stage 1
    /// deleted.
    fn constrain(&self, c: &mut Circuit3) {
        let mut slots = Vec::with_capacity(Self::SLOTS);
        self.push_slots(&mut slots);
        // Point slots are not field wires and carry no constraint, so
        // `push_slots` never hands one back (see its docs); the rest line up
        // with the remaining primitive types one for one.
        let prims: Vec<Prim> = Self::prims()
            .into_iter()
            .filter(|prim| !matches!(prim, Prim::Point))
            .collect();
        assert_eq!(
            slots.len(),
            prims.len(),
            "CircuitArg::push_slots gave {} slots for {} native primitive types",
            slots.len(),
            prims.len()
        );
        for (&slot, prim) in slots.iter().zip(prims) {
            prim.constraint().emit(c, slot);
        }
    }
}

impl<const BITS: u32, V: Vis3> CircuitAbi for Uint<BITS, V> {
    const SLOTS: usize = 1;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        atoms.push(AlignmentAtom::Bytes { length: BITS.div_ceil(8) });
    }

    fn push_prims(prims: &mut Vec<Prim>) {
        prims.push(Prim::Uint { bits: BITS });
    }
}

impl<const BITS: u32> CircuitArg for Uint<BITS, Private> {
    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        Uint::from_field_unchecked(c.arg::<FieldT>(path.as_str()))
    }

    fn push_slots(&self, slots: &mut Vec<Wire3<FieldT, Private>>) {
        slots.push(self.field());
    }
}

/// Compact's `Uint<0..BOUND>`: one slot, whose primitive type is the bound
/// itself run through [`Prim::unsigned`] — so which of the four constraints
/// it gets is the TABLE's decision, not this impl's (a `BoundedUint<256>`
/// lands on `constrain_bits 8`, a `BoundedUint<70000>` on `less_than`).
///
/// The FAB atom is `⌈bitlen(BOUND − 1)/8⌉` bytes, which is NOT the width the
/// constraint runs at and NOT the width a comparison runs at — the three
/// differ for a bounded type and coincide for a sized one
/// (notes/bounded-integers.org §2).
impl<const BOUND: u128, V: Vis3> CircuitAbi for BoundedUint<BOUND, V> {
    const SLOTS: usize = 1;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        atoms.push(AlignmentAtom::Bytes {
            length: uint_atom_bytes(BOUND - 1),
        });
    }

    fn push_prims(prims: &mut Vec<Prim>) {
        prims.push(Prim::unsigned(BOUND - 1));
    }
}

impl<const BOUND: u128> CircuitArg for BoundedUint<BOUND, Private> {
    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        BoundedUint::from_field_unchecked(c.arg::<FieldT>(path.as_str()))
    }

    fn push_slots(&self, slots: &mut Vec<Wire3<FieldT, Private>>) {
        slots.push(self.field());
    }
}

impl<V: Vis3> CircuitAbi for Bool<V> {
    const SLOTS: usize = 1;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        atoms.push(AlignmentAtom::Bytes { length: 1 });
    }

    fn push_prims(prims: &mut Vec<Prim>) {
        prims.push(Prim::Uint { bits: 1 });
    }
}

impl CircuitArg for Bool<Private> {
    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        Bool::from_field_unchecked(c.arg::<FieldT>(path.as_str()))
    }

    fn push_slots(&self, slots: &mut Vec<Wire3<FieldT, Private>>) {
        slots.push(self.field());
    }
}

/// `Bytes<0>`: one zero-length atom, no slot, no constraint — exactly what
/// compactc declares for a `Bytes<0>` parameter (`queueAttestation0`'s
/// `serializedOutput` adds no input).
impl<V: Vis3> CircuitAbi for Bytes0<V> {
    const SLOTS: usize = 0;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        atoms.push(AlignmentAtom::Bytes { length: 0 });
    }

    fn push_prims(_prims: &mut Vec<Prim>) {}
}

impl CircuitArg for Bytes0<Private> {
    fn declare(_c: &mut Circuit3, _path: &ArgPath) -> Self {
        Bytes0::new()
    }

    fn push_slots(&self, _slots: &mut Vec<Wire3<FieldT, Private>>) {}
}

impl<const N: usize, V: Vis3> CircuitAbi for Bytes<N, V> {
    const SLOTS: usize = 1;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        atoms.push(AlignmentAtom::Bytes { length: N as u32 });
    }

    fn push_prims(prims: &mut Vec<Prim>) {
        prims.push(Prim::Uint { bits: 8 * N as u32 });
    }
}

impl<const N: usize> CircuitArg for Bytes<N, Private> {
    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        Bytes::from_field_unchecked(c.arg::<FieldT>(path.as_str()))
    }

    fn push_slots(&self, slots: &mut Vec<Wire3<FieldT, Private>>) {
        slots.push(self.field());
    }
}

impl<V: Vis3> CircuitAbi for B32<V> {
    const SLOTS: usize = 2;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        atoms.push(AlignmentAtom::Bytes { length: 32 });
    }

    /// `hi` is byte 31 alone, `lo` the other 31 bytes little-endian.
    fn push_prims(prims: &mut Vec<Prim>) {
        prims.push(Prim::Uint { bits: 8 });
        prims.push(Prim::Uint { bits: 248 });
    }
}

impl CircuitArg for B32<Private> {
    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        B32 {
            hi: c.arg::<FieldT>(path.suffix("hi").as_str()),
            lo: c.arg::<FieldT>(path.suffix("lo").as_str()),
        }
    }

    fn push_slots(&self, slots: &mut Vec<Wire3<FieldT, Private>>) {
        slots.push(self.hi);
        slots.push(self.lo);
    }
}

/// Compact's `Secp256k1Point`: ONE slot that is not a field element — see
/// [`Secp256k1Point`] for why it has no constraint and no native slot, and
/// notes/ledger-abi.org §3 for the five-atom alignment.
impl<V: Vis3> CircuitAbi for Secp256k1Point<V> {
    const SLOTS: usize = 1;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        atoms.push(AlignmentAtom::Bytes { length: 24 }); // x, low 24 bytes
        atoms.push(AlignmentAtom::Bytes { length: 8 }); // x, high 8 bytes
        atoms.push(AlignmentAtom::Bytes { length: 24 }); // y, low 24 bytes
        atoms.push(AlignmentAtom::Bytes { length: 8 }); // y, high 8 bytes
        atoms.push(AlignmentAtom::Field); // the infinity flag
    }

    fn push_prims(prims: &mut Vec<Prim>) {
        prims.push(Prim::Point);
    }
}

impl CircuitArg for Secp256k1Point<Private> {
    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        Secp256k1Point::from_point(c.arg::<Secp256k1PointT>(path.as_str()))
    }

    /// A point slot is not a native field wire: nothing to constrain, and
    /// nothing a slot list could carry it as.
    fn push_slots(&self, _slots: &mut Vec<Wire3<FieldT, Private>>) {}
}

/// Compact's `Secp256k1Scalar`: ONE slot that is not a field element, the
/// same story as [`Secp256k1Point`] one type over — no constraint, no native
/// slot. The FAB atoms are `b24 + b8` (reduce-to-zkir.ss:34-91,
/// notes/ledger-abi.org §3). `Prim::Point` is the marker for "a slot the
/// native-field machinery must skip", which a scalar slot is for exactly the
/// point's reasons; the constraint table maps it to no constraint either way.
impl<V: Vis3> CircuitAbi for Secp256k1Scalar<V> {
    const SLOTS: usize = 1;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        atoms.push(AlignmentAtom::Bytes { length: 24 }); // low 24 bytes
        atoms.push(AlignmentAtom::Bytes { length: 8 }); // high 8 bytes
    }

    fn push_prims(prims: &mut Vec<Prim>) {
        prims.push(Prim::Point);
    }
}

impl CircuitArg for Secp256k1Scalar<Private> {
    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        Secp256k1Scalar::from_scalar(c.arg::<Secp256k1ScalarT>(path.as_str()))
    }

    /// A scalar slot is not a native field wire: nothing to constrain, and
    /// nothing a slot list could carry it as.
    fn push_slots(&self, _slots: &mut Vec<Wire3<FieldT, Private>>) {}
}

/// Compact's `JubjubPoint`: the same one-non-field-slot story as
/// [`Secp256k1Point`], over a two-`field` alignment.
impl<V: Vis3> CircuitAbi for JubjubPoint<V> {
    const SLOTS: usize = 1;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        atoms.push(AlignmentAtom::Field); // x
        atoms.push(AlignmentAtom::Field); // y
    }

    fn push_prims(prims: &mut Vec<Prim>) {
        prims.push(Prim::Point);
    }
}

impl CircuitArg for JubjubPoint<Private> {
    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        JubjubPoint::from_point(c.arg::<JubjubPointT>(path.as_str()))
    }

    fn push_slots(&self, _slots: &mut Vec<Wire3<FieldT, Private>>) {}
}

/// Compact's `Opaque<'ts-type'>`: ONE native slot carrying the value's
/// `compress` commitment, and NO constraint — `Prim::Opaque` is compactc's
/// `[(topaque ,opaque-type) instr*]` line, so the table emits nothing and this
/// impl says nothing about it.
///
/// Unlike [`Secp256k1Point`], the slot IS a field wire, so `push_slots` pushes
/// it in the ordinary way; what makes it constraint-free is the PRIM, which is
/// where that decision belongs.
impl<T: TsType, V: Vis3> CircuitAbi for Opaque<T, V> {
    const SLOTS: usize = 1;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        atoms.push(AlignmentAtom::Compress);
    }

    fn push_prims(prims: &mut Vec<Prim>) {
        prims.push(Prim::Opaque);
    }
}

impl<T: TsType> CircuitArg for Opaque<T, Private> {
    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        Opaque::from_field_unchecked(c.arg::<FieldT>(path.as_str()))
    }

    fn push_slots(&self, slots: &mut Vec<Wire3<FieldT, Private>>) {
        slots.push(self.field());
    }
}

/// Compact's `MerkleTreeDigest`: ONE native slot under a `field` atom, and NO
/// constraint — `Prim::Field` is compactc's `[(tfield …) instr*]` line, which
/// like `Prim::Opaque` emits nothing (`mtCheckRoot`'s `%r.0` carries no
/// `constrain_bits`).
impl<V: Vis3> CircuitAbi for MerkleTreeDigest<V> {
    const SLOTS: usize = 1;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        atoms.push(AlignmentAtom::Field);
    }

    fn push_prims(prims: &mut Vec<Prim>) {
        prims.push(Prim::Field);
    }
}

impl CircuitArg for MerkleTreeDigest<Private> {
    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        MerkleTreeDigest::from_field_unchecked(c.arg::<FieldT>(path.as_str()))
    }

    fn push_slots(&self, slots: &mut Vec<Wire3<FieldT, Private>>) {
        slots.push(self.field());
    }
}

/// Compact's `ContractAddress`: a struct of one `Bytes<32>`, which flattens
/// to exactly that `Bytes<32>`'s slots.
impl<V: Vis3> CircuitAbi for ContractAddress<V> {
    const SLOTS: usize = <B32<V> as CircuitAbi>::SLOTS;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        <B32<V> as CircuitAbi>::push_atoms(atoms);
    }

    fn push_prims(prims: &mut Vec<Prim>) {
        <B32<V> as CircuitAbi>::push_prims(prims);
    }
}

impl CircuitArg for ContractAddress<Private> {
    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        ContractAddress(B32::declare(c, path))
    }

    fn push_slots(&self, slots: &mut Vec<Wire3<FieldT, Private>>) {
        self.0.push_slots(slots);
    }
}

/// Compact's `UserAddress`: a struct of one `Bytes<32>`, which flattens to
/// exactly that `Bytes<32>`'s slots — the same shape [`ContractAddress`] has,
/// and a separate type for the reason its own docs give.
impl<V: Vis3> CircuitAbi for UserAddress<V> {
    const SLOTS: usize = <B32<V> as CircuitAbi>::SLOTS;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        <B32<V> as CircuitAbi>::push_atoms(atoms);
    }

    fn push_prims(prims: &mut Vec<Prim>) {
        <B32<V> as CircuitAbi>::push_prims(prims);
    }
}

impl CircuitArg for UserAddress<Private> {
    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        UserAddress(B32::declare(c, path))
    }

    fn push_slots(&self, slots: &mut Vec<Wire3<FieldT, Private>>) {
        self.0.push_slots(slots);
    }
}

impl<const N: usize, V: Vis3> CircuitAbi for BytesN<V, N> {
    const SLOTS: usize = Self::LIMBS;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        atoms.extend(BytesN::<V, N>::atoms());
    }

    /// Limb 0 is the leftover (most significant) chunk, every other limb a
    /// full 31 bytes.
    fn push_prims(prims: &mut Vec<Prim>) {
        for i in 0..Self::LIMBS {
            prims.push(Prim::Uint { bits: 8 * Self::limb_len(i) as u32 });
        }
    }
}

impl<const N: usize> CircuitArg for BytesN<Private, N> {
    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        BytesN::from_limbs(
            (0..<Self as CircuitAbi>::SLOTS)
                .map(|i| c.arg::<FieldT>(path.index(i).as_str()))
                .collect(),
        )
    }

    fn push_slots(&self, slots: &mut Vec<Wire3<FieldT, Private>>) {
        slots.extend_from_slice(self.limbs());
    }
}

/// Compact's `Vector<N, T>`: `N` copies of `T` back to back, each element
/// labelled with its index (`words_0`, `words_1`, ...). (The `CircuitAbi`
/// half lives in `minocrab::v3::abi` beside the trait — an array is a
/// foreign type, so only the trait's own crate may describe it.)
impl<T: CircuitArg, const N: usize> CircuitArg for [T; N] {
    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        // Built through a Vec rather than `array::from_fn`, whose call order
        // is not part of its contract: here the order IS the wire layout.
        let mut elements = Vec::with_capacity(N);
        for i in 0..N {
            elements.push(T::declare(c, &path.index(i)));
        }
        match <[T; N]>::try_from(elements) {
            Ok(array) => array,
            Err(_) => unreachable!("N elements were pushed"),
        }
    }

    fn push_slots(&self, slots: &mut Vec<Wire3<FieldT, Private>>) {
        for element in self {
            element.push_slots(slots);
        }
    }
}

/// Compact's `Maybe<T>`: the `is_some` tag followed by the value, which
/// occupies its slots whether or not the tag is set.
///
/// The tag takes the `_is_some` suffix and the value keeps the parent's
/// path — a `Maybe` adds a slot, not a level (`recipient_is_some` then
/// `recipient_...`), which is how the hand-written `claim` labels its
/// `Maybe<Either<..>>` recipient.
impl<T: CircuitAbi, V: Vis3> CircuitAbi for Maybe<T, V> {
    const SLOTS: usize = <Bool<V> as CircuitAbi>::SLOTS + T::SLOTS;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        <Bool<V> as CircuitAbi>::push_atoms(atoms);
        T::push_atoms(atoms);
    }

    fn push_prims(prims: &mut Vec<Prim>) {
        <Bool<V> as CircuitAbi>::push_prims(prims);
        T::push_prims(prims);
    }
}

impl<T: CircuitArg> CircuitArg for Maybe<T, Private> {
    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        Maybe {
            is_some: CircuitArg::declare(c, &path.suffix("is_some")),
            value: T::declare(c, path),
        }
    }

    fn push_slots(&self, slots: &mut Vec<Wire3<FieldT, Private>>) {
        self.is_some.push_slots(slots);
        self.value.push_slots(slots);
    }
}

/// Compact's `Either<A, B>`: the `is_left` tag followed by both arms, each
/// of which occupies its slots whichever way the tag points
/// (`recipient_is_left`, `recipient_left_...`, `recipient_right_...`).
impl<A: CircuitAbi, B: CircuitAbi, V: Vis3> CircuitAbi for Either<A, B, V> {
    const SLOTS: usize = <Bool<V> as CircuitAbi>::SLOTS + A::SLOTS + B::SLOTS;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        <Bool<V> as CircuitAbi>::push_atoms(atoms);
        A::push_atoms(atoms);
        B::push_atoms(atoms);
    }

    fn push_prims(prims: &mut Vec<Prim>) {
        <Bool<V> as CircuitAbi>::push_prims(prims);
        A::push_prims(prims);
        B::push_prims(prims);
    }
}

impl<A: CircuitArg, B: CircuitArg> CircuitArg for Either<A, B, Private> {
    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        Either {
            is_left: CircuitArg::declare(c, &path.suffix("is_left")),
            left: A::declare(c, &path.field("left")),
            right: B::declare(c, &path.field("right")),
        }
    }

    fn push_slots(&self, slots: &mut Vec<Wire3<FieldT, Private>>) {
        self.is_left.push_slots(slots);
        self.left.push_slots(slots);
        self.right.push_slots(slots);
    }
}

/// Compact's `[]` value (Rust's `()`) as an argument leaf: a ZERO-SLOT
/// argument — the attested value of a call that returns nothing.
///
/// `()` already has a [`CircuitAbi`] (`SLOTS = 0`, no atoms, no prims); this
/// impl is the missing other half, needed so a `Pending` over a
/// `Unit`-returning call can form a ticket (notes/evm-calls.org §10, item 3,
/// second paragraph — recorded there as not done because nothing in the
/// corpus filed a no-return call). `declare` touches no slots and
/// `push_slots` pushes nothing, which is law 1 and law 3 satisfied by
/// vacuously doing nothing: there is nothing to declare and nothing to
/// constrain.
impl CircuitArg for () {
    fn declare(_c: &mut Circuit3, _path: &ArgPath) -> Self {}

    fn push_slots(&self, _slots: &mut Vec<Wire3<FieldT, Private>>) {}
}

// ---- CircuitArgs ------------------------------------------------------------

/// A circuit's whole argument list: the per-circuit struct whose fields are
/// the Compact parameters, in declaration order.
///
/// Field order IS the wire contract — it feeds the input schema, the
/// communications commitment and the preimage layout — so an impl declares
/// and constrains its fields in exactly the order the Compact signature
/// lists them (the rule is precedented in `signet.rs`'s record layouts, and
/// backstopped by the interface snapshot and PI equality).
///
/// Written by hand for now; phase 3's `#[derive(CircuitArg)]` /
/// `#[circuit]` generate exactly these impls.
pub trait CircuitArgs: Sized {
    /// Total argument slots — the sum of the fields' [`CircuitAbi::SLOTS`].
    const SLOTS: usize;

    /// Declare every field, in declaration order.
    fn declare(c: &mut Circuit3) -> Self;

    /// Constrain every field, in declaration order.
    fn constrain(&self, c: &mut Circuit3);

    /// The FAB atoms of the argument list, in slot order.
    fn atoms() -> Vec<AlignmentAtom>;
}

/// The empty argument list.
impl CircuitArgs for () {
    const SLOTS: usize = 0;

    fn declare(_c: &mut Circuit3) -> Self {}

    fn constrain(&self, _c: &mut Circuit3) {}

    fn atoms() -> Vec<AlignmentAtom> {
        Vec::new()
    }
}

// ---- CircuitOut -------------------------------------------------------------

/// A value a circuit may return: queued as circuit outputs by [`entry_out`].
///
/// Implemented only for [`Public`] values — returning a value discloses it,
/// so a private one has to pass through `Circuit3::disclose` before it can
/// be returned, and forgetting to is a compile error rather than a leak.
///
/// `label` names the logical value; a multi-slot impl suffixes each slot
/// the way the hand-written circuits do (`"event hash (hi)"` /
/// `"(lo)"`). Output labels live only in the disclosure record — ZKIR's
/// output signature is types only.
///
/// It stayed a string through phase 6: a `Discloses<..>` declaration is
/// about values crossing the private→public gate, and a RETURN already
/// cannot leak (this trait is implemented for public values only), so the
/// declared set is the `Disclosed` records and an output label has nothing
/// to agree with.
#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot be returned from a circuit",
    label = "not a returnable value",
    note = "returning a value DISCLOSES it, so `CircuitOut` is implemented at \
            `Public` only. If this is the `Private` spelling of a leaf, send \
            it through the gate first — `value.disclose_as::<SomeLabel>(c)` — \
            and name the label in the circuit's `Discloses<..>` return type",
    note = "`()` is Compact's `: []` circuit, and `Discloses<D, R>` returns \
            whatever `R` returns; a circuit that returns anything at all also \
            needs `#[circuit(output = \"…\")]`"
)]
pub trait CircuitOut {
    /// Output slots this value occupies.
    const SLOTS: usize;

    /// Queue the slots as circuit outputs, in wire order.
    fn emit(self, c: &mut Circuit3, label: &str);
}

/// `[]` — a circuit that returns nothing.
/// A read may be a circuit's OUTPUT as it is: the proof discloses what it
/// assumed, which is exactly what the `popeq` validates.
impl<T: CircuitOut> CircuitOut for super::Assumed<T> {
    const SLOTS: usize = T::SLOTS;

    fn emit(self, c: &mut Circuit3, label: &str) {
        self.into_inner().emit(c, label)
    }
}

impl CircuitOut for () {
    const SLOTS: usize = 0;

    fn emit(self, _c: &mut Circuit3, _label: &str) {}
}

impl<const BITS: u32> CircuitOut for Uint<BITS, Public> {
    const SLOTS: usize = 1;

    fn emit(self, c: &mut Circuit3, label: &str) {
        c.output(self.field(), label);
    }
}

/// Returning a `Uint<0..BOUND>`: one output slot, the same wire a bounded
/// argument declares (M31, the bounded-ledger fixture — the first circuit
/// in this crate to return one).
impl<const BOUND: u128> CircuitOut for BoundedUint<BOUND, Public> {
    const SLOTS: usize = 1;

    fn emit(self, c: &mut Circuit3, label: &str) {
        c.output(self.field(), label);
    }
}

impl CircuitOut for Bool<Public> {
    const SLOTS: usize = 1;

    fn emit(self, c: &mut Circuit3, label: &str) {
        c.output(self.field(), label);
    }
}

impl<const N: usize> CircuitOut for Bytes<N, Public> {
    const SLOTS: usize = 1;

    fn emit(self, c: &mut Circuit3, label: &str) {
        c.output(self.field(), label);
    }
}

/// Returning an `Opaque` hands the caller back the COMMITMENT it already had —
/// which is what compactc's `outputs: ["Scalar<BLS12-381>"]` for an
/// `Opaque`-returning circuit is (the fixture's `opRet`). There is nothing
/// else to hand back, and the value never left the caller's side to begin with.
impl<T: TsType> CircuitOut for Opaque<T, Public> {
    const SLOTS: usize = 1;

    fn emit(self, c: &mut Circuit3, label: &str) {
        c.output(self.field(), label);
    }
}

impl CircuitOut for B32<Public> {
    const SLOTS: usize = 2;

    fn emit(self, c: &mut Circuit3, label: &str) {
        c.output(self.hi, &format!("{label} (hi)"));
        c.output(self.lo, &format!("{label} (lo)"));
    }
}

/// Returning a coin: its three fields' slots in declaration order, the same
/// layout [`CircuitAbi`] declares for it. `mergeCoin` is what needs it (M17).
impl CircuitOut for ShieldedCoinInfo3<Public> {
    const SLOTS: usize = <B32<Public> as CircuitOut>::SLOTS * 2 + 1;

    fn emit(self, c: &mut Circuit3, label: &str) {
        self.nonce.emit(c, &format!("{label} nonce"));
        self.color.emit(c, &format!("{label} color"));
        c.output(self.value, &format!("{label} value"));
    }
}

/// Returning a `ShieldedSendResult`: the change `Maybe` then the coin sent —
/// `sendShielded`'s return value (M17).
impl CircuitOut for ShieldedSendResult<Public> {
    const SLOTS: usize = <Maybe<ShieldedCoinInfo3<Public>, Public> as CircuitOut>::SLOTS
        + <ShieldedCoinInfo3<Public> as CircuitOut>::SLOTS;

    fn emit(self, c: &mut Circuit3, label: &str) {
        self.change.emit(c, &format!("{label} change"));
        self.sent.emit(c, &format!("{label} sent"));
    }
}

/// Returning a `Maybe<T>`: the tag's slot then the payload's, whichever way
/// the tag points — the same layout the ABI declares, and the same one a
/// `Maybe` argument occupies. `List.head` is what needs it (M16).
impl<T: CircuitOut> CircuitOut for Maybe<T, Public> {
    const SLOTS: usize = <Bool<Public> as CircuitOut>::SLOTS + T::SLOTS;

    fn emit(self, c: &mut Circuit3, label: &str) {
        self.is_some.emit(c, &format!("{label} (is_some)"));
        self.value.emit(c, label);
    }
}

// ---- entry ------------------------------------------------------------------

/// Build a circuit that returns `[]`: the fixed order every v3 entry point
/// follows — declare every argument, check the declaration, constrain every
/// argument, run the body, finish.
///
/// ```ignore
/// pub fn deposit() -> Compiled3 {
///     entry(|c, args: DepositArgs| { .. })
/// }
/// ```
///
/// The body may return anything that occupies no output slot — `()`, or a
/// [`Discloses<D>`](super::Discloses) declaration over it. Returning a
/// value means naming it, which is [`entry_out`].
#[track_caller]
pub fn entry<A: CircuitArgs, O: CircuitOut>(
    body: impl FnOnce(&mut Circuit3, A) -> O,
) -> Compiled3 {
    assert_eq!(
        O::SLOTS,
        0,
        "this circuit returns {} output slots, which need a label: use entry_out",
        O::SLOTS
    );
    entry_out("", body)
}

/// [`entry`] for a circuit that returns a value: `label` names the returned
/// value in the disclosure record (see [`CircuitOut`]).
///
/// Both this and [`entry`] are `#[track_caller]`: their three law checks are
/// properties of a BUILT circuit rather than of a type, so they stayed panics
/// (notes/contract-api.org §Panics) and the location that matters is the
/// `#[circuit]` whose argument list broke the law, not this function.
#[track_caller]
pub fn entry_out<A: CircuitArgs, O: CircuitOut>(
    label: &str,
    body: impl FnOnce(&mut Circuit3, A) -> O,
) -> Compiled3 {
    let mut c = Circuit3::new();

    // Phase 1: declaration only. ZKIR requires every input to precede
    // every instruction, which is why this is separate from constraining
    // at all — and why both halves of law 1 are worth checking.
    let args = A::declare(&mut c);
    assert_eq!(
        c.arg_count(),
        A::SLOTS,
        "CircuitArgs::declare touched {} argument slots, but SLOTS says {}",
        c.arg_count(),
        A::SLOTS
    );
    assert_eq!(
        c.instruction_count(),
        0,
        "CircuitArgs::declare emitted instructions; declaration may only call Circuit3::arg"
    );

    // Phase 2: compactc's input constraints, derived from the types.
    args.constrain(&mut c);

    let out = body(&mut c, args);
    // The hooks (`c.then`, notes/hooks-design.org) run after the whole
    // body and before the outputs, so the disclosure record reads in
    // transcript order. `finish` would flush them too; this is the
    // ordering.
    c.flush_deferred();
    out.emit(&mut c, label);

    // Every ported circuit is an exported entry point, and every exported
    // entry point commits to its cross-contract communications; the
    // hand-written circuits all end in `finish(true)`.
    c.finish(true)
}
