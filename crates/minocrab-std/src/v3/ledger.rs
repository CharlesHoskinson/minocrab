//! The ledger block as TYPES: `#[derive(Ledger)]`, [`LedgerMap`],
//! [`LedgerCell`], [`LedgerCounter`].
//!
//! Below this module, `minocrab_ledger` emits compactc's vm-code for one
//! ledger operation at a time and takes two things a caller has to get right
//! by hand: the FIELD INDEX (a `u8`) and the value's FAB ATOMS (a
//! `Vec<AlignmentAtom>` written out at the call site). Both are silent
//! hazards — an index off by one reads another field, an atom list that does
//! not match the stored value's changes the PI stream — and neither is
//! visible to a type checker.
//!
//! This module removes both, and nothing else:
//!
//! - the index comes from the DECLARATION ORDER of a `#[derive(Ledger)]`
//!   struct that mirrors the Compact `export ledger` block, so the mapping
//!   lives once, where the fields are declared;
//! - the atoms come from the key/value TYPE through [`LedgerRepr`], so
//!   `Map<RequestId, Bytes<32>>` is `LedgerMap<B32<Public>, B32<Public>>` and
//!   nobody writes `vec![AlignmentAtom::Bytes { length: 32 }]` again.
//!
//! THE INVARIANT (notes/contract-api.org §The design): no method here issues
//! more Impact ops than the one Compact operation it names. Every method is a
//! one-line call into `minocrab_ledger`, and `c` and the guard stay VISIBLE
//! in the signature — a ledger operation is a cost, and the call site says so.
//! `map[k]` sugar, `Deref`, `entry()` and iterators are REJECTED for the same
//! reason.
//!
//! NESTING (M22 stage B2) keeps that invariant exactly. `at_key` is the one
//! method that emits NOTHING — it builds compactc's path `f`, which is what
//! an intermediate `Map.lookup` is at compile time — and the leaf method
//! still emits the ONE operation it names, with the path re-encoded into it.
//! A slot is therefore a PATH rather than a field index: see [`FieldPath`]
//! (const, from the declaration, and more than one element as soon as a block
//! declares sixteen fields) and [`KeyPath`] (runtime, one element per
//! `at_key`).

use std::marker::PhantomData;

use minocrab::v3::{
    AnyWire3, CallArg, CallResult, Circuit3, CircuitAbi, FieldT, JubjubPointT,
    Secp256k1PointT, Wire3,
};
use minocrab::{Alignment, AlignmentAtom, AlignmentSegment, Fr, Public};
use super::assumed::{Assumed, ProofWires};
use minocrab_ledger::{
    atom_limbs, cell_read_embedded_at, cell_write_at, counter_increment_at, counter_less_than_at,
    counter_read_at, counter_reset_at, emit, empty_counter, empty_historic_merkle_tree_value,
    empty_list, empty_map, empty_merkle_tree_value, historic_merkle_tree_check_root_at,
    historic_merkle_tree_insert_at, historic_merkle_tree_insert_index_at,
    historic_merkle_tree_reset_at, historic_merkle_tree_reset_history_at, list_head_at,
    list_is_empty_at, list_length_at, list_pop_front_at, list_push_front_at,
    list_push_front_coin_at, list_reset_at, map_insert_adt_default_at, map_insert_at,
    map_insert_coin_at, map_insert_default_at, map_is_empty_at, map_lookup_at,
    map_member_at, map_remove_at, map_reset_at,
    map_size_at, merkle_tree_check_root_at, merkle_tree_insert_at, merkle_tree_insert_index_at,
    merkle_tree_is_full_at, merkle_tree_reset_at, mint_read, set_insert_at,
    set_insert_coin_at, set_is_empty_at, set_remove_at, set_reset_at, set_size_at, ImpactElem,
    ImpactOp, LedgerKey, LedgerValue,
};

use super::{
    coin_commitment, hash, Bool, BoundedUint, Bytes, Bytes0, BytesN, CoinRecipient, ContractAddress,
    Either, JubjubPoint, Maybe, MerkleTreeDigest, Opaque, QualifiedShieldedCoinInfo3,
    Secp256k1Point, ShieldedCoinInfo3, TsType, Uint, UserAddress, B32,
};

/// What a ledger slot's key or value type must be able to do: name its FAB
/// atoms, hand over its limbs, and be rebuilt from the limbs a read witnesses.
///
/// The three facts are exactly [`CircuitAbi::atoms`],
/// [`CallArg::push_call_slots`] and [`CallResult::from_call_slots`] — a
/// ledger write and a cross-contract argument are the same crossing (a
/// public, FAB-aligned value leaving the circuit), so the leaf impls below
/// DELEGATE rather than restate. `LedgerRepr` exists as its own trait, and
/// does NOT require `CircuitAbi`, because a stored record is not an argument:
/// a ledger read is checked by the op's `popeq`, never range-constrained, so
/// requiring [`CircuitAbi::prims`] would make every record type declare
/// constraints that nothing emits.
///
/// Implemented at [`Public`] only, and that is the same soundness statement
/// `CallArg` makes: what the ledger holds is public, so a private value has
/// to pass `disclose` before it can be written — forgetting is a compile
/// error rather than a leak.
#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot sit in a ledger slot",
    label = "not a ledger representation",
    note = "what the ledger holds is PUBLIC — an Impact op writes into the \
            public transcript — so `LedgerRepr` is implemented at `Public` \
            only. A private value has to pass `disclose_as` before it can be \
            written, and forgetting is this error rather than a leak",
    note = "a record type gets its impl from `#[derive(CircuitArg)]`'s \
            `Public` instantiation, or by delegating to the ABI traits the \
            way the leaf table in this module does; `Secp256k1Point` and \
            `JubjubPoint` are `Cell`-only (their limbs come out of `encode`, \
            which has no inverse, so a `Map` value or `Set` element cannot be \
            rebuilt from a read)"
)]
pub trait LedgerRepr: Sized {
    /// This type's FAB atoms, in slot order.
    fn atoms() -> Vec<AlignmentAtom>;

    /// This value's limbs, in slot order.
    ///
    /// Takes `c`: a value whose limbs are COMPUTED rather than stored — a
    /// `Secp256k1Point`, whose five limbs come out of an `encode`
    /// INSTRUCTION — cannot hand them over without emitting. THE PRICE,
    /// recorded because it was worth stating: a repr may emit, so "building
    /// a `LedgerValue` is free" is no longer
    /// true by construction. What replaces it is narrower and still checkable:
    /// a repr emits exactly the instructions the call site would have emitted
    /// itself, immediately before the op, which is what
    /// `tests/v3_ledger.rs`'s byte-equality against the explicit form says.
    fn push_limbs(&self, c: &mut Circuit3, limbs: &mut Vec<Wire3<FieldT, Public>>);

    /// Rebuild from a read's limbs, in slot order.
    fn from_limbs(limbs: Vec<Wire3<FieldT, Public>>) -> Self;

    /// This value's limbs, in slot order.
    fn limbs(&self, c: &mut Circuit3) -> Vec<Wire3<FieldT, Public>> {
        let mut limbs = Vec::new();
        self.push_limbs(c, &mut limbs);
        limbs
    }

    /// The value as `minocrab_ledger` takes it: atoms from the TYPE, limbs
    /// from the value. This is the method that kills hand-written atom lists.
    fn ledger_value(&self, c: &mut Circuit3) -> LedgerValue {
        LedgerValue::new(
            Self::atoms(),
            self.limbs(c).into_iter().map(ImpactElem::Wire).collect(),
        )
    }

    /// Witness a READ of this type: the gates it mints, and the value the
    /// op's `popeq` embeds.
    ///
    /// The default is the native-limb shape — one `public_input` gate per FAB
    /// limb, rebuilt with [`LedgerRepr::from_limbs`] — which is what every
    /// FAB-aligned record does. The one type that overrides it is
    /// [`Secp256k1Point`]: a point cell mints ONE TYPED gate and DERIVES its
    /// five limbs with `encode`, so its read is not a limb read at all.
    ///
    /// Guarded automatically: [`Circuit3::public_transcript_input`] resolves
    /// the ambient scope, so a read inside [`Circuit3::when`] needs no
    /// separate spelling here.
    fn witness_read(c: &mut Circuit3) -> (Self, LedgerValue) {
        let (wires, value) = mint_read(c, Self::atoms());
        (Self::from_limbs(wires), value)
    }
}

/// The leaf impls: pure delegation to the ABI traits, so a leaf's atoms and
/// limb order are stated in exactly one place (`entry.rs` / `call.rs`).
macro_rules! ledger_repr_via_abi {
    ($( $(#[$m:meta])* [$($gen:tt)*] $ty:ty ),* $(,)?) => {$(
        $(#[$m])*
        impl<$($gen)*> ProofWires for $ty {
            fn push_wires(&self, out: &mut Vec<minocrab::v3::Val>) {
                let mut slots = Vec::new();
                <$ty as CallArg>::push_call_slots(self, &mut slots);
                out.extend(slots.iter().map(|w| w.val()));
            }
        }

        $(#[$m])*
        impl<$($gen)*> LedgerRepr for $ty {
            fn atoms() -> Vec<AlignmentAtom> {
                <$ty as CircuitAbi>::atoms()
            }

            fn push_limbs(&self, _c: &mut Circuit3, limbs: &mut Vec<Wire3<FieldT, Public>>) {
                <$ty as CallArg>::push_call_slots(self, limbs)
            }

            #[track_caller]
            fn from_limbs(limbs: Vec<Wire3<FieldT, Public>>) -> Self {
                debug_assert_eq!(
                    limbs.len(),
                    <$ty as CircuitAbi>::SLOTS,
                    "ledger read handed back the wrong number of limbs"
                );
                <$ty as CallResult>::from_call_slots(&limbs)
            }
        }
    )*};
}

ledger_repr_via_abi! {
    [const BITS: u32] Uint<BITS, Public>,
    /// `MerkleTreeDigest` in a ledger slot — one limb under a `field` atom.
    /// A tree's roots are not STORED as digests (the tree holds them), but a
    /// `checkRoot` argument is pushed through this path, and a contract may
    /// keep one in a `Cell`.
    [] MerkleTreeDigest<Public>,
    /// `Map<K, QualifiedShieldedCoinInfo>`'s VALUE read back out — six limbs
    /// under the coin's four atoms (`b32, b32, b16, b8`). The write side of
    /// a coin slot is [`insert_coin`](LedgerMap::insert_coin) (the qualify
    /// dance); this impl is what a `lookup` of the pooled coin needs.
    [] QualifiedShieldedCoinInfo3<Public>,
    [const BOUND: u128] BoundedUint<BOUND, Public>,
    [] Bool<Public>,
    /// `Bytes<0>` in a ledger slot — one zero-length atom and no limb.
    [] Bytes0<Public>,
    [const N: usize] Bytes<N, Public>,
    [] B32<Public>,
    [const N: usize] BytesN<Public, N>,
    [] ContractAddress<Public>,
    [] UserAddress<Public>,
    /// `Either<A, B>` in a ledger or effects slot — the tag's limb then BOTH
    /// arms', whichever way the tag points. Reached by M17's `TokenType` and
    /// `UnshieldedRecipient`, which are `Either`s in Compact's own signatures.
    [A: CircuitAbi + CallArg + CallResult, B: CircuitAbi + CallArg + CallResult]
        Either<A, B, Public>,
    /// `Opaque<'ts-type'>` in a ledger slot — one limb under a `compress`
    /// atom, which is the ordinary delegation. It is a `Cell` type, a `Map`
    /// KEY type, a `Map` VALUE type and a `Set` element type, all four of
    /// which the fixture exercises; unlike [`Secp256k1Point`] there is no
    /// shape it cannot take, because the commitment is a plain field limb
    /// that a read can hand straight back.
    [T: TsType] Opaque<T, Public>,
    /// `export ledger m: Maybe<T>` — Compact's `Maybe` is an ordinary struct
    /// (`{ is_some: Boolean, value: T }`), so a stored one is its tag's limb
    /// followed by the payload's, which is what the ABI delegation already
    /// says. The payload occupies its slots whether or not the tag is set;
    /// that is the format, not a choice made here.
    [T: CircuitAbi + CallArg + CallResult] Maybe<T, Public>,
}

/// `export ledger k: Secp256k1Point` — the one stored type whose limbs are
/// COMPUTED, in both directions.
///
/// A point occupies one slot whose wire is not a field element, and its five
/// FAB limbs (x as b24+b8, y as b24+b8, the infinity field —
/// notes/ledger-abi.org §3) come out of an `encode` instruction. So both
/// halves of the crossing are overridden: [`LedgerRepr::push_limbs`] emits
/// the `encode` a write needs, and [`LedgerRepr::witness_read`] mints the
/// TYPED gate a read witnesses and encodes THAT (claim.zkir:29-33). Before
/// this the field had to be a [`LedgerField`] with `cell_read_point` and a
/// hand-written `cell_write` at the call sites.
impl ProofWires for Secp256k1Point<Public> {
    fn push_wires(&self, out: &mut Vec<minocrab::v3::Val>) {
        out.push(self.point().val());
    }
}

impl LedgerRepr for Secp256k1Point<Public> {
    fn atoms() -> Vec<AlignmentAtom> {
        <Secp256k1Point<Public> as CircuitAbi>::atoms()
    }

    fn push_limbs(&self, c: &mut Circuit3, limbs: &mut Vec<Wire3<FieldT, Public>>) {
        limbs.extend(c.encode(self.point()));
    }

    /// UNREACHABLE by construction: [`LedgerRepr::witness_read`] is
    /// overridden below, and it is the only caller of `from_limbs` in this
    /// module. A point cannot be rebuilt from its encoding — ZKIR has
    /// `encode` and no inverse — so a `LedgerMap<_, Secp256k1Point>`, whose
    /// lookup does go through `from_limbs`, is not supported: store the
    /// point in a CELL (which is the only shape Compact's `Secp256k1Point`
    /// ledger fields take) or store the encoded limbs as a record type.
    #[track_caller]
    fn from_limbs(_limbs: Vec<Wire3<FieldT, Public>>) -> Self {
        unreachable!(
            "a Secp256k1Point is read through its typed gate, not rebuilt from \
             its `encode` limbs — see the impl's docs for the supported shapes"
        )
    }

    fn witness_read(c: &mut Circuit3) -> (Self, LedgerValue) {
        let point = c.public_transcript_input::<Secp256k1PointT>();
        c.label_read_vals(&[point.val()], "a point cell read");
        let point = Secp256k1Point::from_point(point);
        let mut limbs = Vec::new();
        point.push_limbs(c, &mut limbs);
        let value = LedgerValue::new(
            <Self as LedgerRepr>::atoms(),
            limbs.into_iter().map(ImpactElem::Wire).collect(),
        );
        (point, value)
    }
}

/// `export ledger k: JubjubPoint` — the same computed-limb story as
/// [`Secp256k1Point`] above, over two `field` limbs instead of five mixed ones.
///
/// Both halves are overridden for the same reason: `encode` produces the limbs
/// and ZKIR has no inverse, so a write emits the `encode` and a read mints the
/// TYPED gate and encodes that. A `LedgerMap<_, JubjubPoint>` is therefore not
/// supported either — store it in a `Cell`, which is the only shape Compact's
/// own `JubjubPoint` ledger fields take (`test-center/compact/test`'s `x15`).
impl ProofWires for JubjubPoint<Public> {
    fn push_wires(&self, out: &mut Vec<minocrab::v3::Val>) {
        out.push(self.point().val());
    }
}

impl LedgerRepr for JubjubPoint<Public> {
    fn atoms() -> Vec<AlignmentAtom> {
        <JubjubPoint<Public> as CircuitAbi>::atoms()
    }

    fn push_limbs(&self, c: &mut Circuit3, limbs: &mut Vec<Wire3<FieldT, Public>>) {
        limbs.extend(c.encode(self.point()));
    }

    /// UNREACHABLE by construction — see [`Secp256k1Point`]'s impl, which
    /// carries the argument in full.
    #[track_caller]
    fn from_limbs(_limbs: Vec<Wire3<FieldT, Public>>) -> Self {
        unreachable!(
            "a JubjubPoint is read through its typed gate, not rebuilt from \
             its `encode` limbs — see the impl's docs for the supported shapes"
        )
    }

    fn witness_read(c: &mut Circuit3) -> (Self, LedgerValue) {
        let point = c.public_transcript_input::<JubjubPointT>();
        c.label_read_vals(&[point.val()], "a point cell read");
        let point = JubjubPoint::from_point(point);
        let mut limbs = Vec::new();
        point.push_limbs(c, &mut limbs);
        let value = LedgerValue::new(
            <Self as LedgerRepr>::atoms(),
            limbs.into_iter().map(ImpactElem::Wire).collect(),
        );
        (point, value)
    }
}

// ---- the coin arms' shared operands -----------------------------------------

/// What a collection must hold before it grows a COIN ARM: compactc declares
/// `insertCoin` / `pushFrontCoin` under
/// `(when (= value_type QualifiedShieldedCoinInfo))` (midnight-ledger.ss:669
/// for `Set`, :768 for `Map`, :917 for `List`), so there is exactly one
/// implementor and no second one is reachable — the trait is sealed.
///
/// It is a BOUND rather than three impls on the concrete type for the sake of
/// the diagnostic: reaching for a coin arm on the wrong collection is then a
/// trait bound carrying the note below, which is the project's preferred
/// rejection spelling (the same shape as [`KeyedPath`]'s depth bound).
///
/// ```compile_fail
/// use minocrab::v3::Circuit3;
/// use minocrab::Public;
/// use minocrab_std::v3::{CoinRecipient, LedgerSet, ShieldedCoinInfo3, B32};
///
/// const S: LedgerSet<B32<Public>> = LedgerSet::at(0);
///
/// fn f(c: &mut Circuit3, coin: &ShieldedCoinInfo3<Public>, r: &CoinRecipient<Public>) {
///     S.insert_coin(c, coin, r);
/// }
/// ```
///
/// while the same call on a set of coins compiles:
///
/// ```
/// use minocrab::v3::Circuit3;
/// use minocrab::Public;
/// use minocrab_std::v3::{
///     CoinRecipient, LedgerSet, QualifiedShieldedCoinInfo3, ShieldedCoinInfo3,
/// };
///
/// const S: LedgerSet<QualifiedShieldedCoinInfo3<Public>> = LedgerSet::at(0);
///
/// fn f(c: &mut Circuit3, coin: &ShieldedCoinInfo3<Public>, r: &CoinRecipient<Public>) {
///     S.insert_coin(c, coin, r);
/// }
/// ```
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a shielded coin, so this collection has no coin arm",
    label = "expected `QualifiedShieldedCoinInfo3<Public>`",
    note = "compactc declares `insertCoin`/`pushFrontCoin` under \
            `(when (= value_type QualifiedShieldedCoinInfo))` \
            (midnight-ledger.ss:669, :768, :917) — a collection of any other \
            element type has no such method at all. The coin arms live on \
            `LedgerSet<QualifiedShieldedCoinInfo3<Public>>`, \
            `LedgerMap<K, QualifiedShieldedCoinInfo3<Public>>` and \
            `LedgerList<QualifiedShieldedCoinInfo3<Public>>`",
    note = "DECLARED SLOTS ONLY: a coin arm on a handle reached through \
            `at_key` is deliberately not offered — the lowering handles any \
            depth, but no differential covers a nested one \
            (notes/coin-arms-nested-adts.org, stage B1 \"not covered\")"
)]
pub trait CoinArm: sealed::Coin {}

impl sealed::Coin for QualifiedShieldedCoinInfo3<Public> {}
impl CoinArm for QualifiedShieldedCoinInfo3<Public> {}

/// The two operands the QUALIFY DANCE takes, shared by the three coin arms
/// below (`Set.insertCoin`, `Map.insertCoin`, `List.pushFrontCoin`; the
/// family's fourth member, `Cell.writeCoin`, still builds them at its call
/// site in `minocrab-contracts`): the runtime coin COMMITMENT the
/// transaction context's commitment-index map is indexed by, and the 3-atom
/// `ShieldedCoinInfo` — `[nonce: Bytes<32>, color: Bytes<32>,
/// value: Uint<128>]` — the resolved tree index is concatenated onto.
///
/// `coinCommitment(coin, recipient)` is a CIRCUIT computation, a
/// `persistentHash` over the coin preimage plus the recipient's
/// `cond_select` pair, and emits no Impact instruction. So the three methods
/// below still issue exactly the one Impact operation each names — the
/// module's invariant — and the gates they mint are the ones the call site
/// would have minted itself by calling [`coin_commitment`] before the op,
/// which is what compactc's own `rt-coin-commit` expands to.
fn coin_operands(
    c: &mut Circuit3,
    coin: &ShieldedCoinInfo3<Public>,
    recipient: &CoinRecipient<Public>,
) -> (LedgerValue, LedgerValue) {
    let cm = coin_commitment(c, coin, recipient);
    let mut slots = Vec::new();
    coin.push_call_slots(&mut slots);
    (
        LedgerValue::bytes(32, vec![ImpactElem::Wire(cm.hi), ImpactElem::Wire(cm.lo)]),
        LedgerValue::new(
            <ShieldedCoinInfo3<Public> as CircuitAbi>::atoms(),
            slots.into_iter().map(ImpactElem::Wire).collect(),
        ),
    )
}

// ---- WHERE A SLOT LIVES: the path ------------------------------------------
//
// compactc calls it `f`, "the path to the field being operated on"
// (midnight-ledger.ss:133-138), and every ledger operation's vm-code is
// written against it. It has TWO halves, and they differ in when they are
// known:
//
//   - the FIELD path, const, from the declaration. Usually one element — the
//     field index — but `determine-ledger-paths.ss` BATCHES a block's fields
//     into segments of fifteen (`maximum-ledger-segment-length`, langs.ss:851),
//     so a sixteen-field block gives every field a TWO-element path and
//     `#[derive(Ledger)]` hands each slot the path rather than an index;
//   - the KEYS, runtime, one per `at_key` — a map key is generally a circuit
//     wire, so a nested handle is a VALUE holding cloned limbs where a
//     declared handle is a `const`.
//
// Hence two path types and one sealed trait over them. Keeping them apart is
// not tidiness: a declared handle must stay DROP-FREE or
// `const I: u8 = VAULT.field.index();` stops compiling (E0493), and a nested
// handle must own a `Vec` because that is what a key is.

/// The most elements a FIELD path can have: `batch`'s tree is one level deep
/// at fifteen fields, two at 225, three at the 256 a `u8` index allows, and
/// `#[derive(Ledger)]` rejects a wider block than that.
pub const MAX_FIELD_PATH: usize = 3;

/// The deepest `f` any ledger operation can ENCODE, and the reason the depth
/// bound below is what it is.
///
/// `idx`'s low nibble takes sixteen elements, but `insc`'s takes fifteen and
/// `HistoricMerkleTree.resetHistory` closes with `insc len(f) + 2`
/// (midnight-ledger.ss:1338) — so thirteen is the real bound, and it is the
/// tighter of the two asserts `minocrab_ledger` makes at run time.
pub const MAX_LEDGER_PATH: usize = 13;

/// The most `at_key` steps a handle may carry: [`MAX_LEDGER_PATH`] less the
/// widest field path, so that the bound holds whatever block the slot was
/// declared in. Checked as an inline-const assert (E0080) at `at_key`, which
/// is STRICTER than upstream — compactc has the same nibble bound as a source
/// comment and no check at all (midnight-ledger.ss:576-577).
pub const MAX_NESTING: usize = MAX_LEDGER_PATH - MAX_FIELD_PATH;

mod sealed {
    /// Sealing [`super::LedgerPath`]: the two path halves are the two the
    /// wire format has.
    pub trait Path {}
    /// Sealing [`super::LedgerSlot`]: the two families that may sit in a
    /// `Map`'s value position.
    pub trait Slot {}
    /// Sealing [`super::CoinArm`]: one impl, and no downstream second one.
    pub trait Coin {}
}

/// Sealed: where a ledger slot sits. [`FieldPath`] (a declaration) or
/// [`KeyPath`] (an `at_key` chain).
pub trait LedgerPath: Clone + sealed::Path {
    /// How many MAP KEYS this path carries — zero for a declared slot. The
    /// depth bound is stated on this, not on the runtime length.
    const KEYS: usize;

    /// The path one key deeper, which is what `at_key` returns a handle at.
    ///
    /// UNBOUNDED here on purpose: `KeyPath<MAX_NESTING>`'s `Deeper` names a
    /// type with NO [`KeyedPath`] impl, so `at_key`'s `where P::Deeper:
    /// KeyedPath` is the depth bound and it fires at TYPE-CHECK time —
    /// eagerly, in dead code too, which an inline-const assert would not.
    type Deeper;

    /// compactc's `f`, built afresh per operation.
    ///
    /// Per the design of record the path is RE-ENCODED for every op rather
    /// than cached — that is compactc's own shape, and it is what keeps the
    /// differential instruction-for-instruction. It costs allocation at
    /// build time and nothing at all in the circuit.
    fn to_path(&self) -> Vec<LedgerKey>;
}

/// A [`LedgerPath`] that ends in a KEY — the target of `at_key`, and the
/// half a handle owns rather than declares.
#[diagnostic::on_unimplemented(
    message = "a ledger path this deep does not fit the Impact opcodes' nibbles",
    label = "at most ten `at_key` steps (MAX_NESTING)",
    note = "`insc len(f) + 2` is the deepest closing any ledger operation has \
            (HistoricMerkleTree.resetHistory), and `insc`'s operand is a \
            nibble — so `f` may hold at most thirteen elements, of which a \
            field path may take three"
)]
pub trait KeyedPath: LedgerPath {
    /// Root a handle at an already-built path. Not for call sites: `at_key`
    /// is the only caller.
    #[doc(hidden)]
    fn rooted(path: Vec<LedgerKey>) -> Self;
}

/// The const half: a declared field's path, from `#[derive(Ledger)]`.
///
/// An inline array rather than a `Vec` because a declared handle is a `const`
/// item, and a `const` item holding a `Vec` cannot be used in a `const`
/// expression at all (E0493, "destructor cannot be evaluated at
/// compile-time") — which `const SIGNER: u8 = VAULT.signet_signer.index();`
/// is.
#[derive(Clone, Copy)]
pub struct FieldPath {
    elems: [u8; MAX_FIELD_PATH],
    len: u8,
}

impl FieldPath {
    /// The one-element path of a field in a block of fifteen fields or fewer.
    pub const fn field(index: u8) -> Self {
        FieldPath::of(&[index])
    }

    /// A field's full path, as `determine-ledger-paths.ss` computes it.
    pub const fn of(path: &[u8]) -> Self {
        assert!(
            !path.is_empty(),
            "a ledger field's path has at least one element"
        );
        assert!(
            path.len() <= MAX_FIELD_PATH,
            "a ledger field's path is at most three elements — compactc's \
             `batch` is three levels deep at the 256 fields a byte index \
             allows (determine-ledger-paths.ss, langs.ss:851)"
        );
        let mut elems = [0u8; MAX_FIELD_PATH];
        let mut i = 0;
        while i < path.len() {
            elems[i] = path[i];
            i += 1;
        }
        FieldPath {
            elems,
            len: path.len() as u8,
        }
    }

    /// The field INDEX, for a slot whose path is one element.
    ///
    /// A block of sixteen fields or more has no such number — its fields are
    /// segmented and each carries a path — so this asserts, which is E0080
    /// wherever it is used (its call sites are all `const` items).
    pub const fn index(&self) -> u8 {
        assert!(
            self.len == 1,
            "this field's path has more than one element: the block declares \
             sixteen fields or more, so compactc segments it and the field \
             has no single index (notes/coin-arms-nested-adts.org, stage B1 \
             correction (ii))"
        );
        self.elems[0]
    }

    /// The path's elements.
    pub const fn as_slice(&self) -> &[u8] {
        let (path, _) = self.elems.split_at(self.len as usize);
        path
    }

    /// How many elements the path has — the DEPTH a notification carries.
    pub const fn depth(&self) -> u8 {
        self.len
    }

    /// The path of flat field `index` in a block of `total` fields, as
    /// `determine-ledger-paths.ss` computes it — `batch` (langs.ss:851,
    /// segments of at most fifteen; the remainder leads as its own short
    /// segment, then the full ones, re-batched until the top level fits)
    /// walked from the leaf up, in `const` so a ledger block whose slots
    /// are WIDER than one field (a [`super::LedgerWidth`] above one) can
    /// still be laid out as a `const` item. The non-`const` twin in
    /// `minocrab-macros` (`field_paths`) is pinned against this one by the
    /// derive's tests.
    pub const fn in_block(total: usize, index: usize) -> Self {
        assert!(
            total <= 256,
            "a ledger block has at most 256 fields (the index is a byte)"
        );
        assert!(index < total, "ledger field index out of range for its block");
        // Reversed: the leaf's position first, the top level last.
        let mut rev = [0u8; MAX_FIELD_PATH];
        let mut depth = 0usize;
        let mut items = total;
        let mut at = index;
        while items > SEGMENT {
            let r = items % SEGMENT;
            let (group, pos) = if r != 0 {
                if at < r {
                    (0, at)
                } else {
                    (1 + (at - r) / SEGMENT, (at - r) % SEGMENT)
                }
            } else {
                (at / SEGMENT, at % SEGMENT)
            };
            assert!(
                depth < MAX_FIELD_PATH,
                "compactc's `batch` is three levels deep at 256 fields"
            );
            rev[depth] = pos as u8;
            depth += 1;
            items = items / SEGMENT + if r != 0 { 1 } else { 0 };
            at = group;
        }
        rev[depth] = at as u8;
        depth += 1;
        let mut elems = [0u8; MAX_FIELD_PATH];
        let mut i = 0;
        while i < depth {
            elems[i] = rev[depth - 1 - i];
            i += 1;
        }
        FieldPath {
            elems,
            len: depth as u8,
        }
    }
}

/// compactc's `maximum-ledger-segment-length` (langs.ss:851).
const SEGMENT: usize = 15;

/// How many wires a stored `T` reads back as — one per FAB limb of its
/// atoms. `#[derive(LedgerRepr)]` splits a composite read with it.
/// A value the ledger may STORE inline: every [`LedgerRepr`] value, and not
/// an [`Assumed`] one. The bound on every inline write's value parameter,
/// so a read result written straight back is a missing impl — the type's
/// half of "stale values must be named" (notes/hooks-design.org); the
/// backstop below is the other half, for values COMPUTED from a read.
#[diagnostic::on_unimplemented(
    message = "the ledger does not store `{Self}`: it is what an inline read returned, an assumption",
    label = "write `.stale(c)` on it to name the assumption, or compute it on the ledger in a hook",
    note = "an `Assumed<T>` is `T` to the proof and not to the ledger; `x.stale(c)` records that \
            the transaction assumes the read value is still current at landing"
)]
pub trait Fresh<T> {
    /// The value.
    fn fresh(&self) -> &T;
}

impl<T: LedgerRepr> Fresh<T> for T {
    fn fresh(&self) -> &T {
        self
    }
}

/// The value an inline WRITE stores, through the stale-read backstop
/// (`Circuit3::refuse_stale`, notes/hooks-design.org): a value computed
/// from an inline read that was not acknowledged with `.stale(c)` is
/// refused here at build time, naming the read. Keys do not come through
/// this; a key derived from a read adds no assumption the read's own
/// `popeq` does not make.
pub(crate) fn stored<T: LedgerRepr>(c: &mut Circuit3, value: &impl Fresh<T>, what: &str) -> LedgerValue {
    let value = value.fresh().ledger_value(c);
    let wires: Vec<minocrab::v3::Val> = value
        .elems()
        .iter()
        .filter_map(|e| match e {
            ImpactElem::Wire(w) => Some(w.val()),
            ImpactElem::Imm(_) => None,
        })
        .collect();
    c.refuse_stale(&wires, what);
    value
}

pub fn repr_limbs<T: LedgerRepr>() -> usize {
    T::atoms().iter().map(atom_limbs).sum()
}

/// How many LEDGER FIELDS a declared slot occupies, and which Signet
/// response kinds it claims.
///
/// Every slot in this module is one field. A slot that is a GROUP of fields
/// (`signet_flow::Pending`, whose request map and environment map are two
/// consecutive fields) says so here, and `#[derive(Ledger)]` lays the block
/// out from these widths: `Self::at_block(total, start)` on each slot type
/// takes the block's field count and the slot's first flat index, and
/// [`FieldPath::in_block`] does the segmentation. Nothing is written by
/// hand — a slot cannot be given the wrong width because the width is the
/// type's.
///
/// `KINDS` is the same trick for the response-kind byte: a slot that
/// expects an MPC response declares the kind it settles under, and the
/// derive asserts (at compile time, E0080) that no two slots of one block
/// claim the same kind — the MPC's kind byte would be ambiguous otherwise.
pub trait LedgerWidth {
    /// Consecutive ledger fields this slot occupies.
    const WIDTH: usize = 1;
    /// Response kinds this slot settles under (empty for ordinary slots).
    ///
    /// A Signet slot reads it off the FILING it is typed by
    /// (`evm::Filing::KIND`), which is where a deployment's protocol byte
    /// lives; [`assert_distinct_kinds`] is what stops two slots of one block
    /// claiming the same one.
    const KINDS: &'static [u8] = &[];
}

/// `#[derive(Ledger)]`'s kind-uniqueness check: E0080 when two slots of a
/// block claim one response kind.
pub const fn assert_distinct_kinds(kinds: &[&[u8]]) {
    let mut i = 0;
    while i < kinds.len() {
        let mut a = 0;
        while a < kinds[i].len() {
            // Against every LATER slot's kinds, and every later kind of the
            // same slot.
            let mut j = i;
            while j < kinds.len() {
                let mut b = if j == i { a + 1 } else { 0 };
                while b < kinds[j].len() {
                    assert!(
                        kinds[i][a] != kinds[j][b],
                        "two slots of this ledger block settle under the same \
                         Signet response kind: the MPC's kind byte could not \
                         tell their attestations apart. Give each slot's \
                         `Filing` a distinct `KIND`."
                    );
                    b += 1;
                }
                j += 1;
            }
            a += 1;
        }
        i += 1;
    }
}

/// `at_block` and a one-field [`LedgerWidth`] for each slot type: the
/// declared-form constructor `#[derive(Ledger)]` calls.
macro_rules! one_field_slot {
    ($( [$($gen:tt)*] $ty:ty ),* $(,)?) => {$(
        impl<$($gen)*> $ty {
            /// The slot at flat field `index` of a block of `total` fields,
            /// its path segmented as compactc segments it
            /// ([`FieldPath::in_block`]).
            pub const fn at_block(total: usize, index: usize) -> Self {
                Self::at_path(FieldPath::in_block(total, index).as_slice())
            }
        }

        impl<$($gen)*> LedgerWidth for $ty {}
    )*};
}

one_field_slot! {
    [K, V] LedgerMap<K, V>,
    [T] LedgerSet<T>,
    [T] LedgerList<T>,
    [const DEPTH: u8, T] LedgerMerkleTree<DEPTH, T>,
    [const DEPTH: u8, T] LedgerHistoricMerkleTree<DEPTH, T>,
    [T] LedgerCell<T>,
    [] LedgerCounter,
    [] LedgerField,
}

impl sealed::Path for FieldPath {}

impl LedgerPath for FieldPath {
    const KEYS: usize = 0;
    type Deeper = KeyPath<1>;

    fn to_path(&self) -> Vec<LedgerKey> {
        self.elems[..self.len as usize]
            .iter()
            .map(|i| LedgerKey::Field(*i))
            .collect()
    }
}

/// The runtime half: a field path with `KEYS` map keys appended, one per
/// `at_key`.
///
/// The keys are CLONED limbs (wires are `Copy`), which is what lets a nested
/// handle be an ordinary value with no lifetime in sight.
#[derive(Clone)]
pub struct KeyPath<const KEYS: usize> {
    path: Vec<LedgerKey>,
}

macro_rules! key_paths {
    ($( $keys:literal => $deeper:literal ),* $(,)?) => {$(
        impl sealed::Path for KeyPath<$keys> {}

        impl LedgerPath for KeyPath<$keys> {
            const KEYS: usize = $keys;
            type Deeper = KeyPath<$deeper>;

            fn to_path(&self) -> Vec<LedgerKey> {
                self.path.clone()
            }
        }

        impl KeyedPath for KeyPath<$keys> {
            fn rooted(path: Vec<LedgerKey>) -> Self {
                KeyPath { path }
            }
        }
    )*};
}

// One per legal depth. `KeyPath<11>` is DELIBERATELY not among them: it is a
// type with no `KeyedPath` impl, so `at_key` on a ten-key handle fails its
// where-clause — the project's preferred rejection spelling (a missing impl
// beats an assert), with the arithmetic in the `on_unimplemented` note.
key_paths! {
    1 => 2, 2 => 3, 3 => 4, 4 => 5, 5 => 6,
    6 => 7, 7 => 8, 8 => 9, 9 => 10, 10 => 11,
}

// ---- WHAT MAY SIT IN A SLOT: the two families ------------------------------

/// Sealed: what a `Map`'s VALUE position may hold. There are exactly two
/// families and no third.
///
/// | family | bound | what `insertDefault` pushes |
/// |--------|-------|------------------------------|
/// | plain VALUES | [`LedgerRepr`] | a cell of zeros, one limb per FAB limb |
/// | ADT HANDLES | [`LedgerAdt`] | the ADT's own `(initial-value …)` |
///
/// That second column is the whole reason this is a trait rather than a
/// comment. `Map.insert` / `insertDefault` push `(state-value 'ADT value
/// value_type)`, and `assemble-operand-acc`'s `VMstate-value-ADT` case
/// (reduce-to-zkir.ss:424-433) DISCARDS the value and expands the ADT's
/// declared initial value whenever the type is an ADT — the empty map for
/// `Map`/`Set`, `[null, null, 0]` for `List`, `cell 0u64` for `Counter`, the
/// blank pair for the trees. So `insertDefault` is ONE method whose emission
/// is decided by the value type's family, and the fixture circuit
/// `outerInsertDefault` is the differential that pins it.
///
/// The two impls are disjoint by construction: no ADT handle is a
/// [`LedgerRepr`], and the orphan rule stops anything downstream making one.
pub trait LedgerSlot: sealed::Slot {
    /// `map.insertDefault(key)` at `path`, for a map whose value type is
    /// `Self` — the ONE Impact operation, either way.
    fn insert_default_ops(path: &[LedgerKey], key: &LedgerValue) -> Vec<ImpactOp>;
}

impl<T: LedgerRepr> sealed::Slot for T {}

/// The VALUE family: a stored value's default is zeros in every limb
/// (notes/ledger-adts.org finding (c)).
impl<T: LedgerRepr> LedgerSlot for T {
    fn insert_default_ops(path: &[LedgerKey], key: &LedgerValue) -> Vec<ImpactOp> {
        map_insert_default_at(path, key, T::atoms())
    }
}

/// The ADT family: the handle types Compact's `Map` may hold, which is `Map`
/// itself and the five other ADTs (`expand-modules-and-types.ss:256-263` —
/// `Map`'s value formal is the ONE `ADT/Type` across all six declarations, so
/// `Set<List<T>>` and `List<Map<K,V>>` are compactc's own compile errors and
/// must not type here either).
///
/// `at_key` is the whole of it: it builds the path and emits NOTHING, exactly
/// as `.field()` does, and the cost stays at the leaf method where Compact
/// puts it.
pub trait LedgerAdt: LedgerSlot {
    /// The same handle, rooted at a runtime path.
    type Rooted<Q: KeyedPath>;

    /// Root it. `at_key`'s only job past building the path.
    #[doc(hidden)]
    fn rooted_at<Q: KeyedPath>(path: Q) -> Self::Rooted<Q>;
}

// ---- the ledger slots -------------------------------------------------------
//
// Each is a PATH and the phantom types of what it holds, constructed by the
// `at(index)` / `at_path(path)` the derive calls. The declared form is
// `const`-constructible, so a contract's ledger block is a `const` item and
// costs nothing at run time; the nested form (`P = KeyPath<n>`) is an
// ordinary value carrying its keys' limbs.

/// `export ledger m: Map<K, V>` — Compact's `Map` methods, one Impact
/// operation each.
///
/// Every method takes `c`, because every one of them costs: a read mints one
/// `public_input` gate per FAB limb of what it reads and then emits the op's
/// Impact instructions; a write emits the op's instructions.
///
/// ONE FORM: `member(c, &k)` and every other method here is written exactly
/// as Compact writes it (`map.member(key)` — Compact has no guard argument at
/// all) and picks up whatever guard is AMBIENT: the immediate `1` in
/// straight-line code, or a branch condition's wire when the call sits inside
/// [`Circuit3::when`] / [`Circuit3::when_private`] — the one spelling of a
/// conditional (notes/edsl-trim.org §B). There is no separate `_under` /
/// `_guarded` twin to reach for: `c.when(g, |c| MAP.member(c, &k))` is both
/// what a guarded effect and a guarded read are, and the scope is what
/// resolves the guard, not the call.
pub struct LedgerMap<K, V, P = FieldPath> {
    path: P,
    _kv: PhantomData<fn() -> (K, V)>,
}

impl<K, V> LedgerMap<K, V> {
    /// The declared field's path — what a Signet notification carries so
    /// the MPC can walk to this map (`signet_flow::Pending`).
    pub const fn field_path(&self) -> FieldPath {
        self.path
    }

    /// The map held in ledger field `index` (the derive supplies it).
    pub const fn at(index: u8) -> Self {
        LedgerMap {
            path: FieldPath::field(index),
            _kv: PhantomData,
        }
    }

    /// The map held at ledger field PATH `path` — what `#[derive(Ledger)]`
    /// emits, and the only spelling a block of sixteen fields or more has
    /// (see [`FieldPath`]).
    pub const fn at_path(path: &[u8]) -> Self {
        LedgerMap {
            path: FieldPath::of(path),
            _kv: PhantomData,
        }
    }

    /// The ledger field index.
    pub const fn index(&self) -> u8 {
        self.path.index()
    }
}

impl<K, V, P: LedgerPath> LedgerMap<K, V, P> {
    /// compactc's `f` for this slot.
    pub(crate) fn ledger_path(&self) -> Vec<LedgerKey> {
        self.path.to_path()
    }
}

impl<K, V, P> sealed::Slot for LedgerMap<K, V, P> {}

/// A `Map` in a `Map`'s value position: `insertDefault` pushes the EMPTY MAP,
/// not a cell of zeros (see [`LedgerSlot`]).
impl<K, V, P> LedgerSlot for LedgerMap<K, V, P> {
    fn insert_default_ops(path: &[LedgerKey], key: &LedgerValue) -> Vec<ImpactOp> {
        map_insert_adt_default_at(path, key, empty_map())
    }
}

impl<K, V, P> LedgerAdt for LedgerMap<K, V, P> {
    type Rooted<Q: KeyedPath> = LedgerMap<K, V, Q>;

    fn rooted_at<Q: KeyedPath>(path: Q) -> Self::Rooted<Q> {
        LedgerMap {
            path,
            _kv: PhantomData,
        }
    }
}

impl<K: LedgerRepr, A: LedgerAdt, P: LedgerPath> LedgerMap<K, A, P> {
    /// `map.lookup(key)` where the value is an ADT — the INTERMEDIATE lookup,
    /// which emits NOTHING.
    ///
    /// compactc's `propagate-ledger-paths.ss` folds every non-final accessor
    /// into the path `f` at compile time and runs only the LAST accessor's
    /// vm-code, so this is path building and not an operation: it costs no
    /// Impact instruction, no gate and no row, exactly like `.field()`. What
    /// it costs is the key's limbs, which the leaf op would have pushed
    /// anyway — and it takes `c` only because a repr may compute its limbs
    /// ([`LedgerRepr::push_limbs`]).
    ///
    /// The returned handle carries the key's limbs and is an ordinary value;
    /// its methods are the ADT's ordinary surface, each emitting the ONE
    /// Impact operation Compact names, with this path re-encoded into it.
    /// Chaining is the only depth mechanism there is — there is deliberately
    /// no `lookup2(c, &k1, &k2)` family.
    ///
    /// ```ignore
    /// let user = TREASURY.balances.at_key(c, &user_id);  // no instructions
    /// let bal = user.lookup(c, &token);                  // ONE op, path [field, user, ..]
    /// TREASURY.deep.at_key(c, &a).at_key(c, &b).lookup(c, &k);
    /// ```
    ///
    /// Nesting past [`MAX_NESTING`] keys does not compile: `KeyPath<10>`'s
    /// `Deeper` has no [`KeyedPath`] impl, so the eleventh `at_key` fails
    /// this method's where-clause — at TYPE-CHECK time, in dead code too.
    ///
    /// ```compile_fail
    /// use minocrab::v3::Circuit3;
    /// use minocrab::Public;
    /// use minocrab_std::v3::{LedgerMap, Uint, B32};
    ///
    /// type K = B32<Public>;
    /// type L0 = Uint<64, Public>;
    /// type L1 = LedgerMap<K, L0>;
    /// type L2 = LedgerMap<K, L1>;
    /// type L3 = LedgerMap<K, L2>;
    /// type L4 = LedgerMap<K, L3>;
    /// type L5 = LedgerMap<K, L4>;
    /// type L6 = LedgerMap<K, L5>;
    /// type L7 = LedgerMap<K, L6>;
    /// type L8 = LedgerMap<K, L7>;
    /// type L9 = LedgerMap<K, L8>;
    /// type L10 = LedgerMap<K, L9>;
    /// type L11 = LedgerMap<K, L10>;
    /// type L12 = LedgerMap<K, L11>;
    ///
    /// const DEEP: L12 = LedgerMap::at(0);
    ///
    /// fn f(c: &mut Circuit3, k: &K) {
    ///     DEEP.at_key(c, k).at_key(c, k).at_key(c, k).at_key(c, k)
    ///         .at_key(c, k).at_key(c, k).at_key(c, k).at_key(c, k)
    ///         .at_key(c, k).at_key(c, k).at_key(c, k).lookup(c, k);
    /// }
    /// ```
    ///
    /// while TEN keys — the deepest `f` an `insc` nibble can close over a
    /// field path of the maximum width — compiles, on the same types:
    ///
    /// ```
    /// # use minocrab::v3::Circuit3;
    /// # use minocrab::Public;
    /// # use minocrab_std::v3::{LedgerMap, Uint, B32};
    /// # type K = B32<Public>;
    /// # type L0 = Uint<64, Public>;
    /// # type L1 = LedgerMap<K, L0>;
    /// # type L2 = LedgerMap<K, L1>;
    /// # type L3 = LedgerMap<K, L2>;
    /// # type L4 = LedgerMap<K, L3>;
    /// # type L5 = LedgerMap<K, L4>;
    /// # type L6 = LedgerMap<K, L5>;
    /// # type L7 = LedgerMap<K, L6>;
    /// # type L8 = LedgerMap<K, L7>;
    /// # type L9 = LedgerMap<K, L8>;
    /// # type L10 = LedgerMap<K, L9>;
    /// # type L11 = LedgerMap<K, L10>;
    /// # type L12 = LedgerMap<K, L11>;
    /// const DEEP: L12 = LedgerMap::at(0);
    ///
    /// fn f(c: &mut Circuit3, k: &K) {
    ///     DEEP.at_key(c, k).at_key(c, k).at_key(c, k).at_key(c, k)
    ///         .at_key(c, k).at_key(c, k).at_key(c, k).at_key(c, k)
    ///         .at_key(c, k).at_key(c, k).size(c);
    /// }
    /// # let _: fn(&mut Circuit3, &K) = f;
    /// ```
    pub fn at_key(&self, c: &mut Circuit3, key: &K) -> A::Rooted<P::Deeper>
    where
        P::Deeper: KeyedPath,
    {
        // BELT AND BRACES, and unreachable while the impls above stop at
        // `MAX_NESTING`: the where-clause has already rejected anything this
        // could catch. It states the arithmetic in code so that adding a
        // `KeyPath` impl cannot quietly move the bound.
        const {
            assert!(
                P::KEYS + 1 + MAX_FIELD_PATH <= MAX_LEDGER_PATH,
                "a ledger path this deep does not fit the Impact opcodes' \
                 nibbles: `insc len(f) + 2` is the deepest closing any \
                 operation has, so `f` may hold at most thirteen elements, \
                 and a field path may take three of them"
            )
        };
        let mut path = self.ledger_path();
        path.push(LedgerKey::Value(key.ledger_value(c)));
        A::rooted_at(<P::Deeper as KeyedPath>::rooted(path))
    }
}

/// The operations that do not touch the VALUE, so the value type is
/// unconstrained: they read or remove a key, and an ADT-valued map has them
/// exactly as a plain one does.
impl<K: LedgerRepr, V, P: LedgerPath> LedgerMap<K, V, P> {
    /// `map.member(key)` — `dup 0; idx [field]; push key; member; popeqc`.
    pub fn member(&self, c: &mut Circuit3, key: &K) -> Assumed<Bool<Public>> {
        let key = key.ledger_value(c);
        Assumed::of_read(Bool::from_field_unchecked(map_member_at(c, &self.ledger_path(), &key)))
    }

    /// `map.remove(key)` — `idxp [field]; push key; rem; insc 1`.
    pub fn remove(&self, c: &mut Circuit3, key: &K) {
        let key = key.ledger_value(c);
        emit(c, &map_remove_at(&self.ledger_path(), &key));
    }
}

impl<K: LedgerRepr, V: LedgerRepr, P: LedgerPath> LedgerMap<K, V, P> {
    /// `map.lookup(key)` — `dup 0; idx [field]; idx {key}; popeq`. The value
    /// atoms come from `V`.
    ///
    /// A LEAF lookup, and it is TWO `idx` instructions: the path reaches the
    /// map and the key descends with its own one-element `idx`
    /// (midnight-ledger.ss:741-747). Only an INTERMEDIATE lookup —
    /// [`at_key`](LedgerMap::at_key), whose value type is an ADT — folds into
    /// the path and emits nothing at all.
    pub fn lookup(&self, c: &mut Circuit3, key: &K) -> Assumed<V> {
        let key = key.ledger_value(c);
        Assumed::of_read(V::from_limbs(map_lookup_at(c, &self.ledger_path(), &key, V::atoms())))
    }

    /// `map.insert(key, value)` — `idxp [field]; push key; pushs value;
    /// ins 1; insc 1`.
    pub fn insert(&self, c: &mut Circuit3, key: &K, value: &impl Fresh<V>) {
        let key = key.ledger_value(c);
        let value = stored(c, value, "a map insert's value");
        emit(c, &map_insert_at(&self.ledger_path(), &key, &value));
    }
}

/// `insertDefault` is the ONE method whose emission depends on which family
/// the value type belongs to — see [`LedgerSlot`].
impl<K: LedgerRepr, V: LedgerSlot, P: LedgerPath> LedgerMap<K, V, P> {
    /// `map.insertDefault(key)` — `idxp [field]; push key; pushs default;
    /// ins 1; insc 1`.
    ///
    /// The pushed default is `V`'s: zeros in every limb for a stored VALUE
    /// (notes/ledger-adts.org finding (c)), and the ADT's own
    /// `(initial-value …)` — the empty map, `[null, null, 0]`, `cell 0u64`,
    /// the blank tree — when the value type is an ADT
    /// (notes/coin-arms-nested-adts.org, stage B1 correction (iii)).
    pub fn insert_default(&self, c: &mut Circuit3, key: &K) {
        let key = key.ledger_value(c);
        emit(c, &V::insert_default_ops(&self.ledger_path(), &key));
    }
}

/// `Map<K, QualifiedShieldedCoinInfo>` — the ONE value type that grows a
/// method, because compactc declares `insertCoin` under
/// `(when (= value_type QualifiedShieldedCoinInfo))` (midnight-ledger.ss:768).
/// A map of any other value type has no such method, and here that is an
/// unsatisfied [`CoinArm`] bound rather than a runtime complaint.
///
/// DECLARED SLOTS ONLY (`P = FieldPath`). The lowering handles a coin arm at
/// any depth — the four `dup` reaches are functions of `len(f)` and
/// `minocrab_ledger` pins them — but no NESTED coin arm has a differential
/// behind it, so the typed surface does not offer one
/// (notes/coin-arms-nested-adts.org, stage B1 "not covered").
impl<K: LedgerRepr, V: CoinArm> LedgerMap<K, V> {
    /// `map.insertCoin(key, coin, recipient)` — `idxp [field]; push key;
    /// dup 5; push cm; idxc [(1), stack]; push coin; swap 0; concatc 91;
    /// ins 1; insc 1`.
    ///
    /// [`insert`](LedgerMap::insert) with its value push replaced by the
    /// qualify dance: the `ShieldedCoinInfo` is turned into the
    /// `QualifiedShieldedCoinInfo` the map stores by looking its Merkle-tree
    /// index up in the transaction context, ON CHAIN. The index must have
    /// been allocated within the current transaction or the insert fails —
    /// that is upstream's rule, enforced by the VM, not by this signature.
    pub fn insert_coin(
        &self,
        c: &mut Circuit3,
        key: &K,
        coin: &ShieldedCoinInfo3<Public>,
        recipient: &CoinRecipient<Public>,
    ) {
        let key = key.ledger_value(c);
        let (cm, coin) = coin_operands(c, coin, recipient);
        emit(c, &map_insert_coin_at(&self.ledger_path(), &key, &cm, &coin));
    }
}

/// The operations that touch neither the key nor the value type.
impl<K, V, P: LedgerPath> LedgerMap<K, V, P> {
    /// `map.size()` — `dup 0; idx [field]; size; popeqc`.
    pub fn size(&self, c: &mut Circuit3) -> Assumed<Uint<64, Public>> {
        Assumed::of_read(Uint::from_field_unchecked(map_size_at(c, &self.ledger_path())))
    }

    /// `map.isEmpty()` — `dup 0; idx [field]; size; push 0; eq; popeqc`.
    pub fn is_empty(&self, c: &mut Circuit3) -> Assumed<Bool<Public>> {
        Assumed::of_read(Bool::from_field_unchecked(map_is_empty_at(c, &self.ledger_path())))
    }

    /// `map.resetToDefault()` — `push key; pushs (empty map); ins 1`. Needs
    /// no bound on `K`/`V`: an empty map is empty whatever it held.
    ///
    /// At depth 1 that is three instructions; NESTED it is five — the leading
    /// `idxp` over the container's path and the closing `insc len(f) − 1`
    /// that compactc suppresses away at depth 1 both come back
    /// (`suppress-null` / `suppress-zero`, vm.ss:192-194).
    pub fn reset_to_default(&self, c: &mut Circuit3) {
        emit(c, &map_reset_at(&self.ledger_path()));
    }
}

/// `export ledger s: Set<T>` — a `Map` with `Null` values, which is what
/// Compact's `Set` IS.
///
/// Every method here delegates to the `Map` one, and that is a fact about the
/// vm-code rather than a shortcut: compactc's `Set` and `Map` declarations
/// give `member`, `remove`, `size`, `isEmpty` and `resetToDefault` character
/// for character the same instruction sequences, and the corpus fixture's
/// `setRemove` / `setSize` / `setIsEmpty` / `setReset` are byte-identical to
/// `map_remove` / `map_size` / `map_is_empty` / `map_reset`
/// (notes/ledger-adts.org §1). Only [`insert`](LedgerSet::insert) differs, and
/// only in what it stores: a `Null` where a map stores a value.
pub struct LedgerSet<T, P = FieldPath> {
    path: P,
    _t: PhantomData<fn() -> T>,
}

impl<T> LedgerSet<T> {
    /// The set held in ledger field `index` (the derive supplies it).
    pub const fn at(index: u8) -> Self {
        LedgerSet {
            path: FieldPath::field(index),
            _t: PhantomData,
        }
    }

    /// The set held at ledger field PATH `path` (see [`FieldPath`]).
    pub const fn at_path(path: &[u8]) -> Self {
        LedgerSet {
            path: FieldPath::of(path),
            _t: PhantomData,
        }
    }

    /// The ledger field index.
    pub const fn index(&self) -> u8 {
        self.path.index()
    }
}

impl<T, P: LedgerPath> LedgerSet<T, P> {
    /// compactc's `f` for this slot.
    fn ledger_path(&self) -> Vec<LedgerKey> {
        self.path.to_path()
    }
}

impl<T, P> sealed::Slot for LedgerSet<T, P> {}

/// A `Set` in a `Map`'s value position: `insertDefault` pushes the EMPTY MAP,
/// which is a `Set`'s initial value as much as a `Map`'s
/// (midnight-ledger.ss:624).
impl<T, P> LedgerSlot for LedgerSet<T, P> {
    fn insert_default_ops(path: &[LedgerKey], key: &LedgerValue) -> Vec<ImpactOp> {
        map_insert_adt_default_at(path, key, empty_map())
    }
}

impl<T, P> LedgerAdt for LedgerSet<T, P> {
    type Rooted<Q: KeyedPath> = LedgerSet<T, Q>;

    fn rooted_at<Q: KeyedPath>(path: Q) -> Self::Rooted<Q> {
        LedgerSet {
            path,
            _t: PhantomData,
        }
    }
}

impl<T: LedgerRepr, P: LedgerPath> LedgerSet<T, P> {
    /// `set.insert(elem)` — `idxp [field]; push elem; pushs null; ins 1; insc 1`.
    pub fn insert(&self, c: &mut Circuit3, elem: &T) {
        let elem = elem.ledger_value(c);
        emit(c, &set_insert_at(&self.ledger_path(), &elem));
    }

    /// `set.member(elem)` — `dup 0; idx [field]; push elem; member; popeqc`.
    ///
    /// The same op a map's `member` is, which is why it delegates to
    /// `map_member` rather than to a `set_member` that would be its duplicate.
    pub fn member(&self, c: &mut Circuit3, elem: &T) -> Assumed<Bool<Public>> {
        let elem = elem.ledger_value(c);
        Assumed::of_read(Bool::from_field_unchecked(map_member_at(c, &self.ledger_path(), &elem)))
    }

    /// `set.remove(elem)` — `idxp [field]; push elem; rem; insc 1`.
    pub fn remove(&self, c: &mut Circuit3, elem: &T) {
        let elem = elem.ledger_value(c);
        emit(c, &set_remove_at(&self.ledger_path(), &elem));
    }
}

/// `Set<QualifiedShieldedCoinInfo>` — the element type compactc gates
/// `insertCoin` on (midnight-ledger.ss:669).
///
/// DECLARED SLOTS ONLY — see [`LedgerMap::insert_coin`] for why the nested
/// coin arms are not offered.
impl<T: CoinArm> LedgerSet<T> {
    /// `set.insertCoin(coin, recipient)` — `idxp [field]; dup 4; push cm;
    /// idxc [(1), stack]; push coin; swap 0; concatc 91; pushs null; ins 1;
    /// insc 1`.
    ///
    /// [`insert`](LedgerSet::insert) with its element push replaced by the
    /// qualify dance. The qualified coin is the KEY the `Null` is stored
    /// under, which is why the dance runs before the `pushs null`.
    pub fn insert_coin(
        &self,
        c: &mut Circuit3,
        coin: &ShieldedCoinInfo3<Public>,
        recipient: &CoinRecipient<Public>,
    ) {
        let (cm, coin) = coin_operands(c, coin, recipient);
        emit(c, &set_insert_coin_at(&self.ledger_path(), &cm, &coin));
    }
}

impl<T, P: LedgerPath> LedgerSet<T, P> {
    /// `set.size()` — `dup 0; idx [field]; size; popeqc`.
    pub fn size(&self, c: &mut Circuit3) -> Assumed<Uint<64, Public>> {
        Assumed::of_read(Uint::from_field_unchecked(set_size_at(c, &self.ledger_path())))
    }

    /// `set.isEmpty()` — `dup 0; idx [field]; size; push 0; eq; popeqc`.
    pub fn is_empty(&self, c: &mut Circuit3) -> Assumed<Bool<Public>> {
        Assumed::of_read(Bool::from_field_unchecked(set_is_empty_at(c, &self.ledger_path())))
    }

    /// `set.resetToDefault()` — `push key; pushs (empty map); ins 1`.
    pub fn reset_to_default(&self, c: &mut Circuit3) {
        emit(c, &set_reset_at(&self.ledger_path()));
    }
}

// ---- List -------------------------------------------------------------------

/// `export ledger l: List<T>` — an unbounded singly-linked list, stored as an
/// `Array[3]` of `{head cell, tail list, length}` (notes/ledger-adts.org §1).
///
/// Compact's own method names, and the same one-op-per-method invariant as
/// every slot here. [`head`](LedgerList::head) is the one worth reading twice:
/// it returns a [`Maybe<T>`](Maybe) — so it is safe on the empty list — and it
/// does that with Impact-level `branch`/`jmp`, which the CIRCUIT does not see.
/// Its cost is fifteen constant instructions and a `Maybe<T>`'s worth of
/// witnessed limbs, whether the list is empty or not.
pub struct LedgerList<T, P = FieldPath> {
    path: P,
    _t: PhantomData<fn() -> T>,
}

impl<T> LedgerList<T> {
    /// The list held in ledger field `index` (the derive supplies it).
    pub const fn at(index: u8) -> Self {
        LedgerList {
            path: FieldPath::field(index),
            _t: PhantomData,
        }
    }

    /// The list held at ledger field PATH `path` (see [`FieldPath`]).
    pub const fn at_path(path: &[u8]) -> Self {
        LedgerList {
            path: FieldPath::of(path),
            _t: PhantomData,
        }
    }

    /// The ledger field index.
    pub const fn index(&self) -> u8 {
        self.path.index()
    }
}

impl<T, P> sealed::Slot for LedgerList<T, P> {}

/// A `List` in a `Map`'s value position: `insertDefault` pushes a `List`'s
/// initial value, `[null, null, cell 0u64]` (midnight-ledger.ss:800).
impl<T, P> LedgerSlot for LedgerList<T, P> {
    fn insert_default_ops(path: &[LedgerKey], key: &LedgerValue) -> Vec<ImpactOp> {
        map_insert_adt_default_at(path, key, empty_list())
    }
}

impl<T, P> LedgerAdt for LedgerList<T, P> {
    type Rooted<Q: KeyedPath> = LedgerList<T, Q>;

    fn rooted_at<Q: KeyedPath>(path: Q) -> Self::Rooted<Q> {
        LedgerList {
            path,
            _t: PhantomData,
        }
    }
}

impl<T, P: LedgerPath> LedgerList<T, P> {
    /// compactc's `f` for this slot.
    fn ledger_path(&self) -> Vec<LedgerKey> {
        self.path.to_path()
    }

    /// `list.popFront()` — `idxp [field]; idx [1]; insc 1`. Needs no bound on
    /// `T`: the list becomes its own tail, and nothing is read or written.
    pub fn pop_front(&self, c: &mut Circuit3) {
        emit(c, &list_pop_front_at(&self.ledger_path()));
    }

    /// `list.length()` — `dup 0; idx [field]; idx [2]; popeqc`. A stored
    /// count, not a computed `size`.
    pub fn length(&self, c: &mut Circuit3) -> Assumed<Uint<64, Public>> {
        Assumed::of_read(Uint::from_field_unchecked(list_length_at(c, &self.ledger_path())))
    }

    /// `list.isEmpty()` — `dup 0; idx [field]; idx [1]; type; push 1; eq;
    /// popeqc`, i.e. "the tail is null".
    pub fn is_empty(&self, c: &mut Circuit3) -> Assumed<Bool<Public>> {
        Assumed::of_read(Bool::from_field_unchecked(list_is_empty_at(c, &self.ledger_path())))
    }

    /// `list.resetToDefault()` — `push key; pushs [null, null, 0]; ins 1`.
    pub fn reset_to_default(&self, c: &mut Circuit3) {
        emit(c, &list_reset_at(&self.ledger_path()));
    }
}

impl<T: LedgerRepr, P: LedgerPath> LedgerList<T, P> {
    /// `list.pushFront(value)` — thirteen instructions building a new
    /// `[value, old list, len + 1]` node (notes/ledger-adts.org §1).
    ///
    /// The one M16 operation with corpus provenance: it is
    /// `test-caller-contract`'s `requestLog.pushFront(requestId)`.
    pub fn push_front(&self, c: &mut Circuit3, value: &impl Fresh<T>) {
        let value = stored(c, value, "a list push's value");
        emit(c, &list_push_front_at(&self.ledger_path(), &value));
    }

    /// `list.head()` — the first element, or `None` on the empty list.
    pub fn head(&self, c: &mut Circuit3) -> Assumed<Maybe<T, Public>> {
        let mut limbs = list_head_at(c, &self.ledger_path(), T::atoms());
        let value = T::from_limbs(limbs.split_off(1));
        Assumed::of_read(Maybe {
            is_some: Bool::from_field_unchecked(limbs[0]),
            value,
        })
    }
}

/// `List<QualifiedShieldedCoinInfo>` — the element type compactc gates
/// `pushFrontCoin` on (midnight-ledger.ss:917).
///
/// No [`LedgerRepr`] bound, and that is the point of the arm: what the node
/// holds is built ON CHAIN by the qualify dance, so nothing is pushed that
/// the type would have to hand limbs for.
///
/// DECLARED SLOTS ONLY — see [`LedgerMap::insert_coin`].
impl<T: CoinArm> LedgerList<T> {
    /// `list.pushFrontCoin(coin, recipient)` — twenty-one instructions, and
    /// the one coin arm that is not a one-for-one swap on its plain twin.
    ///
    /// [`push_front`](LedgerList::push_front) builds its new node with the
    /// value already in it and this cannot: the qualified coin does not
    /// exist until the dance has run against a node that is already on the
    /// stack. So the node goes on BLANK (`[null, null, null]`), the head
    /// slot's key `0u8` goes on, the dance runs at `dup 7`, and an `insc 1`
    /// puts the coin at `node[0]`. The tail — `node[2] = len + 1`,
    /// `node[1] = the old list` — is `pushFront`'s, instruction for
    /// instruction.
    pub fn push_front_coin(
        &self,
        c: &mut Circuit3,
        coin: &ShieldedCoinInfo3<Public>,
        recipient: &CoinRecipient<Public>,
    ) {
        let (cm, coin) = coin_operands(c, coin, recipient);
        emit(c, &list_push_front_coin_at(&self.ledger_path(), &cm, &coin));
    }
}

// ---- MerkleTree and HistoricMerkleTree --------------------------------------

/// `export ledger t: MerkleTree<DEPTH, T>` — a bounded Merkle tree stored as
/// an `Array[2]` of `{tree, next free index}`.
///
/// `DEPTH` is Compact's `nat`, and Compact's rule is `2 <= nat <= 32`: the
/// height is part of the tree's `field_repr` tag, so a wrong depth is a wrong
/// TRANSCRIPT rather than a runtime error. It is checked by an inline-const
/// assert, per the project's compile-errors-over-panics rule — so a depth
/// outside the range is E0080 at the `at()` that names it:
///
/// ```compile_fail
/// use minocrab::Public;
/// use minocrab_std::v3::{LedgerMerkleTree, B32};
///
/// const T: LedgerMerkleTree<1, B32<Public>> = LedgerMerkleTree::at(0);
/// ```
///
/// while the same line at a legal depth compiles:
///
/// ```
/// use minocrab::Public;
/// use minocrab_std::v3::{LedgerMerkleTree, B32};
///
/// const T: LedgerMerkleTree<2, B32<Public>> = LedgerMerkleTree::at(0);
/// ```
///
/// The five `insert*` methods are TWO instruction streams: `insert` /
/// `insert_hash` share one, and `insert_index` / `insert_hash_index` /
/// `insert_index_default` share the other. What differs between the members of
/// a pair is only where the 32-byte leaf came from — hashed from the item
/// ([`leaf_hash`]), handed over directly, or hashed from `T`'s default.
pub struct LedgerMerkleTree<const DEPTH: u8, T, P = FieldPath> {
    path: P,
    _t: PhantomData<fn() -> T>,
}

/// The `2 <= DEPTH <= 32` check, shared by both tree types.
const fn check_depth(depth: u8) {
    assert!(
        depth >= 2 && depth <= 32,
        "a Merkle tree's depth must satisfy 2 <= DEPTH <= 32 — Compact's own \
         bound, and upstream's BoundedMerkleTree carries the height in its \
         field_repr tag, so a wrong depth is a wrong transcript"
    );
}

impl<const DEPTH: u8, T> LedgerMerkleTree<DEPTH, T> {
    /// The tree held in ledger field `index` (the derive supplies it).
    pub const fn at(index: u8) -> Self {
        const { check_depth(DEPTH) };
        LedgerMerkleTree {
            path: FieldPath::field(index),
            _t: PhantomData,
        }
    }

    /// The tree held at ledger field PATH `path` (see [`FieldPath`]).
    pub const fn at_path(path: &[u8]) -> Self {
        const { check_depth(DEPTH) };
        LedgerMerkleTree {
            path: FieldPath::of(path),
            _t: PhantomData,
        }
    }

    /// The ledger field index.
    pub const fn index(&self) -> u8 {
        self.path.index()
    }
}

impl<const DEPTH: u8, T, P> sealed::Slot for LedgerMerkleTree<DEPTH, T, P> {}

/// A `MerkleTree` in a `Map`'s value position: `insertDefault` pushes the
/// blank tree of this depth and index 0 (midnight-ledger.ss:973).
impl<const DEPTH: u8, T, P> LedgerSlot for LedgerMerkleTree<DEPTH, T, P> {
    fn insert_default_ops(path: &[LedgerKey], key: &LedgerValue) -> Vec<ImpactOp> {
        map_insert_adt_default_at(path, key, empty_merkle_tree_value(DEPTH))
    }
}

impl<const DEPTH: u8, T, P> LedgerAdt for LedgerMerkleTree<DEPTH, T, P> {
    type Rooted<Q: KeyedPath> = LedgerMerkleTree<DEPTH, T, Q>;

    fn rooted_at<Q: KeyedPath>(path: Q) -> Self::Rooted<Q> {
        LedgerMerkleTree {
            path,
            _t: PhantomData,
        }
    }
}

impl<const DEPTH: u8, T, P: LedgerPath> LedgerMerkleTree<DEPTH, T, P> {
    /// compactc's `f` for this slot.
    fn ledger_path(&self) -> Vec<LedgerKey> {
        self.path.to_path()
    }

    /// `t.isFull()` — `!(next < 2^DEPTH)`.
    pub fn is_full(&self, c: &mut Circuit3) -> Assumed<Bool<Public>> {
        Assumed::of_read(Bool::from_field_unchecked(merkle_tree_is_full_at(c, &self.ledger_path(), DEPTH)))
    }

    /// `t.checkRoot(rt)` — whether `rt` is the tree's CURRENT root.
    pub fn check_root(&self, c: &mut Circuit3, root: MerkleTreeDigest<Public>) -> Assumed<Bool<Public>> {
        let root = root.ledger_value(c);
        Assumed::of_read(Bool::from_field_unchecked(merkle_tree_check_root_at(c, &self.ledger_path(), &root)))
    }

    /// `t.insertHash(hash)` — insert a leaf whose digest is already known, at
    /// the first free index.
    pub fn insert_hash(&self, c: &mut Circuit3, hash: &B32<Public>) {
        let leaf = hash.ledger_value(c);
        emit(c, &merkle_tree_insert_at(&self.ledger_path(), &leaf));
    }

    /// `t.insertHashIndex(hash, at)` — insert a known digest at a specific
    /// index, bumping the next-free index to `max(next, at + 1)`.
    pub fn insert_hash_index(
        &self,
        c: &mut Circuit3,
        hash: &B32<Public>,
        at: Uint<64, Public>,
    ) {
        let leaf = hash.ledger_value(c);
        let at = at.ledger_value(c);
        emit(
            c,
            &merkle_tree_insert_index_at(&self.ledger_path(), &leaf, &at),
        );
    }

    /// `t.resetToDefault()` — the blank tree of this depth, and index 0.
    pub fn reset_to_default(&self, c: &mut Circuit3) {
        emit(c, &merkle_tree_reset_at(&self.ledger_path(), DEPTH));
    }
}

impl<const DEPTH: u8, T: LedgerRepr, P: LedgerPath> LedgerMerkleTree<DEPTH, T, P> {
    /// `t.insert(item)` — hash the item into a leaf and insert it at the
    /// first free index.
    pub fn insert(&self, c: &mut Circuit3, item: &impl Fresh<T>) {
        let _ = stored(c, item, "a merkle-tree insert's item");
        let hash = leaf_hash(c, item.fresh());
        self.insert_hash(c, &hash);
    }

    /// `t.insertIndex(item, at)` — hash the item and insert it at `at`.
    pub fn insert_index(&self, c: &mut Circuit3, item: &impl Fresh<T>, at: Uint<64, Public>) {
        let _ = stored(c, item, "a merkle-tree insert's item");
        let hash = leaf_hash(c, item.fresh());
        self.insert_hash_index(c, &hash, at);
    }

    /// `t.insertIndexDefault(at)` — insert `T`'s DEFAULT value at `at`,
    /// which is Compact's way of emulating a removal.
    pub fn insert_index_default(&self, c: &mut Circuit3, at: Uint<64, Public>) {
        let hash = default_leaf_hash::<T>(c);
        self.insert_hash_index(c, &hash, at);
    }
}

/// `export ledger t: HistoricMerkleTree<DEPTH, T>` — [`LedgerMerkleTree`]
/// plus a history: an `Array[3]` whose third slot is a `Map` of every root the
/// tree has ever had.
///
/// Every mutation appends the new root to that map, and
/// [`check_root`](LedgerHistoricMerkleTree::check_root) is a `member` on it
/// rather than an equality against the current root — which is the whole
/// difference between the two tree types, and the reason a contract picks this
/// one: a proof against a root that was current when the prover built it stays
/// valid.
pub struct LedgerHistoricMerkleTree<const DEPTH: u8, T, P = FieldPath> {
    path: P,
    _t: PhantomData<fn() -> T>,
}

impl<const DEPTH: u8, T> LedgerHistoricMerkleTree<DEPTH, T> {
    /// The tree held in ledger field `index` (the derive supplies it).
    pub const fn at(index: u8) -> Self {
        const { check_depth(DEPTH) };
        LedgerHistoricMerkleTree {
            path: FieldPath::field(index),
            _t: PhantomData,
        }
    }

    /// The tree held at ledger field PATH `path` (see [`FieldPath`]).
    pub const fn at_path(path: &[u8]) -> Self {
        const { check_depth(DEPTH) };
        LedgerHistoricMerkleTree {
            path: FieldPath::of(path),
            _t: PhantomData,
        }
    }

    /// The ledger field index.
    pub const fn index(&self) -> u8 {
        self.path.index()
    }
}

impl<const DEPTH: u8, T, P> sealed::Slot for LedgerHistoricMerkleTree<DEPTH, T, P> {}

/// A `HistoricMerkleTree` in a `Map`'s value position: `insertDefault` pushes
/// the blank tree, index 0 and an EMPTY history (midnight-ledger.ss:1129 —
/// the declared initial value, which is what `resetToDefault` pushes before
/// it appends the blank root).
impl<const DEPTH: u8, T, P> LedgerSlot for LedgerHistoricMerkleTree<DEPTH, T, P> {
    fn insert_default_ops(path: &[LedgerKey], key: &LedgerValue) -> Vec<ImpactOp> {
        map_insert_adt_default_at(path, key, empty_historic_merkle_tree_value(DEPTH))
    }
}

impl<const DEPTH: u8, T, P> LedgerAdt for LedgerHistoricMerkleTree<DEPTH, T, P> {
    type Rooted<Q: KeyedPath> = LedgerHistoricMerkleTree<DEPTH, T, Q>;

    fn rooted_at<Q: KeyedPath>(path: Q) -> Self::Rooted<Q> {
        LedgerHistoricMerkleTree {
            path,
            _t: PhantomData,
        }
    }
}

impl<const DEPTH: u8, T, P: LedgerPath> LedgerHistoricMerkleTree<DEPTH, T, P> {
    /// compactc's `f` for this slot.
    fn ledger_path(&self) -> Vec<LedgerKey> {
        self.path.to_path()
    }

    /// `t.isFull()` — the same stream [`LedgerMerkleTree::is_full`] emits;
    /// the history does not affect capacity.
    pub fn is_full(&self, c: &mut Circuit3) -> Assumed<Bool<Public>> {
        Assumed::of_read(Bool::from_field_unchecked(merkle_tree_is_full_at(c, &self.ledger_path(), DEPTH)))
    }

    /// `t.checkRoot(rt)` — whether `rt` is one of the tree's PAST roots.
    pub fn check_root(&self, c: &mut Circuit3, root: MerkleTreeDigest<Public>) -> Assumed<Bool<Public>> {
        let root = root.ledger_value(c);
        Assumed::of_read(Bool::from_field_unchecked(historic_merkle_tree_check_root_at(
            c, &self.ledger_path(), &root,
        )))
    }

    /// `t.insertHash(hash)` — insert a known digest at the first free index,
    /// and append the resulting root to the history.
    pub fn insert_hash(&self, c: &mut Circuit3, hash: &B32<Public>) {
        let leaf = hash.ledger_value(c);
        emit(c, &historic_merkle_tree_insert_at(&self.ledger_path(), &leaf));
    }

    /// `t.insertHashIndex(hash, at)`.
    pub fn insert_hash_index(
        &self,
        c: &mut Circuit3,
        hash: &B32<Public>,
        at: Uint<64, Public>,
    ) {
        let leaf = hash.ledger_value(c);
        let at = at.ledger_value(c);
        emit(
            c,
            &historic_merkle_tree_insert_index_at(&self.ledger_path(), &leaf, &at),
        );
    }

    /// `t.resetHistory()` — forget every past root but the current one.
    pub fn reset_history(&self, c: &mut Circuit3) {
        emit(c, &historic_merkle_tree_reset_history_at(&self.ledger_path()));
    }

    /// `t.resetToDefault()` — the blank tree of this depth, index 0, and a
    /// history holding just the blank tree's root.
    pub fn reset_to_default(&self, c: &mut Circuit3) {
        emit(c, &historic_merkle_tree_reset_at(&self.ledger_path(), DEPTH));
    }
}

impl<const DEPTH: u8, T: LedgerRepr, P: LedgerPath> LedgerHistoricMerkleTree<DEPTH, T, P> {
    /// `t.insert(item)`.
    pub fn insert(&self, c: &mut Circuit3, item: &impl Fresh<T>) {
        let _ = stored(c, item, "a merkle-tree insert's item");
        let hash = leaf_hash(c, item.fresh());
        self.insert_hash(c, &hash);
    }

    /// `t.insertIndex(item, at)`.
    pub fn insert_index(&self, c: &mut Circuit3, item: &impl Fresh<T>, at: Uint<64, Public>) {
        let _ = stored(c, item, "a merkle-tree insert's item");
        let hash = leaf_hash(c, item.fresh());
        self.insert_hash_index(c, &hash, at);
    }

    /// `t.insertIndexDefault(at)`.
    pub fn insert_index_default(&self, c: &mut Circuit3, at: Uint<64, Public>) {
        let hash = default_leaf_hash::<T>(c);
        self.insert_hash_index(c, &hash, at);
    }
}

/// compactc's `rt-leaf-hash`: `persistentHash` of the value's FAB
/// representation behind the domain separator `"mdn:lh"`.
///
/// The SAME preimage Compact's Merkle path circuits hash — a Merkle leaf's
/// digest is one thing whether the tree is in the ledger or the proof.
/// Interop flavor by necessity: the digest is one compactc also computes.
pub fn leaf_hash<T: LedgerRepr>(c: &mut Circuit3, item: &T) -> B32<Public> {
    let limbs: Vec<_> = item.limbs(c).into_iter().map(Wire3::erase).collect();
    leaf_hash_of(c, T::atoms(), &limbs)
}

/// [`leaf_hash`] of `T`'s DEFAULT value — all-zero limbs
/// (notes/ledger-adts.org finding (c)), which is what
/// `insertIndexDefault` hashes.
fn default_leaf_hash<T: LedgerRepr>(c: &mut Circuit3) -> B32<Public> {
    let atoms = T::atoms();
    let zeros = atoms.iter().map(atom_limbs).sum::<usize>();
    // Inline immediates, like the separator: compactc's `insertIndexDefault`
    // hashes `["0x6d646e3a6c68", "0x00", "0x00"]` with no `copy` in sight.
    let limbs = vec![AnyWire3::immediate(0u64); zeros];
    leaf_hash_of(c, atoms, &limbs)
}

fn leaf_hash_of(
    c: &mut Circuit3,
    atoms: Vec<AlignmentAtom>,
    limbs: &[AnyWire3<Public>],
) -> B32<Public> {
    let mut segments = vec![AlignmentSegment::Atom(AlignmentAtom::Bytes {
        length: LEAF_HASH_SEP_LEN as u32,
    })];
    segments.extend(atoms.into_iter().map(AlignmentSegment::Atom));
    // Inlined, not named by a `copy`: compactc puts the separator straight
    // into the `persistent_hash` operand list.
    let mut slots = vec![AnyWire3::immediate(
        Fr::from_le_bytes(LEAF_HASH_DOMAIN_SEP).expect("6 bytes fit"),
    )];
    slots.extend(limbs.iter().copied());
    hash::persistent_hash_compact(c, Alignment(segments), &slots)
}

/// The domain separator of every Merkle leaf digest, in compactc and here.
const LEAF_HASH_DOMAIN_SEP: &[u8; LEAF_HASH_SEP_LEN] = b"mdn:lh";
const LEAF_HASH_SEP_LEN: usize = 6;


/// `export ledger x: T` — a Cell.
pub struct LedgerCell<T> {
    path: FieldPath,
    _t: PhantomData<fn() -> T>,
}

impl<T> LedgerCell<T> {
    /// The cell held in ledger field `index`.
    pub const fn at(index: u8) -> Self {
        LedgerCell {
            path: FieldPath::field(index),
            _t: PhantomData,
        }
    }

    /// The cell held at ledger field PATH `path` (see [`FieldPath`]) — a
    /// sixteen-field block makes EVERY cell write a nested one, both
    /// suppressions live.
    pub const fn at_path(path: &[u8]) -> Self {
        LedgerCell {
            path: FieldPath::of(path),
            _t: PhantomData,
        }
    }

    /// The ledger field index.
    pub const fn index(&self) -> u8 {
        self.path.index()
    }

    /// compactc's `f` for this slot.
    pub(crate) fn ledger_path(&self) -> Vec<LedgerKey> {
        self.path.to_path()
    }
}

impl<T: LedgerRepr> LedgerCell<T> {
    /// `x` (a Cell read) — `dup 0; idx [field]; popeq`.
    pub fn read(&self, c: &mut Circuit3) -> Assumed<T> {
        let (value, embed) = T::witness_read(c);
        cell_read_embedded_at(c, &self.ledger_path(), &embed);
        Assumed::of_read(value)
    }

    /// `x = value` — `push key; pushs value; ins 1`.
    pub fn write(&self, c: &mut Circuit3, value: &impl Fresh<T>) {
        let value = stored(c, value, "a cell write's value");
        emit(c, &cell_write_at(&self.ledger_path(), &value));
    }
}

/// `export ledger n: Counter`.
pub struct LedgerCounter<P = FieldPath> {
    path: P,
}

impl LedgerCounter {
    /// The counter held in ledger field `index`.
    pub const fn at(index: u8) -> Self {
        LedgerCounter {
            path: FieldPath::field(index),
        }
    }

    /// The counter held at ledger field PATH `path` (see [`FieldPath`]).
    pub const fn at_path(path: &[u8]) -> Self {
        LedgerCounter {
            path: FieldPath::of(path),
        }
    }

    /// The ledger field index.
    pub const fn index(&self) -> u8 {
        self.path.index()
    }
}

impl<P> sealed::Slot for LedgerCounter<P> {}

/// A `Counter` in a `Map`'s value position: `insertDefault` pushes
/// `cell 0u64` (midnight-ledger.ss:589).
impl<P> LedgerSlot for LedgerCounter<P> {
    fn insert_default_ops(path: &[LedgerKey], key: &LedgerValue) -> Vec<ImpactOp> {
        map_insert_adt_default_at(path, key, empty_counter())
    }
}

impl<P> LedgerAdt for LedgerCounter<P> {
    type Rooted<Q: KeyedPath> = LedgerCounter<Q>;

    fn rooted_at<Q: KeyedPath>(path: Q) -> Self::Rooted<Q> {
        LedgerCounter { path }
    }
}

impl<P: LedgerPath> LedgerCounter<P> {
    /// compactc's `f` for this slot.
    fn ledger_path(&self) -> Vec<LedgerKey> {
        self.path.to_path()
    }

    /// `n` (a Counter read) — `dup 0; idx [field]; popeqc`.
    pub fn read(&self, c: &mut Circuit3) -> Assumed<Uint<64, Public>> {
        Assumed::of_read(Uint::from_field_unchecked(counter_read_at(c, &self.ledger_path())))
    }

    /// `n.resetToDefault()` — `push key; pushs (cell 0u64); ins 1`, the
    /// fourth of the nine whole-field-replace ops; a nested `Map<K, Counter>`
    /// is what needs it.
    pub fn reset_to_default(&self, c: &mut Circuit3) {
        emit(c, &counter_reset_at(&self.ledger_path()));
    }

    /// `n.increment(amount)` — `idxp [field]; addi amount; insc 1`.
    pub fn increment(&self, c: &mut Circuit3, amount: u32) {
        emit(c, &counter_increment_at(&self.ledger_path(), amount));
    }

    /// `n.lessThan(threshold)` — `dup 0; idx [field]; push threshold; lt;
    /// popeqc`.
    pub fn less_than(&self, c: &mut Circuit3, threshold: u64) -> Assumed<Bool<Public>> {
        let threshold = LedgerValue::bytes(
            8,
            vec![ImpactElem::Imm(minocrab::Fr::from(threshold))],
        );
        Assumed::of_read(Bool::from_field_unchecked(counter_less_than_at(c, &self.ledger_path(), &threshold)))
    }
}

/// A ledger field this layer does not model yet — a `Set`, a coin cell, a
/// curve-point cell — declared so that the fields AFTER it keep their
/// indices, and so that the struct is a faithful transcription of the
/// `export ledger` block. It carries its index and nothing else; the
/// operations stay explicit `minocrab_ledger` calls at the call site.
pub struct LedgerField {
    path: FieldPath,
}

impl LedgerField {
    /// The field's path — for a handle that reads it through another API
    /// (an interface crate's `at_field_path`).
    pub const fn field_path(&self) -> FieldPath {
        self.path
    }

    /// The field at ledger index `index`.
    pub const fn at(index: u8) -> Self {
        LedgerField {
            path: FieldPath::field(index),
        }
    }

    /// The field at ledger PATH `path` (see [`FieldPath`]).
    pub const fn at_path(path: &[u8]) -> Self {
        LedgerField {
            path: FieldPath::of(path),
        }
    }

    /// The ledger field index.
    pub const fn index(&self) -> u8 {
        self.path.index()
    }

    /// compactc's `f` for this slot — for the call sites that still build
    /// their own ops below this layer.
    pub fn ledger_path(&self) -> Vec<LedgerKey> {
        self.path.to_path()
    }
}

#[cfg(test)]
mod block_layout_tests {
    use super::*;

    /// `determine-ledger-paths.ss`'s `batch`, non-const, as the derive's
    /// own module transcribes it — the reference `in_block` is pinned to
    /// for every block size a byte index allows.
    fn field_paths(fields: usize) -> Vec<Vec<u8>> {
        enum Tree {
            Leaf(usize),
            Node(Vec<Tree>),
        }
        fn batch(mut level: Vec<Tree>) -> Vec<Tree> {
            let n = level.len();
            if n <= SEGMENT {
                return level;
            }
            let r = n % SEGMENT;
            let rest: Vec<Tree> = level.split_off(r);
            let mut grouped: Vec<Tree> = Vec::new();
            if r != 0 {
                grouped.push(Tree::Node(level));
            }
            let mut rest = rest.into_iter();
            loop {
                let chunk: Vec<Tree> = rest.by_ref().take(SEGMENT).collect();
                if chunk.is_empty() {
                    break;
                }
                grouped.push(Tree::Node(chunk));
            }
            batch(grouped)
        }
        fn walk(tree: &Tree, prefix: &mut Vec<u8>, out: &mut Vec<(usize, Vec<u8>)>) {
            match tree {
                Tree::Leaf(field) => out.push((*field, prefix.clone())),
                Tree::Node(children) => {
                    for (i, child) in children.iter().enumerate() {
                        prefix.push(i as u8);
                        walk(child, prefix, out);
                        prefix.pop();
                    }
                }
            }
        }
        let top = batch((0..fields).map(Tree::Leaf).collect());
        let mut out = Vec::new();
        walk(&Tree::Node(top), &mut Vec::new(), &mut out);
        out.sort_by_key(|(field, _)| *field);
        out.into_iter().map(|(_, path)| path).collect()
    }

    #[test]
    fn in_block_is_batch_for_every_block_size() {
        for total in 1..=256usize {
            let reference = field_paths(total);
            for (index, path) in reference.iter().enumerate() {
                assert_eq!(
                    FieldPath::in_block(total, index).as_slice(),
                    path.as_slice(),
                    "block of {total}, field {index}"
                );
            }
        }
    }

    #[test]
    fn in_block_agrees_with_the_pinned_sixteen_field_probe() {
        assert_eq!(FieldPath::in_block(16, 0).as_slice(), &[0, 0]);
        assert_eq!(FieldPath::in_block(16, 15).as_slice(), &[1, 14]);
        assert_eq!(FieldPath::in_block(15, 14).as_slice(), &[14]);
        assert_eq!(FieldPath::in_block(226, 225).depth(), 3);
    }

    #[test]
    fn distinct_kinds_accepts_distinct_and_empty() {
        const _: () = assert_distinct_kinds(&[&[], &[0], &[1, 2], &[]]);
    }
}
