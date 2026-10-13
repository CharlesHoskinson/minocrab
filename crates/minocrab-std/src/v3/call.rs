//! The CALLER's side of a cross-contract call: the typed leaves as
//! [`CallArg`]s and [`CallResult`]s.
//!
//! `entry.rs` is the callee's view of a Compact type — how a circuit
//! DECLARES it and constrains it on entry. This is the caller's view of the
//! same type: how its slots are laid out into the argument limbs a
//! `contract_call` hashes into the communications commitment, and how the
//! callee's returned limbs are read back as a typed value.
//!
//! Both views share one [`CircuitAbi`] impl, which is why they cannot
//! disagree about slot count, atoms or per-slot constraints — the thing an
//! interface crate exists to guarantee. What differs is only visibility:
//! `CircuitArg` exists at [`Private`] (arguments are witness data),
//! `CallArg`/`CallResult` at [`Public`] (passing a value cross-contract
//! discloses it, and a callee's results are public downstream).
//!
//! The impls are mechanical; the interesting content is that they exist at
//! `Public` ONLY. `signer.sign_bidirectional(c, one, request_id, …)` with a
//! private `request_id` does not compile, and the fix is `disclose`.

use minocrab::v3::{CallArg, CallResult, FieldT, Wire3};
use minocrab::Public;

use super::{
    Bool, BoundedUint, Bytes, Bytes0, BytesN, CoinColor, CoinNonce, ContractAddress, Either, Maybe,
    MerkleTreeDigest, Opaque, QualifiedShieldedCoinInfo3, ShieldedCoinInfo3, TsType, Uint,
    UserAddress, B32,
};

/// Compact's `Opaque<'ts-type'>` across a contract boundary — one limb, in
/// both directions.
///
/// The argument limb is hashed into the communications commitment like any
/// other, and the RESULT limb is witnessed back with
/// [`LimbConstraint::None`](minocrab::v3::LimbConstraint::None) — which is
/// compactc's own lowering: the fixture's caller emits `private_input %r` with
/// no constraint and binds it only through `transient_hash [cc-rand, arg,
/// result]` (notes/opaque-bridging.org §0a). Nothing here states that; the
/// `Prim::Opaque` in the [`CircuitAbi`](minocrab::v3::CircuitAbi) impl does.
impl<T: TsType> CallArg for Opaque<T, Public> {
    fn push_call_slots(&self, slots: &mut Vec<Wire3<FieldT, Public>>) {
        slots.push(self.field());
    }
}

impl<T: TsType> CallResult for Opaque<T, Public> {
    fn from_call_slots(slots: &[Wire3<FieldT, Public>]) -> Self {
        Opaque::from_field_unchecked(slots[0])
    }
}

/// Compact's `MerkleTreeDigest` across a contract boundary — one limb, and
/// unconstrained on the way back for the same reason an `Opaque` is: the
/// `Prim::Field` in its [`CircuitAbi`](minocrab::v3::CircuitAbi) impl says so.
impl CallArg for MerkleTreeDigest<Public> {
    fn push_call_slots(&self, slots: &mut Vec<Wire3<FieldT, Public>>) {
        slots.push(self.field());
    }
}

impl CallResult for MerkleTreeDigest<Public> {
    fn from_call_slots(slots: &[Wire3<FieldT, Public>]) -> Self {
        MerkleTreeDigest::from_field_unchecked(slots[0])
    }
}

impl<const BITS: u32> CallArg for Uint<BITS, Public> {
    fn push_call_slots(&self, slots: &mut Vec<Wire3<FieldT, Public>>) {
        slots.push(self.field());
    }
}

impl<const BITS: u32> CallResult for Uint<BITS, Public> {
    fn from_call_slots(slots: &[Wire3<FieldT, Public>]) -> Self {
        Uint::from_field_unchecked(slots[0])
    }
}

impl<const BOUND: u128> CallArg for BoundedUint<BOUND, Public> {
    fn push_call_slots(&self, slots: &mut Vec<Wire3<FieldT, Public>>) {
        slots.push(self.field());
    }
}

impl<const BOUND: u128> CallResult for BoundedUint<BOUND, Public> {
    fn from_call_slots(slots: &[Wire3<FieldT, Public>]) -> Self {
        BoundedUint::from_field_unchecked(slots[0])
    }
}

impl CallArg for Bool<Public> {
    fn push_call_slots(&self, slots: &mut Vec<Wire3<FieldT, Public>>) {
        slots.push(self.field());
    }
}

impl CallResult for Bool<Public> {
    fn from_call_slots(slots: &[Wire3<FieldT, Public>]) -> Self {
        Bool::from_field_unchecked(slots[0])
    }
}

impl CallArg for Bytes0<Public> {
    fn push_call_slots(&self, _slots: &mut Vec<Wire3<FieldT, Public>>) {}
}

impl CallResult for Bytes0<Public> {
    fn from_call_slots(_slots: &[Wire3<FieldT, Public>]) -> Self {
        Bytes0::new()
    }
}

impl<const N: usize> CallArg for Bytes<N, Public> {
    fn push_call_slots(&self, slots: &mut Vec<Wire3<FieldT, Public>>) {
        slots.push(self.field());
    }
}

impl<const N: usize> CallResult for Bytes<N, Public> {
    fn from_call_slots(slots: &[Wire3<FieldT, Public>]) -> Self {
        Bytes::from_field_unchecked(slots[0])
    }
}

impl CallArg for B32<Public> {
    fn push_call_slots(&self, slots: &mut Vec<Wire3<FieldT, Public>>) {
        slots.push(self.hi);
        slots.push(self.lo);
    }
}

impl CallResult for B32<Public> {
    fn from_call_slots(slots: &[Wire3<FieldT, Public>]) -> Self {
        B32 {
            hi: slots[0],
            lo: slots[1],
        }
    }
}

impl<const N: usize> CallArg for BytesN<Public, N> {
    fn push_call_slots(&self, slots: &mut Vec<Wire3<FieldT, Public>>) {
        slots.extend_from_slice(self.limbs());
    }
}

impl<const N: usize> CallResult for BytesN<Public, N> {
    fn from_call_slots(slots: &[Wire3<FieldT, Public>]) -> Self {
        BytesN::from_limbs(slots.to_vec())
    }
}

/// Compact's `Maybe<T>`: the tag, then the value, which occupies its slots
/// whether or not the tag is set.
impl<T: CallArg> CallArg for Maybe<T, Public> {
    fn push_call_slots(&self, slots: &mut Vec<Wire3<FieldT, Public>>) {
        self.is_some.push_call_slots(slots);
        self.value.push_call_slots(slots);
    }
}

impl<T: CallResult> CallResult for Maybe<T, Public> {
    fn from_call_slots(slots: &[Wire3<FieldT, Public>]) -> Self {
        Maybe {
            is_some: Bool::from_call_slots(&slots[..1]),
            value: T::from_call_slots(&slots[1..]),
        }
    }
}

/// Compact's `Either<A, B>`: the tag, then BOTH arms.
impl<A: CallArg, B: CallArg> CallArg for Either<A, B, Public> {
    fn push_call_slots(&self, slots: &mut Vec<Wire3<FieldT, Public>>) {
        self.is_left.push_call_slots(slots);
        self.left.push_call_slots(slots);
        self.right.push_call_slots(slots);
    }
}

impl<A: CallResult, B: CallResult> CallResult for Either<A, B, Public> {
    fn from_call_slots(slots: &[Wire3<FieldT, Public>]) -> Self {
        let left_end = 1 + A::SLOTS;
        Either {
            is_left: Bool::from_call_slots(&slots[..1]),
            left: A::from_call_slots(&slots[1..left_end]),
            right: B::from_call_slots(&slots[left_end..]),
        }
    }
}

impl CallArg for ContractAddress<Public> {
    fn push_call_slots(&self, slots: &mut Vec<Wire3<FieldT, Public>>) {
        self.0.push_call_slots(slots);
    }
}

impl CallResult for ContractAddress<Public> {
    fn from_call_slots(slots: &[Wire3<FieldT, Public>]) -> Self {
        ContractAddress(B32::from_call_slots(slots))
    }
}

impl CallArg for UserAddress<Public> {
    fn push_call_slots(&self, slots: &mut Vec<Wire3<FieldT, Public>>) {
        self.0.push_call_slots(slots);
    }
}

impl CallResult for UserAddress<Public> {
    fn from_call_slots(slots: &[Wire3<FieldT, Public>]) -> Self {
        UserAddress(B32::from_call_slots(slots))
    }
}

impl CallArg for ShieldedCoinInfo3<Public> {
    fn push_call_slots(&self, slots: &mut Vec<Wire3<FieldT, Public>>) {
        self.nonce.push_call_slots(slots);
        self.color.push_call_slots(slots);
        slots.push(self.value);
    }
}

impl CallResult for ShieldedCoinInfo3<Public> {
    fn from_call_slots(slots: &[Wire3<FieldT, Public>]) -> Self {
        ShieldedCoinInfo3 {
            nonce: CoinNonce::from_call_slots(&slots[..2]),
            color: CoinColor::from_call_slots(&slots[2..4]),
            value: slots[4],
        }
    }
}

/// A QUALIFIED coin crossing a boundary — [`ShieldedCoinInfo3`]'s slots then
/// the `Uint<64>` tree index. First needed by the AA manager's `pools`
/// (`Map<Bytes<32>, QualifiedShieldedCoinInfo>`), whose `lookup` reads the
/// pooled coin back out.
impl CallArg for QualifiedShieldedCoinInfo3<Public> {
    fn push_call_slots(&self, slots: &mut Vec<Wire3<FieldT, Public>>) {
        self.downcast().push_call_slots(slots);
        slots.push(self.mt_index);
    }
}

impl CallResult for QualifiedShieldedCoinInfo3<Public> {
    fn from_call_slots(slots: &[Wire3<FieldT, Public>]) -> Self {
        let coin = ShieldedCoinInfo3::from_call_slots(&slots[..5]);
        QualifiedShieldedCoinInfo3 {
            nonce: coin.nonce,
            color: coin.color,
            value: coin.value,
            mt_index: slots[5],
        }
    }
}
