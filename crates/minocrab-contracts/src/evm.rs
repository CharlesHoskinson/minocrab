//! Typed EVM calls — the call as a type, the slot infers the rest
//! (M37 rung A, notes/evm-calls.org §§1-2).
//!
//! Today a contract that wants `transfer(to, amount)` on the far side writes
//! out the four-byte selector, encodes each ABI word by hand, counts the
//! words, names a gas envelope and picks a response type. Every one of those
//! is DERIVABLE from one thing: which call it is. This module makes that one
//! thing a type.
//!
//! Three layers:
//!
//! 1. [`AbiType`] — one Rust unit type per Solidity leaf ([`Address`],
//!    [`Bool`], [`Bytes32`], [`U8`], [`U16`], [`U24`], [`U64`], [`U128`],
//!    [`U160`], [`U256`]), plus [`Unit`] for a callee that returns NOTHING. It
//!    carries the leaf's spelling in a selector signature
//!    ([`AbiType::SOLIDITY`]), its spelling in the attested-output schema
//!    the MPC narrows to ([`AbiType::RESPOND`]) and the CIRCUIT VALUE that
//!    stands for it ([`AbiType::Wire`]). [`AbiArg`] adds the encoder from
//!    that value to a canonical 32-byte ABI word ([`AbiArg::word`]) and is
//!    implemented by every leaf EXCEPT `Unit` — which is how "an argument
//!    that returns nothing" stops being expressible (M38 rung B).
//! 2. [`AbiTuple`] — the argument list, for `()` and 1- to 8-tuples of
//!    `AbiArg`s. It knows the WORD COUNT, the comma-joined signature and
//!    how to encode a tuple of wires into words, in order.
//! 3. [`EvmCall`] — the call: a name, an argument tuple, a return type, the
//!    [`Interface`] that exposes it and a gas limit. [`EvmCall::selector`]
//!    is the first four bytes of `keccak256("name(argtypes)")`, computed IN
//!    RUST at circuit-build time and embedded as an immediate. Nothing
//!    hashes keccak in-circuit; in-circuit hashing stays Poseidon throughout
//!    (dmd, 2026-09-05: *"Do we actually need a const fn Keccak? Why not
//!    just run it when we run the eDSL?"* — we do not). The library's calls
//!    live one module per interface: [`erc20`], [`erc4626`], [`erc721`],
//!    [`uniswap_v3`], [`aave_v3`], [`weth`] and [`usdt`]. [`Payable`] marks
//!    the one that carries ether.
//! 4. [`Filing`] — HOW ONE SLOT FILES ONE CALL: the OUTPUT SCHEMA the MPC
//!    decodes the return under, which carries the deployed record's name for
//!    the attested value. That is a fact about a DEPLOYMENT's protocol, not
//!    about the Solidity function (the same `transfer` is decoded for its
//!    flag by a vault and not decoded at all by a protocol that only wants
//!    the verdict), so it sits here rather than on the call.
//!    [`Filed<Call, Schema>`](Filed) is the one-line impl.
//!
//! [`build_tx`] is where the three meet: it turns a callee, an argument
//! tuple and a nonce into the [`EvmTx`] a request files, with the selector,
//! the words, the word count, the gas limit and the fixed fee envelope all
//! read off the call type.
//!
//! # Zero movement
//!
//! The two word encoders ([`address_word`], [`numeric_word`]) are the
//! bodies that used to live in [`crate::signet`], moved here unchanged;
//! `signet::evm_address_abi_word` and `signet::numeric_abi_word` are now
//! one-line delegations to them. `tests/evm_abi.rs` asserts a circuit built
//! through either spelling serializes to byte-identical ZKIR, and the
//! 209-circuit dump is unchanged by the move.
//!
//! # What compiles
//!
//! A `transfer(to, amount)`, whole. The selector, the word count, the fee
//! envelope and the gas limit are not written down anywhere here:
//!
//! ```
//! use minocrab::v3::{Circuit3, FieldT};
//! use minocrab::Private;
//! use minocrab_contracts::evm::{build_tx, erc20};
//! use minocrab_std::v3::{Bytes, Uint};
//!
//! let mut c = Circuit3::new();
//! let to = Bytes::<20, Private>::from_field_unchecked(c.arg::<FieldT>("to"));
//! let amount = Uint::<128, Private>::from_field_unchecked(c.arg::<FieldT>("amount"));
//! let nonce = c.arg::<FieldT>("nonce");
//! let token = Bytes::<20, Private>::from_field_unchecked(c.arg::<FieldT>("token"));
//! let tx = build_tx::<erc20::Transfer, 2>(&mut c, token, (to, amount), nonce);
//! ```
//!
//! THE TWO BLOCKS BELOW ARE THAT SAME CODE, changed in one place each —
//! which is what makes them evidence: the surrounding lines compile, so the
//! rejection is the swap and the number, not a typo.
//!
//! # What does not compile
//!
//! The argument tuple in the wrong order — `transfer` takes the recipient
//! FIRST, and swapping the two is a type error, not a transaction that
//! sends tokens to an address made out of an amount:
//!
//! ```compile_fail
//! use minocrab::v3::{Circuit3, FieldT};
//! use minocrab::Private;
//! use minocrab_contracts::evm::{build_tx, erc20};
//! use minocrab_std::v3::{Bytes, Uint};
//!
//! let mut c = Circuit3::new();
//! let to = Bytes::<20, Private>::from_field_unchecked(c.arg::<FieldT>("to"));
//! let amount = Uint::<128, Private>::from_field_unchecked(c.arg::<FieldT>("amount"));
//! let nonce = c.arg::<FieldT>("nonce");
//! let token = Bytes::<20, Private>::from_field_unchecked(c.arg::<FieldT>("token"));
//! // ERROR: expected `(Bytes<20>, Uint<128>)`, found `(Uint<128>, Bytes<20>)`
//! let tx = build_tx::<erc20::Transfer, 2>(&mut c, token, (amount, to), nonce);
//! ```
//!
//! A `WORDS` that is not the argument tuple's word count — stable Rust
//! cannot INFER the number (notes/evm-calls.org §3), but it can reject a
//! wrong one, and an inline-`const` assert makes that an `error[E0080]` at
//! the call site:
//!
//! ```compile_fail
//! use minocrab::v3::{Circuit3, FieldT};
//! use minocrab::Private;
//! use minocrab_contracts::evm::{build_tx, erc20};
//! use minocrab_std::v3::{Bytes, Uint};
//!
//! let mut c = Circuit3::new();
//! let to = Bytes::<20, Private>::from_field_unchecked(c.arg::<FieldT>("to"));
//! let amount = Uint::<128, Private>::from_field_unchecked(c.arg::<FieldT>("amount"));
//! let nonce = c.arg::<FieldT>("nonce");
//! let token = Bytes::<20, Private>::from_field_unchecked(c.arg::<FieldT>("token"));
//! // error[E0080]: `build_tx::<C, WORDS>` needs WORDS == <C::Args>::WORDS …
//! let tx = build_tx::<erc20::Transfer, 3>(&mut c, token, (to, amount), nonce);
//! ```
//!
//! A call type that does not say whether its return means success. There
//! is NO DEFAULT for [`EvmCall::succeeded`], on purpose: "executed ⇒
//! succeeded" is right for most calls and wrong for an ERC-20 `transfer`,
//! and a default would make the dangerous case the one nobody types:
//!
//! ```compile_fail
//! use minocrab_contracts::evm::{erc20, Address, EvmCall, U64};
//! use minocrab_std::v3::Uint;
//! use minocrab::Private;
//!
//! struct Balance;
//! // ERROR: not all trait items implemented, missing: `succeeded`
//! impl EvmCall for Balance {
//!     type Callee = erc20::Erc20;
//!     const NAME: &'static str = "balanceOf";
//!     type Args = (Address,);
//!     type Return = U64;
//!     type Success = Uint<64, Private>;
//!     const GAS_LIMIT: u64 = 50_000;
//! }
//! ```
//!
//! A [`Unit`] IN AN ARGUMENT TUPLE — "this callee returns nothing" is a
//! RETURN, and it has no ABI word, so it is an [`AbiType`] and not an
//! [`AbiArg`] and a tuple containing it is not an [`AbiTuple`] (M38 rung B;
//! until then this type-checked and reached a build-time panic inside
//! `Unit::word`, notes/evm-calls.org §10 item 3):
//!
//! ```compile_fail
//! use minocrab::v3::Circuit3;
//! use minocrab::Private;
//! use minocrab_contracts::evm::{always, erc20, EvmCall, Unit};
//! use minocrab_std::v3::Check;
//!
//! struct Nothing;
//! impl EvmCall for Nothing {
//!     type Callee = erc20::Erc20;
//!     const NAME: &'static str = "nothing";
//!     // error[E0277]: the trait bound `Unit: AbiArg` is not satisfied
//!     type Args = (Unit,);
//!     type Return = Unit;
//!     type Success = ();
//!     const GAS_LIMIT: u64 = 21_000;
//!     fn succeeded(c: &mut Circuit3, _out: &()) -> Check<Private> {
//!         always(c)
//!     }
//! }
//! ```
//!
//! …and in any position, not just alone — a trailing `Unit` beside real
//! arguments is the shape a "this one returns nothing" note would take if
//! it were written in the wrong place:
//!
//! ```compile_fail
//! use minocrab::v3::Circuit3;
//! use minocrab::Private;
//! use minocrab_contracts::evm::{always, erc20, Address, EvmCall, Unit};
//! use minocrab_std::v3::Check;
//!
//! struct Nothing;
//! impl EvmCall for Nothing {
//!     type Callee = erc20::Erc20;
//!     const NAME: &'static str = "nothing";
//!     // error[E0277]: the trait bound `Unit: AbiArg` is not satisfied
//!     type Args = (Address, Unit);
//!     type Return = Unit;
//!     type Success = ();
//!     const GAS_LIMIT: u64 = 21_000;
//!     fn succeeded(c: &mut Circuit3, _out: &()) -> Check<Private> {
//!         always(c)
//!     }
//! }
//! ```
//!
//! THE SAME CODE WITH THE `Unit` LEFT IN THE ONE PLACE IT BELONGS compiles
//! — as the RETURN, which is what a call to a callee that answers nothing
//! actually has (ERC-2612 `permit`, WETH `deposit`, a USDT `transfer`):
//!
//! ```
//! use minocrab::v3::Circuit3;
//! use minocrab::Private;
//! use minocrab_contracts::evm::{always, erc20, Address, EvmCall, Unit};
//! use minocrab_std::v3::Check;
//!
//! struct Nothing;
//! impl EvmCall for Nothing {
//!     type Callee = erc20::Erc20;
//!     const NAME: &'static str = "nothing";
//!     type Args = (Address,);
//!     type Return = Unit;
//!     type Success = ();
//!     const GAS_LIMIT: u64 = 21_000;
//!     fn succeeded(c: &mut Circuit3, _out: &()) -> Check<Private> {
//!         always(c)
//!     }
//! }
//! assert_eq!(Nothing::signature(), "nothing(address)");
//! ```
//!
//! A projection the return value cannot produce — `()` is [`FromReturn`]
//! for a `Bool` return and for nothing else, so a numeric call cannot
//! quietly throw its answer away:
//!
//! ```compile_fail
//! use minocrab::v3::Circuit3;
//! use minocrab::Private;
//! use minocrab_contracts::evm::{always, erc20, Address, EvmCall, U64};
//! use minocrab_std::v3::{Check, Uint};
//!
//! struct Balance;
//! impl EvmCall for Balance {
//!     type Callee = erc20::Erc20;
//!     const NAME: &'static str = "balanceOf";
//!     type Args = (Address,);
//!     type Return = U64;
//!     // ERROR: the trait bound `(): FromReturn<Uint<64>>` is not satisfied
//!     type Success = ();
//!     const GAS_LIMIT: u64 = 50_000;
//!     fn succeeded(c: &mut Circuit3, _out: &Uint<64, Private>) -> Check<Private> {
//!         always(c)
//!     }
//! }
//! ```
//!
//! THE SAME CODE WITH THE ONE CHANGE REVERTED compiles, so each rejection
//! above is the missing item and the mapping rather than a typo:
//!
//! ```
//! use minocrab::v3::Circuit3;
//! use minocrab::Private;
//! use minocrab_contracts::evm::{always, erc20, Address, EvmCall, U64};
//! use minocrab_std::v3::{Check, Uint};
//!
//! struct Balance;
//! impl EvmCall for Balance {
//!     type Callee = erc20::Erc20;
//!     const NAME: &'static str = "balanceOf";
//!     type Args = (Address,);
//!     type Return = U64;
//!     type Success = Uint<64, Private>;
//!     const GAS_LIMIT: u64 = 50_000;
//!     fn succeeded(c: &mut Circuit3, _out: &Uint<64, Private>) -> Check<Private> {
//!         always(c)
//!     }
//! }
//! assert_eq!(Balance::signature(), "balanceOf(address)");
//! assert_eq!(Balance::selector(), [0x70, 0xa0, 0x82, 0x31]);
//! ```
//!
//! A `Unit` IN AN ARGUMENT TUPLE. [`Unit`] is the leaf that means "this
//! callee returns NOTHING"; an argument that is nothing has no 32-byte word
//! to encode, so it is an [`AbiType`] and not an [`AbiArg`], and
//! [`AbiTuple`] is over `AbiArg`:
//!
//! ```compile_fail
//! use minocrab::v3::Circuit3;
//! use minocrab::Private;
//! use minocrab_contracts::evm::{erc20, Address, Bool, EvmCall, Unit};
//! use minocrab_std::v3::{is_true, Bool as BoolWire, Check};
//!
//! struct Poke;
//! impl EvmCall for Poke {
//!     type Callee = erc20::Erc20;
//!     const NAME: &'static str = "poke";
//!     // ERROR: the trait bound `Unit: AbiArg` is not satisfied
//!     type Args = (Address, Unit);
//!     type Return = Bool;
//!     type Success = ();
//!     const GAS_LIMIT: u64 = 50_000;
//!     fn succeeded(_c: &mut Circuit3, ok: &BoolWire<Private>) -> Check<Private> {
//!         is_true(*ok)
//!     }
//! }
//! ```
//!
//! …and alone, where the tuple is nothing else:
//!
//! ```compile_fail
//! use minocrab::v3::Circuit3;
//! use minocrab::Private;
//! use minocrab_contracts::evm::{erc20, Bool, EvmCall, Unit};
//! use minocrab_std::v3::{is_true, Bool as BoolWire, Check};
//!
//! struct Poke;
//! impl EvmCall for Poke {
//!     type Callee = erc20::Erc20;
//!     const NAME: &'static str = "poke";
//!     // ERROR: the trait bound `Unit: AbiArg` is not satisfied
//!     type Args = (Unit,);
//!     type Return = Bool;
//!     type Success = ();
//!     const GAS_LIMIT: u64 = 50_000;
//!     fn succeeded(_c: &mut Circuit3, ok: &BoolWire<Private>) -> Check<Private> {
//!         is_true(*ok)
//!     }
//! }
//! ```
//!
//! THE SAME CODE WITH THE ONE CHANGE REVERTED compiles — and `Unit` in the
//! position it IS for, the RETURN, compiles beside it. That pair is the
//! whole of the split: one leaf, legal in one position and rejected in the
//! other, with no runtime check anywhere:
//!
//! ```
//! use minocrab::v3::Circuit3;
//! use minocrab::Private;
//! use minocrab_contracts::evm::{always, erc20, Address, Bool, EvmCall, Unit};
//! use minocrab_std::v3::{is_true, Bool as BoolWire, Check};
//!
//! struct Poke;
//! impl EvmCall for Poke {
//!     type Callee = erc20::Erc20;
//!     const NAME: &'static str = "poke";
//!     type Args = (Address,);
//!     type Return = Bool;
//!     type Success = ();
//!     const GAS_LIMIT: u64 = 50_000;
//!     fn succeeded(_c: &mut Circuit3, ok: &BoolWire<Private>) -> Check<Private> {
//!         is_true(*ok)
//!     }
//! }
//!
//! struct Shout;
//! impl EvmCall for Shout {
//!     type Callee = erc20::Erc20;
//!     const NAME: &'static str = "shout";
//!     type Args = (Address,);
//!     type Return = Unit;               // the position `Unit` is FOR
//!     type Success = ();
//!     const GAS_LIMIT: u64 = 50_000;
//!     fn succeeded(c: &mut Circuit3, _out: &()) -> Check<Private> {
//!         always(c)
//!     }
//! }
//! assert_eq!(Shout::signature(), "shout(address)");
//! ```
//!
//! ETHER ON A CALL THAT CANNOT TAKE IT. [`build_tx_payable`] is the only
//! way a non-zero `value` reaches an [`EvmTx`], and its `C: Payable` bound
//! is a missing impl for every call but WETH's `deposit()`:
//!
//! ```compile_fail
//! use minocrab::v3::{Circuit3, FieldT};
//! use minocrab::Private;
//! use minocrab_contracts::evm::{build_tx_payable, erc20};
//! use minocrab_std::v3::{Bytes, Uint};
//!
//! let mut c = Circuit3::new();
//! let to = Bytes::<20, Private>::from_field_unchecked(c.arg::<FieldT>("to"));
//! let amount = Uint::<128, Private>::from_field_unchecked(c.arg::<FieldT>("amount"));
//! let value = Uint::<128, Private>::from_field_unchecked(c.arg::<FieldT>("value"));
//! let nonce = c.arg::<FieldT>("nonce");
//! let token = Bytes::<20, Private>::from_field_unchecked(c.arg::<FieldT>("token"));
//! // ERROR: the trait bound `erc20::Transfer: Payable` is not satisfied
//! let tx = build_tx_payable::<erc20::Transfer, 2>(&mut c, token, (to, amount), value, nonce);
//! ```
//!
//! THE SAME CODE FOR THE CALL THAT IS PAYABLE — `weth::Deposit`, whose
//! ether IS its argument, so the tuple is empty and the word count is zero:
//!
//! ```
//! use minocrab::v3::{Circuit3, FieldT};
//! use minocrab::Private;
//! use minocrab_contracts::evm::{build_tx_payable, weth};
//! use minocrab_std::v3::{Bytes, Uint};
//!
//! let mut c = Circuit3::new();
//! let value = Uint::<128, Private>::from_field_unchecked(c.arg::<FieldT>("value"));
//! let nonce = c.arg::<FieldT>("nonce");
//! let weth9 = Bytes::<20, Private>::from_field_unchecked(c.arg::<FieldT>("weth"));
//! let tx = build_tx_payable::<weth::Deposit, 0>(&mut c, weth9, (), value, nonce);
//! ```

use core::marker::PhantomData;

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Fr, Private};
use minocrab_std::v3::{
    is_true, pow2_const, Bool as BoolWire, Bytes, Bytes0, Check, CircuitArg, Uint, Vis3, B32,
};
use sha3::{Digest as _, Keccak256};

use crate::signet::{reverse_bytes32, EvmCalldata};
use crate::signet_flow::EvmTx;
use crate::signet_v1::{self, OutputSchema};

pub mod aave_v3;
pub mod erc20;
pub mod erc4626;
pub mod erc721;
pub mod uniswap_v3;
pub mod usdt;
pub mod weth;

/// The CONTRACT-FIXED fee envelope the typed-call lineage files under
/// (`Envelope::Fixed`): the priority fee and fee cap the seventeen-circuit
/// vault pinned in its source (1 gwei / 30 gwei). The flush-pattern vault
/// (M44) keeps its envelope in ledger cells instead, so these live here now.
pub const FIXED_PRIORITY_FEE: u64 = 1_000_000_000;
pub const FIXED_MAX_FEE: u64 = 30_000_000_000;

// ---- the encoders (moved from `signet`, unchanged) ---------------------------

/// `evmAddressAbiWord(addr)` — 12 zero bytes then the 20 display-order
/// address bytes. `addr` is the `Bytes<20>` single limb.
///
/// MOVED HERE from `signet` (M37 rung A): this is the body,
/// `signet::evm_address_abi_word` is now a delegation to it, and
/// [`Address::word`] is the typed spelling. Byte-for-byte the same
/// instructions in all three.
pub fn address_word<V: Vis3>(c: &mut Circuit3, addr: Wire3<FieldT, V>) -> B32<V> {
    c.region("abi words", |c| {
        // The word is addr·2^96 (a 12-byte shift), so split the 160-bit
        // limb at bit 152: hi byte = addr >> 152, lo = the rest shifted.
        let (hi, low152) = c.div_mod_power_of_two(addr, 152);
        let shift96 = V::from_public(pow2_const(c, 12));
        let lo = c.mul(low152, shift96);
        B32 { hi, lo }
    })
}

/// `numericAbiWord(value)` — an integer limb as a 32-byte big-endian ABI
/// word: the value's little-endian bytes reversed into the tail.
///
/// MOVED HERE from `signet` (M37 rung A) — see [`address_word`]. The
/// typed spellings are [`Bool::word`], [`U24::word`], [`U64::word`] and
/// [`U128::word`], which differ only in the RANGE their wire type claims:
/// the encoding is the same reversal for all of them, and correct for any
/// limb below `2^248`.
pub fn numeric_word<V: Vis3>(c: &mut Circuit3, value: Wire3<FieldT, V>) -> B32<V> {
    c.region("abi words", |c| {
        // value's 16 LE bytes sit at string positions 0..15 of
        // `B32 { lo: value, hi: 0 }`; the native reversal moves them,
        // reversed, to positions 16..31 — exactly the BE ABI rendering.
        let zero = V::from_public(c.constant(0u64));
        let padded = B32 { hi: zero, lo: value };
        reverse_bytes32(c, &padded)
    })
}

// ---- the ABI type layer ------------------------------------------------------

/// One Solidity leaf: how it is SPELLED and what CIRCUIT VALUE stands for
/// it.
///
/// The implementors are unit types ([`Address`], [`Bool`], …), never
/// instantiated: they exist to be named in an [`EvmCall::Args`] tuple or as
/// an [`EvmCall::Return`].
///
/// THE WORD IS NOT HERE. Encoding a value into a 32-byte ABI word is
/// [`AbiArg`]'s, because the one leaf that is a return and not an argument
/// — [`Unit`], "this callee returns nothing" — has no word to encode.
pub trait AbiType {
    /// The spelling inside the selector signature — what
    /// `keccak256("transfer(address,uint256)")` sees. `U64`, `U128` and
    /// `U256` all spell `"uint256"`: the ABI word is always 32 bytes, and
    /// the Rust type states the RANGE the contract accepts, not the width
    /// on the wire.
    const SOLIDITY: &'static str;

    /// The spelling in the ATTESTED-OUTPUT schema — the narrowing the MPC
    /// applies before it signs (`SUPPLY_RESPOND_SCHEMA`'s `"uint64"`
    /// against `SUPPLY_OUTPUT_SCHEMA`'s `"uint256"`). This is where `U64`
    /// and `U256` part company.
    const RESPOND: &'static str;

    /// The circuit value that stands for this leaf.
    type Wire<V: Vis3>;
}

/// A LEAF THAT CAN STAND IN AN ARGUMENT LIST — an [`AbiType`] that HAS an
/// ABI word, which is every one of them except [`Unit`].
///
/// THE ARGS/RETURN SPLIT (M38 rung B). [`AbiType`] is the RETURN position's
/// bound: a call may return a `bool`, a number, or NOTHING AT ALL, and
/// [`Unit`] is that nothing. This trait is the ARGUMENT position's: an
/// argument is a value that becomes a 32-byte word, and `Unit` has no word
/// to become. So [`AbiTuple`] is over `AbiArg` and `Unit` has no impl,
/// which makes `type Args = (Unit,)` a MISSING TRAIT IMPL —
/// `error[E0277]`, the first rung of the project's ladder — where until
/// this rung it type-checked and reached a build-time panic inside
/// `Unit::word` (notes/evm-calls.org §10 item 3, recorded for dmd).
///
/// The encoder lives here rather than on [`AbiType`] so that `Unit` does
/// not implement it at all: there is no unreachable body and no panic to
/// keep prescriptive.
pub trait AbiArg: AbiType {
    /// The canonical big-endian ABI word for a value of this leaf.
    fn word<V: Vis3>(c: &mut Circuit3, w: &Self::Wire<V>) -> B32<V>;
}

/// Solidity `address` — a `Bytes<20>` limb, left-padded into the word.
pub struct Address;

impl AbiType for Address {
    const SOLIDITY: &'static str = "address";
    const RESPOND: &'static str = "address";
    type Wire<V: Vis3> = Bytes<20, V>;
}

impl AbiArg for Address {
    fn word<V: Vis3>(c: &mut Circuit3, w: &Self::Wire<V>) -> B32<V> {
        address_word(c, w.field())
    }
}

/// Solidity `bool` — 0 or 1 right-aligned in the word.
pub struct Bool;

impl AbiType for Bool {
    const SOLIDITY: &'static str = "bool";
    const RESPOND: &'static str = "bool";
    type Wire<V: Vis3> = BoolWire<V>;
}

impl AbiArg for Bool {
    fn word<V: Vis3>(c: &mut Circuit3, w: &Self::Wire<V>) -> B32<V> {
        numeric_word(c, w.field())
    }
}

/// Solidity `bytes32` — the word IS the value; encoding it is the identity
/// and emits no instruction.
pub struct Bytes32;

impl AbiType for Bytes32 {
    const SOLIDITY: &'static str = "bytes32";
    const RESPOND: &'static str = "bytes32";
    type Wire<V: Vis3> = B32<V>;
}

impl AbiArg for Bytes32 {
    fn word<V: Vis3>(_c: &mut Circuit3, w: &Self::Wire<V>) -> B32<V> {
        *w
    }
}

/// NO RETURN AT ALL — the shape a non-conforming ERC-20 actually has.
///
/// USDT, BNB and other pre-EIP-20-final tokens omit the `bool` their
/// `transfer` is supposed to return. Declaring such a callee's calls with
/// `Return = Unit` is what stops the MPC being asked to decode a `bool`
/// from empty return data — a terminal extraction failure, which it
/// resolves as its FAILURE kind, which would refund a transfer that MOVED
/// the tokens (notes/evm-calls.org §3.1, the dangerous direction).
///
/// `Wire<V> = ()`: no slot, no word, no verdict to read. A call returning
/// it writes [`always`] for its [`EvmCall::succeeded`], because for a call
/// with nothing to say, executing IS succeeding and there is no flag to be
/// fooled by.
///
/// A RETURN TYPE ONLY, and the type system says so: `Unit` is an
/// [`AbiType`] and NOT an [`AbiArg`], so it can be named as an
/// [`EvmCall::Return`] and cannot be named in an [`EvmCall::Args`] tuple.
///
/// `type Args = (Unit,)` is `error[E0277]` — "the trait bound `Unit:
/// AbiArg` is not satisfied" (the module docs carry the gate). Until M38
/// rung B it type-checked and put a build-time panic inside `Unit::word`
/// where the hard rule prefers a compile error — notes/evm-calls.org §10
/// item 3, recorded for dmd and now closed.
pub struct Unit;

impl AbiType for Unit {
    const SOLIDITY: &'static str = "";
    const RESPOND: &'static str = "";
    type Wire<V: Vis3> = ();
}

/// Solidity `uint8` — ERC-2612 `permit`'s signature parity byte `v`, the
/// narrowest integer the library passes.
///
/// The encoding is [`numeric_word`], exactly as [`U24`] and [`U64`]: a
/// 32-byte word is a 32-byte word, and the Rust type states the RANGE the
/// wire claims (`Uint<8>`) rather than a different encoder.
pub struct U8;

impl AbiType for U8 {
    const SOLIDITY: &'static str = "uint8";
    const RESPOND: &'static str = "uint8";
    type Wire<V: Vis3> = Uint<8, V>;
}

impl AbiArg for U8 {
    fn word<V: Vis3>(c: &mut Circuit3, w: &Self::Wire<V>) -> B32<V> {
        numeric_word(c, w.field())
    }
}

/// Solidity `uint16` — Aave v3's `referralCode`, the argument every one of
/// its Pool functions carries and every caller passes zero for.
///
/// The encoding is [`numeric_word`], exactly as [`U8`] and [`U24`]: the
/// three differ only in the RANGE the Rust type claims and in the spelling
/// that goes into the selector — and the spelling is the whole point,
/// because `supply(address,uint256,address,uint16)` and
/// `supply(address,uint256,address,uint256)` are different functions.
pub struct U16;

impl AbiType for U16 {
    const SOLIDITY: &'static str = "uint16";
    const RESPOND: &'static str = "uint16";
    type Wire<V: Vis3> = Uint<16, V>;
}

impl AbiArg for U16 {
    fn word<V: Vis3>(c: &mut Circuit3, w: &Self::Wire<V>) -> B32<V> {
        numeric_word(c, w.field())
    }
}

/// Solidity `uint24` — Uniswap's pool fee tier, the one sub-word integer
/// the corpus actually passes (`SwapRequest::fee`).
pub struct U24;

impl AbiType for U24 {
    const SOLIDITY: &'static str = "uint24";
    const RESPOND: &'static str = "uint24";
    type Wire<V: Vis3> = Uint<24, V>;
}

impl AbiArg for U24 {
    fn word<V: Vis3>(c: &mut Circuit3, w: &Self::Wire<V>) -> B32<V> {
        numeric_word(c, w.field())
    }
}

/// Solidity `uint256` carried by a `Uint<64>` — the range a Midnight-side
/// amount actually occupies (every vault mint is the `Uint<64>` API), and
/// the width the MPC narrows an attested `uint256` OUTPUT to.
pub struct U64;

impl AbiType for U64 {
    const SOLIDITY: &'static str = "uint256";
    const RESPOND: &'static str = "uint64";
    type Wire<V: Vis3> = Uint<64, V>;
}

impl AbiArg for U64 {
    fn word<V: Vis3>(c: &mut Circuit3, w: &Self::Wire<V>) -> B32<V> {
        numeric_word(c, w.field())
    }
}

/// Solidity `uint256` carried by a `Uint<128>` — the width the deployed
/// vault's amounts have on entry (`DepositRequest::amount` and friends).
///
/// A `Uint<64>` reaches it for free (`.widen::<128>()`, no instruction);
/// the other direction is a range check, which is why the vault's own call
/// types take the wider one.
pub struct U128;

impl AbiType for U128 {
    const SOLIDITY: &'static str = "uint256";
    const RESPOND: &'static str = "uint128";
    type Wire<V: Vis3> = Uint<128, V>;
}

impl AbiArg for U128 {
    fn word<V: Vis3>(c: &mut Circuit3, w: &Self::Wire<V>) -> B32<V> {
        numeric_word(c, w.field())
    }
}

/// Solidity `uint160` carried by an ALREADY-ENCODED word.
///
/// The only `uint160` in the corpus is Uniswap's `sqrtPriceLimitX96`, which
/// the vault passes as a literal zero word — no encoder, no instruction.
/// A wire of that width does not fit a `Uint<160>`'s useful operations
/// anyway, so the honest type is "the caller supplies the word".
pub struct U160;

impl AbiType for U160 {
    const SOLIDITY: &'static str = "uint160";
    const RESPOND: &'static str = "uint160";
    type Wire<V: Vis3> = B32<V>;
}

impl AbiArg for U160 {
    fn word<V: Vis3>(_c: &mut Circuit3, w: &Self::Wire<V>) -> B32<V> {
        *w
    }
}

/// Solidity `uint256` at its full width — an ALREADY-ENCODED word, since no
/// single field element holds 256 bits.
///
/// The corpus's one full-width value is the unlimited allowance
/// (`2^128 - 1` as a raw word, `unlimited_allowance_word`), built as a
/// constant `B32` and passed straight through.
pub struct U256;

impl AbiType for U256 {
    const SOLIDITY: &'static str = "uint256";
    const RESPOND: &'static str = "uint256";
    type Wire<V: Vis3> = B32<V>;
}

impl AbiArg for U256 {
    fn word<V: Vis3>(_c: &mut Circuit3, w: &Self::Wire<V>) -> B32<V> {
        *w
    }
}

// ---- the attested return -----------------------------------------------------

/// WHAT THE MPC ATTESTS FOR A RETURN TYPE — `serializedOutput`: its byte
/// width, its circuit shape, and how a circuit reads the ABI value back out
/// of it (M44 rung D).
///
/// A V1 attestation signs the output as BYTES at a width the digest commits
/// to ([`signet_v1::calculate_attestation_digest_v1`]), not as a decoded
/// value: the MPC decodes the EVM return under the record's
/// `outputDeserializationSchema`, re-serializes it with Borsh and signs
/// `[tag, requestId, blockHeight, outputKind, LEN, output]`. So a settle
/// circuit takes the BYTES and narrows them itself, which is where the
/// `Bytes<32> as Uint<128>` hazard lives (bug report 4) — and why the
/// narrowing is written ONCE, here, rather than per settle circuit:
///
/// - a `bool` is one byte, and "true" is `byte == 1` with NO canonicity
///   check, exactly as compactc lowers `deserialize<_, 1>(output).success`;
/// - a `uint256` is 32 little-endian bytes, narrowed by
///   [`signet_v1::checked_truncation_u128`], whose byte-31 check is what
///   stops a 32-byte string being read modulo the field;
/// - nothing at all is [`Bytes0`] — no slot, no limb, and the verdict
///   ([`signet_v1::output_kind`]) is the whole answer.
///
/// SEPARATE FROM [`AbiArg`] in both directions. An argument has a word and
/// may have no attested form ([`Address`] is never a return in the
/// library); a return has an attested form and may have no word
/// ([`Unit`]). A return type with no impl here cannot be named by a slot at
/// all — the missing impl is the rejection, so a call whose attested
/// narrowing nobody has written down does not compile into a `Pending`.
pub trait AbiReturn: AbiType {
    /// `serializedOutput`'s byte width — the `LEN` the attestation digest
    /// commits to.
    const LEN: usize;

    /// The serialized output as a circuit value. Private: it arrives on a
    /// settle ticket.
    type Serialized: CircuitArg + Copy;

    /// Its FAB limbs, in slot order — the tail of the signed preimage.
    fn limbs(out: &Self::Serialized) -> Vec<Wire3<FieldT, Private>>;

    /// The decoded value an [`EvmCall::succeeded`] predicate reads, with
    /// whatever range check the narrowing owes.
    fn decode(c: &mut Circuit3, out: &Self::Serialized) -> Self::Wire<Private>;
}

/// Nothing attested: zero bytes, zero limbs, nothing to decode.
impl AbiReturn for Unit {
    const LEN: usize = 0;
    type Serialized = Bytes0<Private>;

    fn limbs(_out: &Bytes0<Private>) -> Vec<Wire3<FieldT, Private>> {
        Vec::new()
    }

    fn decode(_c: &mut Circuit3, _out: &Bytes0<Private>) {}
}

/// A Borsh `bool`: one byte, true iff it is `1`.
///
/// NO CANONICITY CHECK, deliberately: `deserialize<VaultResponse, 1>(output)
/// .success` in the deployed source is `byte == 1`, so a byte of 2 reads as
/// FALSE rather than as a proof failure, and this lineage says the same
/// thing. The byte is inside the signed digest either way, so the MPC chose
/// it.
impl AbiReturn for Bool {
    const LEN: usize = 1;
    type Serialized = Bytes<1, Private>;

    fn limbs(out: &Bytes<1, Private>) -> Vec<Wire3<FieldT, Private>> {
        vec![out.field()]
    }

    fn decode(c: &mut Circuit3, out: &Bytes<1, Private>) -> BoolWire<Private> {
        let one = c.constant(1u64).private();
        BoolWire::from_field_unchecked(c.test_eq(out.field(), one))
    }
}

/// A Borsh `uint256` narrowed to a `Uint<64>` — the width a shielded mint
/// takes, so the narrowing is TWO checks: byte 31 zero and the low 31 bytes
/// under 2^128 ([`signet_v1::checked_truncation_u128`]), then the 64-bit
/// range check the deployed source's `as Uint<64>` emits.
impl AbiReturn for U64 {
    const LEN: usize = 32;
    type Serialized = B32<Private>;

    fn limbs(out: &B32<Private>) -> Vec<Wire3<FieldT, Private>> {
        vec![out.hi, out.lo]
    }

    fn decode(c: &mut Circuit3, out: &B32<Private>) -> Uint<64, Private> {
        let narrowed = signet_v1::checked_truncation_u128(c, out);
        Uint::<64, Private>::from_field_checked(c, narrowed.field())
    }
}

/// A Borsh `uint256` narrowed to a `Uint<128>` — one
/// [`signet_v1::checked_truncation_u128`] and no more.
impl AbiReturn for U128 {
    const LEN: usize = 32;
    type Serialized = B32<Private>;

    fn limbs(out: &B32<Private>) -> Vec<Wire3<FieldT, Private>> {
        vec![out.hi, out.lo]
    }

    fn decode(c: &mut Circuit3, out: &B32<Private>) -> Uint<128, Private> {
        signet_v1::checked_truncation_u128(c, out)
    }
}

/// A Borsh `uint256` AT ITS FULL WIDTH — the 32 bytes unnarrowed, for a
/// settle that compares them rather than counting with them. No check is
/// owed because nothing is cast.
impl AbiReturn for U256 {
    const LEN: usize = 32;
    type Serialized = B32<Private>;

    fn limbs(out: &B32<Private>) -> Vec<Wire3<FieldT, Private>> {
        vec![out.hi, out.lo]
    }

    fn decode(_c: &mut Circuit3, out: &B32<Private>) -> B32<Private> {
        *out
    }
}

// ---- the argument list -------------------------------------------------------

/// An [`EvmCall`]'s argument list: `()` or a 1- to 8-tuple of [`AbiArg`]s.
///
/// [`AbiArg`] and not [`AbiType`]: [`Unit`] is a return and not an
/// argument, so a tuple containing it has no `AbiTuple` impl.
///
/// Implemented by a declarative `macro_rules!` over the arities — tooling
/// walks into it (notes/evm-calls.org §6: *"macros that don't completely
/// break tooling"*), and there is no attribute macro rewriting anyone's
/// item.
pub trait AbiTuple {
    /// How many ABI words the list encodes to — one per element, since
    /// every leaf here is a static single word.
    const WORDS: usize;

    /// The tuple of circuit values, one [`AbiType::Wire`] per element.
    type Wires<V: Vis3>;

    /// The comma-joined [`AbiType::SOLIDITY`] spellings — the inside of the
    /// selector signature's parentheses. Built at CIRCUIT-BUILD TIME, in
    /// Rust, like the keccak that consumes it.
    fn signature() -> String;

    /// The words, in argument order. The length is always [`Self::WORDS`].
    fn words<V: Vis3>(c: &mut Circuit3, wires: Self::Wires<V>) -> Vec<B32<V>>;
}

impl AbiTuple for () {
    const WORDS: usize = 0;
    type Wires<V: Vis3> = ();

    fn signature() -> String {
        String::new()
    }

    fn words<V: Vis3>(_c: &mut Circuit3, _wires: ()) -> Vec<B32<V>> {
        Vec::new()
    }
}

macro_rules! abi_tuple {
    ($n:literal; $($t:ident => $idx:tt),+) => {
        impl<$($t: AbiArg),+> AbiTuple for ($($t,)+) {
            const WORDS: usize = $n;
            type Wires<V: Vis3> = ($(<$t as AbiType>::Wire<V>,)+);

            fn signature() -> String {
                [$(<$t as AbiType>::SOLIDITY),+].join(",")
            }

            fn words<V: Vis3>(c: &mut Circuit3, wires: Self::Wires<V>) -> Vec<B32<V>> {
                // Left to right, which is argument order, which is word order.
                vec![$(<$t as AbiArg>::word(c, &wires.$idx)),+]
            }
        }
    };
}

abi_tuple!(1; A => 0);
abi_tuple!(2; A => 0, B => 1);
abi_tuple!(3; A => 0, B => 1, C => 2);
abi_tuple!(4; A => 0, B => 1, C => 2, D => 3);
abi_tuple!(5; A => 0, B => 1, C => 2, D => 3, E => 4);
abi_tuple!(6; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5);
abi_tuple!(7; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6);
abi_tuple!(8; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7);

// ---- the arguments, built one at a time ---------------------------------------

/// THE ARGUMENTS OF A CALL, BUILT ONE AT A TIME — a tuple of closures, one
/// per element of [`EvmCall::Args`], each run immediately before its own word
/// is encoded.
///
/// [`AbiTuple::words`] takes the VALUES, which means every argument exists
/// before the first encoder runs. That is the right shape for a caller whose
/// arguments are already in hand, and the wrong one for a caller whose second
/// argument comes from a ledger read: the read would emit before the first
/// argument's word instead of between the two, and the deployed lineages'
/// instruction streams have it between (the vault's `supply` reads
/// `vaultEvmAddress` after encoding `amount`, and `approveStata` builds its
/// constant allowance word after encoding the spender). So
/// [`crate::evm_flow::Pending::request_with`] takes BUILDERS, and the order
/// they emit in is the order the words come out.
///
/// ```
/// # use minocrab::v3::{Circuit3, FieldT};
/// # use minocrab::Private;
/// # use minocrab_contracts::evm::{AbiArgs, Address, U128};
/// # use minocrab_std::v3::{Bytes, Uint};
/// let mut c = Circuit3::new();
/// let to = Bytes::<20, Private>::from_field_unchecked(c.arg::<FieldT>("to"));
/// let amount = Uint::<128, Private>::from_field_unchecked(c.arg::<FieldT>("amount"));
/// let words = AbiArgs::<(Address, U128)>::words(
///     (|_c: &mut Circuit3| to, |_c: &mut Circuit3| amount),
///     &mut c,
/// );
/// assert_eq!(words.len(), 2);
/// ```
pub trait AbiArgs<T: AbiTuple> {
    /// The words, in argument order, each argument built just before it is
    /// encoded. The length is always `T::WORDS`.
    fn words(self, c: &mut Circuit3) -> Vec<B32<Private>>;
}

impl AbiArgs<()> for () {
    fn words(self, _c: &mut Circuit3) -> Vec<B32<Private>> {
        Vec::new()
    }
}

macro_rules! abi_args {
    ($($t:ident / $f:ident => $idx:tt),+) => {
        impl<$($t: AbiArg,)+ $($f: FnOnce(&mut Circuit3) -> <$t as AbiType>::Wire<Private>,)+>
            AbiArgs<($($t,)+)> for ($($f,)+)
        {
            fn words(self, c: &mut Circuit3) -> Vec<B32<Private>> {
                // Build, encode, move on: the emission order a request
                // circuit's ledger reads interleave with.
                vec![$({
                    let w = (self.$idx)(c);
                    <$t as AbiArg>::word(c, &w)
                }),+]
            }
        }
    };
}

abi_args!(A / FA => 0);
abi_args!(A / FA => 0, B / FB => 1);
abi_args!(A / FA => 0, B / FB => 1, C / FC => 2);
abi_args!(A / FA => 0, B / FB => 1, C / FC => 2, D / FD => 3);
abi_args!(A / FA => 0, B / FB => 1, C / FC => 2, D / FD => 3, E / FE => 4);
abi_args!(A / FA => 0, B / FB => 1, C / FC => 2, D / FD => 3, E / FE => 4, F / FF => 5);
abi_args!(
    A / FA => 0, B / FB => 1, C / FC => 2, D / FD => 3, E / FE => 4, F / FF => 5, G / FG => 6
);
abi_args!(
    A / FA => 0, B / FB => 1, C / FC => 2, D / FD => 3, E / FE => 4, F / FF => 5, G / FG => 6,
    H / FH => 7
);

// ---- the callee's interface --------------------------------------------------

/// A CALLEE INTERFACE: a set of functions an EVM contract claims to expose.
///
/// It is what a [`Contract<I>`](crate::evm_flow::Contract) is typed by, and
/// what [`EvmCall::Callee`] names. The library's own set is
/// [`erc20::Erc20`], [`erc4626::Erc4626`] and
/// [`uniswap_v3::UniswapV3Router`] today (`Weth`, `AaveV3Pool`, `Erc721`,
/// `UsdtLike` in rungs B and C); the trait is OPEN, so a contract calling a
/// deployment of its own declares a marker in one line:
///
/// ```
/// use minocrab_contracts::evm::Interface;
///
/// /// The MPC's integration target.
/// pub struct SignetEvmTarget;
/// impl Interface for SignetEvmTarget {}
/// ```
///
/// `'static` because a marker is a unit type and the
/// [`Contract`](crate::evm_flow::Contract) built over it lives in a `const`
/// ledger block.
pub trait Interface: 'static {}

/// INTERFACE INHERITANCE: `I: Extends<Base>` says a `Contract<I>` may be
/// handed a `Base` call.
///
/// Reflexive by the blanket impl below, so an interface always takes its own
/// calls and the common case needs no impl at all. The one inheritance rung
/// A carries is the real one: an ERC-4626 vault IS an ERC-20 (its shares are
/// a token), so `impl Extends<Erc20> for Erc4626` is what lets the deployed
/// vault's `approve_stata` file an [`erc20::Approve`] against its
/// `Contract<Erc4626>` stata-token cell.
///
/// COHERENCE: a downstream crate may write `impl Extends<Erc20> for MyToken`
/// for its OWN marker, and may not write `impl Extends<Erc20> for Erc4626`
/// (the orphan rule). The library decides its own inheritance, which is
/// right — inheritance here is a claim about a deployed contract's ABI.
pub trait Extends<Base: Interface>: Interface {}

/// Every interface takes its own calls.
impl<I: Interface> Extends<I> for I {}

// ---- the filing ---------------------------------------------------------------

/// HOW ONE SLOT FILES ITS CALL — the call plus the facts that are about a
/// DEPLOYMENT's protocol rather than about the Solidity function
/// (notes/evm-interfaces.org §1).
///
/// [`EvmCall`] carries what `transfer` IS. What it cannot carry is what the
/// MPC is asked to DECODE out of the return (`[{"name":"success","type":
/// "bool"}]` for a vault, `[]` for a protocol that only wants the verdict),
/// or what a particular deployed record calls the value that comes back.
/// Those are facts about the SLOT, and this is where a slot states them.
///
/// WHAT WENT, IN M44 RUNG D: the response KIND byte. The V1 record carries
/// none — a request is identified by its id alone, and an attestation is
/// bound to a slot by the slot's own record map (the entry is there or it is
/// not) and by the ticket's TYPE. So two slots of one block may file the
/// same call with the same schema and still not swap tickets, and there is
/// no byte left to allocate by hand.
///
/// [`Filed`] is the off-the-shelf impl, and for most slots it is the whole
/// declaration. A deployment writes the impl out by hand when it needs TWO
/// slots that file the same call under the same schema — the tickets are
/// typed by the filing, so two distinct types are what keep a deposit's
/// `Succeeded` from settling a withdrawal:
///
/// ```
/// use minocrab_contracts::evm::{erc20, Filing};
/// use minocrab_contracts::signet_v1::schema;
///
/// /// `transfer` as this protocol's withdrawal.
/// pub struct Withdrawal;
/// impl Filing for Withdrawal {
///     type Call = erc20::Transfer;
///     type Schema = schema::Success;
/// }
/// ```
pub trait Filing: 'static {
    /// The call this slot files.
    type Call: EvmCall;

    /// THE OUTPUT SCHEMA this slot's records carry — what the MPC decodes
    /// the EVM return under before it attests it
    /// ([`signet_v1::OutputSchema`], the library's five in
    /// [`signet_v1::schema`]).
    ///
    /// It is a wire commitment in the strongest sense: the schema string is
    /// inside the record, so it is inside the request id, so a slot that
    /// files the wrong schema files a DIFFERENT request — and the attested
    /// width it implies is inside the signed digest, so an output of the
    /// wrong width cannot verify.
    ///
    /// The schema and the call's [`AbiReturn`] narrowing have to agree, and
    /// nothing here checks that they do: a `[]` schema with a `Bool` return
    /// asks the MPC for no output and then looks for a byte, which fails at
    /// the digest. Pair them the way [`Filed`]'s doc table does.
    ///
    /// IT CARRIES THE RETURN'S NAME, which is why `RETURN_FIELD` went with
    /// the kind byte in M44 rung D: a V1 attestation's `serializedOutput` is
    /// a flat `Bytes<LEN>` argument, so there is no named field inside it for
    /// a filing to spell — the name the deployed records use (`success`,
    /// `amountIn`, `shares`, `assets`) is inside this schema string, where
    /// the MPC reads it.
    type Schema: OutputSchema;

    /// THE GAS LIMIT THIS SLOT FILES WITH, if it differs from the call's own
    /// default ([`EvmCall::GAS_LIMIT`]).
    ///
    /// A gas limit is a fact about the FUNCTION by default (§2.3) — but a
    /// deployment sometimes knows more than the library's per-function
    /// number does (a route through a proxy, a token with an unusually
    /// expensive hook), and that knowledge is the SLOT's, not the call's. A
    /// `Filing` that leaves this at the default emits exactly what
    /// [`EvmCall::GAS_LIMIT`] does — no filing needed one until this rung,
    /// which is why every filing before it still takes the default
    /// (notes/evm-interfaces.org §10).
    const GAS_LIMIT: u64 = <Self::Call as EvmCall>::GAS_LIMIT;
}

/// THE ONE-LINE FILING: this call, decoded under this schema.
///
/// `type Transfer = Filed<erc20::Transfer, schema::Success>;` and the slot,
/// both tickets and both settle signatures are that one name
/// (notes/evm-interfaces.org §2.2).
///
/// THE PAIRS THAT MAKE SENSE — the schema says what the MPC decodes, the
/// call's [`EvmCall::Return`] says what this contract then narrows, and they
/// have to be the same thing:
///
/// | `Return`             | `Schema`                                 | attested |
/// |----------------------|------------------------------------------|----------|
/// | [`Bool`]             | [`schema::Success`](signet_v1::schema::Success) | 1 byte |
/// | [`U64`] / [`U128`] / [`U256`] | [`schema::AmountIn`](signet_v1::schema::AmountIn), `Shares`, `Assets` | 32 bytes |
/// | [`Unit`]             | [`schema::NoReturn`](signet_v1::schema::NoReturn) | nothing |
///
/// WHY A WRAPPER RATHER THAN A PARAMETER ON THE SLOT: the schema is consumed
/// by the TICKETS too (the attested width is the call's, and `refund`
/// selects between that width and zero), so a slot parameter would put
/// `Succeeded<Call, Schema>` on every settle signature.
///
/// WHAT WENT WITH THE KIND BYTE: the second parameter used to be the
/// protocol's response kind (`Kinded<erc20::Transfer, 1>`), a byte a
/// deployment had to allocate by hand and the Ledger derive had to check was
/// unique per block. V1 records carry no kind, so the parameter is the
/// schema instead — a fact a deployment reads off its own ABI rather than
/// one it invents.
pub struct Filed<Call, Schema>(PhantomData<fn() -> (Call, Schema)>);

impl<Call: EvmCall + 'static, Schema: OutputSchema> Filing for Filed<Call, Schema> {
    type Call = Call;
    type Schema = Schema;
}

// ---- the call ----------------------------------------------------------------

/// A named EVM function call: what it is called, what it takes, what it
/// returns, WHICH INTERFACE EXPOSES IT and what it may spend.
///
/// Everything else — the selector, the word count, the response type, the
/// schema spellings — is DERIVED from these, which is the whole point
/// (notes/evm-calls.org §2).
///
/// WHAT IS NOT HERE, since M38 rung A: the OUTPUT SCHEMA the MPC decodes the
/// return under, and with it the deployed record's name for the attested
/// value. Neither is a fact about the Solidity function — the same
/// `transfer` is decoded for its flag by a vault and left undecoded by a
/// protocol that wants only the verdict — so both live on the SLOT's
/// [`Filing`] (notes/evm-interfaces.org §1).
pub trait EvmCall {
    /// THE INTERFACE THAT EXPOSES THIS FUNCTION.
    ///
    /// A call may be filed only against a `Contract<I>` whose `I`
    /// [`Extends`] this — so a `transfer` cannot be sent to a
    /// [`uniswap_v3::UniswapV3Router`], and an [`erc20::Approve`] can be
    /// sent to an [`erc4626::Erc4626`], which is the deployed vault's stata
    /// token.
    type Callee: Interface;

    /// The Solidity function name, without parentheses.
    const NAME: &'static str;

    /// The argument list.
    type Args: AbiTuple;

    /// The attested return value. `Attested<Return::Wire>`, decoded under
    /// the slot's [`Filing::Schema`], is the response a settle circuit
    /// consumes.
    type Return: AbiType;

    /// The gas LIMIT (not a price; the fee envelope is [`build_tx`]'s).
    ///
    /// A PER-FUNCTION DEFAULT — a `transfer` costs what a transfer costs —
    /// which is why it stayed here when the kind left (§2.3). The library's
    /// values ARE the deployed vault's: [`erc20::CALL_GAS`],
    /// [`erc4626::CALL_GAS`], [`uniswap_v3::SWAP_GAS`]. A deployment that
    /// needs another limit passes [`Envelope::caller`] today.
    const GAS_LIMIT: u64;

    /// The full signature the selector is hashed over.
    ///
    /// The default is `NAME(comma-joined argument types)`. It is overridable
    /// for the one shape the flat join cannot spell: a call whose arguments
    /// are a Solidity STRUCT, which the ABI renders as a nested tuple —
    /// `exactOutputSingle((address,address,…))`. See
    /// [`uniswap_v3::ExactOutputSingle`].
    fn signature() -> String {
        format!("{}({})", Self::NAME, <Self::Args as AbiTuple>::signature())
    }

    /// The four-byte selector: `keccak256(signature())[..4]`.
    ///
    /// Hashed HERE, in Rust, when the circuit is built — a selector is a
    /// build-time constant, and the artifact only ever sees the immediate.
    /// No `keccak256` instruction is emitted by anything in this module.
    fn selector() -> [u8; 4] {
        let digest = Keccak256::digest(Self::signature().as_bytes());
        [digest[0], digest[1], digest[2], digest[3]]
    }

    /// WHAT A SETTLE CIRCUIT IS HANDED once success has been asserted —
    /// the identity by default ([`FromReturn`]), `()` for a call whose
    /// whole return was the flag [`Self::succeeded`] just checked.
    ///
    /// Stable Rust has no associated-type defaults, so every call names it;
    /// it is one line, and it is the line where "does the caller get to see
    /// this?" is answered.
    type Success: FromReturn<<Self::Return as AbiType>::Wire<Private>>;

    /// DID IT WORK? — the predicate [`crate::evm_flow::Pending::complete`]
    /// asserts and [`crate::evm_flow::Pending::refund`] negates, over the
    /// attested return value (notes/evm-calls.org §3.2).
    ///
    /// NO DEFAULT, deliberately. "Executed ⇒ succeeded" is the answer for
    /// most calls and the WRONG one for an ERC-20 `transfer`, which mines
    /// happily and returns `false`; a default would make the dangerous case
    /// the one nobody has to type. So every call type answers, and the two
    /// answers already in the vocabulary are [`always`] (a number came back,
    /// so it executed — the constant-true assert folds away) and
    /// [`is_true`] (the returned flag IS the verdict).
    ///
    /// A call with a business notion of success writes it here — an
    /// ERC-4626 `deposit` that minted zero shares executed perfectly and
    /// achieved nothing:
    ///
    /// ```
    /// # use minocrab::v3::Circuit3;
    /// # use minocrab::Private;
    /// # use minocrab_contracts::evm::{erc4626, Address, AbiType, EvmCall, U128, U64};
    /// # use minocrab_std::v3::{Check, Uint};
    /// struct StrictDeposit;
    /// impl EvmCall for StrictDeposit {
    ///     type Callee = erc4626::Erc4626;
    ///     const NAME: &'static str = "deposit";
    ///     type Args = (U128, Address);
    ///     type Return = U64;
    ///     type Success = Uint<64, Private>;
    ///     const GAS_LIMIT: u64 = 500_000;
    ///
    ///     fn succeeded(_c: &mut Circuit3, shares: &Uint<64, Private>) -> Check<Private> {
    ///         shares.gt(0u64)
    ///     }
    /// }
    /// ```
    ///
    /// The vault's own calls deliberately keep "executed": their deployed
    /// semantics are that, and tightening them is a protocol change rather
    /// than a refactor.
    fn succeeded(
        c: &mut Circuit3,
        output: &<Self::Return as AbiType>::Wire<Private>,
    ) -> Check<Private>;

    /// The projection, applied AFTER [`Self::succeeded`] has been asserted.
    /// The default is [`Self::Success`]'s own [`FromReturn`]; override it
    /// for a projection that needs the circuit (a decode, a range check).
    fn map(
        c: &mut Circuit3,
        output: <Self::Return as AbiType>::Wire<Private>,
    ) -> Self::Success {
        Self::Success::from_return(c, output)
    }
}

// ---- ether ---------------------------------------------------------------------

/// A PAYABLE FUNCTION — one that may be called WITH ETHER ATTACHED.
///
/// Every other call this library builds fixes the transaction's `value`
/// field at zero: a token call moves tokens, not ether. WETH's `deposit()`
/// is the exception — the ether IS the argument, and a `deposit` with
/// `value = 0` wraps nothing.
///
/// A MARKER, not a field, because that is the top rung of the project's
/// ladder (CLAUDE.md: missing impl > distinct types > inline-const assert >
/// panic). [`build_tx_payable`] and
/// [`Pending::request_payable`](crate::evm_flow::Pending::request_payable)
/// are the only ways to put a non-zero `value` on the wire and both are
/// bounded by this trait, so handing ether to an [`erc20::Transfer`] is
/// `error[E0277]` — "the trait bound `Transfer: Payable` is not satisfied"
/// — rather than an amount that silently goes nowhere. Nothing about a non-payable call changes: it has
/// no impl, no extra field and no extra instruction.
///
/// The converse is NOT enforced and is not a mistake: a payable call may be
/// made through the ordinary [`build_tx`], which is a call with no ether —
/// which is what Solidity means by payable.
pub trait Payable: EvmCall {}

// ---- did it work? ------------------------------------------------------------

/// A `Check` that is CONSTANTLY TRUE — the [`EvmCall::succeeded`] of a call
/// whose return carries no failure signal of its own.
///
/// It lowers to `assert` on the IMMEDIATE 1, which
/// `minocrab_ir::v3::passes::drop_true_asserts` removes in
/// `Builder3::finish` (notes/ir-passes.org §11). So "executed is succeeded"
/// costs exactly nothing in the artifact, and it costs it by FOLDING rather
/// than by a branch in this API that an author could take wrongly (dmd,
/// 2026-09-05: *"I'm inclined to just use the fold"*).
pub fn always(c: &mut Circuit3) -> Check<Private> {
    is_true(BoolWire::from_field_unchecked(c.constant(1u64).private()))
}

/// THE PROJECTION [`EvmCall::map`] applies to an attested return value —
/// what a settle circuit is handed once success has been asserted.
///
/// The default is the IDENTITY (the blanket impl below), so a call that
/// wants the number back writes `type Success = Uint<64, Private>` and
/// nothing else. The one other impl is the interesting one: a `Bool` return
/// maps to `()`, because a flag [`EvmCall::succeeded`] has already asserted
/// carries no information a caller could act on, and handing it back is an
/// invitation to re-read it as data (notes/evm-calls.org §3.2, the
/// filter-map).
///
/// A domain projection — an amount into a newtype, a raw word into a
/// decoded value — is an impl of this trait plus an override of
/// [`EvmCall::map`].
pub trait FromReturn<W> {
    /// Build the projection from the attested wire.
    fn from_return(c: &mut Circuit3, w: W) -> Self;
}

/// THE IDENTITY: hand back exactly what the MPC attested.
impl<W> FromReturn<W> for W {
    fn from_return(_c: &mut Circuit3, w: W) -> W {
        w
    }
}

/// A `bool` return that `succeeded` has already asserted says nothing more.
impl<V: Vis3> FromReturn<BoolWire<V>> for () {
    fn from_return(_c: &mut Circuit3, _w: BoolWire<V>) {}
}

// ---- the transaction ---------------------------------------------------------

/// The [`EvmTx`] a request files for `C`, from a callee, an argument tuple
/// and a nonce — the future `Pending::request` body's core.
///
/// What it reads off the call type: the selector (an immediate), the gas
/// limit, the word count. What it fixes: `value = 0` (these are token
/// calls, never ether transfers), `calldata_is_some = 1`, and the
/// contract-FIXED fee envelope — 1 gwei priority, 30 gwei cap, the same two
/// numbers `erc20_vault::FIXED_PRIORITY_FEE` / `FIXED_MAX_FEE` name and the
/// vault's `FixedGas` emits. What it does NOT read: the chain id, which is
/// the Signet block's (`Pending::request` supplies it, so a request cannot
/// name another chain than the one the contract is configured for).
///
/// `WORDS` IS NAMED BY THE CALLER because stable Rust cannot write
/// `EvmTx<{ <C::Args as AbiTuple>::WORDS }>` — that needs
/// `generic_const_exprs` (notes/evm-calls.org §3). What it CAN do is reject
/// a wrong one, which is the inline-`const` assert below and an
/// `error[E0080]` at the call site.
///
/// Instruction order is the vault's: the words first (the caller has
/// already built the argument wires), then the fee envelope, then the
/// transaction's constants — so a vault circuit moving onto this emits the
/// same stream it emits today.
pub fn build_tx<C: EvmCall, const WORDS: usize>(
    c: &mut Circuit3,
    callee: Bytes<20, Private>,
    args: <C::Args as AbiTuple>::Wires<Private>,
    nonce: Wire3<FieldT, Private>,
) -> EvmTx<WORDS> {
    build_tx_at::<C, WORDS>(c, callee, args, nonce, C::GAS_LIMIT)
}

/// [`build_tx`], but the fee envelope's gas limit is [`Filing::GAS_LIMIT`]
/// rather than the call's own default — what
/// [`Pending::request`](crate::evm_flow::Pending::request) builds a
/// `Pending<F, …>` slot's transaction from (notes/evm-interfaces.org §10).
///
/// `Filing::GAS_LIMIT`'s default is `Self::Call::GAS_LIMIT`, so an
/// unoverridden filing emits exactly what [`build_tx`] does — ZERO
/// MOVEMENT for every filing that does not name this const.
pub fn build_tx_filed<F: Filing, const WORDS: usize>(
    c: &mut Circuit3,
    callee: Bytes<20, Private>,
    args: <<F::Call as EvmCall>::Args as AbiTuple>::Wires<Private>,
    nonce: Wire3<FieldT, Private>,
) -> EvmTx<WORDS> {
    build_tx_at::<F::Call, WORDS>(c, callee, args, nonce, F::GAS_LIMIT)
}

/// The shared body of [`build_tx`] and [`build_tx_filed`]: `gas_limit` is
/// the only thing that differs between the two callers.
fn build_tx_at<C: EvmCall, const WORDS: usize>(
    c: &mut Circuit3,
    callee: Bytes<20, Private>,
    args: <C::Args as AbiTuple>::Wires<Private>,
    nonce: Wire3<FieldT, Private>,
    gas_limit: u64,
) -> EvmTx<WORDS> {
    const {
        assert!(
            WORDS == <C::Args as AbiTuple>::WORDS,
            "`build_tx::<C, WORDS>` needs WORDS == <C::Args as AbiTuple>::WORDS — \
             the record's calldata capacity IS the argument list's word count. \
             Stable Rust cannot infer it (generic_const_exprs), so name the \
             number the tuple actually encodes to."
        )
    };

    let words = <C::Args as AbiTuple>::words(c, args);
    finish_tx::<C, WORDS>(c, words, Envelope::fixed(), |_| callee, nonce, gas_limit)
}

/// [`build_tx`] FROM WORDS THAT ARE ALREADY ENCODED — what an outbox EMIT
/// has, and all it has: the argument words were encoded at the CALL, from
/// typed wires, and have been sitting in the outbox as stored limbs ever
/// since ([`crate::evm_flow::Outbox`]).
///
/// Everything else is [`build_tx`]: the same const-checked `WORDS`, the same
/// emission order through `finish_tx`. Two things the emit supplies rather
/// than the stored entry, because supplying them IS the emit
/// (notes/nonce-admin.org §4, §1.1): the NONCE, which the contract assigned
/// blind at the call and the emit reads off the snapshot, and the ENVELOPE,
/// which is the contract's — neither is ever a requester's argument.
///
/// The words are a LEDGER READ privatized, not a prover's value: nothing
/// re-encodes them here and nothing needs to, because the read's `popeq`
/// binds them to the stored entry [`AbiTuple::words`] encoded at insert.
pub fn build_tx_from_words<C: EvmCall, const WORDS: usize>(
    c: &mut Circuit3,
    callee: Bytes<20, Private>,
    words: [B32<Private>; WORDS],
    envelope: Envelope,
    nonce: Wire3<FieldT, Private>,
    gas_limit: u64,
) -> EvmTx<WORDS> {
    const {
        assert!(
            WORDS == <C::Args as AbiTuple>::WORDS,
            "`build_tx_from_words::<C, WORDS>` needs WORDS == <C::Args as \
             AbiTuple>::WORDS — the record's calldata capacity IS the \
             argument list's word count. Stable Rust cannot infer it \
             (generic_const_exprs), so name the number the tuple actually \
             encodes to."
        )
    };

    finish_tx::<C, WORDS>(c, words.to_vec(), envelope, |_| callee, nonce, gas_limit)
}

/// [`build_tx`] FOR A CALL THAT CARRIES ETHER — the transaction's `value`
/// field is a real amount rather than the constant zero.
///
/// `C: Payable` is the whole gate: WETH's `deposit()` has the impl and an
/// ERC-20 `transfer` does not, so an amount cannot be attached to a call
/// that would ignore it. Everything else is [`build_tx`] — the same
/// envelope, the same emission order, the same const-checked `WORDS`.
pub fn build_tx_payable<C: Payable, const WORDS: usize>(
    c: &mut Circuit3,
    callee: Bytes<20, Private>,
    args: <C::Args as AbiTuple>::Wires<Private>,
    value: Uint<128, Private>,
    nonce: Wire3<FieldT, Private>,
) -> EvmTx<WORDS> {
    build_tx_payable_at::<C, WORDS>(c, callee, args, value, nonce, C::GAS_LIMIT)
}

/// [`build_tx_filed`] for a [`Payable`] call —
/// [`Pending::request_payable`](crate::evm_flow::Pending::request_payable)'s
/// counterpart to [`build_tx_payable`], reading the slot's
/// [`Filing::GAS_LIMIT`] instead of the call's.
pub fn build_tx_payable_filed<F: Filing, const WORDS: usize>(
    c: &mut Circuit3,
    callee: Bytes<20, Private>,
    args: <<F::Call as EvmCall>::Args as AbiTuple>::Wires<Private>,
    value: Uint<128, Private>,
    nonce: Wire3<FieldT, Private>,
) -> EvmTx<WORDS>
where
    F::Call: Payable,
{
    build_tx_payable_at::<F::Call, WORDS>(c, callee, args, value, nonce, F::GAS_LIMIT)
}

/// The shared body of [`build_tx_payable`] and [`build_tx_payable_filed`].
fn build_tx_payable_at<C: Payable, const WORDS: usize>(
    c: &mut Circuit3,
    callee: Bytes<20, Private>,
    args: <C::Args as AbiTuple>::Wires<Private>,
    value: Uint<128, Private>,
    nonce: Wire3<FieldT, Private>,
    gas_limit: u64,
) -> EvmTx<WORDS> {
    const {
        assert!(
            WORDS == <C::Args as AbiTuple>::WORDS,
            "`build_tx_payable::<C, WORDS>` needs WORDS == <C::Args as AbiTuple>::WORDS \
             — the record's calldata capacity IS the argument list's word count. \
             Stable Rust cannot infer it (generic_const_exprs), so name the \
             number the tuple actually encodes to."
        )
    };

    let words = <C::Args as AbiTuple>::words(c, args);
    finish_tx::<C, WORDS>(
        c,
        words,
        Envelope::fixed().ether(value),
        |_| callee,
        nonce,
        gas_limit,
    )
}

/// WHO PAYS, AND HOW THE TRANSACTION'S CONSTANTS ARE SPELLED — everything
/// about the request that is neither the callee, the arguments nor the nonce.
///
/// Two independent answers, in one value because they are the two things a
/// [`build_tx_with`] caller ever has to say:
///
/// - THE FEES ([`Envelope::fixed`] / [`Envelope::caller`]). The fixed
///   envelope is the contract's own constant one — 1 gwei priority, 30 gwei
///   cap (`erc20_vault::FIXED_PRIORITY_FEE` / `FIXED_MAX_FEE`) and
///   [`EvmCall::GAS_LIMIT`]. The caller's envelope is the shape the vault's
///   `deposit` has: the transaction is paid from the DEPOSITOR's own EVM
///   account, so the depositor picks all three, and they are circuit
///   arguments (notes/evm-calls.org §9's second rung-A finding; §7 is the
///   conversation about giving them an administrator-set home instead).
/// - THE SPELLING ([`Envelope::literal`]). See that method.
pub struct Envelope {
    fees: Fees,
    tail: Tail,
}

enum Fees {
    Fixed,
    Caller {
        max_priority_fee_per_gas: Uint<128, Private>,
        max_fee_per_gas: Uint<128, Private>,
        gas_limit: Uint<64, Private>,
    },
}

enum Tail {
    Named {
        /// The ether the transaction carries, for a [`Payable`] call.
        /// `None` — every non-payable call — is the constant zero, named
        /// where it has always been named.
        value: Option<Wire3<FieldT, Private>>,
    },
    Literal {
        value: Option<Wire3<FieldT, Private>>,
        calldata_is_some: Wire3<FieldT, Private>,
    },
}

impl Envelope {
    /// The contract's own fee envelope: 1 gwei priority, 30 gwei cap, the
    /// call's [`EvmCall::GAS_LIMIT`].
    pub fn fixed() -> Self {
        Envelope {
            fees: Fees::Fixed,
            tail: Tail::Named { value: None },
        }
    }

    /// THE CALLER'S fee envelope — all three numbers as circuit arguments,
    /// for a transaction paid from the caller's own EVM account rather than
    /// the contract's.
    pub fn caller(
        max_priority_fee_per_gas: Uint<128, Private>,
        max_fee_per_gas: Uint<128, Private>,
        gas_limit: Uint<64, Private>,
    ) -> Self {
        Envelope {
            fees: Fees::Caller {
                max_priority_fee_per_gas,
                max_fee_per_gas,
                gas_limit,
            },
            tail: Tail::Named { value: None },
        }
    }

    /// THE HAND-WRITTEN SPELLING of the transaction's constant fields, for a
    /// circuit whose artifact must not move.
    ///
    /// `value = 0` (a token call carries no ether — [`build_tx_payable`] is
    /// the one exception) and `calldata_is_some = 1` (there is always
    /// calldata) are constants of every call this API
    /// builds, and by default [`build_tx_with`] NAMES them, after the fee
    /// envelope and the callee and before the word count and the selector —
    /// the order the vault's `erc20_call` helper named them in, and the order
    /// five of its seven request circuits emit.
    ///
    /// The other two — `swap` and `redeem` — spell their `EvmTx` out as a
    /// struct literal, which named the selector and the word count FIRST and
    /// took `value` and `calldata_is_some` from a zero and a one the circuit
    /// already held (for a `sqrtPriceLimitX96` word and a coin burn). This
    /// selects that spelling: selector, word count, callee, fees, then
    /// `value` only if it is not supplied.
    ///
    /// IT CHANGES NO INSTRUCTION. Every one of these is a `Copy` of an
    /// immediate, and `minocrab_ir::v3::passes::fold_immediate_copies` folds
    /// each into its consumers and deletes it inside `Builder3::finish`, so
    /// the two spellings execute identically and cost identical rows. What
    /// they do not share is the SEQUENTIAL NAMES the surviving instructions
    /// get, because the counter runs over every emitted instruction including
    /// the folded ones. A deployed artifact is compared byte for byte, so a
    /// lineage that spells its transaction the second way keeps saying so.
    /// (notes/evm-calls.org §11 — recorded for dmd: the alternative is to
    /// renumber after folding, which would move every circuit in the tree.)
    pub fn literal(
        self,
        value: Option<Wire3<FieldT, Private>>,
        calldata_is_some: Wire3<FieldT, Private>,
    ) -> Self {
        Envelope {
            fees: self.fees,
            tail: Tail::Literal {
                value,
                calldata_is_some,
            },
        }
    }

    /// THE ETHER — private, and reachable only through
    /// [`build_tx_payable`], whose `C: Payable` bound is the gate. A public
    /// `with_value` on this type could not name the call it will build, so
    /// it could not tell a WETH `deposit` from a `transfer`; the bound goes
    /// where the call is known instead (notes/evm-interfaces.org §5).
    fn ether(self, value: Uint<128, Private>) -> Self {
        Envelope {
            fees: self.fees,
            tail: Tail::Named {
                value: Some(value.field()),
            },
        }
    }

    /// The three fee fields, in wire order. `gas_limit` is the [`Fees::Fixed`]
    /// case's immediate — [`build_tx`] and [`build_tx_payable`] pass the
    /// call's own [`EvmCall::GAS_LIMIT`]; [`build_tx_filed`] and
    /// [`build_tx_payable_filed`] pass the slot's [`Filing::GAS_LIMIT`]
    /// instead (notes/evm-interfaces.org §10). [`Fees::Caller`] ignores it —
    /// its own wire is already the caller's number.
    fn fee_wires(fees: Fees, gas_limit: u64, c: &mut Circuit3) -> [Wire3<FieldT, Private>; 3] {
        match fees {
            Fees::Fixed => {
                let priority_fee = c.constant(FIXED_PRIORITY_FEE);
                let max_fee = c.constant(FIXED_MAX_FEE);
                let gas_limit = c.constant(gas_limit);
                [
                    priority_fee.private(),
                    max_fee.private(),
                    gas_limit.private(),
                ]
            }
            Fees::Caller {
                max_priority_fee_per_gas,
                max_fee_per_gas,
                gas_limit,
            } => [
                max_priority_fee_per_gas.field(),
                max_fee_per_gas.field(),
                gas_limit.field(),
            ],
        }
    }
}

/// [`build_tx`] for a caller who has to control WHEN each piece emits: the
/// arguments as builders ([`AbiArgs`]), the fee envelope, and the callee as a
/// builder too.
///
/// The emission order is the deployed vault's, and that is the whole point of
/// the shape: each argument is built and encoded before the next is built,
/// then the envelope, then the callee, then the transaction's own four
/// constants. A request circuit that reads `vaultEvmAddress` between its two
/// words, or its callee cell after the gas constants, keeps its stream.
///
/// `gas_limit` is the [`Envelope::fixed`] case's immediate — [`build_tx`]'s
/// callers pass [`EvmCall::GAS_LIMIT`], and
/// [`Pending::request_with`](crate::evm_flow::Pending::request_with) /
/// [`Fired::request_with`](crate::evm_flow::Fired::request_with) pass the
/// slot's [`Filing::GAS_LIMIT`] instead (notes/evm-interfaces.org §10). An
/// [`Envelope::caller`] envelope ignores it — its own wire is already the
/// caller's number.
pub fn build_tx_with<C: EvmCall, const WORDS: usize>(
    c: &mut Circuit3,
    callee: impl FnOnce(&mut Circuit3) -> Bytes<20, Private>,
    args: impl AbiArgs<C::Args>,
    envelope: Envelope,
    nonce: Wire3<FieldT, Private>,
    gas_limit: u64,
) -> EvmTx<WORDS> {
    const {
        assert!(
            WORDS == <C::Args as AbiTuple>::WORDS,
            "`build_tx_with::<C, WORDS>` needs WORDS == <C::Args as AbiTuple>::WORDS — \
             the record's calldata capacity IS the argument list's word count. \
             Stable Rust cannot infer it (generic_const_exprs), so name the \
             number the tuple actually encodes to."
        )
    };

    let words = args.words(c);
    finish_tx::<C, WORDS>(c, words, envelope, callee, nonce, gas_limit)
}

/// The shared tail of [`build_tx`] and [`build_tx_with`]: envelope, callee,
/// then `value = 0`, `calldata_is_some = 1`, the word count and the selector.
fn finish_tx<C: EvmCall, const WORDS: usize>(
    c: &mut Circuit3,
    words: Vec<B32<Private>>,
    envelope: Envelope,
    callee: impl FnOnce(&mut Circuit3) -> Bytes<20, Private>,
    nonce: Wire3<FieldT, Private>,
    gas_limit: u64,
) -> EvmTx<WORDS> {
    let words: [B32<Private>; WORDS] = match words.try_into() {
        Ok(words) => words,
        // Unreachable: the const asserts above pin WORDS to the tuple's
        // count, and both word builders yield exactly that many.
        Err(_) => unreachable!("the argument list yields <C::Args>::WORDS words"),
    };

    let selector_imm =
        || Fr::from_le_bytes(&C::selector()).expect("four bytes fit a field element");
    let Envelope { fees, tail } = envelope;

    // The two spellings differ only in the ORDER these immediates are named
    // and in which of them the caller already holds — see `Envelope::literal`.
    let ([priority_fee, max_fee, gas_limit], to, value, calldata_is_some, no_words, selector) =
        match tail {
            Tail::Named { value } => {
                let fees = Envelope::fee_wires(fees, gas_limit, c);
                let to = callee(c).field();
                // `None` is every non-payable call: the immediate zero,
                // named exactly where it has always been named.
                let value = value.unwrap_or_else(|| c.constant(0u64).private());
                let calldata_is_some = c.constant(1u64).private();
                let no_words = c.constant(WORDS as u64).private();
                let selector = c.constant(selector_imm()).private();
                (fees, to, value, calldata_is_some, no_words, selector)
            }
            Tail::Literal {
                value,
                calldata_is_some,
            } => {
                let selector = c.constant(selector_imm()).private();
                let no_words = c.constant(WORDS as u64).private();
                let to = callee(c).field();
                let fees = Envelope::fee_wires(fees, gas_limit, c);
                let value = value.unwrap_or_else(|| c.constant(0u64).private());
                (fees, to, value, calldata_is_some, no_words, selector)
            }
        };

    EvmTx {
        nonce,
        max_priority_fee_per_gas: priority_fee,
        max_fee_per_gas: max_fee,
        gas_limit,
        to,
        value,
        calldata_is_some,
        calldata: EvmCalldata {
            selector,
            no_words,
            words,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The selector signatures, spelled out. `tests/evm_abi.rs` pins the
    /// HASHES against the vault's constants (which the differential suite
    /// pins against compactc's own calldata); this pins the strings that go
    /// into them, where a typo would otherwise only show as four wrong bytes.
    #[test]
    fn signatures_read_as_solidity() {
        assert_eq!(erc20::Transfer::signature(), "transfer(address,uint256)");
        assert_eq!(erc20::Approve::signature(), "approve(address,uint256)");
        assert_eq!(
            uniswap_v3::ExactOutputSingle::signature(),
            "exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))"
        );
        assert_eq!(erc4626::Deposit::signature(), "deposit(uint256,address)");
        assert_eq!(erc4626::Redeem::signature(), "redeem(uint256,address,address)");
    }

    /// The empty argument list is a real one: `f()`, not `f(())`.
    #[test]
    fn the_empty_tuple_signs_as_nothing() {
        struct Noop;
        impl EvmCall for Noop {
            type Callee = erc20::Erc20;
            const NAME: &'static str = "noop";
            type Args = ();
            type Return = Bool;
            type Success = ();
            const GAS_LIMIT: u64 = 21_000;

            fn succeeded(_c: &mut Circuit3, ok: &BoolWire<Private>) -> Check<Private> {
                is_true(*ok)
            }
        }
        assert_eq!(Noop::signature(), "noop()");
        assert_eq!(<() as AbiTuple>::WORDS, 0);
    }

    /// Word counts are arities, all the way to eight.
    #[test]
    fn word_counts_are_arities() {
        assert_eq!(<(Address,) as AbiTuple>::WORDS, 1);
        assert_eq!(<<erc20::Transfer as EvmCall>::Args as AbiTuple>::WORDS, 2);
        assert_eq!(<<erc4626::Redeem as EvmCall>::Args as AbiTuple>::WORDS, 3);
        assert_eq!(
            <<uniswap_v3::ExactOutputSingle as EvmCall>::Args as AbiTuple>::WORDS,
            7
        );
        assert_eq!(
            <(Address, Address, Address, Address, Address, Address, Address, Address) as AbiTuple>::WORDS,
            8
        );
    }

    /// THE GAS DEFAULTS ARE THE DEPLOYED VAULT'S, re-homed (§2.3): the
    /// numbers moved into this library and the vault's own constants are
    /// aliases of them, so no request circuit's gas immediate can move.
    #[test]
    fn the_gas_defaults_are_the_vaults() {
        use crate::evm::{erc20::CALL_GAS as ERC20_CALL_GAS, erc4626::CALL_GAS as LENDING_GAS, uniswap_v3::SWAP_GAS};

        assert_eq!(erc20::Transfer::GAS_LIMIT, ERC20_CALL_GAS);
        assert_eq!(erc20::Approve::GAS_LIMIT, ERC20_CALL_GAS);
        assert_eq!(uniswap_v3::ExactOutputSingle::GAS_LIMIT, SWAP_GAS);
        assert_eq!(erc4626::Deposit::GAS_LIMIT, LENDING_GAS);
        assert_eq!(erc4626::Redeem::GAS_LIMIT, LENDING_GAS);
    }

    /// A `Filed` filing IS its call under its schema, and the gas limit is
    /// the call's own default.
    #[test]
    fn filed_files_the_call_under_the_named_schema() {
        use crate::signet_v1::{schema, OutputSchema};
        type Transfer = Filed<erc20::Transfer, schema::Success>;

        assert_eq!(
            <<Transfer as Filing>::Schema as OutputSchema>::BYTES,
            br#"[{"name":"success","type":"bool"}]"#
        );
        assert_eq!(<Transfer as Filing>::GAS_LIMIT, erc20::CALL_GAS);
        assert_eq!(
            <<Transfer as Filing>::Call as EvmCall>::signature(),
            "transfer(address,uint256)"
        );
    }

    /// THE FIVE OUTPUT SCHEMAS ARE THE DEPLOYED STRINGS, byte for byte, at
    /// the widths `notes/vault-flush.org` §2 names (2, 34, 36, 38) — the
    /// record's limbing depends on the length, and the length is in the
    /// signed request id.
    #[test]
    fn the_output_schemas_are_the_deployed_strings() {
        use crate::erc20_vault as v;
        use crate::signet_v1::{schema, OutputSchema};

        assert_eq!(schema::NoReturn::BYTES, v::REPLACE_NONCE_OUTPUT_SCHEMA);
        assert_eq!(schema::Success::BYTES, v::VAULT_OUTPUT_SCHEMA);
        assert_eq!(schema::AmountIn::BYTES, v::SWAP_OUTPUT_SCHEMA);
        assert_eq!(schema::Shares::BYTES, v::SUPPLY_OUTPUT_SCHEMA);
        assert_eq!(schema::Assets::BYTES, v::REDEEM_OUTPUT_SCHEMA);

        assert_eq!(schema::NoReturn::BYTES.len(), 2);
        assert_eq!(schema::Success::BYTES.len(), 34);
        assert_eq!(schema::AmountIn::BYTES.len(), 38);
        assert_eq!(schema::Shares::BYTES.len(), 36);
        assert_eq!(schema::Assets::BYTES.len(), 36);
    }

    /// THE ATTESTED WIDTHS: what the MPC's Borsh of each return type takes,
    /// which is the `LEN` inside the attestation digest and therefore the
    /// width a settle circuit must verify at.
    #[test]
    fn the_attested_widths_are_the_borsh_widths() {
        assert_eq!(<Unit as AbiReturn>::LEN, 0);
        assert_eq!(<Bool as AbiReturn>::LEN, 1);
        assert_eq!(<U64 as AbiReturn>::LEN, 32);
        assert_eq!(<U128 as AbiReturn>::LEN, 32);
        assert_eq!(<U256 as AbiReturn>::LEN, 32);
    }

    /// The narrowing the MPC applies, as the schema literals spell it.
    #[test]
    fn respond_spellings_are_the_schemas() {
        assert_eq!(<erc4626::Deposit as EvmCall>::Return::RESPOND, "uint64");
        assert_eq!(<erc4626::Deposit as EvmCall>::Return::SOLIDITY, "uint256");
        assert_eq!(<erc20::Transfer as EvmCall>::Return::RESPOND, "bool");
    }
}
