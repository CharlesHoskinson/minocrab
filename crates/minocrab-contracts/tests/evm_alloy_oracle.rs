//! M38 rung D — THE FIXTURE ORACLE: every EVM call's selector and every ABI
//! word pinned against **alloy's** encoder, not against our own.
//!
//! `tests/evm_abi.rs` checks our selectors against the vault's constants
//! (which `erc20_vault_differential` pins against compactc's own calldata)
//! and our words against the host-side model in `tests/vault/prims.rs`.
//! Both of those are OURS. This file adds the outside witness: each call is
//! declared a SECOND time, in Solidity, through `alloy_sol_types::sol!`, and
//! the assertions are
//!
//! 1. `Call::signature() == solCall::SIGNATURE`,
//! 2. `Call::selector() == solCall::SELECTOR`, and
//! 3. for GENERATED argument values, the words our `AbiType::word` encoders
//!    produce as circuit wires — run through the simulator and read back as
//!    bytes — equal `solCall { .. }.abi_encode()[4..]` split into 32-byte
//!    words.
//!
//! The dependency is pinned EXACTLY at `alloy-sol-types`/`alloy-primitives`
//! 1.6.1, the versions sig-net/mpc's own `Cargo.lock` resolves (the four
//! macro crates behind them are pinned to 1.6.1 in our lock too), so the
//! oracle is the encoder the MPC itself runs rather than "some ABI library".
//!
//! `tests/evm_abi.rs`'s compactc-calldata pins stay exactly as they are:
//! they are the INDEPENDENT control, and alloy does not replace them.
//!
//! # Adding a row
//!
//! Adding a call to this oracle needs three things and touches no harness
//! code:
//!
//! 1. A `sol!` declaration of the function as ETHEREUM spells it, in the
//!    interface's `sol_*` module below. `uint256` wherever our word type is
//!    `U64`/`U128`/`U256` — those are OUR range bounds on a 32-byte word,
//!    not different Solidity types. A struct argument is a `struct` item
//!    plus a function taking it (see [`sol_uniswap_v3`]).
//! 2. A [`SampleLeaf`] impl for any `AbiType` the call uses that has none
//!    yet — the host-side value, its proptest strategy, the field limbs it
//!    enters the circuit as, and how to rebuild the wire from them. All TEN
//!    of today's leaves already have one (`U8` joined at M38 rung B, for
//!    ERC-2612 `permit`'s `v`; `U16` at rung C, for Aave v3's
//!    `referralCode`).
//! 3. One row in the [`oracle_rows!`] invocation:
//!
//!    ```text
//!    /// doc comment
//!    name: our::CallType => sol_mod::fnNameCall,
//!    |(a, b, ..)| sol_mod::fnNameCall { a: …, b: … };
//!    ```
//!
//!    The pattern destructures the generated `Values` tuple (one entry per
//!    argument, in order, of that leaf's [`SampleLeaf::Value`] type); the
//!    expression builds the alloy call struct from them. The macro emits a
//!    `mod name` with a `signature_and_selector` test and a proptest `words`
//!    test.
//!
//! # What is not pinned here
//!
//! The RETURN types. `EvmCall::Return` is what the MPC attests and narrows
//! (`AbiType::RESPOND`), and the narrowing is a Signet protocol fact, not an
//! ABI one — alloy has nothing to say about it. `tests/evm_abi.rs` and
//! `src/evm.rs`'s unit tests keep those.

use alloy_primitives::aliases::{U160, U24};
use alloy_primitives::{Address as SolAddress, FixedBytes, U256 as SolU256};
use alloy_sol_types::SolCall;
use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Fr, Private};
use minocrab_contracts::evm::{
    aave_v3, erc20, erc4626, erc721, uniswap_v3, usdt, weth, AbiArg, AbiTuple, AbiType, Address,
    Bool, Bytes32, EvmCall, U128, U16 as OurU16, U160 as OurU160, U24 as OurU24, U256 as OurU256,
    U64, U8 as OurU8,
};
use minocrab_sim::v3::simulate;
use minocrab_std::v3::{is_true, Bool as BoolWire, Bytes, Check, Uint, B32};
use minocrab_zkir::v3::IrValue;
use proptest::prelude::*;

use std::borrow::Cow;

use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage};

mod vault;

use vault::gen::config;
use vault::prims::{b20, b32_slots, u128_limb};

// ---- the Solidity side: each interface as Ethereum spells it ------------------

/// ERC-20, from the EIP — plus the two OpenZeppelin allowance deltas and
/// ERC-2612's `permit`, which are not in EIP-20 but are on the tokens that
/// matter. `uint256` for every amount: our `U128` (transfer) and `U256`
/// (approve) are range claims on the same 32-byte word.
mod sol_erc20 {
    alloy_sol_types::sol! {
        function transfer(address to, uint256 amount) external returns (bool);
        function approve(address spender, uint256 amount) external returns (bool);
        function transferFrom(address from, address to, uint256 amount)
            external returns (bool);
        function increaseAllowance(address spender, uint256 addedValue)
            external returns (bool);
        function decreaseAllowance(address spender, uint256 subtractedValue)
            external returns (bool);
        function permit(
            address owner,
            address spender,
            uint256 value,
            uint256 deadline,
            uint8 v,
            bytes32 r,
            bytes32 s
        ) external;
    }
}

/// WETH9, as the deployed contract declares it. `deposit()` is PAYABLE and
/// takes no arguments — the ether is the argument — and neither call
/// returns anything.
mod sol_weth {
    alloy_sol_types::sol! {
        function deposit() external payable;
        function withdraw(uint256 wad) external;
    }
}

/// THE NON-CONFORMING TOKENS, declared as they really are: the same three
/// functions with NO RETURN.
///
/// A Solidity signature does not mention the return type, so alloy hashes
/// these to the ERC-20 selectors above — which is precisely the fact that
/// makes `UsdtLike` a TYPE distinction rather than a wire one, and having
/// alloy say so is worth a row (see [`usdt_selectors_are_the_erc20_ones`]).
mod sol_usdt {
    alloy_sol_types::sol! {
        function transfer(address to, uint256 amount) external;
        function approve(address spender, uint256 amount) external;
        function transferFrom(address from, address to, uint256 amount) external;
    }
}

/// ERC-4626, from the EIP.
mod sol_erc4626 {
    alloy_sol_types::sol! {
        function deposit(uint256 assets, address receiver) external returns (uint256 shares);
        function mint(uint256 shares, address receiver) external returns (uint256 assets);
        function withdraw(uint256 assets, address receiver, address owner)
            external returns (uint256 shares);
        function redeem(uint256 shares, address receiver, address owner)
            external returns (uint256 assets);
    }
}

/// Aave v3's `Pool`, from the deployed `IPool` interface. Every one of
/// these is static-width, and `referralCode` is the `uint16` that makes
/// [`supply`](sol_aave_v3::supplyCall) a different function from the
/// `uint256`-tailed one a careless declaration would produce.
mod sol_aave_v3 {
    alloy_sol_types::sol! {
        function supply(
            address asset,
            uint256 amount,
            address onBehalfOf,
            uint16 referralCode
        ) external;
        // FLAT, not a nested struct — verified against `IPool.sol` on
        // `aave-dao/aave-v3-origin`'s `main` (notes/evm-interfaces.org §10).
        function supplyWithPermit(
            address asset,
            uint256 amount,
            address onBehalfOf,
            uint16 referralCode,
            uint256 deadline,
            uint8 permitV,
            bytes32 permitR,
            bytes32 permitS
        ) external;
        function withdraw(address asset, uint256 amount, address to)
            external returns (uint256);
        function borrow(
            address asset,
            uint256 amount,
            uint256 interestRateMode,
            uint16 referralCode,
            address onBehalfOf
        ) external;
        function repay(
            address asset,
            uint256 amount,
            uint256 interestRateMode,
            address onBehalfOf
        ) external returns (uint256);
    }
}

/// ERC-721, from the EIP — declared with NO RETURNS, which is what the
/// standard says and what makes two of these hash to ERC-20's selectors
/// while meaning something else (see
/// [`erc721_selectors_are_the_erc20_ones`]). `uint256 tokenId` is the same
/// 32-byte word ERC-20 spells `uint256 amount`.
mod sol_erc721 {
    alloy_sol_types::sol! {
        function transferFrom(address from, address to, uint256 tokenId) external;
        function approve(address to, uint256 tokenId) external;
        function setApprovalForAll(address operator, bool approved) external;
    }
}

/// Uniswap V3's `ISwapRouter` — the STRUCT argument, which the ABI renders
/// as a nested tuple and which is the whole reason
/// [`uniswap_v3::ExactOutputSingle`] overrides `EvmCall::signature()`.
/// alloy is the authority on the rendering here:
/// `exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))`.
mod sol_uniswap_v3 {
    alloy_sol_types::sol! {
        struct ExactOutputSingleParams {
            address tokenIn;
            address tokenOut;
            uint24 fee;
            address recipient;
            uint256 amountOut;
            uint256 amountInMaximum;
            uint160 sqrtPriceLimitX96;
        }

        struct ExactInputSingleParams {
            address tokenIn;
            address tokenOut;
            uint24 fee;
            address recipient;
            uint256 amountIn;
            uint256 amountOutMinimum;
            uint160 sqrtPriceLimitX96;
        }

        function exactOutputSingle(ExactOutputSingleParams calldata params)
            external payable returns (uint256 amountIn);
        function exactInputSingle(ExactInputSingleParams calldata params)
            external payable returns (uint256 amountOut);
    }
}

/// EVERY LEAF IN ONE CALL. Rung A's five shipped calls between them never
/// passed a `bool` or a `bytes32` as an ARGUMENT (both appeared only as
/// returns), so this synthetic function is where those two encoders meet
/// alloy. It is also the demonstration that a row costs a `sol!` line and a
/// table entry: nothing below it is call-specific.
///
/// The two narrow leaves are deliberately not here: rung B's ERC-2612
/// `permit` passes a `U8` for real and rung C's Aave `supply` a `U16`, so
/// both are checked by shipped calls rather than by a synthetic one, and
/// `bytes32` now is too (permit's `r` and `s`). Rung C's ERC-721
/// `setApprovalForAll` does the same for the `bool`; this probe keeps it
/// anyway, as the one place every leaf meets alloy in ONE call.
mod sol_probe {
    alloy_sol_types::sol! {
        function abiLeafProbe(
            address who,
            bool flag,
            bytes32 tag,
            uint24 fee,
            uint256 small,
            uint256 wide,
            uint160 price,
            uint256 raw
        ) external returns (bool);
    }
}

/// THE NEGATIVE CONTROLS (see [`the_oracle_can_fail`] and
/// [`the_router_shape_is_the_one_we_declare`]).
///
/// 1. `transfer` with the wrong argument WIDTH — same name, same arity, one
///    type different.
/// 2. Uniswap's ORIGINAL `SwapRouter`, whose `ExactOutputSingleParams`
///    carries a `deadline` field the deployed `SwapRouter02` dropped. Same
///    function name, same struct-wrapped shape, one extra field.
///
/// Both are the failure this whole file exists to be able to detect, and
/// (2) is a live hazard rather than a contrived one: pointing our call type
/// at the wrong router generation is a plausible mistake, and it shows here
/// as four different bytes.
mod sol_wrong {
    alloy_sol_types::sol! {
        function transfer(address to, uint128 amount) external returns (bool);

        struct ExactOutputSingleParamsWithDeadline {
            address tokenIn;
            address tokenOut;
            uint24 fee;
            address recipient;
            uint256 deadline;
            uint256 amountOut;
            uint256 amountInMaximum;
            uint160 sqrtPriceLimitX96;
        }

        struct ExactInputSingleParamsWithDeadline {
            address tokenIn;
            address tokenOut;
            uint24 fee;
            address recipient;
            uint256 deadline;
            uint256 amountIn;
            uint256 amountOutMinimum;
            uint160 sqrtPriceLimitX96;
        }

        function exactOutputSingle(ExactOutputSingleParamsWithDeadline calldata params)
            external payable returns (uint256 amountIn);
        function exactInputSingle(ExactInputSingleParamsWithDeadline calldata params)
            external payable returns (uint256 amountOut);
    }
}

/// Our side of the all-leaves probe. A test-local [`EvmCall`]: the callee
/// and the gas limit are arbitrary (nothing files this call), the ARGUMENT
/// TUPLE is the point.
struct AbiLeafProbe;

impl EvmCall for AbiLeafProbe {
    type Callee = erc20::Erc20;
    const NAME: &'static str = "abiLeafProbe";
    type Args = (
        Address,
        Bool,
        Bytes32,
        OurU24,
        U64,
        U128,
        OurU160,
        OurU256,
    );
    type Return = Bool;
    type Success = ();
    const GAS_LIMIT: u64 = 100_000;

    fn succeeded(_c: &mut Circuit3, ok: &BoolWire<Private>) -> Check<Private> {
        is_true(*ok)
    }
}

// ---- the harness: a leaf's host-side sample ----------------------------------

/// HOW A LEAF IS SAMPLED — the four facts the oracle needs about an
/// [`AbiType`] that a circuit is going to be handed a value of.
///
/// Deliberately a SEPARATE trait from `AbiArg` rather than more methods on
/// it: the sample side is test-only, and the library's leaf traits stay what
/// they are.
///
/// The supertrait is [`AbiArg`] and not `AbiType` (M38 rung B): `AbiType` is
/// the RETURN position's bound and `AbiArg` the ARGUMENT position's, and
/// only arguments are sampled — there is no word to encode for `Unit`, and
/// `SampleArgs`'s `AbiTuple` supertrait would not hold for it anyway.
trait SampleLeaf: AbiArg {
    /// The host-side value — what the alloy call struct is built from.
    /// `'static` because a proptest `BoxedStrategy` is.
    type Value: std::fmt::Debug + Clone + 'static;

    /// How many circuit arguments (field limbs) the value occupies. One for
    /// a leaf carried by a single limb, two for a `B32` (`hi`, `lo`).
    const SLOTS: usize;

    /// Generated values, INSIDE the leaf's range: the range is what our
    /// Rust type claims and what makes `numeric_word` correct, so sampling
    /// outside it would be testing an encoder nobody may call.
    fn strategy() -> BoxedStrategy<Self::Value>;

    /// The field limbs the value enters the circuit as. Exactly
    /// [`Self::SLOTS`] of them.
    fn limbs(v: &Self::Value) -> Vec<Fr>;

    /// The wire, rebuilt from that many argument wires.
    fn wire(args: &[Wire3<FieldT, Private>]) -> <Self as AbiType>::Wire<Private>;
}

/// An address is twenty bytes, unconstrained.
impl SampleLeaf for Address {
    type Value = [u8; 20];
    const SLOTS: usize = 1;

    fn strategy() -> BoxedStrategy<[u8; 20]> {
        any::<[u8; 20]>().boxed()
    }

    fn limbs(v: &[u8; 20]) -> Vec<Fr> {
        vec![b20(v)]
    }

    fn wire(args: &[Wire3<FieldT, Private>]) -> Bytes<20, Private> {
        Bytes::<20, Private>::from_field_unchecked(args[0])
    }
}

/// Both values, every time — `any::<bool>()` is the two-element strategy,
/// and [`bool_covers_both_values`] pins them without waiting on the sampler.
impl SampleLeaf for Bool {
    type Value = bool;
    const SLOTS: usize = 1;

    fn strategy() -> BoxedStrategy<bool> {
        any::<bool>().boxed()
    }

    fn limbs(v: &bool) -> Vec<Fr> {
        vec![Fr::from(u64::from(*v))]
    }

    fn wire(args: &[Wire3<FieldT, Private>]) -> BoolWire<Private> {
        BoolWire::<Private>::from_field_unchecked(args[0])
    }
}

/// A `bytes32` IS the word; the value is the thirty-two bytes.
impl SampleLeaf for Bytes32 {
    type Value = [u8; 32];
    const SLOTS: usize = 2;

    fn strategy() -> BoxedStrategy<[u8; 32]> {
        any::<[u8; 32]>().boxed()
    }

    fn limbs(v: &[u8; 32]) -> Vec<Fr> {
        let (hi, lo) = b32_slots(v);
        vec![hi, lo]
    }

    fn wire(args: &[Wire3<FieldT, Private>]) -> B32<Private> {
        B32 {
            hi: args[0],
            lo: args[1],
        }
    }
}

/// `uint24` — Uniswap's fee tier. Sampled across the whole 24-bit range,
/// with the deployed tiers (100 / 500 / 3000 / 10000) and both ends of the
/// range given their own arms, so the values a swap actually carries are
/// always among the cases.
impl SampleLeaf for OurU24 {
    type Value = u32;
    const SLOTS: usize = 1;

    fn strategy() -> BoxedStrategy<u32> {
        prop_oneof![
            Just(0u32),
            Just(100u32),
            Just(500u32),
            Just(3_000u32),
            Just(10_000u32),
            Just((1u32 << 24) - 1),
            0u32..(1u32 << 24),
        ]
        .boxed()
    }

    fn limbs(v: &u32) -> Vec<Fr> {
        vec![Fr::from(u64::from(*v))]
    }

    fn wire(args: &[Wire3<FieldT, Private>]) -> Uint<24, Private> {
        Uint::<24, Private>::from_field_unchecked(args[0])
    }
}

/// `uint8` — ERC-2612 `permit`'s signature parity byte. 27 and 28 are the
/// only values a real signature carries (EIP-155 chains add a chain-derived
/// pair), so both get their own arm beside the whole-range sampler: the
/// encoder is the same reversal for any of them, and this is the leaf where
/// a wrong `SOLIDITY` spelling would move a selector.
impl SampleLeaf for OurU8 {
    type Value = u8;
    const SLOTS: usize = 1;

    fn strategy() -> BoxedStrategy<u8> {
        prop_oneof![Just(0u8), Just(27u8), Just(28u8), Just(u8::MAX), any::<u8>()].boxed()
    }

    fn limbs(v: &u8) -> Vec<Fr> {
        vec![Fr::from(u64::from(*v))]
    }

    fn wire(args: &[Wire3<FieldT, Private>]) -> Uint<8, Private> {
        Uint::<8, Private>::from_field_unchecked(args[0])
    }
}

/// `uint16` — Aave v3's `referralCode` (M38 rung C). Zero gets its own arm
/// because zero is what every integrator passes, both ends of the range get
/// one because they are where a truncation would show, and the whole range
/// is sampled behind them.
impl SampleLeaf for OurU16 {
    type Value = u16;
    const SLOTS: usize = 1;

    fn strategy() -> BoxedStrategy<u16> {
        prop_oneof![Just(0u16), Just(1u16), Just(u16::MAX), any::<u16>()].boxed()
    }

    fn limbs(v: &u16) -> Vec<Fr> {
        vec![Fr::from(u64::from(*v))]
    }

    fn wire(args: &[Wire3<FieldT, Private>]) -> Uint<16, Private> {
        Uint::<16, Private>::from_field_unchecked(args[0])
    }
}

/// `uint256` carried by a `Uint<64>` — the Midnight-side amount width.
impl SampleLeaf for U64 {
    type Value = u64;
    const SLOTS: usize = 1;

    fn strategy() -> BoxedStrategy<u64> {
        prop_oneof![Just(0u64), Just(1u64), Just(u64::MAX), any::<u64>()].boxed()
    }

    fn limbs(v: &u64) -> Vec<Fr> {
        vec![Fr::from(*v)]
    }

    fn wire(args: &[Wire3<FieldT, Private>]) -> Uint<64, Private> {
        Uint::<64, Private>::from_field_unchecked(args[0])
    }
}

/// `uint256` carried by a `Uint<128>` — the vault's own amount width. The
/// `u64::MAX`/`u64::MAX + 1` step is where a 64-bit truncation would show.
impl SampleLeaf for U128 {
    type Value = u128;
    const SLOTS: usize = 1;

    fn strategy() -> BoxedStrategy<u128> {
        prop_oneof![
            Just(0u128),
            Just(1u128),
            Just(u128::from(u64::MAX)),
            Just(u128::from(u64::MAX) + 1),
            Just(u128::MAX),
            any::<u128>(),
        ]
        .boxed()
    }

    fn limbs(v: &u128) -> Vec<Fr> {
        vec![u128_limb(*v)]
    }

    fn wire(args: &[Wire3<FieldT, Private>]) -> Uint<128, Private> {
        Uint::<128, Private>::from_field_unchecked(args[0])
    }
}

/// `uint160` — an ALREADY-ENCODED word, so the value is the 160-bit number's
/// twenty big-endian bytes and the wire is the left-padded word built from
/// them. Sampling only in-range is the point: `uint160` is what the ABI says
/// the field holds.
impl SampleLeaf for OurU160 {
    type Value = [u8; 20];
    const SLOTS: usize = 2;

    fn strategy() -> BoxedStrategy<[u8; 20]> {
        prop_oneof![Just([0u8; 20]), Just([0xff; 20]), any::<[u8; 20]>()].boxed()
    }

    fn limbs(v: &[u8; 20]) -> Vec<Fr> {
        let (hi, lo) = b32_slots(&left_pad(v));
        vec![hi, lo]
    }

    fn wire(args: &[Wire3<FieldT, Private>]) -> B32<Private> {
        B32 {
            hi: args[0],
            lo: args[1],
        }
    }
}

/// `uint256` at full width — an already-encoded word, so the value is the
/// thirty-two bytes. The unlimited allowance (`0xff..ff`) has its own arm.
impl SampleLeaf for OurU256 {
    type Value = [u8; 32];
    const SLOTS: usize = 2;

    fn strategy() -> BoxedStrategy<[u8; 32]> {
        prop_oneof![
            Just([0u8; 32]),
            Just([0xff; 32]),
            Just(unlimited_allowance()),
            any::<[u8; 32]>(),
        ]
        .boxed()
    }

    fn limbs(v: &[u8; 32]) -> Vec<Fr> {
        let (hi, lo) = b32_slots(v);
        vec![hi, lo]
    }

    fn wire(args: &[Wire3<FieldT, Private>]) -> B32<Private> {
        B32 {
            hi: args[0],
            lo: args[1],
        }
    }
}

/// Twenty big-endian bytes left-padded into a 32-byte word.
fn left_pad(v: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(v);
    w
}

/// The vault's constant approval word: `2^128 - 1`.
fn unlimited_allowance() -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&[0xff; 16]);
    w
}

// ---- the harness: an argument list's host-side sample -------------------------

/// The same four facts for a whole [`AbiTuple`], element by element. The
/// impls are a `macro_rules!` over the arities, like `AbiTuple`'s own.
trait SampleArgs: AbiTuple {
    /// One [`SampleLeaf::Value`] per element, in argument order.
    type Values: std::fmt::Debug + Clone;

    fn strategy() -> BoxedStrategy<Self::Values>;

    /// Every element's limbs, concatenated — the circuit's argument list.
    fn limbs(v: &Self::Values) -> Vec<Fr>;

    /// The wires, rebuilt from that argument list.
    fn wires(args: &[Wire3<FieldT, Private>]) -> Self::Wires<Private>;
}

/// THE EMPTY ARGUMENT LIST — WETH's `deposit()`, whose only argument is the
/// ether in the transaction's `value` field and whose calldata is therefore
/// four selector bytes and nothing else.
///
/// Worth having as a row rather than assuming: `abi_encode()` on a
/// no-argument call is exactly the selector, and this is the one case where
/// our word count and alloy's could disagree by being empty for different
/// reasons.
impl SampleArgs for () {
    type Values = ();

    fn strategy() -> BoxedStrategy<()> {
        Just(()).boxed()
    }

    fn limbs(_v: &()) -> Vec<Fr> {
        Vec::new()
    }

    fn wires(_args: &[Wire3<FieldT, Private>]) {}
}

macro_rules! sample_args {
    ($($t:ident => $idx:tt),+) => {
        impl<$($t: SampleLeaf),+> SampleArgs for ($($t,)+) {
            type Values = ($(<$t as SampleLeaf>::Value,)+);

            fn strategy() -> BoxedStrategy<Self::Values> {
                ($(<$t as SampleLeaf>::strategy(),)+).boxed()
            }

            fn limbs(v: &Self::Values) -> Vec<Fr> {
                let mut out = Vec::new();
                $(out.extend(<$t as SampleLeaf>::limbs(&v.$idx));)+
                out
            }

            #[allow(unused_assignments, reason = "the last element still advances `at`")]
            fn wires(args: &[Wire3<FieldT, Private>]) -> Self::Wires<Private> {
                // Left to right, which is argument order: a tuple
                // expression evaluates its operands in order, so `at`
                // walks the limb list exactly as `limbs` laid it out.
                let mut at = 0usize;
                ($({
                    let n = <$t as SampleLeaf>::SLOTS;
                    let w = <$t as SampleLeaf>::wire(&args[at..at + n]);
                    at += n;
                    w
                },)+)
            }
        }
    };
}

sample_args!(A => 0);
sample_args!(A => 0, B => 1);
sample_args!(A => 0, B => 1, C => 2);
sample_args!(A => 0, B => 1, C => 2, D => 3);
sample_args!(A => 0, B => 1, C => 2, D => 3, E => 4);
sample_args!(A => 0, B => 1, C => 2, D => 3, E => 4, F => 5);
sample_args!(A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6);
sample_args!(A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7);

// ---- the harness: running our encoder ----------------------------------------

fn preimage(inputs: &[Fr]) -> ProofPreimage {
    ProofPreimage {
        inputs: inputs.to_vec(),
        private_transcript: Vec::new(),
        public_transcript_inputs: Vec::new(),
        public_transcript_outputs: Vec::new(),
        binding_input: 0.into(),
        communications_commitment: None,
        key_location: KeyLocation(Cow::Borrowed("minocrab-evm-alloy-oracle")),
    }
}

/// A simulated `B32`'s `(hi, lo)` slot pair read back as the THIRTY-TWO
/// BYTES of the ABI word.
///
/// `B32` stores byte 31 in `hi` and bytes 0..31 as `lo`'s little-endian
/// limb (`vault::prims::b32_slots` is the forward direction, and the vault
/// differential pins it against compactc). The final line re-derives the
/// pair from the bytes and asserts it matches, so a bug in THIS reader
/// cannot hide a bug in the encoder it is reading.
fn word_bytes(hi: Fr, lo: Fr) -> [u8; 32] {
    let mut out = [0u8; 32];

    let mut lo_le = lo.as_le_bytes();
    lo_le.resize(32, 0);
    assert!(
        lo_le[31..].iter().all(|b| *b == 0),
        "the low limb of a B32 holds 31 bytes, got {lo_le:?}"
    );
    out[..31].copy_from_slice(&lo_le[..31]);

    let mut hi_le = hi.as_le_bytes();
    hi_le.resize(32, 0);
    assert!(
        hi_le[1..].iter().all(|b| *b == 0),
        "the high limb of a B32 is one byte, got {hi_le:?}"
    );
    out[31] = hi_le[0];

    assert_eq!(b32_slots(&out), (hi, lo), "the word reader is not b32_slots");
    out
}

/// OUR words for `C`'s arguments: the sample values as circuit arguments,
/// `AbiTuple::words` over the rebuilt wires, run under the simulator, each
/// word read back as bytes.
fn our_words<C: EvmCall>(values: &<C::Args as SampleArgs>::Values) -> Vec<[u8; 32]>
where
    C::Args: SampleArgs,
{
    let limbs = <C::Args as SampleArgs>::limbs(values);

    let mut c = Circuit3::new();
    let args: Vec<Wire3<FieldT, Private>> = (0..limbs.len())
        .map(|i| c.arg::<FieldT>(&format!("a{i}")))
        .collect();
    let wires = <C::Args as SampleArgs>::wires(&args);
    let words = <C::Args as AbiTuple>::words(&mut c, wires);
    let count = words.len();
    assert_eq!(
        count,
        <C::Args as AbiTuple>::WORDS,
        "the encoder produced a different number of words than the tuple declares"
    );
    for (i, w) in words.into_iter().enumerate() {
        let hi = c.disclose(w.hi, "hi");
        let lo = c.disclose(w.lo, "lo");
        c.output(hi, &format!("w{i}.hi"));
        c.output(lo, &format!("w{i}.lo"));
    }
    let compiled = c.finish(false);
    let run = simulate(&compiled.ir, &preimage(&limbs)).expect("the encoders accept the sample");

    let native = |i: usize| match &run.outputs[i] {
        IrValue::Native(f) => *f,
        other => panic!("output {i} is not native: {other:?}"),
    };
    (0..count)
        .map(|i| word_bytes(native(2 * i), native(2 * i + 1)))
        .collect()
}

/// `encoded` is `solCall::abi_encode()` — four selector bytes then the
/// static words. Split it.
fn alloy_words(encoded: &[u8]) -> Vec<[u8; 32]> {
    let tail = &encoded[4..];
    assert_eq!(tail.len() % 32, 0, "a static encoding is whole words");
    // `chunks`, not `chunks_exact`: clippy now asks for `as_chunks`, which is
    // Rust 1.88, past the workspace's 1.85 floor; the assert above makes
    // every chunk a whole word either way.
    tail.chunks(32)
        .map(|w| <[u8; 32]>::try_from(w).expect("a whole word"))
        .collect()
}

/// THE SIGNATURE AND THE SELECTOR, ours against alloy's.
fn pin_signature<C: EvmCall, S: SolCall>() {
    assert_eq!(
        C::signature(),
        S::SIGNATURE,
        "our selector signature is not the one alloy hashes"
    );
    assert_eq!(
        C::selector(),
        S::SELECTOR,
        "our selector is not alloy's for {}",
        S::SIGNATURE
    );
}

/// THE WORDS, ours against alloy's, one 32-byte word at a time so a failure
/// names the argument that disagrees.
fn oracle<C: EvmCall>(values: &<C::Args as SampleArgs>::Values, encoded: &[u8])
where
    C::Args: SampleArgs,
{
    assert_eq!(
        &encoded[..4],
        &C::selector()[..],
        "alloy's calldata does not start with our selector"
    );

    let ours = our_words::<C>(values);
    let theirs = alloy_words(encoded);
    assert_eq!(
        ours.len(),
        theirs.len(),
        "word count: ours {} vs alloy {} for {}",
        ours.len(),
        theirs.len(),
        C::signature()
    );
    for (i, (a, b)) in ours.iter().zip(theirs.iter()).enumerate() {
        assert_eq!(
            a,
            b,
            "{}: word {i} disagrees with alloy\n  ours  0x{}\n  alloy 0x{}\n  values {values:?}",
            C::signature(),
            hex(a),
            hex(b),
        );
    }
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---- the rows ----------------------------------------------------------------

/// One row per call: our type, alloy's type, and how the sampled values
/// build alloy's call struct. Everything else is the harness above.
macro_rules! oracle_rows {
    ($(
        $(#[$attr:meta])*
        $name:ident : $call:ty => $sol:ty,
        |$pat:pat_param| $build:expr;
    )*) => { $(
        $(#[$attr])*
        mod $name {
            use super::*;

            /// The signature string and the four selector bytes.
            #[test]
            fn signature_and_selector() {
                pin_signature::<$call, $sol>();
            }

            proptest! {
                #![proptest_config(config())]

                /// Every ABI word, on generated argument values.
                #[test]
                fn words(values in <<$call as EvmCall>::Args as SampleArgs>::strategy()) {
                    let $pat = values.clone();
                    let sol: $sol = $build;
                    oracle::<$call>(&values, &sol.abi_encode());
                }
            }
        }
    )* };
}

oracle_rows! {
    /// `transfer(address,uint256)` — a9059cbb.
    transfer: erc20::Transfer => sol_erc20::transferCall,
    |(to, amount)| sol_erc20::transferCall {
        to: SolAddress::from(to),
        amount: SolU256::from(amount),
    };

    /// `approve(address,uint256)` — 095ea7b3. The allowance is an
    /// already-encoded word on our side, so alloy reads it back from bytes.
    approve: erc20::Approve => sol_erc20::approveCall,
    |(spender, allowance)| sol_erc20::approveCall {
        spender: SolAddress::from(spender),
        amount: SolU256::from_be_bytes(allowance),
    };

    /// `deposit(uint256,address)` — 6e553f65.
    deposit: erc4626::Deposit => sol_erc4626::depositCall,
    |(assets, receiver)| sol_erc4626::depositCall {
        assets: SolU256::from(assets),
        receiver: SolAddress::from(receiver),
    };

    /// `redeem(uint256,address,address)` — ba087652.
    redeem: erc4626::Redeem => sol_erc4626::redeemCall,
    |(shares, receiver, owner)| sol_erc4626::redeemCall {
        shares: SolU256::from(shares),
        receiver: SolAddress::from(receiver),
        owner: SolAddress::from(owner),
    };

    /// `exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))`
    /// — 5023b4df. THE NESTED TUPLE: alloy renders the struct argument, and
    /// its seven fields encode as seven flat words exactly as our flat
    /// argument tuple does.
    exact_output_single: uniswap_v3::ExactOutputSingle => sol_uniswap_v3::exactOutputSingleCall,
    |(token_in, token_out, fee, recipient, amount_out, amount_in_max, price)|
        sol_uniswap_v3::exactOutputSingleCall {
            params: sol_uniswap_v3::ExactOutputSingleParams {
                tokenIn: SolAddress::from(token_in),
                tokenOut: SolAddress::from(token_out),
                fee: U24::from(fee),
                recipient: SolAddress::from(recipient),
                amountOut: SolU256::from(amount_out),
                amountInMaximum: SolU256::from(amount_in_max),
                sqrtPriceLimitX96: U160::from_be_slice(&price),
            },
        };

    /// `transferFrom(address,address,uint256)` — 23b872dd.
    transfer_from: erc20::TransferFrom => sol_erc20::transferFromCall,
    |(from, to, amount)| sol_erc20::transferFromCall {
        from: SolAddress::from(from),
        to: SolAddress::from(to),
        amount: SolU256::from(amount),
    };

    /// `increaseAllowance(address,uint256)` — 39509351. OpenZeppelin's, not
    /// EIP-20's; alloy does not care whose it is, it hashes the signature.
    increase_allowance: erc20::IncreaseAllowance => sol_erc20::increaseAllowanceCall,
    |(spender, added)| sol_erc20::increaseAllowanceCall {
        spender: SolAddress::from(spender),
        addedValue: SolU256::from(added),
    };

    /// `decreaseAllowance(address,uint256)` — a457c2d7.
    decrease_allowance: erc20::DecreaseAllowance => sol_erc20::decreaseAllowanceCall,
    |(spender, subtracted)| sol_erc20::decreaseAllowanceCall {
        spender: SolAddress::from(spender),
        subtractedValue: SolU256::from(subtracted),
    };

    /// ERC-2612 `permit(address,address,uint256,uint256,uint8,bytes32,bytes32)`
    /// — d505accf. SEVEN static words and the library's only `uint8`: if our
    /// `U8` spelled itself `uint256` the selector would be something else
    /// entirely, and this row is where that shows.
    permit: erc20::Permit => sol_erc20::permitCall,
    |(owner, spender, value, deadline, v, r, s)| sol_erc20::permitCall {
        owner: SolAddress::from(owner),
        spender: SolAddress::from(spender),
        value: SolU256::from_be_bytes(value),
        deadline: SolU256::from_be_bytes(deadline),
        v,
        r: FixedBytes::<32>::from(r),
        s: FixedBytes::<32>::from(s),
    };

    /// `deposit()` — d0e30db0. THE ZERO-ARGUMENT ROW: alloy's `abi_encode()`
    /// is four bytes, our word list is empty, and the two agree on nothing
    /// being there. (The ether it carries is the transaction's `value`
    /// field, which is not calldata and so not alloy's business.)
    weth_deposit: weth::Deposit => sol_weth::depositCall,
    |()| sol_weth::depositCall {};

    /// `withdraw(uint256)` — 2e1a7d4d.
    weth_withdraw: weth::Withdraw => sol_weth::withdrawCall,
    |(wad,)| sol_weth::withdrawCall {
        wad: SolU256::from(wad),
    };

    /// USDT's `transfer(address,uint256)` — a9059cbb, the ERC-20 selector.
    /// The calldata is byte-identical to `transfer` above; only the declared
    /// RETURN differs, and a signature does not carry one.
    usdt_transfer: usdt::Transfer => sol_usdt::transferCall,
    |(to, amount)| sol_usdt::transferCall {
        to: SolAddress::from(to),
        amount: SolU256::from(amount),
    };

    /// USDT's `approve(address,uint256)` — 095ea7b3.
    usdt_approve: usdt::Approve => sol_usdt::approveCall,
    |(spender, allowance)| sol_usdt::approveCall {
        spender: SolAddress::from(spender),
        amount: SolU256::from_be_bytes(allowance),
    };

    /// USDT's `transferFrom(address,address,uint256)` — 23b872dd.
    usdt_transfer_from: usdt::TransferFrom => sol_usdt::transferFromCall,
    |(from, to, amount)| sol_usdt::transferFromCall {
        from: SolAddress::from(from),
        to: SolAddress::from(to),
        amount: SolU256::from(amount),
    };

    /// `mint(uint256,address)` — 94bf804d. [`deposit`](deposit)'s
    /// exact-output twin: the same two argument TYPES in the same order, a
    /// different name, and therefore a different function.
    erc4626_mint: erc4626::Mint => sol_erc4626::mintCall,
    |(shares, receiver)| sol_erc4626::mintCall {
        shares: SolU256::from(shares),
        receiver: SolAddress::from(receiver),
    };

    /// `withdraw(uint256,address,address)` — b460af94. Its argument types
    /// are [`redeem`](redeem)'s exactly, which is the case a selector is
    /// there to separate: only the NAME differs, and the four bytes do.
    erc4626_withdraw: erc4626::Withdraw => sol_erc4626::withdrawCall,
    |(assets, receiver, owner)| sol_erc4626::withdrawCall {
        assets: SolU256::from(assets),
        receiver: SolAddress::from(receiver),
        owner: SolAddress::from(owner),
    };

    /// `exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))`
    /// — 04e45aaf. `SwapRouter02`'s seven-field struct, the mirror of
    /// [`exact_output_single`](exact_output_single): the same seven words in
    /// the same order, with the two amount fields meaning the other thing.
    /// The eight-field original-router form is `414bf389` and is pinned as a
    /// negative control in
    /// [`the_router_shape_is_the_one_we_declare`].
    exact_input_single: uniswap_v3::ExactInputSingle => sol_uniswap_v3::exactInputSingleCall,
    |(token_in, token_out, fee, recipient, amount_in, amount_out_min, price)|
        sol_uniswap_v3::exactInputSingleCall {
            params: sol_uniswap_v3::ExactInputSingleParams {
                tokenIn: SolAddress::from(token_in),
                tokenOut: SolAddress::from(token_out),
                fee: U24::from(fee),
                recipient: SolAddress::from(recipient),
                amountIn: SolU256::from(amount_in),
                amountOutMinimum: SolU256::from(amount_out_min),
                sqrtPriceLimitX96: U160::from_be_slice(&price),
            },
        };

    /// Aave v3 `supply(address,uint256,address,uint16)` — 617ba037, and the
    /// library's only `uint16`: spell `referralCode` as a `uint256` and the
    /// selector is a different function entirely, which is what this row
    /// stops.
    aave_supply: aave_v3::Supply => sol_aave_v3::supplyCall,
    |(asset, amount, on_behalf_of, referral)| sol_aave_v3::supplyCall {
        asset: SolAddress::from(asset),
        amount: SolU256::from(amount),
        onBehalfOf: SolAddress::from(on_behalf_of),
        referralCode: referral,
    };

    /// Aave v3 `supplyWithPermit(address,uint256,address,uint16,uint256,
    /// uint8,bytes32,bytes32)` — [`Supply`](aave_v3::Supply) and
    /// [`Permit`](erc20::Permit) folded into one call (M38 rung H,
    /// notes/evm-interfaces.org §10). EIGHT static words — the maximum
    /// arity this library's `AbiTuple` implements — and FLAT, not the
    /// nested `(uint8,bytes32,bytes32)` struct rung C's own doc guessed:
    /// `IPool.sol` declares eight plain parameters, which is what
    /// `sol_aave_v3::supplyWithPermitCall` above also declares, so a wrong
    /// guess here would show as a selector disagreement.
    aave_supply_with_permit: aave_v3::SupplyWithPermit => sol_aave_v3::supplyWithPermitCall,
    |(asset, amount, on_behalf_of, referral, deadline, v, r, s)| sol_aave_v3::supplyWithPermitCall {
        asset: SolAddress::from(asset),
        amount: SolU256::from(amount),
        onBehalfOf: SolAddress::from(on_behalf_of),
        referralCode: referral,
        deadline: SolU256::from_be_bytes(deadline),
        permitV: v,
        permitR: FixedBytes::<32>::from(r),
        permitS: FixedBytes::<32>::from(s),
    };

    /// Aave v3 `withdraw(address,uint256,address)` — 69328dec. Note the
    /// SAME NAME as [`erc4626_withdraw`](erc4626_withdraw) with a different
    /// argument list: two interfaces, two selectors, and the callee marker
    /// is what keeps them apart on our side.
    aave_withdraw: aave_v3::Withdraw => sol_aave_v3::withdrawCall,
    |(asset, amount, to)| sol_aave_v3::withdrawCall {
        asset: SolAddress::from(asset),
        amount: SolU256::from(amount),
        to: SolAddress::from(to),
    };

    /// Aave v3 `borrow(address,uint256,uint256,uint16,address)` — a415bcad.
    /// FIVE words, and the one call whose `uint16` sits in the MIDDLE of the
    /// list rather than at the end — a word-order bug here is invisible to
    /// the selector and shows only in the word comparison.
    aave_borrow: aave_v3::Borrow => sol_aave_v3::borrowCall,
    |(asset, amount, mode, referral, on_behalf_of)| sol_aave_v3::borrowCall {
        asset: SolAddress::from(asset),
        amount: SolU256::from(amount),
        interestRateMode: SolU256::from(mode),
        referralCode: referral,
        onBehalfOf: SolAddress::from(on_behalf_of),
    };

    /// Aave v3 `repay(address,uint256,uint256,address)` — 573ade81. No
    /// `referralCode`: paying a debt down refers nobody, and dropping the
    /// argument is why this is not `borrow`'s shape minus a word.
    aave_repay: aave_v3::Repay => sol_aave_v3::repayCall,
    |(asset, amount, mode, on_behalf_of)| sol_aave_v3::repayCall {
        asset: SolAddress::from(asset),
        amount: SolU256::from(amount),
        interestRateMode: SolU256::from(mode),
        onBehalfOf: SolAddress::from(on_behalf_of),
    };

    /// ERC-721 `transferFrom(address,address,uint256)` — 23b872dd, THE
    /// ERC-20 SELECTOR. The calldata is byte-identical to
    /// [`transfer_from`](transfer_from)'s; the two differ only in the
    /// declared return, which a signature does not carry — and alloy saying
    /// so is the point of the row.
    erc721_transfer_from: erc721::TransferFrom => sol_erc721::transferFromCall,
    |(from, to, token_id)| sol_erc721::transferFromCall {
        from: SolAddress::from(from),
        to: SolAddress::from(to),
        tokenId: SolU256::from_be_bytes(token_id),
    };

    /// ERC-721 `approve(address,uint256)` — 095ea7b3, the ERC-20 selector
    /// again, for [`erc721_transfer_from`](erc721_transfer_from)'s reason.
    erc721_approve: erc721::Approve => sol_erc721::approveCall,
    |(to, token_id)| sol_erc721::approveCall {
        to: SolAddress::from(to),
        tokenId: SolU256::from_be_bytes(token_id),
    };

    /// ERC-721 `setApprovalForAll(address,bool)` — a22cb465. The one shipped
    /// call that passes a `bool` as an ARGUMENT (every other `bool` in the
    /// library is a return), so this row retires half of what
    /// [`all_leaves`](all_leaves)'s synthetic probe was standing in for.
    erc721_set_approval_for_all: erc721::SetApprovalForAll
        => sol_erc721::setApprovalForAllCall,
    |(operator, approved)| sol_erc721::setApprovalForAllCall {
        operator: SolAddress::from(operator),
        approved,
    };

    /// ALL EIGHT LEAVES AT ONCE — including the `bool` and the `bytes32`
    /// that no shipped call passes as an argument.
    all_leaves: AbiLeafProbe => sol_probe::abiLeafProbeCall,
    |(who, flag, tag, fee, small, wide, price, raw)| sol_probe::abiLeafProbeCall {
        who: SolAddress::from(who),
        flag,
        tag: FixedBytes::<32>::from(tag),
        fee: U24::from(fee),
        small: SolU256::from(small),
        wide: SolU256::from(wide),
        price: U160::from_be_slice(&price),
        raw: SolU256::from_be_bytes(raw),
    };
}

// ---- the controls ------------------------------------------------------------

/// THE ORACLE CAN FAIL. A deliberately wrong Solidity declaration —
/// `transfer(address,uint128)`, the same name and arity with one type
/// changed — hashes to a different selector, so an agreement above is a
/// fact about the encodings rather than about the test always passing.
///
/// It is also the argument for spelling `U64`/`U128` as `uint256` in every
/// row: a `uintN` that is our RANGE rather than Ethereum's width would move
/// the selector, and this is what that looks like.
#[test]
fn the_oracle_can_fail() {
    assert_eq!(
        sol_wrong::transferCall::SIGNATURE,
        "transfer(address,uint128)"
    );
    assert_ne!(
        erc20::Transfer::selector(),
        sol_wrong::transferCall::SELECTOR,
        "the wrong Solidity type produced the same selector"
    );
    assert_ne!(
        erc20::Transfer::signature(),
        sol_wrong::transferCall::SIGNATURE
    );
}

/// AND THE WORD COMPARISON CAN FAIL. The selector control above says nothing
/// about [`oracle`]'s word loop — a harness that compared an empty list to an
/// empty list would pass that one too. So: `deposit(uint256,address)` with
/// its two arguments TRANSPOSED disagrees with our words, and the same two
/// values in the right order still agree.
///
/// Argument ORDER is the right thing to perturb. It is the ABI mistake a
/// flat reading of a call makes ("deposit into an account" puts the account
/// first), it is INVISIBLE to the selector — `deposit(uint256,address)` is
/// that signature however the caller fills it — and it is exactly what
/// `EvmCall::Args` being an ORDERED tuple claims.
#[test]
fn the_word_comparison_can_fail() {
    let assets = 42u128;
    let receiver = [0x44u8; 20];
    let ours = our_words::<erc4626::Deposit>(&(assets, receiver));

    // The right order: our two words ARE alloy's — the positive twin, so
    // the inequality below is the transposition and not a broken harness.
    let right = sol_erc4626::depositCall {
        assets: SolU256::from(assets),
        receiver: SolAddress::from(receiver),
    }
    .abi_encode();
    assert_eq!(ours, alloy_words(&right));

    // The same two values transposed: the receiver's twenty bytes read as
    // the amount, the amount read as an address.
    let mut amount_as_address = [0u8; 20];
    amount_as_address[4..].copy_from_slice(&assets.to_be_bytes());
    let wrong = sol_erc4626::depositCall {
        assets: SolU256::from_be_bytes(left_pad(&receiver)),
        receiver: SolAddress::from(amount_as_address),
    }
    .abi_encode();
    assert_ne!(
        ours,
        alloy_words(&wrong),
        "the word comparison does not see argument order"
    );
}

/// THE ROUTER GENERATION IS PINNED, and alloy is what pins it. Our
/// [`uniswap_v3::ExactOutputSingle`] and [`uniswap_v3::ExactInputSingle`]
/// are `SwapRouter02`'s seven-field shapes (`5023b4df` and `04e45aaf`); the
/// original `SwapRouter`'s params structs have a `deadline` between
/// `recipient` and the amounts, and those eight-field shapes are different
/// functions (`db3e2198` and `414bf389`) that our seven words would not
/// fill.
///
/// This is the negative control that matters for the two calls whose
/// `signature()` we override: the extra parentheses are pinned by
/// `tests/evm_abi.rs`, and the FIELD LIST is pinned here. It is a live
/// hazard rather than a contrived one — `414bf389` is the selector most of
/// the Uniswap documentation on the internet shows.
#[test]
fn the_router_shape_is_the_one_we_declare() {
    assert_eq!(
        sol_wrong::exactOutputSingleCall::SIGNATURE,
        "exactOutputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))"
    );
    assert_eq!(
        sol_wrong::exactOutputSingleCall::SELECTOR,
        [0xdb, 0x3e, 0x21, 0x98],
        "the deadline-bearing SwapRouter selector"
    );
    assert_ne!(
        uniswap_v3::ExactOutputSingle::selector(),
        sol_wrong::exactOutputSingleCall::SELECTOR,
        "our call type hashes to the deadline-bearing router's selector"
    );
    assert_eq!(
        uniswap_v3::ExactOutputSingle::selector(),
        [0x50, 0x23, 0xb4, 0xdf],
        "SwapRouter02's exactOutputSingle"
    );

    // The same, for the input side (M38 rung C).
    assert_eq!(
        sol_wrong::exactInputSingleCall::SIGNATURE,
        "exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))"
    );
    assert_eq!(
        sol_wrong::exactInputSingleCall::SELECTOR,
        [0x41, 0x4b, 0xf3, 0x89],
        "the deadline-bearing SwapRouter selector"
    );
    assert_ne!(
        uniswap_v3::ExactInputSingle::selector(),
        sol_wrong::exactInputSingleCall::SELECTOR,
        "our call type hashes to the deadline-bearing router's selector"
    );
    assert_eq!(
        uniswap_v3::ExactInputSingle::selector(),
        [0x04, 0xe4, 0x5a, 0xaf],
        "SwapRouter02's exactInputSingle"
    );

    // The two directions are DIFFERENT FUNCTIONS with identical argument
    // types — the case where only the name separates them.
    assert_ne!(
        uniswap_v3::ExactInputSingle::selector(),
        uniswap_v3::ExactOutputSingle::selector()
    );
}

/// THE NON-CONFORMING TOKENS HASH TO ERC-20's SELECTORS, and alloy is what
/// says so: a Solidity signature does not carry the return type, so
/// `transfer(address,uint256)` is `a9059cbb` whether it returns a `bool` or
/// nothing at all.
///
/// That is the fact [`UsdtLike`](usdt::UsdtLike) is built around. The wire
/// cannot tell the two apart, so the TYPE has to — and this test is the
/// evidence that the calldata really is identical, which is what makes
/// declaring a USDT address as an `Erc20` a silent hazard rather than a
/// loud one (notes/evm-calls.org §3.1).
#[test]
fn usdt_selectors_are_the_erc20_ones() {
    assert_eq!(usdt::Transfer::selector(), erc20::Transfer::selector());
    assert_eq!(usdt::Approve::selector(), erc20::Approve::selector());
    assert_eq!(
        usdt::TransferFrom::selector(),
        erc20::TransferFrom::selector()
    );

    // …and alloy agrees, from its own two declarations.
    assert_eq!(
        sol_usdt::transferCall::SELECTOR,
        sol_erc20::transferCall::SELECTOR
    );
    assert_eq!(
        sol_usdt::approveCall::SELECTOR,
        sol_erc20::approveCall::SELECTOR
    );
    assert_eq!(
        sol_usdt::transferFromCall::SELECTOR,
        sol_erc20::transferFromCall::SELECTOR
    );
}

/// AND SO DO TWO OF ERC-721's (M38 rung C) — the same fact, on a standard
/// nobody thinks of as a token variant.
///
/// `transferFrom(address,address,uint256)` and `approve(address,uint256)`
/// are ERC-20's signatures exactly, so an NFT and a fungible token file
/// byte-identical calldata for functions that return different things. The
/// callee's INTERFACE is what distinguishes them
/// ([`erc721`](minocrab_contracts::evm::erc721)'s module docs carry the
/// compile_fail gates for both directions); nothing on the wire does, and
/// this test is why we can say that rather than hope it.
///
/// `setApprovalForAll` is the counter-example in the same file: a name
/// ERC-20 does not have, and therefore four bytes of its own.
#[test]
fn erc721_selectors_are_the_erc20_ones() {
    assert_eq!(
        erc721::TransferFrom::selector(),
        erc20::TransferFrom::selector()
    );
    assert_eq!(erc721::Approve::selector(), erc20::Approve::selector());
    assert_ne!(
        erc721::SetApprovalForAll::selector(),
        erc721::Approve::selector()
    );

    assert_eq!(
        sol_erc721::transferFromCall::SELECTOR,
        sol_erc20::transferFromCall::SELECTOR
    );
    assert_eq!(
        sol_erc721::approveCall::SELECTOR,
        sol_erc20::approveCall::SELECTOR
    );
    assert_eq!(
        sol_erc721::setApprovalForAllCall::SELECTOR,
        [0xa2, 0x2c, 0xb4, 0x65]
    );
}

/// BOTH BOOL VALUES, without waiting on the sampler: `false` encodes to the
/// zero word and `true` to a word whose last byte is 1, and alloy says so.
#[test]
fn bool_covers_both_values() {
    for flag in [false, true] {
        let values = (
            [0x11u8; 20],
            flag,
            [0x22u8; 32],
            3_000u32,
            7u64,
            9u128,
            [0x33u8; 20],
            [0x44u8; 32],
        );
        let sol = sol_probe::abiLeafProbeCall {
            who: SolAddress::from(values.0),
            flag,
            tag: FixedBytes::<32>::from(values.2),
            fee: U24::from(values.3),
            small: SolU256::from(values.4),
            wide: SolU256::from(values.5),
            price: U160::from_be_slice(&values.6),
            raw: SolU256::from_be_bytes(values.7),
        };
        oracle::<AbiLeafProbe>(&values, &sol.abi_encode());

        // …and the bool word itself is the one everyone can read off.
        let mut expected = [0u8; 32];
        expected[31] = u8::from(flag);
        assert_eq!(our_words::<AbiLeafProbe>(&values)[1], expected);
    }
}

/// THE NARROW TYPES AT THEIR BOUNDS, deterministically: the largest value
/// each leaf's Rust type can hold still encodes to alloy's word. The
/// proptest rows sample these too (each strategy has an arm for them); this
/// is the version that runs even at `PROPTEST_CASES=1`.
#[test]
fn every_leaf_at_its_upper_bound() {
    let values = (
        [0xffu8; 20],
        true,
        [0xffu8; 32],
        (1u32 << 24) - 1,
        u64::MAX,
        u128::MAX,
        [0xffu8; 20],
        [0xffu8; 32],
    );
    let sol = sol_probe::abiLeafProbeCall {
        who: SolAddress::from(values.0),
        flag: values.1,
        tag: FixedBytes::<32>::from(values.2),
        fee: U24::from(values.3),
        small: SolU256::from(values.4),
        wide: SolU256::from(values.5),
        price: U160::from_be_slice(&values.6),
        raw: SolU256::from_be_bytes(values.7),
    };
    oracle::<AbiLeafProbe>(&values, &sol.abi_encode());
}

/// THE PROBE IS EVERY LEAF, in the order its `sol!` twin declares them —
/// the one fact about the synthetic call worth pinning, since a leaf
/// dropped from its tuple would silently stop being checked at all.
#[test]
fn the_probe_is_every_leaf() {
    assert_eq!(
        AbiLeafProbe::signature(),
        "abiLeafProbe(address,bool,bytes32,uint24,uint256,uint256,uint160,uint256)"
    );
    assert_eq!(<<AbiLeafProbe as EvmCall>::Args as AbiTuple>::WORDS, 8);
}
