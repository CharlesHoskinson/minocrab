//! ONE SLOT PER INTERFACE RUNG C ADDS — an ERC-4626 `mint`, a
//! `SwapRouter02` `exactInputSingle`, an Aave v3 `supply` and an ERC-721
//! `setApprovalForAll`, each filed against a `Contract<I>` of its own
//! interface and each settled by both tickets (M38 rung C,
//! notes/evm-interfaces.org §6) — plus rung H's Aave `supplyWithPermit`,
//! the EIGHT-WORD slot at the library's maximum arity
//! (notes/evm-interfaces.org §10).
//!
//! What the four have between them that no earlier test did:
//!
//! 1. FOUR DIFFERENT CALLEE MARKERS IN ONE BLOCK. Every `request` here
//!    would be a missing `Extends` impl against any of the other three
//!    addresses, and the block still lays out and still settles — the
//!    interface is a type, not a runtime tag (`evm_abi::
//!    the_interface_marker_costs_no_instruction` is the ZKIR half of that).
//! 2. A SEVEN-WORD SLOT. `exactInputSingle`'s nested-tuple argument is the
//!    widest record the library builds, and the `WORDS` inline-const assert
//!    has to agree with `AbiTuple::WORDS` for it.
//! 3. THE `uint16`. Aave's `referralCode` is the first [`U16`] any slot
//!    files, and it enters as a circuit argument rather than a constant so
//!    the encoder is really exercised.
//! 4. THE `bool` AS AN ARGUMENT. `setApprovalForAll(operator, approved)` is
//!    the only shipped call that passes one; every other `bool` in the
//!    library is a return being read.
//!
//! Two return shapes settle side by side: the ERC-4626 mint and the swap
//! attest a narrowed `uint256` (`Success = Uint<64, Private>`), the Aave
//! supply and the ERC-721 approval attest NOTHING (`Return = Unit`, so
//! `outcome.output` is `()`).
//!
//! IT IS A TEST-ONLY CONTRACT, like `tests/evm_no_return.rs`'s: it
//! exercises the API without adding circuits to the crate's frozen
//! snapshots (`tests/support/mod.rs` lists what those cover). Nothing here
//! is a deployment, and none of the addresses, fee tiers or referral codes
//! mean anything.

use minocrab::v3::Circuit3;
use minocrab::{Private, Public};
use minocrab_contracts::evm::{aave_v3, erc4626, erc721, uniswap_v3, Filed};
use minocrab_contracts::evm_flow::{Contract, Failed, Owned, Pending, Succeeded};
use minocrab_contracts::signet_v1::schema;
use minocrab_contracts::signet_flow::{Requested, Settled, Signet};
use minocrab_sim::v3::cost;
use minocrab_std::v3::{
    circuit, label, Bool, Bytes, CircuitArg, Disclose, Discloses, Ledger, LedgerRepr, Uint, B32,
};

// ---- the filings --------------------------------------------------------------

/// `mint(shares, receiver)` on an ERC-4626 vault — a `uint256` of assets.
type MintShares = Filed<erc4626::Mint, schema::Shares>;
/// `exactInputSingle(params)` on `SwapRouter02` — a `uint256` out.
type SwapIn = Filed<uniswap_v3::ExactInputSingle, schema::AmountIn>;
/// `supply(asset, amount, onBehalfOf, referralCode)` on Aave v3's `Pool` —
/// no return at all.
type SupplyToPool = Filed<aave_v3::Supply, schema::NoReturn>;
/// `setApprovalForAll(operator, approved)` on an NFT — no return.
type ApproveOperator = Filed<erc721::SetApprovalForAll, schema::NoReturn>;
/// `supplyWithPermit(asset, amount, onBehalfOf, referralCode, deadline,
/// permitV, permitR, permitS)` on Aave v3's `Pool` — no return.
type SupplyPermitToPool = Filed<aave_v3::SupplyWithPermit, schema::NoReturn>;

/// What a settle needs back.
#[derive(LedgerRepr)]
struct Amount {
    amount: Uint<64, Public>,
}

/// Four Signet fields and five slots, two fields each.
#[derive(Ledger)]
struct Positions {
    signet: Signet,
    mints: Pending<MintShares, Owned<Amount>, 2>,
    swaps: Pending<SwapIn, Amount, 7>,
    supplies: Pending<SupplyToPool, Amount, 4>,
    operators: Pending<ApproveOperator, Amount, 2>,
    supplies_with_permit: Pending<SupplyPermitToPool, Amount, 8>,
}

const POSITIONS: Positions = Positions::new();

label! {
    Shares = "the share count minted";
    AmountIn = "the amount put into the swap";
    Supplied = "the amount supplied to the pool";
    Granted = "whether the operator was granted or revoked";
    Owner = "the minter's refund commitment";
    Recipient = "own public key as refund recipient";
}

// ---- the argument structs -----------------------------------------------------

/// `SwapRouter02`'s `ExactInputSingleParams` minus `sqrtPriceLimitX96`,
/// which this contract fixes at the zero word (the deployed vault does the
/// same for its `exactOutputSingle`). A struct rather than six loose
/// parameters for the reason the vault has one: a swap has more arguments
/// than a circuit signature wants to carry.
#[derive(CircuitArg)]
struct SwapRequest {
    token_in: Bytes<20>,
    token_out: Bytes<20>,
    fee: Uint<24>,
    recipient: Bytes<20>,
    amount_in: Uint<128>,
    amount_out_minimum: Uint<128>,
}

/// Aave's `supply` arguments, `referralCode` included — passed rather than
/// fixed, so the [`U16`](minocrab_contracts::evm::U16) encoder runs on a
/// real wire.
#[derive(CircuitArg)]
struct SupplyRequest {
    asset: Bytes<20>,
    amount: Uint<128>,
    on_behalf_of: Bytes<20>,
    referral_code: Uint<16>,
}

/// [`SupplyRequest`] plus an ERC-2612 permit signature: `deadline` is a
/// [`B32`] because [`U256`](minocrab_contracts::evm::U256)'s wire IS the
/// already-encoded word (the same reason [`SwapRequest`]'s
/// `sqrtPriceLimitX96` needs no encoder), and `permit_r` / `permit_s` are
/// the two `bytes32` halves of the signature the caller relays without
/// computing anything about.
#[derive(CircuitArg)]
struct SupplyWithPermitRequest {
    asset: Bytes<20>,
    amount: Uint<128>,
    on_behalf_of: Bytes<20>,
    referral_code: Uint<16>,
    deadline: B32<Private>,
    permit_v: Uint<8>,
    permit_r: B32<Private>,
    permit_s: B32<Private>,
}

// ---- the circuits -------------------------------------------------------------

/// MINT AN EXACT NUMBER OF SHARES: `vault.mint(shares, receiver)`, whose
/// cost in assets is not known until it runs and comes back as the attested
/// return.
///
/// The callee is a `Contract<Erc4626>` — the same cell would take an
/// `erc20::Approve` (an ERC-4626 vault IS an ERC-20) and would not take
/// anything from [`aave_v3`] or [`erc721`].
#[circuit]
fn mint_shares(
    c: &mut Circuit3,
    evm_nonce: Uint<64>,
    vault: Contract<erc4626::Erc4626>,
    shares: Uint<64>,
    receiver: Bytes<20>,
) -> Discloses<(Shares, Owner, Requested)> {
    let minted = shares.field().disclose_as::<Shares>(c);
    POSITIONS.mints.request_owned::<Owner>(
        c,
        vault,
        (shares.widen::<128>(), receiver),
        evm_nonce,
        |_, _| Amount {
            amount: Uint::from_field_unchecked(minted),
        },
    );
    Discloses::of(())
}

/// SETTLE THE MINT. `erc4626::Mint::succeeded` is `always` — executed is
/// succeeded — so what `complete` checks is the kind, the signature and the
/// record, and the attested `assets` is what the mint COST.
#[circuit]
fn complete_mint(c: &mut Circuit3, ticket: Succeeded<MintShares>) -> Discloses<Settled> {
    let outcome = POSITIONS.mints.complete(c, ticket);
    let _requested = outcome.env.inner.amount;
    // A narrowed `uint256`: the assets the vault pulled.
    let _assets: Uint<64, _> = outcome.output;
    Discloses::of(())
}

/// REFUND THE MINT, through the owner gate: the stored commitment is opened
/// against a freshly witnessed secret before the caller's public key comes
/// back as the recipient.
#[circuit]
fn refund_mint(
    c: &mut Circuit3,
    ticket: Failed<MintShares>,
) -> Discloses<(Settled, Recipient)> {
    let (_owner, env, _assets) = POSITIONS.mints.refund_to_owner::<Recipient>(c, ticket);
    let Amount { amount: _ } = *env;
    Discloses::of(())
}

/// SPEND EXACTLY `amountIn`: `router.exactInputSingle(params)` on
/// `SwapRouter02`, seven words in a nested tuple.
///
/// `sqrtPriceLimitX96` is the zero word — a `U160` wire IS the encoded
/// word, so building it emits no instruction.
#[circuit]
fn swap_in(
    c: &mut Circuit3,
    evm_nonce: Uint<64>,
    router: Contract<uniswap_v3::UniswapV3Router>,
    swap: SwapRequest,
) -> Discloses<(AmountIn, Requested)> {
    let zero = c.constant(0u64).private();
    let spent = swap.amount_in.field().disclose_as::<AmountIn>(c);
    POSITIONS.swaps.request(
        c,
        router,
        (
            swap.token_in,
            swap.token_out,
            swap.fee,
            swap.recipient,
            swap.amount_in,
            swap.amount_out_minimum,
            B32 { hi: zero, lo: zero },
        ),
        evm_nonce,
        |_, _| Amount {
            amount: Uint::from_field_unchecked(spent),
        },
    );
    Discloses::of(())
}

/// SETTLE THE SWAP — the attested `amountOut`, narrowed to `uint64`.
#[circuit]
fn complete_swap(c: &mut Circuit3, ticket: Succeeded<SwapIn>) -> Discloses<Settled> {
    let outcome = POSITIONS.swaps.complete(c, ticket);
    let _amount_out: Uint<64, _> = outcome.output;
    Discloses::of(())
}

/// REFUND THE SWAP — the router reverts on slippage, which reaches us as
/// the MPC's failure kind.
#[circuit]
fn refund_swap(c: &mut Circuit3, ticket: Failed<SwapIn>) -> Discloses<Settled> {
    let _outcome = POSITIONS.swaps.refund(c, ticket);
    Discloses::of(())
}

/// LEND: `pool.supply(asset, amount, onBehalfOf, referralCode)`. The
/// `referralCode` is the library's first `uint16` on the wire, and it is a
/// circuit argument here rather than a constant so the encoder runs.
#[circuit]
fn supply_to_pool(
    c: &mut Circuit3,
    evm_nonce: Uint<64>,
    pool: Contract<aave_v3::AaveV3Pool>,
    supply: SupplyRequest,
) -> Discloses<(Supplied, Requested)> {
    let supplied = supply.amount.field().disclose_as::<Supplied>(c);
    POSITIONS.supplies.request(
        c,
        pool,
        (
            supply.asset,
            supply.amount,
            supply.on_behalf_of,
            supply.referral_code,
        ),
        evm_nonce,
        |_, _| Amount {
            amount: Uint::from_field_unchecked(supplied),
        },
    );
    Discloses::of(())
}

/// SETTLE THE SUPPLY. Aave's `supply` is `void`, so the attested value is
/// `()` and mined IS succeeded — the aTokens minted are the `amount`
/// argument, one for one, and there is nothing for the MPC to decode.
#[circuit]
fn complete_supply(c: &mut Circuit3, ticket: Succeeded<SupplyToPool>) -> Discloses<Settled> {
    let outcome = POSITIONS.supplies.complete(c, ticket);
    let _amount = outcome.env.amount;
    let () = outcome.output;
    Discloses::of(())
}

/// REFUND THE SUPPLY — with `succeeded = always`, the only refundable
/// outcome is the MPC's own failure kind.
#[circuit]
fn refund_supply(c: &mut Circuit3, ticket: Failed<SupplyToPool>) -> Discloses<Settled> {
    let _outcome = POSITIONS.supplies.refund(c, ticket);
    Discloses::of(())
}

/// LEND WITH A PERMIT: `pool.supplyWithPermit(asset, amount, onBehalfOf,
/// referralCode, deadline, permitV, permitR, permitS)` — `aave_v3::Supply` and an
/// ERC-2612 signature in one request, EIGHT words wide (M38 rung H,
/// notes/evm-interfaces.org §10).
#[circuit]
fn supply_with_permit_to_pool(
    c: &mut Circuit3,
    evm_nonce: Uint<64>,
    pool: Contract<aave_v3::AaveV3Pool>,
    supply: SupplyWithPermitRequest,
) -> Discloses<(Supplied, Requested)> {
    let supplied = supply.amount.field().disclose_as::<Supplied>(c);
    POSITIONS.supplies_with_permit.request(
        c,
        pool,
        (
            supply.asset,
            supply.amount,
            supply.on_behalf_of,
            supply.referral_code,
            supply.deadline,
            supply.permit_v,
            supply.permit_r,
            supply.permit_s,
        ),
        evm_nonce,
        |_, _| Amount {
            amount: Uint::from_field_unchecked(supplied),
        },
    );
    Discloses::of(())
}

/// SETTLE THE PERMITTED SUPPLY. Like `aave_v3::Supply`'s, `supplyWithPermit` is
/// `void`, so the attested value is `()` and mined IS succeeded.
#[circuit]
fn complete_supply_with_permit(
    c: &mut Circuit3,
    ticket: Succeeded<SupplyPermitToPool>,
) -> Discloses<Settled> {
    let outcome = POSITIONS.supplies_with_permit.complete(c, ticket);
    let _amount = outcome.env.amount;
    let () = outcome.output;
    Discloses::of(())
}

/// REFUND THE PERMITTED SUPPLY — with `succeeded = always`, the only
/// refundable outcome is the MPC's own failure kind (a bad signature, an
/// expired deadline, or an unhealthy position all revert on-chain).
#[circuit]
fn refund_supply_with_permit(
    c: &mut Circuit3,
    ticket: Failed<SupplyPermitToPool>,
) -> Discloses<Settled> {
    let _outcome = POSITIONS.supplies_with_permit.refund(c, ticket);
    Discloses::of(())
}

/// GRANT (OR REVOKE) AN NFT OPERATOR: `nft.setApprovalForAll(operator,
/// approved)` — a `bool` in ARGUMENT position, on an interface that is not
/// an `Erc20` and will not be handed one.
#[circuit]
fn approve_operator(
    c: &mut Circuit3,
    evm_nonce: Uint<64>,
    nft: Contract<erc721::Erc721>,
    operator: Bytes<20>,
    approved: Bool,
) -> Discloses<(Granted, Requested)> {
    let granted = approved.field().disclose_as::<Granted>(c);
    POSITIONS.operators.request(
        c,
        nft,
        (operator, approved),
        evm_nonce,
        |_, _| Amount {
            amount: Uint::from_field_unchecked(granted),
        },
    );
    Discloses::of(())
}

/// SETTLE THE GRANT. `setApprovalForAll` is `void` — an operator approval
/// that mined IS granted.
#[circuit]
fn complete_operator(c: &mut Circuit3, ticket: Succeeded<ApproveOperator>) -> Discloses<Settled> {
    let outcome = POSITIONS.operators.complete(c, ticket);
    let () = outcome.output;
    Discloses::of(())
}

/// REFUND THE GRANT.
#[circuit]
fn refund_operator(c: &mut Circuit3, ticket: Failed<ApproveOperator>) -> Discloses<Settled> {
    let _outcome = POSITIONS.operators.refund(c, ticket);
    Discloses::of(())
}

// ---- the tests ----------------------------------------------------------------

/// The block's layout: four Signet fields, then two fields per slot,
/// whatever the slot's word count.
#[test]
fn the_block_is_laid_out_by_slot() {
    assert_eq!(POSITIONS.signet.signer.index(), 0);
    assert_eq!(POSITIONS.mints.record_path().as_slice(), &[4]);
    assert_eq!(POSITIONS.swaps.record_path().as_slice(), &[6]);
    assert_eq!(POSITIONS.supplies.record_path().as_slice(), &[8]);
    assert_eq!(POSITIONS.operators.record_path().as_slice(), &[10]);
    assert_eq!(POSITIONS.operators.record_path().depth(), 1);
    assert_eq!(POSITIONS.supplies_with_permit.record_path().as_slice(), &[12]);
    assert_eq!(POSITIONS.supplies_with_permit.record_path().depth(), 1);
}

/// Every circuit builds at a finite cost, and a settle costs what a
/// secp256k1 verification costs whatever the return shape is.
#[test]
fn the_circuits_build_at_a_finite_cost() {
    let (k_mint, rows_mint) = cost(&mint_shares().ir);
    let (k_swap, rows_swap) = cost(&swap_in().ir);
    let (k_supply, rows_supply) = cost(&supply_to_pool().ir);
    let (k_operator, rows_operator) = cost(&approve_operator().ir);
    let (k_supply_permit, rows_supply_permit) = cost(&supply_with_permit_to_pool().ir);

    let (k_mint_done, rows_mint_done) = cost(&complete_mint().ir);
    let (k_swap_done, _) = cost(&complete_swap().ir);
    let (k_supply_done, _) = cost(&complete_supply().ir);
    let (k_operator_done, _) = cost(&complete_operator().ir);
    let (k_supply_permit_done, _) = cost(&complete_supply_with_permit().ir);

    let (k_mint_ref, _) = cost(&refund_mint().ir);
    let (k_swap_ref, _) = cost(&refund_swap().ir);
    let (k_supply_ref, _) = cost(&refund_supply().ir);
    let (k_operator_ref, _) = cost(&refund_operator().ir);
    let (k_supply_permit_ref, _) = cost(&refund_supply_with_permit().ir);

    assert!(
        rows_mint > 0
            && rows_swap > 0
            && rows_supply > 0
            && rows_operator > 0
            && rows_supply_permit > 0
    );
    assert!(rows_mint_done > rows_mint, "{rows_mint_done} {rows_mint}");
    // The seven-word swap is the widest record the library files, so it
    // costs more rows to hash than the two-word mint.
    assert!(rows_swap > rows_mint, "{rows_swap} {rows_mint}");
    // The eight-word supplyWithPermit is the widest record of ALL, one word
    // past the swap.
    assert!(
        rows_supply_permit > rows_swap,
        "{rows_supply_permit} {rows_swap}"
    );

    assert!(
        k_mint <= 14
            && k_swap <= 14
            && k_supply <= 14
            && k_operator <= 14
            && k_supply_permit <= 14,
        "{k_mint} {k_swap} {k_supply} {k_operator} {k_supply_permit}"
    );
    assert!(
        k_mint_done <= 15
            && k_swap_done <= 15
            && k_supply_done <= 15
            && k_operator_done <= 15
            && k_supply_permit_done <= 15,
        "{k_mint_done} {k_swap_done} {k_supply_done} {k_operator_done} {k_supply_permit_done}"
    );
    assert!(
        k_mint_ref <= 15
            && k_swap_ref <= 15
            && k_supply_ref <= 15
            && k_operator_ref <= 15
            && k_supply_permit_ref <= 15,
        "{k_mint_ref} {k_swap_ref} {k_supply_ref} {k_operator_ref} {k_supply_permit_ref}"
    );
}

/// EACH CALL REACHES ITS OWN INTERFACE AND NO OTHER. The positive half is
/// the four circuits above; this is the shape of the bound they satisfy,
/// isolated — and the negative half (an `erc20::TransferFrom` on a
/// `Contract<Erc721>`, and the other direction) is a `compile_fail` pair in
/// `evm::erc721`'s module docs, because a test that does not compile is not
/// a test.
#[test]
fn each_call_reaches_its_own_interface() {
    fn reaches<C: minocrab_contracts::evm::EvmCall, I: minocrab_contracts::evm::Extends<C::Callee>>(
    ) {
    }

    reaches::<erc4626::Mint, erc4626::Erc4626>();
    reaches::<erc4626::Withdraw, erc4626::Erc4626>();
    reaches::<uniswap_v3::ExactInputSingle, uniswap_v3::UniswapV3Router>();
    reaches::<aave_v3::Supply, aave_v3::AaveV3Pool>();
    reaches::<aave_v3::SupplyWithPermit, aave_v3::AaveV3Pool>();
    reaches::<aave_v3::Borrow, aave_v3::AaveV3Pool>();
    reaches::<aave_v3::Repay, aave_v3::AaveV3Pool>();
    reaches::<erc721::SetApprovalForAll, erc721::Erc721>();
    reaches::<erc721::TransferFrom, erc721::Erc721>();

    // An ERC-4626 vault IS an ERC-20; the other three markers are not, and
    // are not extended by anything.
    reaches::<minocrab_contracts::evm::erc20::Approve, erc4626::Erc4626>();
}
