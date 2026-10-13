//! A SLOT OVER A CALL THAT RETURNS NOTHING — `Return = Unit`, and the
//! tickets that settle it (M38 rung B, notes/evm-interfaces.org §5).
//!
//! Two things this file is the witness for, neither of which could be
//! written before this rung:
//!
//! 1. A `Pending<Filed<usdt::Transfer, NoReturn>, Env, 2>` — the NON-CONFORMING
//!    token's transfer, the one whose absent `bool` would otherwise be read
//!    as a flag (notes/evm-calls.org §3.1) — forms `Succeeded` and `Failed`
//!    tickets and settles with them. The attested value is `()`: zero
//!    argument slots, nothing to decode, nothing to be fooled by. `()`
//!    became a `CircuitArg` and a `CircuitBorsh` in minocrab-std for this
//!    (M37 finding iii, second part), and this is what needed it.
//! 2. WETH's payable `deposit()` — zero calldata words, the ether in the
//!    transaction's `value` field — files through `request_payable` and
//!    settles the same way. `Withdraw` is its non-payable twin, and the
//!    same `Contract<Weth>` cell takes an `erc20::Transfer` too, which is
//!    interface inheritance's first shipped use.
//!
//! IT IS A TEST-ONLY CONTRACT, like `tests/nested_typed.rs`'s: it exercises
//! the API without adding circuits to the crate's frozen snapshots
//! (`tests/support/mod.rs` lists what those cover). Nothing here is a
//! deployment.

use minocrab::v3::Circuit3;
use minocrab::Public;
use minocrab_contracts::evm::{erc20, usdt, weth, Filed};
use minocrab_contracts::evm_flow::{
    Contract, Failed, Owned, Pending, Succeeded,
};
use minocrab_contracts::signet_flow::{Requested, Settled, Signet};
use minocrab_contracts::signet_v1::schema;
use minocrab_sim::v3::cost;
use minocrab_std::v3::{
    circuit, label, Bytes, Disclose, Discloses, Ledger, LedgerRepr, Uint,
};

// ---- the filings --------------------------------------------------------------

/// A USDT-like `transfer`, filed with the `[]` schema — the MPC is asked to
/// decode NOTHING, which is the whole point: there is no `bool` to look for.
type Tether = Filed<usdt::Transfer, schema::NoReturn>;
/// WETH's payable `deposit()` — no argument words, no return.
type Wrap = Filed<weth::Deposit, schema::NoReturn>;
/// WETH's `withdraw(uint256)`.
type Unwrap = Filed<weth::Withdraw, schema::NoReturn>;

/// What a settle needs back.
#[derive(LedgerRepr)]
struct Amount {
    amount: Uint<64, Public>,
}

/// Four Signet fields and three slots — the tether's two maps, and one pair
/// each for the two WETH calls.
#[derive(Ledger)]
struct Wallet {
    signet: Signet,
    tethers: Pending<Tether, Owned<Amount>, 2>,
    wraps: Pending<Wrap, Amount, 0>,
    unwraps: Pending<Unwrap, Amount, 1>,
}

const WALLET: Wallet = Wallet::new();

label! {
    Sent = "the amount sent";
    Owner = "the sender's refund commitment";
    Recipient = "own public key as refund recipient";
}

// ---- the circuits -------------------------------------------------------------

/// File `tether.transfer(to, amount)` against an address that DOES NOT
/// RETURN A FLAG — a `Contract<UsdtLike>`, which is the only kind of
/// callee this slot accepts.
#[circuit]
fn send_tether(
    c: &mut Circuit3,
    evm_nonce: Uint<64>,
    tether: Contract<usdt::UsdtLike>,
    to: Bytes<20>,
    amount: Uint<64>,
) -> Discloses<(Sent, Owner, Requested)> {
    let sent = amount.field().disclose_as::<Sent>(c);
    WALLET.tethers.request_owned::<Owner>(
        c,
        tether,
        (to, amount.widen::<128>()),
        evm_nonce,
        |_, _| Amount {
            amount: Uint::from_field_unchecked(sent),
        },
    );
    Discloses::of(())
}

/// SETTLE THE SUCCESS OF A CALL WITH NO RETURN. The ticket's attested value
/// is `()` — the kind byte is the whole of the MPC's output — and
/// `usdt::Transfer::succeeded` is `always`, so what `complete` checks is
/// the kind, the signature, the record's own kind and its format version.
///
/// That is the honest reading for this token: it returns nothing, so mined
/// IS succeeded. The dangerous alternative is what the type forbids —
/// declaring a `bool` the token never sends, whose failed decode the MPC
/// resolves as its FAILURE kind, refunding a transfer that moved the money.
#[circuit]
fn complete_tether(c: &mut Circuit3, ticket: Succeeded<Tether>) -> Discloses<Settled> {
    let outcome = WALLET.tethers.complete(c, ticket);
    let _amount = outcome.env.inner.amount;
    // The projection of a `Unit` return IS `()`, and naming it says so.
    let () = outcome.output;
    Discloses::of(())
}

/// SETTLE THE NON-SUCCESS. With `succeeded = always`, the only refundable
/// outcome is the MPC's own failure kind — reverted or never mined — which
/// is exactly right for a call that cannot report a business failure of its
/// own.
#[circuit]
fn refund_tether(
    c: &mut Circuit3,
    ticket: Failed<Tether>,
) -> Discloses<(Settled, Recipient)> {
    let (_owner, env, ()) = WALLET.tethers.refund_to_owner::<Recipient>(c, ticket);
    let Amount { amount: _amount } = *env;
    Discloses::of(())
}

/// WRAP ETHER: `weth.deposit()` with the amount in the transaction's
/// `value` field. No calldata words at all — the slot is `Pending<_, _, 0>`
/// — and `request_payable` is the only method that will take the amount,
/// because `weth::Deposit` is the only call with a `Payable` impl.
#[circuit]
fn wrap(
    c: &mut Circuit3,
    evm_nonce: Uint<64>,
    weth: Contract<weth::Weth>,
    amount: Uint<64>,
) -> Discloses<(Sent, Requested)> {
    let sent = amount.field().disclose_as::<Sent>(c);
    WALLET.wraps.request_payable(
        c,
        weth,
        (),
        amount.widen::<128>(),
        evm_nonce,
        |_, _| Amount {
            amount: Uint::from_field_unchecked(sent),
        },
    );
    Discloses::of(())
}

/// UNWRAP: `weth.withdraw(amount)` — one word, no return, and NOT payable,
/// so it goes through the ordinary `request`.
#[circuit]
fn unwrap(
    c: &mut Circuit3,
    evm_nonce: Uint<64>,
    weth: Contract<weth::Weth>,
    amount: Uint<64>,
) -> Discloses<(Sent, Requested)> {
    let sent = amount.field().disclose_as::<Sent>(c);
    WALLET.unwraps.request(
        c,
        weth,
        (amount.widen::<128>(),),
        evm_nonce,
        |_, _| Amount {
            amount: Uint::from_field_unchecked(sent),
        },
    );
    Discloses::of(())
}

/// The wrap's completion — a `Unit` return again, and the same `()`.
#[circuit]
fn complete_wrap(c: &mut Circuit3, ticket: Succeeded<Wrap>) -> Discloses<Settled> {
    let outcome = WALLET.wraps.complete(c, ticket);
    let () = outcome.output;
    Discloses::of(())
}

// ---- the tests ----------------------------------------------------------------

/// The block's layout: four Signet fields, then two fields per slot.
#[test]
fn the_block_is_laid_out_by_slot_width() {
    assert_eq!(WALLET.signet.signer.index(), 0);
    assert_eq!(WALLET.tethers.record_path().as_slice(), &[4]);
    assert_eq!(WALLET.wraps.record_path().as_slice(), &[6]);
    assert_eq!(WALLET.unwraps.record_path().as_slice(), &[8]);
    assert_eq!(WALLET.unwraps.record_path().depth(), 1);
}

/// Every circuit builds, and a settle costs what a secp256k1 verification
/// costs — the `Unit` return changes nothing about that, because the
/// attested output is empty at both widths the digest can take.
#[test]
fn the_circuits_build_at_a_finite_cost() {
    let (k_send, rows_send) = cost(&send_tether().ir);
    let (k_wrap, rows_wrap) = cost(&wrap().ir);
    let (k_unwrap, _) = cost(&unwrap().ir);
    let (k_done, rows_done) = cost(&complete_tether().ir);
    let (k_ref, _) = cost(&refund_tether().ir);
    let (k_wrapped, _) = cost(&complete_wrap().ir);

    assert!(rows_send > 0 && rows_wrap > 0);
    assert!(rows_done > rows_send, "{rows_done} {rows_send}");
    assert!(
        k_send <= 14 && k_wrap <= 14 && k_unwrap <= 14,
        "{k_send} {k_wrap} {k_unwrap}"
    );
    assert!(
        k_done <= 15 && k_ref <= 15 && k_wrapped <= 15,
        "{k_done} {k_ref} {k_wrapped}"
    );
}

/// THE ONE PAYABLE CALL IN THE LIBRARY. `request_payable`'s bound,
/// isolated: it holds for WETH's `deposit()` and for nothing else, so the
/// ether has exactly one place it can go.
///
/// The NEGATIVE direction — an amount handed to an `erc20::Transfer` slot
/// — is a `compile_fail` twin in `evm_flow`'s module docs, because a test
/// that does not compile is not a test. What `value` actually reaches the
/// wire is `evm_abi::a_payable_call_carries_its_value`.
#[test]
fn weth_deposit_is_the_one_payable_call() {
    fn payable<C: minocrab_contracts::evm::Payable>() {}

    payable::<weth::Deposit>();
}

/// A `Contract<Weth>` TAKES AN ERC-20 CALL — inheritance, in a lineage
/// rather than in an isolated bound (notes/evm-interfaces.org §4's "waiting
/// for a consumer"). The same cell that files `deposit` files `transfer`.
#[test]
fn a_weth_contract_takes_an_erc20_transfer() {
    fn reaches<C: minocrab_contracts::evm::EvmCall, I: minocrab_contracts::evm::Extends<C::Callee>>(
    ) {
    }

    reaches::<weth::Deposit, weth::Weth>();
    reaches::<erc20::Transfer, weth::Weth>();
    reaches::<erc20::Approve, weth::Weth>();
}
