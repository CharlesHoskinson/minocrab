//! THE README'S CROSS-CHAIN EXAMPLE, COMPILED — notes/evm-calls.org §0's
//! target shape, as a real contract with real circuits (M37 rung C).
//!
//! A treasury that sends ERC-20 tokens on an EVM chain through Sig Network's
//! MPC. Three circuits, and every line of them is business:
//!
//! - `send(token, to, amount)` files `transfer(to, amount)` against `token`,
//!   remembering the amount and the CALLER;
//! - `complete(ticket)` settles a successful transfer — anyone may call it,
//!   because the MPC's attestation is the gate;
//! - `refund(ticket)` settles a non-success — only the original caller may
//!   call it, because the environment's owner commitment is opened with a
//!   fresh witness.
//!
//! WHAT IS NOT WRITTEN HERE, and where it went (the point of the milestone):
//!
//! | not written                       | comes from                     |
//! |-----------------------------------|--------------------------------|
//! | `a9059cbb`                        | `erc20::Transfer::selector()`  |
//! | the two ABI words, the word count | `AbiTuple` (checked, E0080)    |
//! | the output schema in the record   | `Filed<_, schema::Success>`    |
//! | the attested width and its decode | `AbiReturn for Bool`           |
//! | the gas envelope and limit        | `build_tx` + `erc20::Transfer` |
//! | the signing path                  | `Signing::contract`            |
//! | the notification depth and path   | the slot's own ledger path     |
//! | the MPC key version               | `Signet::mpc_key_version`      |
//! | `&TREASURY.signet`                | `#[derive(Ledger)]`            |
//! | the owner commitment and its gate | `Owned` + `request_owned`      |
//! | "a `false` must not complete"     | `erc20::Transfer::succeeded`   |
//!
//! WHAT IS STILL WRITTEN, on purpose (notes/evm-calls.org §5): the labels,
//! the `Discloses` tuple, and the one value §7 has yet to find a home for —
//! the EVM nonce. (The MPC key version found one in M44 rung D: it is a cell
//! of the `Signet` block, so no circuit takes it.)
//!
//! CALLEE ALLOW-LIST: this example takes the token as an argument, which a
//! deployment must not do unqualified — a non-conforming ERC-20 that returns
//! nothing produces an attested FAILURE for a transfer that moved the tokens
//! (crate::evm_flow's hazard note, notes/evm-calls.org §3.1). A real treasury
//! pins its tokens in a ledger cell and builds the callee with
//! `Contract::from_address`.

use minocrab::v3::Circuit3;
use minocrab::Public;
use minocrab_std::v3::{
    contract, label, Bytes, Disclose, Discloses, Ledger, LedgerRepr, Uint,
};

use crate::evm::erc20::{self, Erc20};
use crate::evm::Filed;
use crate::evm_flow::{Contract, Failed, Owned, Pending, Succeeded};
use crate::signet_flow::{Requested, Settled, Signet};
use crate::signet_v1::schema;

/// HOW THIS TREASURY FILES ITS ONE CALL: the library's
/// [`erc20::Transfer`], decoded under the `success` schema.
///
/// The schema is the one the deployed lineage files a `transfer` with —
/// `[{"name":"success","type":"bool"}]` — so the MPC decodes the `bool` and
/// attests one byte, which [`erc20::Transfer`]'s own
/// [`EvmCall::succeeded`](crate::evm::EvmCall::succeeded) then reads.
///
/// One name, written once: the slot, both tickets and both settle
/// signatures are all `Transfer` (notes/evm-interfaces.org §2.2).
pub type Transfer = Filed<erc20::Transfer, schema::Success>;

/// What `refund` needs back: how much was sent.
///
/// `#[derive(LedgerRepr)]` has no impl at `Private`, so nothing secret can
/// be captured here by accident; the caller's identity travels as the
/// [`Owned`] wrapper's commitment instead.
#[derive(LedgerRepr)]
pub struct Amount {
    /// The `Uint<64>` the caller asked to send.
    pub amount: Uint<64, Public>,
}

/// Six ledger fields from two declarations: the Signet configuration
/// (signer, MPC key, key version, chain id) and the transfer slot's record
/// and environment maps.
#[derive(Ledger)]
pub struct Treasury {
    /// The block's one Sig Network configuration. `#[derive(Ledger)]` finds
    /// it by name and threads its offset into `transfers`.
    pub signet: Signet,
    /// Every `transfer` this treasury has in flight, with the caller
    /// committed into each environment.
    pub transfers: Pending<Transfer, Owned<Amount>, 2>,
}

/// The contract's ledger handle.
pub const TREASURY: Treasury = Treasury::new();

label! {
    /// The amount, disclosed on filing: it is in the calldata the MPC reads.
    pub SentAmount = "the amount sent";
    /// The owner commitment, disclosed on filing: it is stored.
    pub OwnerCommitment = "the sender's refund commitment";
    /// The refund recipient, disclosed on refunding: the original caller's
    /// own public key.
    pub RefundRecipient = "own public key as refund recipient";
}

#[contract]
impl Treasury {
    /// `send(evmNonce, token, to, amount)` — file
    /// `token.transfer(to, amount)`, remembering the amount and the caller.
    #[circuit]
    pub fn send(
        c: &mut Circuit3,
        evm_nonce: Uint<64>,
        token: Contract<Erc20>,
        to: Bytes<20>,
        amount: Uint<64>,
    ) -> Discloses<(SentAmount, OwnerCommitment, Requested)> {
        let sent = amount.field().disclose_as::<SentAmount>(c);
        // `Uint<64> -> Uint<128>` is free: the ABI word is 32 bytes either
        // way and the Rust type states the range the contract accepts.
        TREASURY.transfers.request_owned::<OwnerCommitment>(
            c,
            token,
            (to, amount.widen::<128>()),
            evm_nonce,
            |_, _| Amount {
                amount: Uint::from_field_unchecked(sent),
            },
        );
        Discloses::of(())
    }

    /// `complete(ticket)` — the transfer executed AND returned `true`.
    ///
    /// ANYONE MAY CALL THIS: the attestation is the gate, and there is no
    /// witness in the circuit at all. And the attested `false` case cannot
    /// reach here: `erc20::Transfer`'s return is `Bool`, and its
    /// `EvmCall::succeeded` is that flag, which `complete` asserts — so
    /// nothing in this body has to remember to look.
    #[circuit]
    pub fn complete(c: &mut Circuit3, ticket: Succeeded<Transfer>) -> Discloses<Settled> {
        let outcome = TREASURY.transfers.complete(c, ticket);
        let _amount = outcome.env.inner.amount;
        Discloses::of(())
    }

    /// `refund(ticket)` — the transfer did not succeed, either way it can
    /// fail: the MPC's `failed` / `unviable` verdict, or an `executed` call
    /// that returned `false`.
    ///
    /// ONLY THE ORIGINAL CALLER: `refund_to_owner` witnesses a fresh secret
    /// and opens the environment's commitment against it. A real treasury
    /// re-mints `amount` to `owner` here; this example stops at naming them,
    /// so the circuit is the API and nothing else.
    #[circuit]
    pub fn refund(
        c: &mut Circuit3,
        ticket: Failed<Transfer>,
    ) -> Discloses<(Settled, RefundRecipient)> {
        // The attested flag comes back too — `false` for a mined call that
        // moved nothing, and prover-chosen padding when the MPC's verdict
        // was a non-execution (whose attested output is empty). A treasury
        // has no use for it; naming it `_` says so where dropping it
        // silently would not.
        let (_owner, _env, _flag) = TREASURY
            .transfers
            .refund_to_owner::<RefundRecipient>(c, ticket);
        let Amount { amount: _amount } = *_env;
        Discloses::of(())
    }
}
