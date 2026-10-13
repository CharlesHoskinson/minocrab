//! ERC-721 — the NFT interface, and its three STATIC calls (M38 rung C,
//! notes/evm-interfaces.org §2.4).
//!
//! [`Erc721`] is a marker of its own — NOT `Extends<Erc20>` and not
//! extended by one. The two standards are siblings that happen to share a
//! vocabulary: an ERC-721 has a `balanceOf`, an `approve` and a
//! `transferFrom` too, and they mean something else.
//!
//! # The shared selectors, and why they are not a problem HERE
//!
//! Two of the three calls below hash to ERC-20's selectors, byte for byte:
//!
//! | this module | ERC-20's | selector |
//! |-------------|----------|----------|
//! | [`TransferFrom`] `(from, to, tokenId)` | [`erc20::TransferFrom`] `(from, to, amount)` | `23b872dd` |
//! | [`Approve`] `(to, tokenId)` | [`erc20::Approve`] `(spender, amount)` | `095ea7b3` |
//!
//! Both pairs spell `(address,address,uint256)` and `(address,uint256)`, so
//! the calldata a caller files is IDENTICAL and no amount of care about the
//! signature could separate them. What separates them is the RETURN, and
//! that is not on the wire the caller sends:
//!
//! - an ERC-20 `transferFrom` returns a `bool` and our type says so, so the
//!   MPC decodes a flag and [`succeeded`](super::EvmCall::succeeded) is
//!   `is_true`;
//! - an ERC-721 `transferFrom` returns NOTHING and reverts on failure, so
//!   our type is `Return = Unit` and `succeeded` is [`always`].
//!
//! Get that backwards in either direction and you get exactly the two
//! hazards notes/evm-calls.org §3.1 is about. Declaring an NFT transfer as
//! the ERC-20 one asks the MPC to decode a `bool` out of empty return data:
//! the decode fails terminally, the request resolves as the FAILURE kind,
//! and a settle circuit refunds a transfer that moved the token. Declaring
//! an ERC-20 transfer as the NFT one throws the flag away: a token that
//! returned `false` completes as a success.
//!
//! THE CALLEE'S INTERFACE IS THE TYPE THAT DISTINGUISHES THEM. A
//! `Contract<Erc721>` is an address a contract has CLAIMED is an NFT, and
//! the `Extends` bound on `request` will not let an `erc20::TransferFrom`
//! near it — not because the bytes differ but because the claim does. Both
//! directions are compile errors:
//!
//! ```compile_fail
//! use minocrab::v3::Circuit3;
//! use minocrab::{Private, Public};
//! use minocrab_contracts::evm::{erc20, erc721, Filed};
//! use minocrab_contracts::signet_v1::schema;
//! use minocrab_contracts::evm_flow::{Contract, Pending};
//! use minocrab_contracts::signet_flow::Signet;
//! use minocrab_std::v3::{Bytes, Ledger, LedgerRepr, Uint};
//!
//! #[derive(LedgerRepr)] struct Amount { amount: Uint<64, Public> }
//!
//! #[derive(Ledger)]
//! struct Block {
//!     signet: Signet,
//!     pulls: Pending<Filed<erc20::TransferFrom, schema::Success>, Amount, 3>,
//! }
//! const BLOCK: Block = Block::new();
//!
//! fn pull(
//!     c: &mut Circuit3,
//!     // AN NFT, whose `transferFrom` returns nothing …
//!     callee: Contract<erc721::Erc721>,
//!     from: Bytes<20, Private>,
//!     to: Bytes<20, Private>,
//!     amount: Uint<128, Private>,
//!     nonce: Uint<64>,
//!     env: Amount,
//! ) {
//!     // ERROR: the trait bound `Erc721: Extends<Erc20>` is not satisfied
//!     BLOCK.pulls.request(
//!         c, callee, (from, to, amount), nonce, |_, _| env,
//!     );
//! }
//! ```
//!
//! and the other way round, where the flag would be discarded:
//!
//! ```compile_fail
//! use minocrab::v3::Circuit3;
//! use minocrab::{Private, Public};
//! use minocrab_contracts::evm::{erc20, erc721, Filed};
//! use minocrab_contracts::signet_v1::schema;
//! use minocrab_contracts::evm_flow::{Contract, Pending};
//! use minocrab_contracts::signet_flow::Signet;
//! use minocrab_std::v3::{Bytes, Ledger, LedgerRepr, Uint, B32};
//!
//! #[derive(LedgerRepr)] struct Amount { amount: Uint<64, Public> }
//!
//! #[derive(Ledger)]
//! struct Block {
//!     signet: Signet,
//!     pulls: Pending<Filed<erc721::TransferFrom, schema::NoReturn>, Amount, 3>,
//! }
//! const BLOCK: Block = Block::new();
//!
//! fn pull(
//!     c: &mut Circuit3,
//!     // A FUNGIBLE TOKEN, whose `transferFrom` returns a flag …
//!     callee: Contract<erc20::Erc20>,
//!     from: Bytes<20, Private>,
//!     to: Bytes<20, Private>,
//!     token_id: B32<Private>,
//!     nonce: Uint<64>,
//!     env: Amount,
//! ) {
//!     // ERROR: the trait bound `Erc20: Extends<Erc721>` is not satisfied
//!     BLOCK.pulls.request(
//!         c, callee, (from, to, token_id), nonce, |_, _| env,
//!     );
//! }
//! ```
//!
//! THE POSITIVE TWIN — the same two slots, each filed against the callee
//! whose interface it names, in one block:
//!
//! ```
//! use minocrab::v3::Circuit3;
//! use minocrab::{Private, Public};
//! use minocrab_contracts::evm::{erc20, erc721, Filed};
//! use minocrab_contracts::signet_v1::schema;
//! use minocrab_contracts::evm_flow::{Contract, Pending};
//! use minocrab_contracts::signet_flow::Signet;
//! use minocrab_std::v3::{Bytes, Ledger, LedgerRepr, Uint, B32};
//!
//! #[derive(LedgerRepr)] struct Amount { amount: Uint<64, Public> }
//!
//! #[derive(Ledger)]
//! struct Block {
//!     signet: Signet,
//!     coins: Pending<Filed<erc20::TransferFrom, schema::Success>, Amount, 3>,
//!     nfts: Pending<Filed<erc721::TransferFrom, schema::NoReturn>, Amount, 3>,
//! }
//! const BLOCK: Block = Block::new();
//!
//! #[allow(clippy::too_many_arguments)]
//! fn pull_both(
//!     c: &mut Circuit3,
//!     token: Contract<erc20::Erc20>,
//!     nft: Contract<erc721::Erc721>,
//!     from: Bytes<20, Private>,
//!     to: Bytes<20, Private>,
//!     amount: Uint<128, Private>,
//!     token_id: B32<Private>,
//!     nonce: Uint<64>,
//! ) {
//!     BLOCK.coins.request(
//!         c, token, (from, to, amount), nonce,
//!         |c, _| Amount { amount: Uint::from_field_unchecked(c.constant(0)) },
//!     );
//!     BLOCK.nfts.request(
//!         c, nft, (from, to, token_id), nonce,
//!         |c, _| Amount { amount: Uint::from_field_unchecked(c.constant(0)) },
//!     );
//! }
//! ```
//!
//! # What is NOT here
//!
//! `safeTransferFrom` in both its overloads. The three-argument one is
//! static, but the four-argument one takes a `bytes data` — a DYNAMIC type,
//! which is rung E — and shipping only half of a pair whose whole point is
//! the receiver hook would be worse than shipping neither. `setApprovalForAll`
//! is here because it is the approval an operator contract actually needs,
//! and [`Approve`] because a single-token approval is the narrower grant.

use minocrab::v3::Circuit3;
use minocrab::Private;
use minocrab_std::v3::Check;

use super::erc20;
use super::{always, Address, Bool, EvmCall, Interface, Unit, U256};

/// AN ERC-721 NON-FUNGIBLE TOKEN — the callee marker.
///
/// A SIBLING of [`Erc20`](super::erc20::Erc20) and not a subtype, for the
/// reason the module docs give at length: the two share two selectors and
/// mean different things by them. There is no `Extends` impl in either
/// direction and there will not be one.
///
/// Like every marker here it records the CLAIM a contract made when it
/// built the address, not a check on the deployment — an ERC-165
/// `supportsInterface` probe is the on-chain way to check, and it is a
/// query rather than something a circuit can do (notes/evm-calls.org §3.1
/// on the callee allow-list).
pub struct Erc721;

impl Interface for Erc721 {}

/// The gas limit an ERC-721 call defaults to.
///
/// [`erc20::CALL_GAS`] — the same 100,000, aliased rather than re-typed. An
/// NFT `transferFrom` writes an owner, clears an approval and emits, which
/// is a token transfer's work; no second magic number.
pub const CALL_GAS: u64 = erc20::CALL_GAS;

/// `transferFrom(address,address,uint256)` — selector `23b872dd`,
/// `(from, to, tokenId)`, NO RETURN.
///
/// THE SAME SELECTOR AS [`erc20::TransferFrom`] AND A DIFFERENT FUNCTION.
/// The module docs are the whole argument; the short form is that an
/// ERC-721 `transferFrom` returns `void` and reverts on failure, so
/// [`Return`](EvmCall::Return) is [`Unit`] and
/// [`succeeded`](EvmCall::succeeded) is [`always`] — asking the MPC for the
/// `bool` the ERC-20 one returns would resolve every successful transfer as
/// a decode failure.
///
/// `tokenId` IS A [`U256`] — an already-encoded word, not an amount. NFT
/// ids are not counters in general: ENS names are ids derived by hashing,
/// and plenty of collections mint from a hash or a packed struct, so the
/// honest width is the full 256 bits and there is no arithmetic a circuit
/// does on one. (`erc20::TransferFrom`'s third argument is a [`U128`], the
/// width a Midnight-side amount has — same `uint256` spelling, same
/// selector, different claim.)
///
/// UNSAFE IN THE STANDARD'S SENSE: `transferFrom` does not call the
/// receiver's `onERC721Received` hook, so sending to a contract that cannot
/// handle NFTs burns the token. That is `safeTransferFrom`'s job and it
/// takes a `bytes` argument (see the module docs).
///
/// [`U128`]: super::U128
pub struct TransferFrom;

impl EvmCall for TransferFrom {
    type Callee = Erc721;
    const NAME: &'static str = "transferFrom";
    type Args = (Address, Address, U256);
    type Return = Unit;
    type Success = ();
    const GAS_LIMIT: u64 = CALL_GAS;

    fn succeeded(c: &mut Circuit3, _out: &()) -> Check<Private> {
        // The constant-true assert this makes is removed by
        // `drop_true_asserts` in `Builder3::finish`.
        always(c)
    }
}

/// `approve(address,uint256)` — selector `095ea7b3`, `(to, tokenId)`, NO
/// RETURN.
///
/// THE SAME SELECTOR AS [`erc20::Approve`] AND A DIFFERENT FUNCTION, for
/// [`TransferFrom`]'s reason and with the same consequence if the two are
/// confused. It also grants something different: ERC-20's `approve` is an
/// allowance over an AMOUNT that many spenders may each hold, ERC-721's
/// names ONE address as the approved operator for ONE token and REPLACES
/// whatever was there.
///
/// NO RETURN: `approve` is `void` here where ERC-20's returns a `bool`.
pub struct Approve;

impl EvmCall for Approve {
    type Callee = Erc721;
    const NAME: &'static str = "approve";
    type Args = (Address, U256);
    type Return = Unit;
    type Success = ();
    const GAS_LIMIT: u64 = CALL_GAS;

    fn succeeded(c: &mut Circuit3, _out: &()) -> Check<Private> {
        always(c)
    }
}

/// `setApprovalForAll(address,bool)` — selector `a22cb465`,
/// `(operator, approved)`, NO RETURN.
///
/// THE BLANKET GRANT, and the one an operator contract — a marketplace, a
/// vault, ours — actually asks for: `operator` may move EVERY token the
/// caller owns in this collection, now and in future, until the same call
/// revokes it with `approved = false`. There is no per-token bookkeeping
/// and no amount.
///
/// It is the ERC-721 call with a selector of its own, so it is the one that
/// cannot be confused with anything in [`erc20`]. It is also the one whose
/// argument is a [`Bool`] — the only `bool` any shipped call in this
/// library passes as an ARGUMENT rather than reads as a return.
///
/// NO RETURN, and revoking is the same call with `false`: an operator
/// approval that mined IS granted, so [`succeeded`](EvmCall::succeeded) is
/// [`always`].
pub struct SetApprovalForAll;

impl EvmCall for SetApprovalForAll {
    type Callee = Erc721;
    const NAME: &'static str = "setApprovalForAll";
    type Args = (Address, Bool);
    type Return = Unit;
    type Success = ();
    const GAS_LIMIT: u64 = CALL_GAS;

    fn succeeded(c: &mut Circuit3, _out: &()) -> Check<Private> {
        always(c)
    }
}
