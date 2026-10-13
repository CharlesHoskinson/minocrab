//! The typed EVM call as a ledger slot: `Pending<Filing, Env, WORDS>`
//! (M37 rungs B and C, notes/evm-calls.org §§3-4; M38 rung A,
//! notes/evm-interfaces.org §2).
//!
//! [`crate::evm`] made the CALL a type — its name, its argument list, its
//! return, the interface that exposes it, its gas limit and the rule by
//! which its return says "it worked". This module makes the SLOT a type
//! over a FILING of that call: the call plus the OUTPUT SCHEMA this
//! deployment files it under, which [`Filed`](crate::evm::Filed) supplies in
//! one line.
//!
//! ```ignore
//! type Transfer = Filed<erc20::Transfer, schema::Success>;
//!
//! #[derive(Ledger)]
//! pub struct Treasury {
//!     pub signet: Signet,
//!     pub transfers: Pending<Transfer, Owned<Amount>, 2>,
//! }
//! ```
//!
//! and everything else follows. What a contract author no longer writes:
//! the selector, the ABI words, the attested width and its narrowing, the
//! schema literal, the gas envelope, the signing path, the notification
//! path, the MPC key version, the `&SELF.signet` argument
//! (`#[derive(Ledger)]` threads the block's Signet offset into every
//! `Pending` field) and — with [`Owned`] — the owner commitment's
//! construction and opening.
//!
//! THE VOCABULARY IS V1 SINCE M44 RUNG D (notes/vault-flush.org §6): the
//! records are [`crate::signet_v1::EventRecordV1`], the tickets carry a
//! `RespondBidirectionalEvent` and a flat serialized output, and the
//! response KIND BYTE is gone from both — `crate::signet_flow`'s header is
//! the list of what that subtracted.
//!
//! # The two tickets are SYMMETRIC
//!
//! [`Succeeded<F>`] and [`Failed<F>`], and nothing else settles a request
//! — and `F` is the FILING, so a ticket for one slot's filing cannot settle
//! another's, even when the two file the same Solidity function:
//!
//! - [`Pending::complete`] takes a `Succeeded`, verifies the attestation at
//!   the call's attested width, asserts the MPC's verdict is `executed`,
//!   consumes the entry — and then asserts the call's own
//!   [`EvmCall::succeeded`] predicate over the decoded output. A mined ERC-20
//!   `transfer` that returned `false` therefore CANNOT complete, whoever
//!   presents it (notes/evm-calls.org §3: the spurious-completion hole the
//!   deployed vault leaves open by putting a refund branch inside its
//!   `completeWithdraw`).
//! - [`Pending::refund`] takes a `Failed`, and accepts EITHER a `failed` /
//!   `unviable` verdict (reverted, never mined, or an undecodable return —
//!   §3.1) OR `executed` with the success predicate false.
//!
//! So the two non-successes are one ticket, the success is the other, and
//! neither stands in for the other.
//!
//! WHAT BINDS AN ATTESTATION TO A SLOT, now that there is no kind byte: the
//! slot's own record map. `complete` and `refund` consume the entry the
//! request filed, and the signed digest commits to the id that entry is
//! keyed by — so an attestation for a request another slot filed finds
//! nothing to consume in this one (`Pending::consume`).
//!
//! # HAZARD, carried forward from §3.1
//!
//! The MPC resolves a request as FAILED when the receipt reverted, when the
//! transaction never mined, AND when the return data does not decode into
//! the declared output schema. A non-conforming ERC-20 that returns NOTHING
//! (USDT and friends) therefore produces an attested failure for a transfer
//! that MOVED the tokens — a spurious refund this API cannot see from the
//! attestation alone. Until the callee's return shape is declared per token
//! (a `Contract<Erc20NoReturn>` marker) or success is read off the
//! `Transfer` event, **a contract using this module needs a callee
//! allow-list**, exactly as the deployed vault has one in effect through its
//! configured ERC-20 addresses.
//!
//! # What `Failed<F>` costs
//!
//! The two accepted attestations have DIFFERENT PREIMAGES, and under V1 they
//! differ in the WIDTH as well as in the limbs: a `failed` or `unviable`
//! request has no return to decode, so the MPC attests ZERO bytes and the
//! digest's `LEN` field is `0`, where an `executed` call's is the return's
//! own width. Poseidon is not a stream, so one hash cannot cover both:
//! [`Pending::refund`] hashes the preimage BOTH ways, selects the field
//! element by the verdict and verifies ONCE. The extra cost is one
//! `transient_hash` and one `cond_select` beside the ~30k rows of the ECDSA
//! verification that follows — measured in
//! `tests/treasury.rs::the_refund_pays_one_extra_digest`.
//!
//! # What does not compile
//!
//! A CALL SENT TO AN INTERFACE THAT DOES NOT EXPOSE IT — the first rung of
//! the ladder (notes/evm-interfaces.org §2.5). `erc20::Transfer::Callee` is
//! `Erc20`, and a Uniswap router is not one, so there is no `Extends` impl:
//!
//! ```compile_fail
//! use minocrab::v3::Circuit3;
//! use minocrab::{Private, Public};
//! use minocrab_contracts::evm::{erc20, uniswap_v3, Filed};
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
//!     transfers: Pending<Filed<erc20::Transfer, schema::Success>, Amount, 2>,
//! }
//! const BLOCK: Block = Block::new();
//!
//! fn send(
//!     c: &mut Circuit3,
//!     // ERROR: the trait bound `UniswapV3Router: Extends<Erc20>` is not satisfied
//!     callee: Contract<uniswap_v3::UniswapV3Router>,
//!     to: Bytes<20, Private>,
//!     amount: Uint<128, Private>,
//!     nonce: Uint<64>,
//!     env: Amount,
//! ) {
//!     BLOCK.transfers.request(c, callee, (to, amount), nonce, |_, _| env);
//! }
//! ```
//!
//! THE SAME CODE WITH THE ONE CHANGE REVERTED compiles — the callee's
//! interface is the only difference, so the rejection is the interface:
//!
//! ```
//! use minocrab::v3::Circuit3;
//! use minocrab::{Private, Public};
//! use minocrab_contracts::evm::{erc20, Filed};
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
//!     transfers: Pending<Filed<erc20::Transfer, schema::Success>, Amount, 2>,
//! }
//! const BLOCK: Block = Block::new();
//!
//! fn send(
//!     c: &mut Circuit3,
//!     callee: Contract<erc20::Erc20>,
//!     to: Bytes<20, Private>,
//!     amount: Uint<128, Private>,
//!     nonce: Uint<64>,
//!     env: Amount,
//! ) {
//!     BLOCK.transfers.request(c, callee, (to, amount), nonce, |_, _| env);
//! }
//! ```
//!
//! A ticket for one FILING handed to another's slot — and the two filings
//! here are the SAME Solidity call at two kinds, which is exactly the pair
//! the deployed vault has (`transfer` as a claim and as a withdrawal):
//!
//! ```compile_fail
//! use minocrab::v3::Circuit3;
//! use minocrab_contracts::evm::{erc20, Filed};
//! use minocrab_contracts::signet_v1::schema;
//! use minocrab_contracts::evm_flow::{Owned, Pending, Succeeded};
//! use minocrab_contracts::signet_flow::Signet;
//! use minocrab_std::v3::{Ledger, LedgerRepr, Uint};
//! use minocrab::Public;
//!
//! #[derive(LedgerRepr)] struct Amount { amount: Uint<64, Public> }
//!
//! #[derive(Ledger)]
//! struct Block {
//!     signet: Signet,
//!     transfers: Pending<Filed<erc20::Transfer, schema::Success>, Owned<Amount>, 2>,
//! }
//! const BLOCK: Block = Block::new();
//!
//! fn settle(c: &mut Circuit3, ticket: Succeeded<Filed<erc20::Transfer, schema::NoReturn>>) {
//!     // ERROR: expected `Succeeded<Filed<Transfer, Success>>`,
//!     //        found `Succeeded<Filed<Transfer, NoReturn>>`
//!     BLOCK.transfers.complete(c, ticket);
//! }
//! ```
//!
//! THE SAME CODE WITH THE ONE CHANGE REVERTED compiles:
//!
//! ```
//! use minocrab::v3::Circuit3;
//! use minocrab_contracts::evm::{erc20, Filed};
//! use minocrab_contracts::signet_v1::schema;
//! use minocrab_contracts::evm_flow::{Owned, Pending, Succeeded};
//! use minocrab_contracts::signet_flow::Signet;
//! use minocrab_std::v3::{Ledger, LedgerRepr, Uint};
//! use minocrab::Public;
//!
//! #[derive(LedgerRepr)] struct Amount { amount: Uint<64, Public> }
//!
//! #[derive(Ledger)]
//! struct Block {
//!     signet: Signet,
//!     transfers: Pending<Filed<erc20::Transfer, schema::Success>, Owned<Amount>, 2>,
//! }
//! const BLOCK: Block = Block::new();
//!
//! fn settle(c: &mut Circuit3, ticket: Succeeded<Filed<erc20::Transfer, schema::Success>>) {
//!     BLOCK.transfers.complete(c, ticket);
//! }
//! ```
//!
//! A `WORDS` that is not the call's argument-word count — `error[E0080]`
//! from the slot's constructor, which `#[derive(Ledger)]` calls:
//!
//! ```compile_fail
//! use minocrab_contracts::evm::{erc20, Filed};
//! use minocrab_contracts::signet_v1::schema;
//! use minocrab_contracts::evm_flow::{Owned, Pending};
//! use minocrab_contracts::signet_flow::Signet;
//! use minocrab_std::v3::{Ledger, LedgerRepr, Uint};
//! use minocrab::Public;
//!
//! #[derive(LedgerRepr)] struct Amount { amount: Uint<64, Public> }
//!
//! #[derive(Ledger)]
//! struct Block {
//!     signet: Signet,
//!     // error[E0080]: `Pending<F, Env, WORDS>` needs WORDS == …
//!     transfers: Pending<Filed<erc20::Transfer, schema::Success>, Owned<Amount>, 3>,
//! }
//! const BLOCK: Block = Block::new();
//! const _: usize = BLOCK.transfers.record_path().depth() as usize;
//! ```
//!
//! A RETURN TYPE WHOSE ATTESTED FORM NOBODY HAS WRITTEN DOWN — the rung the
//! kind-byte doctest used to occupy (two slots of one block at one response
//! kind was `error[E0080]` from the derive's `assert_distinct_kinds`; V1
//! records carry no kind, so two slots may now file the same call with the
//! same schema and the derive has nothing left to check).
//!
//! What took its place is a check the `fff3421c` lineage could not make: a
//! slot's attested output has to have a WIDTH and a NARROWING, and
//! [`AbiReturn`] is where those live. `Address` is an [`AbiType`] with no
//! `AbiReturn` impl, so a call declaring it as a return cannot be filed:
//!
//! ```compile_fail
//! use minocrab::v3::Circuit3;
//! use minocrab_contracts::evm::{erc20, always, Address, Check, EvmCall, Filed};
//! use minocrab_contracts::evm_flow::{Owned, Pending, Succeeded};
//! use minocrab_contracts::signet_flow::Signet;
//! use minocrab_contracts::signet_v1::schema;
//! use minocrab_std::v3::{Bytes, Ledger, LedgerRepr, Uint};
//! use minocrab::{Private, Public};
//!
//! #[derive(LedgerRepr)] struct Amount { amount: Uint<64, Public> }
//!
//! /// A hypothetical `owner()`-shaped call: its return is an address.
//! struct WhoOwnsIt;
//! impl EvmCall for WhoOwnsIt {
//!     type Callee = erc20::Erc20;
//!     const NAME: &'static str = "owner";
//!     type Args = ();
//!     type Return = Address;
//!     type Success = Bytes<20, Private>;
//!     const GAS_LIMIT: u64 = erc20::CALL_GAS;
//!     fn succeeded(c: &mut Circuit3, _: &Bytes<20, Private>) -> Check<Private> {
//!         always(c)
//!     }
//! }
//!
//! #[derive(Ledger)]
//! struct Block {
//!     signet: Signet,
//!     owners: Pending<Filed<WhoOwnsIt, schema::Success>, Owned<Amount>, 0>,
//! }
//! const BLOCK: Block = Block::new();
//!
//! // ERROR: the trait bound `Address: AbiReturn` is not satisfied
//! fn settle(c: &mut Circuit3, ticket: Succeeded<Filed<WhoOwnsIt, schema::Success>>) {
//!     BLOCK.owners.complete(c, ticket);
//! }
//! ```
//!
//! THE SAME CALL WITH A RETURN THAT HAS ONE compiles — `U256` is 32 attested
//! bytes and the narrowing is written once, in [`AbiReturn`]:
//!
//! ```
//! use minocrab::v3::Circuit3;
//! use minocrab_contracts::evm::{erc20, always, EvmCall, Filed, U256};
//! use minocrab_contracts::evm_flow::{Owned, Pending, Succeeded};
//! use minocrab_contracts::signet_flow::Signet;
//! use minocrab_contracts::signet_v1::schema;
//! use minocrab_std::v3::{Check, Ledger, LedgerRepr, Uint, B32};
//! use minocrab::{Private, Public};
//!
//! #[derive(LedgerRepr)] struct Amount { amount: Uint<64, Public> }
//!
//! struct WhatIsItWorth;
//! impl EvmCall for WhatIsItWorth {
//!     type Callee = erc20::Erc20;
//!     const NAME: &'static str = "price";
//!     type Args = ();
//!     type Return = U256;
//!     type Success = B32<Private>;
//!     const GAS_LIMIT: u64 = erc20::CALL_GAS;
//!     fn succeeded(c: &mut Circuit3, _: &B32<Private>) -> Check<Private> {
//!         always(c)
//!     }
//! }
//!
//! #[derive(Ledger)]
//! struct Block {
//!     signet: Signet,
//!     prices: Pending<Filed<WhatIsItWorth, schema::AmountIn>, Owned<Amount>, 0>,
//! }
//! const BLOCK: Block = Block::new();
//!
//! fn settle(c: &mut Circuit3, ticket: Succeeded<Filed<WhatIsItWorth, schema::AmountIn>>) {
//!     BLOCK.prices.complete(c, ticket);
//! }
//! ```
//!
//! A `Pending` slot in a block with no `Signet` field — the derive's own
//! error, because there would be no configuration to read the MPC key,
//! the nonce and the chain from:
//!
//! ```compile_fail
//! use minocrab_contracts::evm::{erc20, Filed};
//! use minocrab_contracts::signet_v1::schema;
//! use minocrab_contracts::evm_flow::{Owned, Pending};
//! use minocrab_std::v3::{Ledger, LedgerCounter, LedgerRepr, Uint};
//! use minocrab::Public;
//!
//! #[derive(LedgerRepr)] struct Amount { amount: Uint<64, Public> }
//!
//! #[derive(Ledger)]
//! struct Block {
//!     initialized: LedgerCounter,
//!     // ERROR: a `Pending` slot needs the block's `Signet` field …
//!     transfers: Pending<Filed<erc20::Transfer, schema::Success>, Owned<Amount>, 2>,
//! }
//! ```
//!
//! TWO `Signet` fields — one contract, one MPC key, one nonce sequence:
//!
//! ```compile_fail
//! use minocrab_contracts::evm::{erc20, Filed};
//! use minocrab_contracts::signet_v1::schema;
//! use minocrab_contracts::evm_flow::{Owned, Pending};
//! use minocrab_contracts::signet_flow::Signet;
//! use minocrab_std::v3::{Ledger, LedgerRepr, Uint};
//! use minocrab::Public;
//!
//! #[derive(LedgerRepr)] struct Amount { amount: Uint<64, Public> }
//!
//! #[derive(Ledger)]
//! struct Block {
//!     signet: Signet,
//!     // ERROR: #[derive(Ledger)] wants EXACTLY ONE `Signet` field per block
//!     other: Signet,
//!     transfers: Pending<Filed<erc20::Transfer, schema::Success>, Owned<Amount>, 2>,
//! }
//! ```
//!
//! ETHER ON A CALL THAT CANNOT TAKE IT — `Pending::request_payable` is
//! bounded by [`Payable`], and an ERC-20 `transfer`
//! has no impl, so an amount cannot be attached to a call that would
//! ignore it and leave the ether with the contract (M38 rung B):
//!
//! ```compile_fail
//! use minocrab::v3::Circuit3;
//! use minocrab::{Private, Public};
//! use minocrab_contracts::evm::{erc20, Filed};
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
//!     transfers: Pending<Filed<erc20::Transfer, schema::Success>, Amount, 2>,
//! }
//! const BLOCK: Block = Block::new();
//!
//! fn send(
//!     c: &mut Circuit3,
//!     callee: Contract<erc20::Erc20>,
//!     to: Bytes<20, Private>,
//!     amount: Uint<128, Private>,
//!     nonce: Uint<64>,
//!     env: Amount,
//! ) {
//!     // ERROR: the trait bound `erc20::Transfer: Payable` is not satisfied
//!     BLOCK.transfers.request_payable(
//!         c, callee, (to, amount), amount, nonce, |_, _| env,
//!     );
//! }
//! ```
//!
//! THE SAME CALL THAT DOES TAKE ETHER compiles — WETH's `deposit()`, whose
//! ether IS its argument (it has no calldata beyond the selector, so the
//! slot's `WORDS` is zero):
//!
//! ```
//! use minocrab::v3::Circuit3;
//! use minocrab::{Private, Public};
//! use minocrab_contracts::evm::{weth, Filed};
//! use minocrab_contracts::signet_v1::schema;
//! use minocrab_contracts::evm_flow::{Contract, Pending};
//! use minocrab_contracts::signet_flow::Signet;
//! use minocrab_std::v3::{Ledger, LedgerRepr, Uint};
//!
//! #[derive(LedgerRepr)] struct Amount { amount: Uint<64, Public> }
//!
//! #[derive(Ledger)]
//! struct Block {
//!     signet: Signet,
//!     wraps: Pending<Filed<weth::Deposit, schema::NoReturn>, Amount, 0>,
//! }
//! const BLOCK: Block = Block::new();
//!
//! fn wrap(
//!     c: &mut Circuit3,
//!     callee: Contract<weth::Weth>,
//!     amount: Uint<128, Private>,
//!     nonce: Uint<64>,
//!     env: Amount,
//! ) {
//!     BLOCK.wraps.request_payable(
//!         c, callee, (), amount, nonce, |_, _| env,
//!     );
//! }
//! ```
//!
//! A CONFORMING TOKEN'S CALL FILED AGAINST A NON-CONFORMING ONE, and the
//! other direction. `UsdtLike` is a SIBLING of `Erc20`, not a subtype:
//! neither `Extends` the other, so neither address takes the other's calls.
//! That is what stops a USDT address being handed to a slot that declares a
//! `bool` return, whose absent return the MPC would resolve as its FAILURE
//! kind — refunding a transfer that moved the tokens
//! (notes/evm-calls.org §3.1, the dangerous direction):
//!
//! ```compile_fail
//! use minocrab::v3::Circuit3;
//! use minocrab::{Private, Public};
//! use minocrab_contracts::evm::{erc20, usdt, Filed};
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
//!     transfers: Pending<Filed<usdt::Transfer, schema::NoReturn>, Amount, 2>,
//! }
//! const BLOCK: Block = Block::new();
//!
//! fn send(
//!     c: &mut Circuit3,
//!     // ERROR: the trait bound `Erc20: Extends<UsdtLike>` is not satisfied
//!     callee: Contract<erc20::Erc20>,
//!     to: Bytes<20, Private>,
//!     amount: Uint<128, Private>,
//!     nonce: Uint<64>,
//!     env: Amount,
//! ) {
//!     BLOCK.transfers.request(c, callee, (to, amount), nonce, |_, _| env);
//! }
//! ```
//!
//! ```compile_fail
//! use minocrab::v3::Circuit3;
//! use minocrab::{Private, Public};
//! use minocrab_contracts::evm::{erc20, usdt, Filed};
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
//!     transfers: Pending<Filed<erc20::Transfer, schema::Success>, Amount, 2>,
//! }
//! const BLOCK: Block = Block::new();
//!
//! fn send(
//!     c: &mut Circuit3,
//!     // ERROR: the trait bound `UsdtLike: Extends<Erc20>` is not satisfied
//!     callee: Contract<usdt::UsdtLike>,
//!     to: Bytes<20, Private>,
//!     amount: Uint<128, Private>,
//!     nonce: Uint<64>,
//!     env: Amount,
//! ) {
//!     BLOCK.transfers.request(c, callee, (to, amount), nonce, |_, _| env);
//! }
//! ```
//!
//! THE SAME CODE WITH EACH CALLEE MATCHED TO ITS OWN INTERFACE compiles,
//! and the two slots are the same two words on the wire — the difference is
//! entirely in what the MPC is asked to decode:
//!
//! ```
//! use minocrab::v3::Circuit3;
//! use minocrab::{Private, Public};
//! use minocrab_contracts::evm::{erc20, usdt, Filed};
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
//!     conforming: Pending<Filed<erc20::Transfer, schema::Success>, Amount, 2>,
//!     non_conforming: Pending<Filed<usdt::Transfer, schema::NoReturn>, Amount, 2>,
//! }
//! const BLOCK: Block = Block::new();
//!
//! fn send(
//!     c: &mut Circuit3,
//!     token: Contract<erc20::Erc20>,
//!     tether: Contract<usdt::UsdtLike>,
//!     to: Bytes<20, Private>,
//!     amount: Uint<128, Private>,
//!     nonce: Uint<64>,
//!     one: Amount,
//!     two: Amount,
//! ) {
//!     BLOCK.conforming.request(c, token, (to, amount), nonce, |_, _| one);
//!     BLOCK.non_conforming.request(c, tether, (to, amount), nonce, |_, _| two);
//! }
//! ```
//!
//! A callee where a recipient belongs — `Contract<I>` and `Bytes<20>` are
//! the same twenty bytes and do not unify:
//!
//! ```compile_fail
//! use minocrab::v3::{Circuit3, FieldT};
//! use minocrab::Private;
//! use minocrab_contracts::evm::erc20;
//! use minocrab_contracts::evm_flow::Contract;
//! use minocrab_std::v3::Bytes;
//!
//! fn f(c: &mut Circuit3, callee: Contract<erc20::Erc20>) -> Bytes<20, Private> {
//!     // ERROR: expected `Bytes<20>`, found `Contract<Erc20>`
//!     callee
//! }
//! ```

use core::marker::PhantomData;

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Private, Public};
use minocrab_std::v3::hash::{transient_hash_compact, upgrade_from_transient};
use minocrab_std::v3::{
    eq, is_true, label, not, own_public_key, repr_limbs, ArgPath, Bool, Bytes, CircuitAbi,
    CircuitArg, Assumed, Disclose, DisclosureLabel, FieldPath, LedgerMap, LedgerRepr, LedgerWidth,
    Prim, ProofWires, Uint, Vis3, ZswapCoinPublicKey, B32,
};
use minocrab::v3::Val;
use signet_signer_interface::{RequestId, RespondBidirectionalEvent};

use crate::common::{self, SecretKey};
use crate::evm::{
    build_tx_filed, build_tx_from_words, build_tx_payable_filed, build_tx_with, AbiArgs, AbiReturn,
    AbiTuple, AbiType, Envelope, EvmCall, Extends, Filing, Interface, Payable,
};
use crate::signet::Secp256k1SigLimbs;
use crate::signet_v1::{
    self, output_kind, EventRecordV1, OutputSchema,
};
use crate::signet_flow::{
    file_request, BlockHeightSettled, EvmTx, Outcome, RequestIdSettled, SignRequest, Signet,
    Signing,
};

/// The refund commitment's domain pad, `pad(32, "vault:refund:")` — the
/// seventeen-circuit vault's `refundCommitment` tag, which `Owned` keeps
/// (the flush-pattern vault has no refund commitment: M44).
pub const REFUND_PAD: &str = "vault:refund:";

/// A call's attested return value DECODED, as a circuit wire.
pub type Ret<C> = <<C as EvmCall>::Return as AbiType>::Wire<Private>;

/// The CALL a [`Filing`] files — `F::Call`, spelled once so a slot's
/// signatures read as sentences rather than as projections.
pub type Called<F> = <F as Filing>::Call;

/// The RETURN TYPE of a filing's call — the leaf whose [`AbiReturn`] says
/// how wide the attested output is and how it narrows.
pub type Returned<F> = <Called<F> as EvmCall>::Return;

/// THE SERIALIZED OUTPUT a filing's attestation carries: the MPC's Borsh of
/// the decoded return at the call's own width (`Bytes0`, `Bytes<1>`, `B32`).
pub type Serialized<F> = <Returned<F> as AbiReturn>::Serialized;

/// The V1 RECORD a filing's slot stores — the event's limbs under the
/// filing's own output schema.
pub type Record<F, const WORDS: usize> =
    EventRecordV1<WORDS, <<F as Filing>::Schema as OutputSchema>::At<Public>>;

/// The INTERFACE a filing's call must be sent to: the callee of `F`'s call.
/// A `Contract<I>` reaches it when `I: Extends<Callee<F>>`.
pub type Callee<F> = <Called<F> as EvmCall>::Callee;


// ---- the callee ---------------------------------------------------------------

/// THE ADDRESS OF A CONTRACT THAT CLAIMS INTERFACE `I` — a `Bytes<20>`
/// that knows what it answers.
///
/// Two things it buys, at no wire cost (the shape is a bare `Bytes<20>`,
/// one argument slot, the same schema):
///
/// - A callee and a recipient are both twenty bytes and mean opposite
///   things; `Contract<Erc20>` and `Bytes<20>` do not unify, so the two
///   cannot be swapped in a `request` call.
/// - A call goes only where its interface does. `request` takes a
///   `Contract<I>` with `I: Extends<Callee<F>>`, so an
///   [`erc20::Transfer`](crate::evm::erc20::Transfer) filed against a
///   `Contract<UniswapV3Router>` is a MISSING IMPL, and an
///   [`erc20::Approve`](crate::evm::erc20::Approve) against a
///   `Contract<Erc4626>` compiles because an ERC-4626 vault IS an ERC-20.
///
/// WHAT IT DOES NOT BUY: any check that the deployed address at the other
/// end really is that interface. The type records the CLAIM the contract
/// made when it built the value, which is why the callee-allow-list hazard
/// (this module's header) is about where the address came from.
pub struct Contract<I: Interface> {
    address: Bytes<20, Private>,
    _interface: PhantomData<fn() -> I>,
}

impl<I: Interface> Clone for Contract<I> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<I: Interface> Copy for Contract<I> {}

impl<I: Interface> Contract<I> {
    /// The callee from an address the contract already holds — a ledger
    /// cell's value, typically (the vault keeps its `stataToken` in one).
    ///
    /// `c` is taken and unused: reinterpreting a limb emits nothing, and the
    /// parameter is here so that adding a check (a non-zero assert, an
    /// allow-list membership) later does not move every call site.
    pub fn from_address<V: Vis3>(_c: &mut Circuit3, address: Bytes<20, V>) -> Self {
        Contract {
            address: Bytes::from_field_unchecked(address.field().private()),
            _interface: PhantomData,
        }
    }

    /// The twenty address bytes.
    pub fn address(&self) -> Bytes<20, Private> {
        self.address
    }
}

impl<I: Interface> CircuitAbi for Contract<I> {
    const SLOTS: usize = <Bytes<20, Private>>::SLOTS;

    fn push_atoms(atoms: &mut Vec<minocrab::AlignmentAtom>) {
        <Bytes<20, Private>>::push_atoms(atoms);
    }

    fn push_prims(prims: &mut Vec<Prim>) {
        <Bytes<20, Private>>::push_prims(prims);
    }
}

impl<I: Interface> CircuitArg for Contract<I> {
    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        Contract {
            address: <Bytes<20, Private>>::declare(c, path),
            _interface: PhantomData,
        }
    }

    fn push_slots(&self, slots: &mut Vec<Wire3<FieldT, Private>>) {
        self.address.push_slots(slots);
    }
}

// ---- the tickets --------------------------------------------------------------

/// Both tickets carry `(respond, serializedOutput)` — the two arguments the
/// deployed `queueAttestation*` circuits take, named for the CALL rather
/// than for an environment/response pair.
///
/// THE REQUEST ID IS NOT A SEPARATE FIELD any more: V1's
/// `RespondBidirectionalEvent` carries it, beside the height, the verdict,
/// the width and the digest, and all of those are inside the signed
/// preimage — so a ticket cannot name one request and verify another.
macro_rules! ticket {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        pub struct $name<F: Filing>
        where
            Returned<F>: AbiReturn,
        {
            /// The MPC's attestation: `{ requestId, blockHeight, outputKind,
            /// serializedOutputLength, digest, signature }`. The signature is
            /// in circuit-input form (`bigR.x` and `s` little-endian; the
            /// reversal is the transaction builder's).
            pub respond: RespondBidirectionalEvent<Private>,
            /// `serializedOutput`: the MPC's Borsh of the decoded return at
            /// the call's own width ([`AbiReturn::LEN`]) — flat bytes, not a
            /// decoded value, because that is what the digest commits to.
            pub output: Serialized<F>,
            _filing: PhantomData<fn() -> F>,
        }

        impl<F: Filing> CircuitAbi for $name<F>
        where
            Returned<F>: AbiReturn,
        {
            const SLOTS: usize =
                <RespondBidirectionalEvent<Private>>::SLOTS + <Serialized<F>>::SLOTS;

            fn push_atoms(atoms: &mut Vec<minocrab::AlignmentAtom>) {
                <RespondBidirectionalEvent<Private>>::push_atoms(atoms);
                <Serialized<F>>::push_atoms(atoms);
            }

            fn push_prims(prims: &mut Vec<Prim>) {
                <RespondBidirectionalEvent<Private>>::push_prims(prims);
                <Serialized<F>>::push_prims(prims);
            }
        }

        impl<F: Filing> CircuitArg for $name<F>
        where
            Returned<F>: AbiReturn,
        {
            fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
                $name {
                    respond: <RespondBidirectionalEvent<Private>>::declare(
                        c,
                        &path.field("respond"),
                    ),
                    output: <Serialized<F>>::declare(c, &path.field("serializedOutput")),
                    _filing: PhantomData,
                }
            }

            fn push_slots(&self, slots: &mut Vec<Wire3<FieldT, Private>>) {
                self.respond.push_slots(slots);
                self.output.push_slots(slots);
            }
        }
    };
}

ticket!(
    Succeeded,
    "THE CALL EXECUTED AND SUCCEEDED — the only ticket [`Pending::complete`] \
     takes.\n\n\
     The claim is CHECKED, not believed: `complete` verifies the signature \
     over the attested width, asserts the verdict is \
     [`output_kind::EXECUTED`](crate::signet_v1::output_kind::EXECUTED), \
     consumes this slot's own entry, and then asserts the call's \
     [`EvmCall::succeeded`] predicate over the decoded output. What the \
     ticket's TYPE buys is that a ticket for filing `X` cannot be handed to a \
     slot filed as `Y`, and that a [`Failed`] cannot be handed to `complete` \
     at all."
);

ticket!(
    Failed,
    "THE CALL DID NOT SUCCEED — the only ticket [`Pending::refund`] takes, \
     for both non-successes.\n\n\
     Either the MPC's verdict was \
     [`FAILED`](crate::signet_v1::output_kind::FAILED) or \
     [`UNVIABLE`](crate::signet_v1::output_kind::UNVIABLE) (reverted, never \
     mined, or an undecodable return — and then the attested output is \
     EMPTY), or it was `EXECUTED` with a return the call's \
     [`EvmCall::succeeded`] says is not a success (an ERC-20 `transfer` that \
     mined and returned `false`). The wire shape is [`Succeeded`]'s; in the \
     first case the output slots carry the prover's padding and are not part \
     of the signed preimage."
);

// ---- what survives privately, with a TYPED domain -----------------------------

/// A commitment's DOMAIN, as a type.
///
/// `signet_flow::Commit` takes the domain as a `&str` at both ends, so a
/// `to` and an `open` that disagree is a proof that never verifies — a
/// runtime symptom for a spelling mistake. Here the pad is carried by a
/// marker type, so the disagreement does not compile.
pub trait CommitTag {
    /// The 32-byte pad the digest starts with.
    const PAD: &'static str;
}

/// The owner commitment's domain: the vault's `"vault:refund:"`, so a record
/// and an environment written through [`Owned`] are byte-identical to the
/// ones the deployed lineage writes.
pub struct OwnerTag;

impl CommitTag for OwnerTag {
    const PAD: &'static str = REFUND_PAD;
}

/// A commitment to a private value, stored in an environment and OPENED on
/// the settle side with a fresh witness — the one way a secret crosses the
/// suspension.
///
/// `transientHash([pad(32, Tag::PAD), value, requestId])`, split into a
/// `Bytes<32>`: the construction `signet_flow::Commit` performs, with the
/// domain moved from an argument to a type parameter. Binding the REQUEST ID
/// in is what keeps two requests by one owner unlinkable.
///
/// # What does not compile
///
/// Opening a commitment under another tag — the two are different types:
///
/// ```compile_fail
/// use minocrab::v3::Circuit3;
/// use minocrab_contracts::common::{witness_sk, SecretKey};
/// use minocrab_contracts::evm_flow::{Commit, CommitTag};
/// use minocrab::Private;
/// use minocrab_std::v3::label;
///
/// struct Owner;
/// impl CommitTag for Owner { const PAD: &'static str = "a:"; }
/// struct Beneficiary;
/// impl CommitTag for Beneficiary { const PAD: &'static str = "b:"; }
/// label! { Digest = "digest"; }
///
/// fn f(c: &mut Circuit3, id: signet_signer_interface::RequestId<minocrab::Public>) {
///     let sk = witness_sk(c);
///     let made: Commit<SecretKey<Private>, Owner> = Commit::to::<Digest, _>(c, &sk, id);
///     // ERROR: expected `Commit<_, Beneficiary>`, found `Commit<_, Owner>`
///     let opened: Commit<SecretKey<Private>, Beneficiary> = made;
///     opened.open(c, &sk, id, "nope");
/// }
/// ```
pub struct Commit<T, Tag> {
    digest: B32<Public>,
    _t: PhantomData<fn() -> (T, Tag)>,
}

impl<T, Tag> Clone for Commit<T, Tag> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T, Tag> Copy for Commit<T, Tag> {}

/// WHAT A COMMITMENT IS BOUND TO — the value hashed in after the pad and the
/// committed value, so that one owner's two commitments differ.
///
/// [`RequestId`] is the binding a [`Pending`] request has, and the only one
/// there was until the outbox: the id exists at filing time, so the
/// commitment can name it. An [`Outbox`] request has no id when it is made
/// (the record, hence the id, is created at EMIT — notes/stream-design.org),
/// so it binds to its [`Handle`] instead: the content-derived key the
/// requester keeps.
///
/// The trait exists so that neither binding can be spelled where the other
/// belongs and still hash the same: each pushes its OWN limbs, and the two
/// are different types.
pub trait CommitBinding {
    /// The limbs this binding contributes to the commitment's preimage.
    fn push_binding(&self, inputs: &mut Vec<Wire3<FieldT, Private>>);
}

impl CommitBinding for RequestId<Public> {
    fn push_binding(&self, inputs: &mut Vec<Wire3<FieldT, Private>>) {
        let id = self.bytes();
        inputs.push(id.hi.private());
        inputs.push(id.lo.private());
    }
}

impl CommitBinding for Handle<Public> {
    fn push_binding(&self, inputs: &mut Vec<Wire3<FieldT, Private>>) {
        inputs.push(self.value().private());
    }
}

impl<T: CircuitArg, Tag: CommitTag> Commit<T, Tag> {
    fn digest_of<B: CommitBinding>(c: &mut Circuit3, value: &T, bind: B) -> B32<Private> {
        c.region("signet flow: commitment", |c| {
            let pad = B32::pad(c, Tag::PAD);
            let mut inputs = vec![pad.hi.private(), pad.lo.private()];
            value.push_slots(&mut inputs);
            bind.push_binding(&mut inputs);
            let f = c.transient_hash(&inputs);
            let (hi, lo) = c.div_mod_power_of_two(f, 248);
            B32 { hi, lo }
        })
    }

    /// Commit to `value` for this request, disclosing the digest under `L`
    /// (it is stored, so it is public — the label names it in the disclosure
    /// inventory).
    pub fn to<L: DisclosureLabel, B: CommitBinding>(
        c: &mut Circuit3,
        value: &T,
        bind: B,
    ) -> Self {
        let digest = Self::digest_of(c, value, bind).disclose_as::<L>(c);
        Commit {
            digest,
            _t: PhantomData,
        }
    }

    /// Assert that `value` (a FRESH witness on the settle side) is what this
    /// commitment was made to, for this request.
    pub fn open<B: CommitBinding>(
        &self,
        c: &mut Circuit3,
        value: &T,
        bind: B,
        message: &'static str,
    ) {
        let recomputed = Self::digest_of(c, value, bind);
        let stored = self.digest.private();
        c.assert(
            eq(recomputed.hi, stored.hi)
                .and(eq(recomputed.lo, stored.lo))
                .message(message),
        );
    }
}

impl<T, Tag> ProofWires for Commit<T, Tag> {
    fn push_wires(&self, out: &mut Vec<Val>) {
        self.digest.push_wires(out)
    }
}

impl<T, Tag> LedgerRepr for Commit<T, Tag> {
    fn atoms() -> Vec<minocrab::AlignmentAtom> {
        <B32<Public> as LedgerRepr>::atoms()
    }

    fn push_limbs(&self, c: &mut Circuit3, limbs: &mut Vec<Wire3<FieldT, Public>>) {
        LedgerRepr::push_limbs(&self.digest, c, limbs)
    }

    fn from_limbs(limbs: Vec<Wire3<FieldT, Public>>) -> Self {
        Commit {
            digest: B32::from_limbs(limbs),
            _t: PhantomData,
        }
    }
}

// ---- the owned environment ----------------------------------------------------

/// "ONLY THE ORIGINAL CALLER MAY REFUND", as an environment wrapper.
///
/// [`Pending::request_owned`] witnesses the caller's secret key and commits
/// it bound to the request id; [`Pending::refund_to_owner`] witnesses a
/// FRESH secret and opens the commitment. [`Pending::complete`] has no
/// method that consumes a secret at all — which is the point: the deployed
/// vault's Gap 2 (a `completeWithdraw` that hoists a secret witness for a
/// refund branch it may not take) is not writable on this API.
pub struct Owned<E> {
    /// The caller, as a commitment bound to this request.
    pub owner: Commit<SecretKey<Private>, OwnerTag>,
    /// Whatever else the settle side needs.
    pub inner: E,
}

impl<E: ProofWires> ProofWires for Owned<E> {
    fn push_wires(&self, out: &mut Vec<Val>) {
        self.owner.push_wires(out);
        self.inner.push_wires(out);
    }
}

impl<E: LedgerRepr> LedgerRepr for Owned<E> {
    fn atoms() -> Vec<minocrab::AlignmentAtom> {
        let mut atoms = <Commit<SecretKey<Private>, OwnerTag> as LedgerRepr>::atoms();
        atoms.extend(E::atoms());
        atoms
    }

    fn push_limbs(&self, c: &mut Circuit3, limbs: &mut Vec<Wire3<FieldT, Public>>) {
        LedgerRepr::push_limbs(&self.owner, c, limbs);
        LedgerRepr::push_limbs(&self.inner, c, limbs);
    }

    fn from_limbs(limbs: Vec<Wire3<FieldT, Public>>) -> Self {
        let mut limbs = limbs.into_iter();
        let owner = <Commit<SecretKey<Private>, OwnerTag> as LedgerRepr>::from_limbs(
            limbs
                .by_ref()
                .take(repr_limbs::<Commit<SecretKey<Private>, OwnerTag>>())
                .collect(),
        );
        Owned {
            owner,
            inner: E::from_limbs(limbs.collect()),
        }
    }
}

// ---- the slot -----------------------------------------------------------------

/// A suspended EVM CALL: two ledger fields (the MPC-facing record map and
/// the caller's environment map) plus the block's [`Signet`] configuration,
/// typed by the call it makes.
///
/// `F` IS THE FILING, not the call: the call plus the output schema this
/// deployment files it under ([`Filed<Call, Schema>`](crate::evm::Filed) for
/// the one-line case). Two slots of one block may file the same Solidity
/// function under two schemas — or under the SAME schema — and their tickets
/// still do not unify, because the ticket is typed by the filing.
///
/// `WORDS` is the record's calldata capacity. Stable Rust cannot write
/// `EventRecordV1<{ <Call::Args as AbiTuple>::WORDS }, _>`
/// (`generic_const_exprs`), so the number is NAMED and CHECKED — an
/// inline-`const` assert in the constructor makes a mismatch an
/// `error[E0080]` (notes/evm-calls.org §3).
///
/// The `Signet` handle is built by `#[derive(Ledger)]`, which finds the
/// block's one `Signet` field and threads its offset in
/// ([`Self::at_block_with_signet`]). That is why `request`, `complete` and
/// `refund` take no `&SELF.signet`.
pub struct Pending<F: Filing, Env, const WORDS: usize = 2> {
    records: LedgerMap<RequestId<Public>, Record<F, WORDS>>,
    envs: LedgerMap<RequestId<Public>, Env>,
    signet: Signet,
    _filing: PhantomData<fn() -> F>,
}

impl<F: Filing, Env, const WORDS: usize> Pending<F, Env, WORDS> {
    /// The slot's two fields from flat index `start`, against the block's
    /// `Signet` at `signet_start` — what `#[derive(Ledger)]` emits for a
    /// field whose type is spelled `Pending`.
    pub const fn at_block_with_signet(total: usize, start: usize, signet_start: usize) -> Self {
        const {
            assert!(
                WORDS == <<Called<F> as EvmCall>::Args as AbiTuple>::WORDS,
                "`Pending<F, Env, WORDS>` needs WORDS == <F::Call::Args as \
                 AbiTuple>::WORDS — the record's calldata capacity IS the \
                 call's argument-word count. Stable Rust cannot infer it \
                 (generic_const_exprs), so name the number the argument \
                 tuple encodes to."
            )
        }
        Pending {
            records: LedgerMap::at_block(total, start),
            envs: LedgerMap::at_block(total, start + 1),
            signet: Signet::at_block(total, signet_start),
            _filing: PhantomData,
        }
    }

    /// The record map's ledger path: the notification's `depth ‖ path`.
    pub const fn record_path(&self) -> FieldPath {
        self.records.field_path()
    }
}

// ---- the fire-and-forget slot -------------------------------------------------

/// A CALL THAT IS NEVER SETTLED — Sig Network's fire-and-forget shape (the
/// vault's `approveRouter` and `approveStata`): ONE ledger field, the record
/// map, and [`Fired::request_with`] as its only operation.
///
/// No settle method exists, so "nothing settles this slot" is a fact about
/// the TYPE rather than a convention: there is no `Succeeded<F>` any circuit
/// of the contract can consume, and the record entry is never removed. An
/// attestation for one of these requests is a message nobody has a circuit
/// for, which is the intent.
pub struct Fired<F: Filing, const WORDS: usize = 2> {
    records: LedgerMap<RequestId<Public>, Record<F, WORDS>>,
    signet: Signet,
    _filing: PhantomData<fn() -> F>,
}

impl<F: Filing, const WORDS: usize> Fired<F, WORDS> {
    /// The slot's one field at flat index `start`, against the block's
    /// `Signet` at `signet_start` — what `#[derive(Ledger)]` emits for a
    /// field whose type is spelled `Fired`.
    pub const fn at_block_with_signet(total: usize, start: usize, signet_start: usize) -> Self {
        const {
            assert!(
                WORDS == <<Called<F> as EvmCall>::Args as AbiTuple>::WORDS,
                "`Fired<F, WORDS>` needs WORDS == <F::Call::Args as \
                 AbiTuple>::WORDS — the record's calldata capacity IS the \
                 call's argument-word count. Stable Rust cannot infer it \
                 (generic_const_exprs), so name the number the argument \
                 tuple encodes to."
            )
        }
        Fired {
            records: LedgerMap::at_block(total, start),
            signet: Signet::at_block(total, signet_start),
            _filing: PhantomData,
        }
    }

    /// The record map's ledger path: the notification's `depth ‖ path`.
    pub const fn record_path(&self) -> FieldPath {
        self.records.field_path()
    }

    /// File the call and notify the MPC; nothing is kept for a settle.
    /// Discloses `signet_flow::Requested`.
    ///
    /// The shape is [`Pending::request_with`]'s minus the environment: the
    /// callee and the arguments are builders, so a ledger read emits where
    /// the circuit reads it, and `signer` answers whose key signs.
    pub fn request_with<I: Extends<Callee<F>>>(
        &self,
        c: &mut Circuit3,
        callee: impl FnOnce(&mut Circuit3) -> Contract<I>,
        args: impl AbiArgs<<Called<F> as EvmCall>::Args>,
        envelope: Envelope,
        nonce: Uint<64>,
        signer: impl FnOnce(&mut Circuit3) -> Signing,
    ) -> RequestId<Public> {
        let tx = build_tx_with::<Called<F>, WORDS>(
            c,
            |c| callee(c).address,
            args,
            envelope,
            nonce.field(),
            F::GAS_LIMIT,
        );
        let signing = signer(c);
        file_request::<WORDS, F::Schema>(
            c,
            &self.signet,
            &self.records,
            SignRequest { signing, tx },
            <<Called<F> as EvmCall>::Args as AbiTuple>::WORDS,
            |_, _| {},
        )
    }
}

impl<F: Filing, const WORDS: usize> LedgerWidth for Fired<F, WORDS> {}

impl<F: Filing, Env, const WORDS: usize> LedgerWidth for Pending<F, Env, WORDS> {
    const WIDTH: usize = 2;
}

impl<F: Filing, Env: LedgerRepr, const WORDS: usize> Pending<F, Env, WORDS>
where
    Returned<F>: AbiReturn,
{
    /// FILE THE CALL. Builds `F::Call`'s transaction from the callee and the
    /// argument tuple, files the signing record under `F::Schema`, stores the
    /// environment beside it and notifies the singleton with this slot's own
    /// ledger path. Returns the disclosed request id, and discloses
    /// `signet_flow::Requested` plus whatever `env` discloses.
    ///
    /// THE CALLEE IS TYPED BY ITS INTERFACE: any `Contract<I>` whose `I`
    /// [`Extends`] the call's own [`EvmCall::Callee`] is accepted, and
    /// nothing else is.
    ///
    /// `nonce` is still the CALLER'S: the prover picks the EVM nonce, which
    /// is why [`Outbox`] exists (the nonce it assigns is the ledger's, and
    /// the circuit never reads it). The MPC key version is no longer an
    /// argument at all — it is `Signet::mpc_key_version`, the home
    /// notes/evm-calls.org §7 was looking for.
    pub fn request(
        &self,
        c: &mut Circuit3,
        callee: Contract<impl Extends<Callee<F>>>,
        args: <<Called<F> as EvmCall>::Args as AbiTuple>::Wires<Private>,
        nonce: Uint<64>,
        env: impl FnOnce(&mut Circuit3, RequestId<Public>) -> Env,
    ) -> RequestId<Public> {
        let tx = build_tx_filed::<F, WORDS>(c, callee.address, args, nonce.field());
        self.file(c, tx, env)
    }

    /// FILE THE CALL WITH ETHER ATTACHED — [`Self::request`] for a
    /// [`Payable`] call, whose transaction's `value` field is a real amount
    /// rather than the constant zero.
    ///
    /// `Called<F>: Payable` is the gate, and it is a MISSING TRAIT IMPL for
    /// every other call in the library: an amount cannot be handed to an
    /// `erc20::Transfer`, which would ignore it and send the ether nowhere
    /// (notes/evm-interfaces.org §5). WETH's
    /// [`weth::Deposit`](crate::evm::weth::Deposit) is the one call that
    /// has the impl, and the ether IS its argument — `deposit()` has no
    /// calldata beyond the selector.
    ///
    /// Everything else is [`Self::request`]: the same callee bound, the
    /// same environment, the same record, the same disclosures. A payable
    /// call filed through `request` instead carries no ether, which is what
    /// Solidity means by payable — the type does not force an amount, it
    /// forbids one where there is nowhere for it to go.
    ///
    /// The ether comes from the CONTRACT's derived EVM account — the one the
    /// MPC signs for — so a contract that files this must have ether there,
    /// which this API can no more check than it can check a token balance.
    #[allow(clippy::too_many_arguments)]
    pub fn request_payable(
        &self,
        c: &mut Circuit3,
        callee: Contract<impl Extends<Callee<F>>>,
        args: <<Called<F> as EvmCall>::Args as AbiTuple>::Wires<Private>,
        value: Uint<128, Private>,
        nonce: Uint<64>,
        env: impl FnOnce(&mut Circuit3, RequestId<Public>) -> Env,
    ) -> RequestId<Public>
    where
        Called<F>: Payable,
    {
        let tx = build_tx_payable_filed::<F, WORDS>(c, callee.address, args, value, nonce.field());
        self.file(c, tx, env)
    }

    /// The shared tail of [`Self::request`] and [`Self::request_payable`]:
    /// the contract's own signing path, the record filed under this slot's
    /// output schema, and the environment stored beside it.
    fn file(
        &self,
        c: &mut Circuit3,
        tx: EvmTx<WORDS>,
        env: impl FnOnce(&mut Circuit3, RequestId<Public>) -> Env,
    ) -> RequestId<Public> {
        let signing = Signing::contract(c);
        file_request::<WORDS, F::Schema>(
            c,
            &self.signet,
            &self.records,
            SignRequest { signing, tx },
            <<Called<F> as EvmCall>::Args as AbiTuple>::WORDS,
            |c, request_id| {
                // The environment is built AFTER the id exists, so a
                // `Commit` in it binds to this request and no other.
                let env = env(c, request_id);
                self.envs.insert(c, &request_id, &env);
            },
        )
    }

    /// [`Self::request`] WITH THE THREE THINGS A DEPLOYED LINEAGE CANNOT LET
    /// THE SLOT CHOOSE — the shape the vault's seventeen circuits need, and
    /// the one `request` is the convenience wrapper over.
    ///
    /// - `callee` and `args` are BUILDERS ([`AbiArgs`]), not values, so a
    ///   ledger read emits exactly where the circuit reads it: `supply` reads
    ///   `vaultEvmAddress` between its two argument words, `approveStata`
    ///   reads its callee after the gas constants. Building them up front
    ///   would move those instructions.
    /// - `envelope` is the fee envelope: [`Envelope::fixed`] for a contract
    ///   that pays its own way, [`Envelope::caller`] for the vault's
    ///   `deposit`, whose transaction is paid from the DEPOSITOR's EVM
    ///   account and whose three gas numbers are therefore circuit arguments.
    /// - `signer` runs AFTER the transaction and BEFORE the record is filed,
    ///   and answers "whose key signs this": it returns a [`Signing`] — the
    ///   path, and whether the reserved-path assert is emitted for it — and
    ///   whatever else the environment will need. That is where the vault
    ///   witnesses the secret its refund commitment is made to — after the
    ///   transaction, which is where its deployed stream has it — and where
    ///   `deposit` names the depositor's own commitment as the path instead
    ///   of the contract's.
    ///
    /// A REQUEST STILL CANNOT NAME AN ARBITRARY PATH FROM ITS INPUTS in any
    /// useful sense: the path is built by contract code here, not read off an
    /// argument. `deposit`'s per-user path is a commitment the same circuit
    /// just derived from a witnessed secret.
    #[allow(clippy::too_many_arguments)]
    pub fn request_with<S, I: Extends<Callee<F>>>(
        &self,
        c: &mut Circuit3,
        callee: impl FnOnce(&mut Circuit3) -> Contract<I>,
        args: impl AbiArgs<<Called<F> as EvmCall>::Args>,
        envelope: Envelope,
        nonce: Uint<64>,
        signer: impl FnOnce(&mut Circuit3) -> (Signing, S),
        env: impl FnOnce(&mut Circuit3, RequestId<Public>, &S) -> Env,
    ) -> RequestId<Public> {
        let tx = build_tx_with::<Called<F>, WORDS>(
            c,
            |c| callee(c).address,
            args,
            envelope,
            nonce.field(),
            F::GAS_LIMIT,
        );
        let (signing, carried) = signer(c);
        file_request::<WORDS, F::Schema>(
            c,
            &self.signet,
            &self.records,
            SignRequest { signing, tx },
            <<Called<F> as EvmCall>::Args as AbiTuple>::WORDS,
            |c, request_id| {
                // The environment is built AFTER the id exists, so a
                // `Commit` in it binds to this request and no other.
                let env = env(c, request_id, &carried);
                self.envs.insert(c, &request_id, &env);
            },
        )
    }

    /// SETTLE A SUCCESS. Verifies the MPC's signature over the V1
    /// attestation digest at the call's attested WIDTH, asserts the verdict
    /// is `executed`, consumes record and environment — and then asserts the
    /// call's [`EvmCall::succeeded`] predicate over the decoded output.
    ///
    /// FOUR CHECKS, AND EACH ONE REJECTS A DIFFERENT LIE:
    ///
    /// - the signature binds the id, the height, the verdict, the width and
    ///   the output together, so none of them can be swapped;
    /// - `outputKind == executed` rejects an attestation that says the
    ///   transaction reverted or never mined — where the `fff3421c` lineage
    ///   had a kind BYTE to compare, V1 has the MPC's verdict;
    /// - the record entry must be in THIS slot's map, which is what binds an
    ///   attestation to the slot that filed the request (the kind byte's old
    ///   job, done by the ledger instead);
    /// - and the call's own predicate rejects a mined `transfer` that
    ///   returned `false` (notes/evm-calls.org §3: the spurious-completion
    ///   hole the deployed vault leaves open by putting a refund branch
    ///   inside its `completeWithdraw`).
    ///
    /// ANYONE MAY CALL IT: the attestation is the gate, and no secret is
    /// witnessed. Discloses `signet_flow::Settled`.
    pub fn complete(
        &self,
        c: &mut Circuit3,
        ticket: Succeeded<F>,
    ) -> Outcome<Env, <Called<F> as EvmCall>::Success> {
        let request_id = ticket.respond.request_id.disclose_as::<RequestIdSettled>(c);
        let block_height = ticket.respond.block_height.disclose_as::<BlockHeightSettled>(c);
        let output = ticket.output;

        c.region("signet flow: attestation", |c| {
            let key = self.signet.mpc_response_key.read(c);
            let limbs = <Returned<F> as AbiReturn>::limbs(&output);
            let valid = signet_v1::verify_respond_bidirectional_event_v1_at(
                c,
                <Returned<F> as AbiReturn>::LEN as u64,
                &limbs,
                &ticket.respond,
                key.point().private(),
            );
            c.assert_with(valid, Some("Invalid attestation signature"));
            let executed = c.constant(output_kind::EXECUTED).private();
            let is_executed = c.test_eq(ticket.respond.output_kind.field(), executed);
            c.assert_with(is_executed, Some("The attested call did not execute"));
        });

        let env = self.consume(c, request_id);
        let decoded = <Returned<F> as AbiReturn>::decode(c, &output);
        let succeeded = <Called<F> as EvmCall>::succeeded(c, &decoded);
        c.assert(succeeded.message("The attested call did not succeed"));

        Outcome {
            request_id,
            block_height,
            env,
            // The projection runs AFTER the assert, so nothing a caller can
            // read has escaped the check.
            output: <Called<F> as EvmCall>::map(c, decoded),
        }
    }

    /// SETTLE A NON-SUCCESS. Accepts the MPC's `failed` or `unviable`
    /// verdict — whose attested output is EMPTY — OR `executed` with the
    /// [`EvmCall::succeeded`] predicate false. Discloses
    /// `signet_flow::Settled`.
    ///
    /// THE TWO ACCEPTED ATTESTATIONS SIGN DIFFERENT PREIMAGES, and they
    /// differ in both the WIDTH and the limbs: a failed or unviable request
    /// has no return to decode, so the MPC attests zero bytes and the
    /// digest's `LEN` field is `0`, where an executed call's is the return's
    /// own width. Poseidon is not a stream, so one hash cannot cover both:
    /// the preimage is hashed BOTH ways, the field element is selected by the
    /// verdict, and the signature is verified ONCE
    /// ([`signet_v1::attestation_transient_hash_v1`]). The extra cost is one
    /// `transient_hash` and one `cond_select` beside the ~30k rows of the
    /// ECDSA verification that follows.
    ///
    /// The output slots are still DECODED in the failure arms, because a
    /// circuit has one instruction stream: a prover whose request failed
    /// supplies zeros, which satisfy the narrowing's range checks, and those
    /// bytes are outside the signed digest either way.
    pub fn refund(&self, c: &mut Circuit3, ticket: Failed<F>) -> Outcome<Env, Ret<Called<F>>> {
        let request_id = ticket.respond.request_id.disclose_as::<RequestIdSettled>(c);
        let block_height = ticket.respond.block_height.disclose_as::<BlockHeightSettled>(c);
        let output = ticket.output;

        let decoded = {
            let event = &ticket.respond;
            let limbs = <Returned<F> as AbiReturn>::limbs(&output);
            let (digest, is_executed) = c.region("signet flow: attestation", |c| {
                let executed_hash = signet_v1::attestation_transient_hash_v1(
                    c,
                    &event.request_id,
                    event.block_height.field(),
                    event.output_kind.field(),
                    <Returned<F> as AbiReturn>::LEN as u64,
                    &limbs,
                );
                let empty_hash = signet_v1::attestation_transient_hash_v1(
                    c,
                    &event.request_id,
                    event.block_height.field(),
                    event.output_kind.field(),
                    0,
                    &[],
                );
                let executed = c.constant(output_kind::EXECUTED).private();
                let is_executed = c.test_eq(event.output_kind.field(), executed);
                let digest = c.cond_select(is_executed, executed_hash, empty_hash);
                (upgrade_from_transient(c, digest), is_executed)
            });

            c.region("signet flow: attestation", |c| {
                let key = self.signet.mpc_response_key.read(c);
                let valid = signet_v1::verify_attestation_signature(
                    c,
                    &digest,
                    &Secp256k1SigLimbs {
                        big_r_x: event.signature.big_r.x,
                        s: event.signature.s,
                    },
                    key.point().private(),
                );
                c.assert_with(valid, Some("Invalid attestation signature"));

                // …and the verdict is one this slot refunds on: a
                // non-execution, or an execution the call calls a failure.
                let decoded = <Returned<F> as AbiReturn>::decode(c, &output);
                let succeeded = <Called<F> as EvmCall>::succeeded(c, &decoded);
                let not_executed = not(is_true(Bool::from_field_unchecked(is_executed)));
                let executed_and_failed =
                    is_true(Bool::from_field_unchecked(is_executed)).and(not(succeeded));
                c.assert(
                    not_executed
                        .or(executed_and_failed)
                        .message("Not a refundable outcome"),
                );
                decoded
            })
        };

        let env = self.consume(c, request_id);
        Outcome {
            request_id,
            block_height,
            env,
            output: decoded,
        }
    }

    /// Read and remove the record and the environment.
    ///
    /// THE MEMBERSHIP CHECK IS THE SLOT BINDING. A V1 record carries neither
    /// a response kind nor a format version — the two fields the `fff3421c`
    /// lineage re-asserted here — so what ties an attestation to this slot is
    /// that this slot's own record map holds its id, and that the attestation
    /// verified under a digest that commits to that id. A ticket for a
    /// request another slot filed finds nothing to consume.
    fn consume(&self, c: &mut Circuit3, request_id: RequestId<Public>) -> Assumed<Env> {
        c.region("signet flow: consume", |c| {
            let found = self.records.member(c, &request_id);
            c.assert(is_true(found).message("Request not found"));
            self.records.remove(c, &request_id);
            let env = self.envs.lookup(c, &request_id);
            self.envs.remove(c, &request_id);
            env
        })
    }
}

impl<F: Filing, E: LedgerRepr, const WORDS: usize> Pending<F, Owned<E>, WORDS>
where
    Returned<F>: AbiReturn,
{
    /// [`Pending::request`] with the caller's identity committed into the
    /// environment: the secret key is witnessed here and bound to the
    /// request id, and only a prover who can re-witness it may
    /// [`Self::refund_to_owner`].
    ///
    /// `L` labels the commitment in the disclosure inventory (it is stored,
    /// so it is public).
    pub fn request_owned<L: DisclosureLabel>(
        &self,
        c: &mut Circuit3,
        callee: Contract<impl Extends<Callee<F>>>,
        args: <<Called<F> as EvmCall>::Args as AbiTuple>::Wires<Private>,
        nonce: Uint<64>,
        inner: impl FnOnce(&mut Circuit3, RequestId<Public>) -> E,
    ) -> RequestId<Public> {
        let sk = common::witness_sk(c);
        self.request(c, callee, args, nonce, |c, request_id| Owned {
            owner: Commit::to::<L, _>(c, &sk, request_id),
            inner: inner(c, request_id),
        })
    }

    /// [`Pending::refund`] with the OWNER GATE: a fresh secret is witnessed
    /// and the stored commitment is opened against it, and the caller's own
    /// public key comes back as the recipient.
    ///
    /// `L` labels that public key. There is deliberately no `complete`
    /// counterpart — a completion never opens the commitment and never
    /// witnesses a secret.
    pub fn refund_to_owner<L: DisclosureLabel>(
        &self,
        c: &mut Circuit3,
        ticket: Failed<F>,
    ) -> (ZswapCoinPublicKey<Public>, Assumed<E>, Ret<Called<F>>) {
        let outcome = self.refund(c, ticket);
        let sk = common::witness_sk(c);
        outcome
            .env
            .owner
            .open(c, &sk, outcome.request_id, "Not the owner");
        let owner = own_public_key(c).disclose_as::<L>(c);
        (owner, outcome.env.map(|e| e.inner), outcome.output)
    }
}

// ---- the outbox: a request that does not choose its nonce -------------------------

label! {
    /// The pre-record a call files: the callee and the calldata words the
    /// emit will build a transaction from. Stored, so public — and no more
    /// public than a `Pending` request's calldata, which is disclosed into
    /// the record in the same way, one transaction later.
    pub QueuedRecordFiled = "queued pre-record";
}

/// Everything [`Outbox::call`] discloses, as one type — the label set a
/// call circuit declares, [`crate::signet_flow::Requested`]'s twin for the
/// write-side half of an outbox request. There is no notification and no
/// request id yet, so the record and the two cross-call labels are not in it.
pub type Inserted = (QueuedRecordFiled,);

/// THE OUTBOX KEY, and what the requester keeps: the Poseidon hash of the
/// pre-record (callee, calldata words) — content-derived, so unsquattable
/// and computed by anyone who knows the request; the request id MINUS the
/// nonce (notes/stream-design.org, "emit restored").
///
/// Two byte-identical requests share a handle, so the second is refused
/// while the first is between call and emit and accepted after: the
/// spec's C1 behaviour for identical payloads, one phase earlier. It is NOT
/// a request id and does not unify with one: an attestation settles a
/// `RequestId`, which includes the nonce the emit assigned.
///
/// Visibility-generic like the leaves, and like them `Private` by default:
/// an `emit` circuit takes a `Handle` argument and discloses it; the ledger
/// keys on `Handle<Public>`.
#[derive(Clone, Copy)]
pub struct Handle<V: Vis3 = Private>(Wire3<FieldT, V>);

impl<V: Vis3> Handle<V> {
    /// The hash, as a field element.
    pub fn value(self) -> Wire3<FieldT, V> {
        self.0
    }

    /// A handle from a field element already in hand. UNCHECKED: nothing
    /// ties it to a pre-record; [`PreRecord::handle`] is the constructor
    /// that does.
    pub fn from_field_unchecked(w: Wire3<FieldT, V>) -> Self {
        Handle(w)
    }
}

impl ProofWires for Handle<Public> {
    fn push_wires(&self, out: &mut Vec<Val>) {
        out.push(self.0.val());
    }
}

impl LedgerRepr for Handle<Public> {
    fn atoms() -> Vec<minocrab::AlignmentAtom> {
        vec![minocrab::AlignmentAtom::Field]
    }

    fn push_limbs(&self, _c: &mut Circuit3, limbs: &mut Vec<Wire3<FieldT, Public>>) {
        limbs.push(self.0);
    }

    fn from_limbs(limbs: Vec<Wire3<FieldT, Public>>) -> Self {
        assert_eq!(limbs.len(), 1, "a handle is one field limb");
        Handle(limbs[0])
    }
}

impl<V: Vis3> CircuitAbi for Handle<V> {
    const SLOTS: usize = 1;

    fn push_atoms(atoms: &mut Vec<minocrab::AlignmentAtom>) {
        atoms.push(minocrab::AlignmentAtom::Field);
    }

    fn push_prims(prims: &mut Vec<Prim>) {
        prims.push(Prim::Field);
    }
}

impl CircuitArg for Handle<Private> {
    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        Handle(c.arg::<FieldT>(path.as_str()))
    }

    fn push_slots(&self, slots: &mut Vec<Wire3<FieldT, Private>>) {
        slots.push(self.0);
    }
}

impl Disclose for Handle<Private> {
    type Public = Handle<Public>;

    fn disclose_as<L: DisclosureLabel>(self, c: &mut Circuit3) -> Handle<Public> {
        Handle(self.0.disclose_as::<L>(c))
    }
}

/// THE TRANSACTION MINUS ITS NONCE — what a call files and an emit turns
/// into a record.
///
/// Two fields, and they are exactly the two an emit cannot derive from the
/// call type: the callee and the encoded ABI words. Everything else in the
/// transaction is the CONTRACT'S — the selector, the word count and the gas
/// limit from [`EvmCall`], the fee envelope from the contract
/// (notes/nonce-admin.org §1.1: a requester picks neither a nonce nor a fee,
/// because an unminable transaction is a denial of service on every later
/// nonce of the path), the chain id and the MPC KEY VERSION from the
/// [`Signet`] block, and the nonce from the outbox's accumulator,
/// snapshotted at the call.
///
/// THE KEY VERSION WENT IN M44 RUNG D, with the argument that carried it: it
/// is `Signet::mpc_key_version`, a cell, read at the emit like the chain id.
/// So a pre-record is one limb shorter and a call one argument shorter.
pub struct PreRecord<const WORDS: usize>(Vec<Wire3<FieldT, Public>>);

impl<const WORDS: usize> PreRecord<WORDS> {
    /// One limb for the callee, two per word.
    pub const LIMBS: usize = 1 + 2 * WORDS;

    /// Assemble and DISCLOSE the pre-record: it is about to be stored, so
    /// every limb is public, and the label names them in the inventory.
    fn file(c: &mut Circuit3, callee: Bytes<20, Private>, words: &[B32<Private>]) -> Self {
        let mut limbs = vec![callee.field()];
        for word in words {
            limbs.push(word.hi);
            limbs.push(word.lo);
        }
        PreRecord(limbs.disclose_as::<QueuedRecordFiled>(c))
    }

    /// The [`Handle`]: a Poseidon hash over the disclosed limbs, computed
    /// once at the call (it has no k pressure) and again by whoever emits.
    pub fn handle(&self, c: &mut Circuit3) -> Handle<Public> {
        Handle(transient_hash_compact(c, &self.0))
    }

    fn callee(&self) -> Bytes<20, Private> {
        Bytes::from_field_unchecked(self.0[0].private())
    }

    fn words(&self) -> [B32<Private>; WORDS] {
        core::array::from_fn(|i| B32 {
            hi: self.0[1 + 2 * i].private(),
            lo: self.0[2 + 2 * i].private(),
        })
    }
}

impl<const WORDS: usize> ProofWires for PreRecord<WORDS> {
    fn push_wires(&self, out: &mut Vec<Val>) {
        out.extend(self.0.iter().map(|w| w.val()));
    }
}

impl<const WORDS: usize> LedgerRepr for PreRecord<WORDS> {
    fn atoms() -> Vec<minocrab::AlignmentAtom> {
        let mut atoms = <Bytes<20, Public> as LedgerRepr>::atoms();
        for _ in 0..WORDS {
            atoms.extend(<B32<Public> as LedgerRepr>::atoms());
        }
        atoms
    }

    fn push_limbs(&self, _c: &mut Circuit3, limbs: &mut Vec<Wire3<FieldT, Public>>) {
        limbs.extend_from_slice(&self.0);
    }

    fn from_limbs(limbs: Vec<Wire3<FieldT, Public>>) -> Self {
        assert_eq!(
            limbs.len(),
            Self::LIMBS,
            "a {WORDS}-word pre-record takes {} limbs",
            Self::LIMBS
        );
        PreRecord(limbs)
    }
}

/// ONE QUEUE ENTRY: the pre-record and the environment, in one map value.
///
/// They are stored together because they are inserted together, emitted
/// together and removed together — one `insert`, one `lookup`, one `remove`
/// rather than three of each, and no state in which a pre-record has lost
/// its environment.
pub struct QueueEntry<Env, const WORDS: usize> {
    /// The transaction minus its nonce.
    pub pre: PreRecord<WORDS>,
    /// What the settle side will need, moved verbatim into the `Pending`
    /// environment map under the request id at flush.
    pub env: Env,
}

impl<Env: ProofWires, const WORDS: usize> ProofWires for QueueEntry<Env, WORDS> {
    fn push_wires(&self, out: &mut Vec<Val>) {
        self.pre.push_wires(out);
        self.env.push_wires(out);
    }
}

impl<Env: LedgerRepr, const WORDS: usize> LedgerRepr for QueueEntry<Env, WORDS> {
    fn atoms() -> Vec<minocrab::AlignmentAtom> {
        let mut atoms = <PreRecord<WORDS> as LedgerRepr>::atoms();
        atoms.extend(Env::atoms());
        atoms
    }

    fn push_limbs(&self, c: &mut Circuit3, limbs: &mut Vec<Wire3<FieldT, Public>>) {
        LedgerRepr::push_limbs(&self.pre, c, limbs);
        LedgerRepr::push_limbs(&self.env, c, limbs);
    }

    fn from_limbs(limbs: Vec<Wire3<FieldT, Public>>) -> Self {
        let mut limbs = limbs.into_iter();
        let pre = <PreRecord<WORDS> as LedgerRepr>::from_limbs(
            limbs.by_ref().take(PreRecord::<WORDS>::LIMBS).collect(),
        );
        QueueEntry {
            pre,
            env: Env::from_limbs(limbs.collect()),
        }
    }
}

/// [`Owned`] FOR AN OUTBOX REQUEST: the commitment binds to the HANDLE,
/// because there is no request id when the request is made.
///
/// The handle is stored beside the commitment for one reason: the settle
/// side has only the request id, and the commitment does not open under it.
/// Carrying the handle in the environment is what lets a refund happen with
/// the requester never present at the emit (notes/nonce-admin.org §4(ii)).
pub struct HandleOwned<E> {
    /// The outbox key this request was filed under.
    pub handle: Handle<Public>,
    /// The requester, as a commitment bound to that handle.
    pub owner: Commit<SecretKey<Private>, OwnerTag>,
    /// Whatever else the settle side needs.
    pub inner: E,
}

impl<E: ProofWires> ProofWires for HandleOwned<E> {
    fn push_wires(&self, out: &mut Vec<Val>) {
        self.handle.push_wires(out);
        self.owner.push_wires(out);
        self.inner.push_wires(out);
    }
}

impl<E: LedgerRepr> LedgerRepr for HandleOwned<E> {
    fn atoms() -> Vec<minocrab::AlignmentAtom> {
        let mut atoms = <Handle<Public> as LedgerRepr>::atoms();
        atoms.extend(<Commit<SecretKey<Private>, OwnerTag> as LedgerRepr>::atoms());
        atoms.extend(E::atoms());
        atoms
    }

    fn push_limbs(&self, c: &mut Circuit3, limbs: &mut Vec<Wire3<FieldT, Public>>) {
        LedgerRepr::push_limbs(&self.handle, c, limbs);
        LedgerRepr::push_limbs(&self.owner, c, limbs);
        LedgerRepr::push_limbs(&self.inner, c, limbs);
    }

    fn from_limbs(limbs: Vec<Wire3<FieldT, Public>>) -> Self {
        let mut limbs = limbs.into_iter();
        let handle = <Handle<Public> as LedgerRepr>::from_limbs(
            limbs.by_ref().take(repr_limbs::<Handle<Public>>()).collect(),
        );
        let owner = <Commit<SecretKey<Private>, OwnerTag> as LedgerRepr>::from_limbs(
            limbs
                .by_ref()
                .take(repr_limbs::<Commit<SecretKey<Private>, OwnerTag>>())
                .collect(),
        );
        HandleOwned {
            handle,
            owner,
            inner: E::from_limbs(limbs.collect()),
        }
    }
}

mod outbox;

pub use outbox::{Emitted, HandleEmitted, Outbox, OutboxSpec, Outstanding};
