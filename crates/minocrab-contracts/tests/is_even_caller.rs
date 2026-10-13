//! M35 rung F — the idiot-proofing pass, made measurable.
//!
//! The MPC's own integration caller (`signet-midnight-integration`'s
//! test-caller-contract: `initialise`, `submitIsEvenRequest`, a verify
//! circuit; the shape `midnight_stream.rs` drives against a real cluster),
//! written here FROM THE PUBLIC API AND ITS DOCS ALONE — no vault code
//! consulted — with a log of every point a mistake was possible.
//!
//! THE MISTAKE LOG (what could have gone wrong, and what catches it):
//!
//! | # | the mistake                                              | caught by                                   |
//! |---|----------------------------------------------------------|---------------------------------------------|
//! | 1 | forgetting the `signet: Signet` slot in the block         | E0609: `request` needs `&Signet`, no field   |
//! | 2 | a settle circuit taking another slot's ticket             | E0308 (`Succeeded<Call>` carries the call)   |
//! | 3 | a response type that is not a Borsh record               | E0277 (`Attestable: CircuitBorsh`)           |
//! | 4 | two slot filings with one kind byte                       | E0080, prescriptive (`assert_distinct_kinds`)|
//! | 5 | capturing a private value in the environment             | E0277 (no `LedgerRepr` at `Private`)         |
//! | 6 | a `WORDS` that is not the call's argument-word count       | E0080, prescriptive (the slot's constructor) |
//! | 7 | hand-writing the notification's path bytes / depth        | impossible: derived from the slot            |
//! | 8 | hand-writing the record's kind / version / sender / chain | impossible: from the type and the context    |
//! | 9 | forgetting the freshness check, the nonce, the insert     | impossible: inside `request`                 |
//! |10 | forgetting the record's kind/version bind, the remove     | impossible: inside `complete`                |
//! |11 | reading the response before verifying it                 | impossible: `complete` is the constructor    |
//! |12 | declaring the wrong label set on a circuit               | the generated disclosure TEST (not compile)  |
//! |13 | forgetting `assert_initialised`                          | NOT CAUGHT — a business gate, by design      |
//! |14 | forgetting to check `output.result` after settling        | CAUGHT since M37 D: `EvmCall::succeeded`     |
//! |15 | `initialise` storing a response key the MPC won't derive  | NOT CAUGHT at build; `settle` fails to prove |
//! |16 | `initialise` leaving caip2 / chain id zero                | NOT CAUGHT at build; the MPC drops the record|
//! |17 | `key_version == 0`                                        | in-circuit assert (`construct_…_event_v2`)   |
//!
//! Hand-maintained invariants left per flow: 13, 14 (the two the design
//! keeps in the circuit) and the deployment facts 15, 16. Everything the
//! §7 table listed as hand-synchronised (kind, version, path bytes, the
//! map/env/nonce triple, the verify→kind→lookup→remove order) is gone.

use minocrab::v3::Circuit3;
use minocrab::{Private, Public};
use minocrab_contracts::common::SigningPath;
use minocrab_contracts::evm::{Envelope, EvmCall, Filing, Interface, U256};
use minocrab_contracts::evm_flow::{Contract, Pending, Succeeded};
use minocrab_contracts::signet_flow::{Requested, Settled, Signet, Signing};
use minocrab_sim::v3::cost;
use minocrab_std::v3::{
    circuit, is_true, label, Bool, Bytes, Check, Disclose, Discloses, Ledger, LedgerCounter,
    LedgerRepr, Secp256k1Point, Uint, B32,
};

/// THE CALLEE'S INTERFACE — the MPC's integration target, declared by this
/// contract in one line, which is what `trait Interface` being OPEN buys:
/// nothing in the library knows about this deployment, and a
/// `Contract<SignetEvmTarget>` still cannot be handed an ERC-20 `transfer`.
struct SignetEvmTarget;

impl Interface for SignetEvmTarget {}

/// `SignetEvmTarget.isEven(uint256) -> bool`.
///
/// The argument is a [`U256`] — an ALREADY-ENCODED word, which is what
/// the MPC's own caller passes (`argWord`), and whose encoder is the
/// identity.
struct IsEven;

impl EvmCall for IsEven {
    type Callee = SignetEvmTarget;
    const NAME: &'static str = "isEven";
    type Args = (U256,);
    type Return = minocrab_contracts::evm::Bool;
    type Success = Bool<Private>;
    const GAS_LIMIT: u64 = 100_000;

    fn succeeded(_c: &mut Circuit3, ok: &Bool<Private>) -> Check<Private> {
        is_true(*ok)
    }
}

minocrab_contracts::output_schema! {
    /// `[{"name":"result","type":"bool"}]` — the flag THIS deployment's
    /// records name `result`, not the library's `success`. The name is a
    /// fact about the protocol, and since M44 rung D it lives in the schema
    /// string the MPC decodes under, so declaring one here is the whole of
    /// what `RETURN_FIELD` used to say.
    pub struct Result = b"[{\"name\":\"result\",\"type\":\"bool\"}]";
}

/// HOW THIS CALLER FILES IT: under its own [`Result`] schema, because the
/// response record names the flag `result` rather than `success`. That is a
/// fact about THIS deployment's protocol, which is why it is here and not on
/// [`IsEven`] (M38 rung A, notes/evm-interfaces.org §1).
struct IsEvenResult;

impl Filing for IsEvenResult {
    type Call = IsEven;
    type Schema = Result;
}

/// What the verify circuit gets back: which argument was asked about.
#[derive(LedgerRepr)]
struct IsEvenEnv {
    argument: B32<Public>,
}

#[derive(Ledger)]
struct Caller {
    initialised: LedgerCounter,
    signet: Signet,
    is_even: Pending<IsEvenResult, IsEvenEnv, 1>,
}

const CALLER: Caller = Caller::new();

label! {
    ResponseKey = "the MPC response key";
    KeyVersion = "the MPC key version";
    ChainId = "the EVM chain id";
    Argument = "the isEven argument";
    Outcome = "the attested isEven result";
}

/// `keccak256("isEven(uint256)")[..4]` = `2a2e1320`, the four bytes in
/// order.
///
/// M37 rung D no longer writes this into the circuit —
/// [`EvmCall::selector`] hashes the signature — and
/// `the_selector_is_the_one_the_mpcs_caller_asks_for` below checks that the
/// hash is these bytes.
///
/// FOUND IN THE PORT, and worth saying: the hand-written circuit embedded
/// them as `c.constant(0x2a2e1320u64)`, i.e. BIG-endian in the field
/// element, where every differential-checked lineage in this workspace
/// embeds `Fr::from_le_bytes(selector)` — `erc20_vault`'s `TRANSFER_SELECTOR`
/// is pinned against compactc's own calldata that way. This file's contract
/// is a test caller with no on-chain twin, so the byte order was never
/// caught; the typed API gives it the checked one.
const IS_EVEN_SELECTOR: [u8; 4] = [0x2a, 0x2e, 0x13, 0x20];

fn assert_initialised(c: &mut Circuit3) {
    let n = CALLER.initialised.read(c);
    c.assert(n.gt(0u64).message("Not initialised"));
}

/// Pin the MPC response key (derived for this contract's address), the key
/// VERSION and the destination chain, once.
///
/// The caip2 id went with the V1 vocabulary (`executionDest` is the constant
/// `ethereumCaip2Id()`); the key version took its place as a cell, which is
/// why `submitIsEvenRequest` below no longer takes one.
#[circuit]
fn initialise(
    c: &mut Circuit3,
    response_key: Secp256k1Point,
    key_version: Uint<8>,
    chain_id: Uint<64>,
) -> Discloses<(ResponseKey, KeyVersion, ChainId)> {
    let n = CALLER.initialised.read(c);
    c.assert(n.eq(0u64).message("Already initialised"));
    CALLER.initialised.increment(c, 1);
    let key = response_key.disclose_as::<ResponseKey>(c);
    let key_version = key_version.disclose_as::<KeyVersion>(c);
    let chain_id = chain_id.disclose_as::<ChainId>(c);
    CALLER.signet.initialize(c, &key, &key_version, &chain_id);
    Discloses::of(())
}

/// `submitIsEvenRequest(evmNonce, to, argWord)`: ask the MPC to sign
/// `isEven(argWord)` to `to`, under a fixed gas envelope.
#[circuit]
fn submit_is_even_request(
    c: &mut Circuit3,
    evm_nonce: Uint<64>,
    to: Bytes<20>,
    arg_word: B32<Private>,
) -> Discloses<(Argument, Requested)> {
    assert_initialised(c);
    let argument = arg_word.disclose_as::<Argument>(c);
    CALLER.is_even.request_with(
        c,
        |c| Contract::<SignetEvmTarget>::from_address(c, to),
        (|_c: &mut Circuit3| arg_word,),
        Envelope::fixed(),
        evm_nonce,
        |c| {
            let path = SigningPath(B32::pad(c, "caller-path")).private();
            (Signing::derived(path), ())
        },
        |_c, _id, ()| IsEvenEnv { argument },
    );
    Discloses::of(())
}

/// `verifyResponse`: settle, and publish the attested result.
#[circuit]
fn verify_response(
    c: &mut Circuit3,
    ticket: Succeeded<IsEvenResult>,
) -> Discloses<(Settled, Outcome)> {
    assert_initialised(c);
    // `complete` asserts `IsEven::succeeded` — the attested flag itself —
    // so mistake 14 is no longer this circuit's to remember. What it still
    // chooses is whether to PUBLISH the answer, which it does.
    let outcome = CALLER.is_even.complete(c, ticket);
    let _asked_about = outcome.env.argument;
    let _result = outcome.output.field().disclose_as::<Outcome>(c);
    Discloses::of(())
}

/// `keccak256("isEven(uint256)")[..4]` as the typed call hashes it — the
/// four bytes the MPC's own caller asks for.
#[test]
fn the_selector_is_the_one_the_mpcs_caller_asks_for() {
    assert_eq!(IsEven::signature(), "isEven(uint256)");
    assert_eq!(IsEven::selector(), IS_EVEN_SELECTOR);
    // The non-circularity control: a signature this repository does not use
    // hashes to something else.
    assert_ne!(
        IsEven::selector(),
        {
            use sha3::Digest as _;
            let d = sha3::Keccak256::digest(b"isEven(uint64)");
            [d[0], d[1], d[2], d[3]]
        },
        "the spelling of the argument type is part of the selector"
    );
}

/// Six fields, flat: the request map at field 5, depth 1 — the MPC's
/// caller kept its map at field 4 "so the tests prove the MPC locates it via
/// the field position named in the notification"; here that position is
/// derived and this test states it. It moved down one at M44 rung D, when
/// `Signet` lost its request-nonce counter.
#[test]
fn the_request_map_is_where_the_notification_says() {
    assert_eq!(CALLER.is_even.record_path().as_slice(), &[5]);
    assert_eq!(CALLER.is_even.record_path().depth(), 1);
}

#[test]
fn the_three_circuits_build() {
    let (k_init, _) = cost(&initialise().ir);
    let (k_req, rows_req) = cost(&submit_is_even_request().ir);
    let (k_ver, rows_ver) = cost(&verify_response().ir);
    eprintln!("initialise k={k_init}; submit k={k_req} rows={rows_req}; verify k={k_ver} rows={rows_ver}");
    assert!(k_init <= 13 && k_req <= 14 && k_ver <= 15);
}
