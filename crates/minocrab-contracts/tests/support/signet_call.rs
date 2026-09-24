//! A Signet singleton call BUILT THE WAY THE LEDGER BUILDS IT (M29 rung C),
//! now through `minocrab-publisher` (M30 rung A).
//!
//! Every proof preimage the singleton's tests use comes from here, and this
//! module never assembles one by hand. The path is the production path:
//!
//! ```text
//! Impact program  ──partition_transcripts──▶  Transcript (gas, effects, version)
//!                                                    │
//! arguments as an AlignedValue ──────────────────────┤
//!                                                    ▼
//!                                       ContractCallPrototype
//!                                                    │
//!               Intent::add_call ──▶ communication_commitment
//!                                    ContractCallExt::construct_proof
//!                                    (ledger/src/construct.rs:515-573)
//!                                                    ▼
//!                                            ProofPreimage
//! ```
//!
//! That is exactly what `sig-net/mpc`'s TypeScript sidecar does through the
//! ledger-v9 WASM bindings (`midnight-publisher-ts/src/intent.ts`). Since
//! M30 rung A it is also LIBRARY code — `minocrab_publisher::call` — rather
//! than test code, so the preimage under test is the one the Rust publisher
//! produces, not a look-alike. What is left in this file is only what is
//! test-only: the fixed randomness, the fixed address, the deployment
//! helpers, and the limb arithmetic the construction gate checks the
//! ledger's own field vector against.
//!
//! The one thing NOT taken from the ledger is the Impact program itself
//! (`minocrab_publisher::call::log_ops`): in production it comes from
//! compactc's generated JS executor. `tests/signet_ledger_apply.rs` closes
//! that gap against `sig-net/mpc`'s captured on-chain transactions.

use midnight_base_crypto::fab::AlignedValue;
use midnight_base_crypto::hash::HashOutput;
use midnight_base_crypto::time::{Duration, Timestamp};
use midnight_coin_structure::contract::ContractAddress;
use midnight_ledger::construct::ContractCallPrototype;
use midnight_ledger::semantics::{TransactionContext, TransactionResult};
use midnight_ledger::structure::{
    ContractAction, ContractDeploy, Intent, LedgerState, ProofPreimageMarker,
    ProofPreimageVersioned, Signature, Transaction, INITIAL_PARAMETERS,
};
use midnight_ledger::verify::WellFormedStrictness;
use midnight_onchain_runtime::context::BlockContext;
use midnight_onchain_state::state::{ContractState, StateValue};
use midnight_onchain_vm::ops::Op;
use midnight_onchain_vm::result_mode::ResultModeVerify;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::Array;
use midnight_transient_crypto::commitment::PedersenRandomness;
use midnight_transient_crypto::proofs::{ProofPreimage, VerifierKey};
use minocrab::Fr;
use minocrab_publisher::call::{Attestation, EcdsaSignature};
use rand::rngs::StdRng;
use rand::SeedableRng;

// The FAB primitives, the Impact program, the empty contract state, the
// operation constructor and the prototype builder all live in the publisher
// crate now; re-exported under their old names so the suites that import them
// from `support::signet_call` read unchanged.
pub use minocrab_publisher::call::{empty_state, log_ops, operation, SIGNER_CIRCUITS};
pub use minocrab_publisher::call::Attestation as RespondAttestation;
pub use minocrab_publisher::fab::{bytesn_value, cell, scalar_input};

pub type VmOp = Op<ResultModeVerify, InMemoryDB>;
pub type PreimageIntent = Intent<Signature, ProofPreimageMarker, PedersenRandomness, InMemoryDB>;

/// The communication-commitment randomness every singleton call in the test
/// suite is built with. FIXED, not sampled: the benchmark harness reads the
/// preimages these tests dump (`support::dump_preimage`), so a preimage has
/// to be reproducible across runs. A publisher samples it per call, which is
/// why the library takes it as an argument.
pub const COMM_RAND: u64 = 0x516_e37;

/// The seed for the intent's binding randomness, for the same reason.
const INTENT_SEED: u64 = 0x5169_6e65_7400;

/// The address the tests deploy the singleton at. Arbitrary and fixed; the
/// real one differs per deployment and is not part of the proven statement
/// (it enters only through `binding_input`, which `construct_proof` leaves
/// at zero and proving overwrites).
pub const SINGLETON_ADDRESS_BYTES: [u8; 32] = [0x5a; 32];

pub fn singleton_address() -> ContractAddress {
    ContractAddress(HashOutput(SINGLETON_ADDRESS_BYTES))
}

// ---- limb arithmetic, the construction gate's second reading ---------------

/// A `Bytes<32>`'s two FAB slots: hi = byte 31, lo = bytes 0..31 LE.
pub fn b32_slots(bytes: &[u8; 32]) -> (Fr, Fr) {
    (
        Fr::from(u64::from(bytes[31])),
        Fr::from_le_bytes(&bytes[..31]).expect("31 bytes fit"),
    )
}

/// A `Bytes<128>`'s five FAB slots: 31-byte chunks from the front, limb 0
/// the trailing leftover.
pub fn b128_limbs(bytes: &[u8; 128]) -> Vec<Fr> {
    let mut chunks: Vec<&[u8]> = bytes.chunks(31).collect();
    chunks.reverse();
    chunks
        .into_iter()
        .map(|c| Fr::from_le_bytes(c).expect("31 bytes fit"))
        .collect()
}

// ---- the call --------------------------------------------------------------

/// One singleton call, as a [`ContractCallPrototype`] —
/// `minocrab_publisher::call::call_prototype` with this suite's fixed
/// randomness and `INITIAL_PARAMETERS`.
///
/// The parameters are the publisher's argument, not its constant (M30 A);
/// `INITIAL_PARAMETERS` is what these gates have always partitioned against
/// and what their pinned preimages carry, so it is spelled out HERE, once.
pub fn call_prototype(
    entry_point: &str,
    address: ContractAddress,
    input: AlignedValue,
    misc_bytes: &[u8],
) -> ContractCallPrototype<InMemoryDB> {
    minocrab_publisher::call::call_prototype(
        entry_point,
        address,
        &empty_state(),
        &INITIAL_PARAMETERS,
        input,
        misc_bytes,
        Fr::from(COMM_RAND),
    )
    .expect("the singleton's Push+Log program partitions")
}

/// The prototypes as one [`Intent`] — `Intent::new` folds each through
/// `add_call::<ProofPreimage>`, which computes the communication commitment
/// and calls `ContractCallExt::construct_proof`.
pub fn call_intent(protos: Vec<ContractCallPrototype<InMemoryDB>>, ttl: Timestamp) -> PreimageIntent {
    let mut rng = StdRng::seed_from_u64(INTENT_SEED);
    Intent::new(&mut rng, None, None, protos, vec![], vec![], None, ttl)
}

/// The default TTL the tests build intents with: an hour past the block time
/// they apply at, the same margin `midnight_ledger::test_utilities`'
/// `test_intents` uses.
pub fn ttl(tblock: Timestamp) -> Timestamp {
    tblock + Duration::from_secs(3600)
}

/// Every `ContractCall` in an intent, in order.
pub fn calls_of(
    intent: &PreimageIntent,
) -> Vec<midnight_ledger::structure::ContractCall<ProofPreimageMarker, InMemoryDB>> {
    intent
        .actions
        .iter_deref()
        .filter_map(|action| match action {
            ContractAction::Call(call) => Some((**call).clone()),
            _ => None,
        })
        .collect()
}

/// THE construction gate's subject: the ledger's own `ProofPreimage` for one
/// singleton call.
///
/// Built by putting the prototype through `Intent::new` and reading the
/// preimage back out of the resulting `ContractCall`, so the bytes under
/// test are the ones a real intent carries — not a reconstruction of what
/// `construct_proof` would have said.
pub fn call_preimage(entry_point: &str, input: AlignedValue, misc_bytes: &[u8]) -> ProofPreimage {
    let proto = call_prototype(entry_point, singleton_address(), input, misc_bytes);
    let intent = call_intent(vec![proto], ttl(Timestamp::from_secs(0)));
    let calls = calls_of(&intent);
    assert_eq!(calls.len(), 1, "one prototype makes one call");
    match &calls[0].proof {
        ProofPreimageVersioned::V2(pi) => (**pi).clone(),
        // `#[non_exhaustive]` upstream: a variant added by a ledger bump is a
        // preimage shape this suite has never seen, and the honest answer is
        // to stop rather than to guess at it (notes/version-bump.org).
        other => panic!("unknown ProofPreimageVersioned variant: {other:?}"),
    }
}

// ---- deploying the singleton and applying a call ---------------------------

/// One of the COMMITTED managed verifier keys (M29 rung A:
/// `crates/signet-artifacts/managed/keys/<circuit>.verifier`, written by the
/// pinned `zkir-v3`'s keygen and gated byte-for-byte by `signet-artifacts`'
/// `generated_equals_committed`).
///
/// Read by path rather than through the `signet-artifacts` crate: that crate
/// depends on `minocrab-contracts`, so depending back on it — even as a
/// dev-dependency — would make the graph harder to read than a path join
/// deserves.
pub fn managed_verifier_key(circuit: &str) -> VerifierKey {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../signet-artifacts/managed/keys")
        .join(format!("{circuit}.verifier"));
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    midnight_serialize::tagged_deserialize(&mut &bytes[..])
        .unwrap_or_else(|e| panic!("{} is a tagged VerifierKey: {e}", path.display()))
}

/// The singleton as this repo would deploy it: NO ledger fields (all three
/// signer circuits are stateless), one operation per circuit under whatever
/// verifier key `key` supplies.
pub fn singleton_contract_state(
    key: impl Fn(&str) -> Option<VerifierKey>,
) -> ContractState<InMemoryDB> {
    let mut operations = midnight_storage::storage::HashMap::new();
    for circuit in SIGNER_CIRCUITS {
        operations = operations.insert(circuit.as_bytes().into(), operation(key(circuit)));
    }
    ContractState::new(StateValue::Array(Array::new()), operations, Default::default())
}

/// Balancing and limits OFF: there is no DUST wallet anywhere in this
/// workspace (notes/mpc-publisher.org §2 names that as the gap M30 C
/// closes), and none of these transactions carries a zswap offer.
pub fn unbalanced_strictness() -> WellFormedStrictness {
    let mut s = WellFormedStrictness::default();
    s.enforce_balancing = false;
    s.enforce_limits = false;
    s
}

pub fn tx_context(
    ledger: &LedgerState<InMemoryDB>,
    tblock: Timestamp,
) -> TransactionContext<InMemoryDB> {
    TransactionContext {
        ref_state: ledger.clone(),
        block_context: BlockContext { tblock, ..BlockContext::default() },
        whitelist: None,
    }
}

/// One intent, at segment 1, as a proof-preimage transaction on
/// `local-test`.
pub fn preimage_tx(
    intent: PreimageIntent,
) -> Transaction<Signature, ProofPreimageMarker, PedersenRandomness, InMemoryDB> {
    Transaction::from_intents(
        "local-test",
        midnight_storage::storage::HashMap::new().insert(1, intent),
    )
}

/// `ContractDeploy` the singleton into a fresh `LedgerState`, `well_formed`
/// it and `apply` it — the state a respond call is then made against.
pub fn deploy_singleton(
    state: ContractState<InMemoryDB>,
    tblock: Timestamp,
) -> (LedgerState<InMemoryDB>, ContractAddress) {
    let ledger: LedgerState<InMemoryDB> = LedgerState::new("local-test");
    let mut rng = StdRng::seed_from_u64(0x5369_676e_6574);
    let deploy = ContractDeploy::new(&mut rng, state);
    let address = deploy.address();
    let tx = preimage_tx(call_intent(vec![], ttl(tblock)).add_deploy(deploy));
    let vtx = tx
        .well_formed(&ledger, unbalanced_strictness(), tblock)
        .expect("the singleton deploy is well formed");
    let (after, result) = ledger.apply(&vtx, &tx_context(&ledger, tblock));
    assert!(
        matches!(result, TransactionResult::Success(_)),
        "the singleton deploy must apply: {result:?}"
    );
    assert!(after.index(address).is_some(), "the singleton is in the state after the deploy");
    (after, address)
}

/// The 288-byte Misc envelope of a respond-shaped event —
/// `minocrab_publisher::call::respond_misc`, with the signature's four fields
/// spread out the way this suite's call sites (and its tamper twins) hold
/// them.
pub fn respond_misc(
    name: &str,
    request_id: &[u8; 32],
    big_r_x: &[u8; 32],
    big_r_y: &[u8; 32],
    s: &[u8; 32],
    recovery_id: u8,
) -> Vec<u8> {
    minocrab_publisher::call::respond_misc(name, request_id, &signature(big_r_x, big_r_y, s, recovery_id))
}

/// A respond call's arguments with their COMPACT alignment: four
/// `Bytes<32>` then a one-byte `Uint<8>`.
pub fn respond_input(
    request_id: &[u8; 32],
    big_r_x: &[u8; 32],
    big_r_y: &[u8; 32],
    s: &[u8; 32],
    recovery_id: u8,
) -> AlignedValue {
    minocrab_publisher::call::respond_input(request_id, &signature(big_r_x, big_r_y, s, recovery_id))
}

/// `respondBidirectional`'s 288 Misc bytes (PR #127's layout) —
/// `minocrab_publisher::call::respond_bidirectional_misc`, with the signature
/// spread out as above.
pub fn respond_bidirectional_misc(
    request_id: &[u8; 32],
    attestation: &Attestation,
    big_r_x: &[u8; 32],
    big_r_y: &[u8; 32],
    s: &[u8; 32],
    recovery_id: u8,
) -> Vec<u8> {
    minocrab_publisher::call::respond_bidirectional_misc(
        minocrab_contracts::signet_contract::RESPOND_BIDIRECTIONAL_EVENT,
        request_id,
        attestation,
        &signature(big_r_x, big_r_y, s, recovery_id),
    )
}

/// `respondBidirectional`'s arguments with their COMPACT alignment: fourteen
/// field limbs.
pub fn respond_bidirectional_input(
    request_id: &[u8; 32],
    attestation: &Attestation,
    big_r_x: &[u8; 32],
    big_r_y: &[u8; 32],
    s: &[u8; 32],
    recovery_id: u8,
) -> AlignedValue {
    minocrab_publisher::call::respond_bidirectional_input(
        request_id,
        attestation,
        &signature(big_r_x, big_r_y, s, recovery_id),
    )
}

/// The attestation every bidirectional scenario in this suite uses: a
/// finalised height with all eight bytes live, the `failed` verdict (variant
/// 1, so a zero-vs-one confusion with `executed` is visible), a width that
/// is not the height, and a digest distinct from the id.
pub fn sample_attestation() -> Attestation {
    let mut digest = [0u8; 32];
    for (i, b) in digest.iter_mut().enumerate() {
        *b = 0xd1u8.wrapping_add((i as u8).wrapping_mul(29));
    }
    Attestation {
        block_height: 0x0102_0304_0506_0708,
        output_kind: 1,
        serialized_output_length: 0x0000_0000_0000_0020,
        digest,
    }
}

fn signature(
    big_r_x: &[u8; 32],
    big_r_y: &[u8; 32],
    s: &[u8; 32],
    recovery_id: u8,
) -> EcdsaSignature {
    EcdsaSignature { big_r_x: *big_r_x, big_r_y: *big_r_y, s: *s, recovery_id }
}
