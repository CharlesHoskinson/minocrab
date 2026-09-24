//! M30 rung A — THE PUBLIC SURFACE: one function per signer circuit.
//!
//! Each takes the values the MPC actually holds — a request id and a
//! signature (or a notification) — and returns everything a
//! [`ContractCallPrototype`] needs:
//!
//! | piece | here |
//! |---|---|
//! | the arguments, as an `AlignedValue` | [`SignerCall::input`] |
//! | the transcript ops (the Impact program) | [`SignerCall::ops`] |
//! | the key location: address, circuit id, verifier-key hash | [`SignerCall::key_location`] |
//!
//! and [`SignerCall::prototype`] folds them into the prototype itself, given
//! the two things that are NOT the publisher's to invent: the contract's
//! state and the chain's [`LedgerParameters`].
//!
//! This is M29 rung C's path made a library. `minocrab-contracts`'
//! `tests/support/signet_call.rs` now calls these functions, so the
//! construction, ledger-apply and real-proving gates run on the same
//! preimages, byte for byte, that they pinned before the move.
//!
//! # The parameters are an INPUT
//!
//! `partition_transcripts` computes the transcript's DECLARED gas against
//! whatever `LedgerParameters` it is handed, and M29 D measured the
//! consequence: the captured chain's respond transaction declares
//! `compute_time` 2.208 ms where a transcript partitioned against
//! `INITIAL_PARAMETERS` at our pin declares 1.303 ms. A publisher that
//! assumes `INITIAL_PARAMETERS` therefore declares the wrong cost on any
//! chain whose parameters have moved, and the failure mode is a rejected
//! transaction on chain, not a failing test here. So nothing in this crate
//! reaches for `INITIAL_PARAMETERS`: the parameters arrive as an argument,
//! and `LedgerState::parameters` is where a caller with a node gets them.

use std::borrow::Cow;

use midnight_base_crypto::fab::AlignedValue;
use midnight_base_crypto::hash::HashOutput;
use midnight_coin_structure::contract::ContractAddress;
use midnight_ledger::construct::{
    communication_commitment, partition_transcripts, ContractCallPrototype, PreTranscript,
};
use midnight_ledger::structure::LedgerParameters;
use midnight_onchain_runtime::context::QueryContext;
use midnight_onchain_state::state::{
    ChargedState, ContractOperation, ContractState, EntryPointBuf, StateValue,
};
use midnight_onchain_vm::ops::Op;
use midnight_onchain_vm::result_mode::ResultModeVerify;
use midnight_storage::db::{DB, InMemoryDB};
use midnight_storage::storage::Array;
use midnight_transient_crypto::curve::Fr;
use midnight_transient_crypto::proofs::{KeyLocation, VerifierKey};
use signet_protocol::circuits::{
    RESPOND_BIDIRECTIONAL_EVENT, SIGNATURE_RESPONDED_EVENT, SIGN_BIDIRECTIONAL_EVENT,
};
use signet_protocol::misc::{MISC_SIZE, MISC_TAG, MISC_VERSION};

use crate::error::PublishError;
use crate::fab::{bytesn_value, cell};

/// One Impact op stream, as the ledger's transcript machinery takes it.
pub type VmOp<D> = Op<ResultModeVerify, D>;

// ---- the circuits ----------------------------------------------------------

pub const SIGN_BIDIRECTIONAL: &str = "signBidirectional";
pub const RESPOND: &str = "respond";
pub const RESPOND_BIDIRECTIONAL: &str = "respondBidirectional";

/// The three signer circuits' COMPACT names — what the sidecar's `expectedVk`
/// table and `RESPOND_CIRCUITS` key by, what
/// `crates/signet-artifacts/managed/` names its files, and what the captured
/// on-chain transactions carry as entry points. NOT the Rust function names.
pub const SIGNER_CIRCUITS: [&str; 3] = [SIGN_BIDIRECTIONAL, RESPOND, RESPOND_BIDIRECTIONAL];

/// The event name a circuit's Misc envelope opens with — the 32-byte field
/// `sig-net/mpc`'s reader selects its `EmissionKind` on.
pub fn event_name(circuit: &str) -> Result<&'static str, PublishError> {
    match circuit {
        SIGN_BIDIRECTIONAL => Ok(SIGN_BIDIRECTIONAL_EVENT),
        RESPOND => Ok(SIGNATURE_RESPONDED_EVENT),
        RESPOND_BIDIRECTIONAL => Ok(RESPOND_BIDIRECTIONAL_EVENT),
        other => Err(PublishError::UnknownCircuit(other.to_string())),
    }
}

// ---- the key location ------------------------------------------------------

/// Lowercase hex, the spelling `hashVerifierKey` and
/// `encodeContractKeyLocation` use.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Where the proving key for one call lives: the deployed contract, the
/// circuit inside it, and the hash of the verifier key that contract's
/// operation carries.
///
/// This is the Rust twin of `@midnight-ntwrk/compact-js`'s
/// `ContractKeyLocation` (`dist/cjs/ContractKeyLocation.js`), which the
/// sidecar builds with `encodeContractKeyLocation({contractAddress,
/// circuitId, verifierKeyHash})` and its proof server parses back. The wire
/// spelling is
///
/// ```text
/// contract:<64-hex address>/<circuitId>?vk=<64-hex verifier key hash>
/// ```
///
/// and [`encode`](ContractKeyLocation::encode) reproduces it exactly,
/// including the three rejections that function makes.
///
/// # Which spelling goes into the preimage
///
/// [`key_location`](ContractKeyLocation::key_location) — the BARE circuit id —
/// is what this crate puts in a `ContractCallPrototype`, because that is what
/// M29 C pinned and what `crates/signet-artifacts/managed/` names its files.
/// The field is not part of the proven statement and does not survive proving
/// (a `Proof` carries no `key_location`), so it is a resolver-steering string
/// and nothing more; [`encoded_key_location`](ContractKeyLocation::encoded_key_location)
/// is the sidecar-compatible alternative for a resolver that wants the
/// address and the hash too, and [`crate::keys::ManagedDir`] accepts either.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractKeyLocation {
    pub contract_address: ContractAddress,
    pub circuit_id: String,
    pub verifier_key_hash: String,
}

impl ContractKeyLocation {
    /// The three checks `encodeContractKeyLocation` makes, made once, up
    /// front: a 64-char lowercase hex verifier-key hash, and a non-empty
    /// circuit id containing neither `/` nor `?`. (The address cannot fail —
    /// a `ContractAddress` is 32 bytes by construction.)
    pub fn new(
        contract_address: ContractAddress,
        circuit_id: impl Into<String>,
        verifier_key_hash: impl Into<String>,
    ) -> Result<ContractKeyLocation, PublishError> {
        let circuit_id = circuit_id.into();
        let verifier_key_hash = verifier_key_hash.into();
        if circuit_id.is_empty() || circuit_id.contains('/') || circuit_id.contains('?') {
            return Err(PublishError::KeyLocation(format!(
                "circuit id '{circuit_id}' must be non-empty and contain no '/' or '?'"
            )));
        }
        if !is_hex64(&verifier_key_hash) {
            return Err(PublishError::KeyLocation(format!(
                "verifier key hash '{verifier_key_hash}' must be 64 lowercase hex characters"
            )));
        }
        Ok(ContractKeyLocation { contract_address, circuit_id, verifier_key_hash })
    }

    /// `contract:<address>/<circuitId>?vk=<hash>` — compact-js's
    /// `encodeContractKeyLocation`, character for character.
    pub fn encode(&self) -> String {
        format!(
            "contract:{}/{}?vk={}",
            hex(&self.contract_address.0 .0),
            self.circuit_id,
            self.verifier_key_hash
        )
    }

    /// compact-js's `parseContractKeyLocation`: its regex is
    /// `^contract:([0-9a-f]{64})/([^/?]+)\?vk=([0-9a-f]{64})$`, and anything
    /// else is `undefined` there and an error here.
    pub fn parse(s: &str) -> Result<ContractKeyLocation, PublishError> {
        let bad = || PublishError::KeyLocation(format!("'{s}' is not a contract key location"));
        let rest = s.strip_prefix("contract:").ok_or_else(bad)?;
        let (address, rest) = rest.split_once('/').ok_or_else(bad)?;
        let (circuit_id, vk) = rest.split_once("?vk=").ok_or_else(bad)?;
        if !is_hex64(address) || !is_hex64(vk) || circuit_id.contains('/') || circuit_id.contains('?')
        {
            return Err(bad());
        }
        let mut raw = [0u8; 32];
        for (i, byte) in raw.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&address[i * 2..i * 2 + 2], 16).map_err(|_| bad())?;
        }
        ContractKeyLocation::new(ContractAddress(HashOutput(raw)), circuit_id, vk)
    }

    /// The `KeyLocation` this crate writes into a prototype: the bare circuit
    /// id. See the type's docs for why that, and not [`Self::encode`].
    pub fn key_location(&self) -> KeyLocation {
        KeyLocation(Cow::Owned(self.circuit_id.clone()))
    }

    /// The sidecar-compatible `KeyLocation`: the whole encoded location.
    pub fn encoded_key_location(&self) -> KeyLocation {
        KeyLocation(Cow::Owned(self.encode()))
    }
}

/// The deployed singleton a publisher builds calls against: its address, and
/// the verifier-key hash per circuit.
///
/// The hash table is the package's `expectedVk` — `{circuit ->
/// hashVerifierKey(<circuit>.verifier)}`, generated by
/// `crates/signet-artifacts` and checked by the sidecar's build and prove
/// paths before it will use a key. Carrying it here means a publisher can
/// make the same check: notes/mpc-publisher.org §5.2 is explicit that a lying
/// endpoint's respond call fails safe ONLY while that gate stays.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deployment {
    pub address: ContractAddress,
    /// Circuit id -> 64-hex verifier-key hash.
    pub expected_vk: std::collections::BTreeMap<String, String>,
}

impl Deployment {
    pub fn new(
        address: ContractAddress,
        expected_vk: impl IntoIterator<Item = (String, String)>,
    ) -> Deployment {
        Deployment { address, expected_vk: expected_vk.into_iter().collect() }
    }

    /// THE `expectedVk` GATE: every circuit in the table is an operation on
    /// `state` whose v3 verifier key hashes to the value the table records.
    ///
    /// This is `sig-net/mpc`'s `prover.ts` check
    /// (`hashVerifierKey(verifierKey) !== verifierKeyHash` before it will
    /// prove), moved to the side that matters more: `state` is what the NODE
    /// says the contract carries, and notes/mpc-publisher.org §5.2 makes this
    /// gate the reason a lying endpoint's respond call fails safe. Nothing in
    /// the publish path calls it automatically — the pure core has no node —
    /// so a caller with a contract state should, once per pinned read.
    pub fn check_deployed<D: DB>(
        &self,
        state: &ContractState<D>,
    ) -> Result<(), PublishError> {
        for (circuit, expected) in &self.expected_vk {
            let entry_point: EntryPointBuf = circuit.as_bytes().into();
            let op = state
                .operations
                .get(&entry_point)
                .ok_or_else(|| PublishError::UnknownCircuit(circuit.clone()))?;
            let vk = op.v3.as_ref().ok_or_else(|| PublishError::VerifierKeyMismatch {
                circuit: circuit.clone(),
                expected: expected.clone(),
                got: "no v3 verifier key on the deployed operation".to_string(),
            })?;
            let mut bytes = Vec::new();
            midnight_serialize::tagged_serialize(vk, &mut bytes).map_err(|e| {
                PublishError::Decode {
                    path: format!("the deployed operation for '{circuit}'"),
                    what: "VerifierKey",
                    message: e.to_string(),
                }
            })?;
            let got = signet_protocol::hash_verifier_key(&bytes);
            if &got != expected {
                return Err(PublishError::VerifierKeyMismatch {
                    circuit: circuit.clone(),
                    expected: expected.clone(),
                    got,
                });
            }
        }
        Ok(())
    }

    /// The key location for one circuit, or [`PublishError::UnknownCircuit`]
    /// if the deployment's table does not carry it.
    pub fn key_location(&self, circuit: &str) -> Result<ContractKeyLocation, PublishError> {
        let hash = self
            .expected_vk
            .get(circuit)
            .ok_or_else(|| PublishError::UnknownCircuit(circuit.to_string()))?;
        ContractKeyLocation::new(self.address, circuit, hash.clone())
    }
}

// ---- the arguments ---------------------------------------------------------

/// The signature the MPC produces: `{ bigR: { x, y }, s, recoveryId }`, the
/// shape both respond circuits take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EcdsaSignature {
    pub big_r_x: [u8; 32],
    pub big_r_y: [u8; 32],
    pub s: [u8; 32],
    pub recovery_id: u8,
}

/// The attestation half of `respondBidirectional`'s argument since
/// midnight-integration PR #127 (M43): what the MPC signs over besides the
/// request id — the finalised destination block, its verdict, the width of
/// the output it attests — and the digest the signature is over, carried so
/// a reader holding no output can check the signature.
///
/// `output_kind` is Compact's `enum OutputKind { executed, failed, unviable
/// }`, i.e. the variant INDEX (0, 1, 2); the circuit constrains it below 3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attestation {
    pub block_height: u64,
    pub output_kind: u8,
    pub serialized_output_length: u64,
    pub digest: [u8; 32],
}

/// `signBidirectional`'s second argument: `{ version: Uint<8>, payload:
/// Bytes<128> }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Notification {
    pub version: u8,
    pub payload: [u8; 128],
}

/// `pad(32, name)` followed by 256 zero bytes — the envelope every signer
/// event fills in.
///
/// # Panics
///
/// If `name` is longer than 32 bytes. The three names are contract
/// constants (22–25 bytes); a longer one is a change to the contract, caught
/// at the first test that builds an envelope, not a runtime input.
fn misc_with_name(name: &str) -> Vec<u8> {
    assert!(
        name.len() <= 32,
        "a Misc event name is padded into 32 bytes; '{name}' is {} bytes long",
        name.len()
    );
    let mut bytes = vec![0u8; MISC_SIZE];
    bytes[..name.len()].copy_from_slice(name.as_bytes());
    bytes
}

/// A respond event's 288 Misc bytes:
/// `pad(32, name)` ‖ requestId(32) ‖ x(32) ‖ y(32) ‖ s(32) ‖ recoveryId(1)
/// ‖ zeros(127).
pub fn respond_misc(name: &str, request_id: &[u8; 32], sig: &EcdsaSignature) -> Vec<u8> {
    let mut bytes = misc_with_name(name);
    bytes[32..64].copy_from_slice(request_id);
    bytes[64..96].copy_from_slice(&sig.big_r_x);
    bytes[96..128].copy_from_slice(&sig.big_r_y);
    bytes[128..160].copy_from_slice(&sig.s);
    bytes[160] = sig.recovery_id;
    bytes
}

/// A respond call's arguments with their COMPACT alignment: four `Bytes<32>`
/// then a one-byte `Uint<8>`. Nine field limbs.
pub fn respond_input(request_id: &[u8; 32], sig: &EcdsaSignature) -> AlignedValue {
    AlignedValue::concat([
        &bytesn_value(32, request_id),
        &bytesn_value(32, &sig.big_r_x),
        &bytesn_value(32, &sig.big_r_y),
        &bytesn_value(32, &sig.s),
        &bytesn_value(1, &[sig.recovery_id]),
    ])
}

/// `respondBidirectional`'s 288 Misc bytes (PR #127's layout):
/// `pad(32, name)` ‖ requestId(32) ‖ blockHeight LE(8) ‖ outputKind(1) ‖
/// serializedOutputLength LE(8) ‖ digest(32) ‖ x(32) ‖ y(32) ‖ s(32) ‖
/// recoveryId(1) ‖ zeros(78). The two `Uint<64>`s are `as Bytes<8>`, which
/// Compact spells little-endian.
pub fn respond_bidirectional_misc(
    name: &str,
    request_id: &[u8; 32],
    attestation: &Attestation,
    sig: &EcdsaSignature,
) -> Vec<u8> {
    let mut bytes = misc_with_name(name);
    bytes[32..64].copy_from_slice(request_id);
    bytes[64..72].copy_from_slice(&attestation.block_height.to_le_bytes());
    bytes[72] = attestation.output_kind;
    bytes[73..81].copy_from_slice(&attestation.serialized_output_length.to_le_bytes());
    bytes[81..113].copy_from_slice(&attestation.digest);
    bytes[113..145].copy_from_slice(&sig.big_r_x);
    bytes[145..177].copy_from_slice(&sig.big_r_y);
    bytes[177..209].copy_from_slice(&sig.s);
    bytes[209] = sig.recovery_id;
    bytes
}

/// `respondBidirectional`'s arguments with their COMPACT alignment, in the
/// struct's field order: `Bytes<32>`, `Uint<64>` (an eight-byte atom),
/// the enum (a one-byte atom), `Uint<64>`, `Bytes<32>`, then the signature's
/// four. Fourteen field limbs.
pub fn respond_bidirectional_input(
    request_id: &[u8; 32],
    attestation: &Attestation,
    sig: &EcdsaSignature,
) -> AlignedValue {
    AlignedValue::concat([
        &bytesn_value(32, request_id),
        &bytesn_value(8, &attestation.block_height.to_le_bytes()),
        &bytesn_value(1, &[attestation.output_kind]),
        &bytesn_value(8, &attestation.serialized_output_length.to_le_bytes()),
        &bytesn_value(32, &attestation.digest),
        &bytesn_value(32, &sig.big_r_x),
        &bytesn_value(32, &sig.big_r_y),
        &bytesn_value(32, &sig.s),
        &bytesn_value(1, &[sig.recovery_id]),
    ])
}

/// `signBidirectional`'s 288 Misc bytes:
/// `pad(32, name)` ‖ version(1) ‖ requestId(32) ‖ payload(128) ‖ zeros(95).
pub fn sign_bidirectional_misc(request_id: &[u8; 32], notification: &Notification) -> Vec<u8> {
    let mut bytes = misc_with_name(SIGN_BIDIRECTIONAL_EVENT);
    bytes[32] = notification.version;
    bytes[33..65].copy_from_slice(request_id);
    bytes[65..193].copy_from_slice(&notification.payload);
    bytes
}

/// `signBidirectional`'s arguments: `Bytes<32>`, `Uint<8>`, `Bytes<128>`.
/// Eight field limbs.
pub fn sign_bidirectional_input(
    request_id: &[u8; 32],
    notification: &Notification,
) -> AlignedValue {
    AlignedValue::concat([
        &bytesn_value(32, request_id),
        &bytesn_value(1, &[notification.version]),
        &bytesn_value(128, &notification.payload),
    ])
}

// ---- the transcript --------------------------------------------------------

/// The singleton's Impact program: one Misc event, `Push` + `Log`.
///
/// In the TypeScript stack this comes out of compactc's generated JS
/// executor. `minocrab-contracts`' `tests/signet_ledger_apply.rs` checks
/// these two ops, op for op, against the ones `sig-net/mpc`'s CAPTURED
/// on-chain respond transactions carry — which is what licenses writing them
/// here.
pub fn log_ops<D: DB>(misc_bytes: &[u8]) -> Vec<VmOp<D>> {
    vec![
        Op::Push {
            storage: false,
            value: StateValue::Array(
                vec![
                    cell(bytesn_value(4, &MISC_VERSION.to_le_bytes())),
                    cell(bytesn_value(1, &[MISC_TAG])),
                    cell(bytesn_value(MISC_SIZE as u32, misc_bytes)),
                ]
                .into(),
            ),
        },
        Op::Log,
    ]
}

/// The singleton's state: NO ledger fields — all three signer circuits are
/// stateless, so the state a call runs against is empty and identical for
/// every one of them.
pub fn empty_state<D: DB>() -> ChargedState<D> {
    ChargedState::new(StateValue::Array(Array::new()))
}

/// A `ContractOperation` for one circuit under a verifier key.
pub fn operation(vk: Option<VerifierKey>) -> ContractOperation {
    ContractOperation::new(vk, None)
}

// ---- the call --------------------------------------------------------------

/// Everything a [`ContractCallPrototype`] needs for one signer call, and
/// nothing a chain has to tell us.
///
/// Built by [`respond`], [`respond_bidirectional`] and
/// [`sign_bidirectional`]; turned into the prototype by
/// [`SignerCall::prototype`].
pub struct SignerCall<D: DB = InMemoryDB> {
    /// The Compact circuit name, which is also the entry point the deployed
    /// contract routes by.
    pub circuit: &'static str,
    /// The arguments, aligned the way the Compact declaration types them.
    pub input: AlignedValue,
    /// The Impact program: `Push` the Misc envelope, `Log` it.
    pub ops: Vec<VmOp<D>>,
    /// The 288 bytes the program logs — kept beside the ops so a caller can
    /// check them without re-running the VM.
    pub misc: Vec<u8>,
    /// Address, circuit id and verifier-key hash.
    pub key_location: ContractKeyLocation,
}

/// Everything but the ops, which are a long `Push` of the same bytes `misc`
/// already shows.
impl<D: DB> std::fmt::Debug for SignerCall<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerCall")
            .field("circuit", &self.circuit)
            .field("input", &self.input)
            .field("misc", &hex(&self.misc))
            .field("key_location", &self.key_location)
            .finish_non_exhaustive()
    }
}

impl<D: DB> Clone for SignerCall<D> {
    fn clone(&self) -> Self {
        SignerCall {
            circuit: self.circuit,
            input: self.input.clone(),
            ops: self.ops.clone(),
            misc: self.misc.clone(),
            key_location: self.key_location.clone(),
        }
    }
}

impl<D: DB> SignerCall<D> {
    /// The prototype for this call: the ledger runs the program to build the
    /// transcript ([`partition_transcripts`], which decides the
    /// guaranteed/fallible split, the gas heuristic and the transcript
    /// version), and the prototype carries the arguments beside it.
    ///
    /// `state` is the contract's state (empty for these three circuits — see
    /// [`empty_state`]) and `parameters` is the CHAIN's, not a constant of
    /// this crate: see the module header.
    pub fn prototype(
        &self,
        state: &ChargedState<D>,
        parameters: &LedgerParameters,
        comm_rand: Fr,
    ) -> Result<ContractCallPrototype<D>, PublishError> {
        call_prototype(
            self.circuit,
            self.key_location.contract_address,
            state,
            parameters,
            self.input.clone(),
            &self.misc,
            comm_rand,
        )
    }
}

/// `respond(signatureRespondedEvent)` — the call the MPC makes to publish a
/// signature for a request that came in over Midnight. PR #127 moved the
/// request id INTO the event struct; the field vector and the payload are
/// unchanged, so this builder is what it always was.
pub fn respond<D: DB>(
    deployment: &Deployment,
    request_id: &[u8; 32],
    signature: &EcdsaSignature,
) -> Result<SignerCall<D>, PublishError> {
    signer_call(deployment, RESPOND, respond_input(request_id, signature), |name| {
        respond_misc(name, request_id, signature)
    })
}

/// `respondBidirectional(respondBidirectionalEvent)` — the MPC's attestation
/// of a foreign execution: the request id, the [`Attestation`] it signed
/// over, and the signature. Since PR #127 this is NOT [`respond`] under
/// another name: the payload carries the block height, output kind, output
/// width and digest between the id and the signature.
pub fn respond_bidirectional<D: DB>(
    deployment: &Deployment,
    request_id: &[u8; 32],
    attestation: &Attestation,
    signature: &EcdsaSignature,
) -> Result<SignerCall<D>, PublishError> {
    signer_call(
        deployment,
        RESPOND_BIDIRECTIONAL,
        respond_bidirectional_input(request_id, attestation, signature),
        |name| respond_bidirectional_misc(name, request_id, attestation, signature),
    )
}

/// `signBidirectional(requestId, notification)` — the REQUEST side. The MPC
/// does not make this call (it reads it); it is here because M29 C's
/// construction gate covers all three signer circuits and a publisher's key
/// material, key locations and resolver are keyed by the same three names.
pub fn sign_bidirectional<D: DB>(
    deployment: &Deployment,
    request_id: &[u8; 32],
    notification: &Notification,
) -> Result<SignerCall<D>, PublishError> {
    signer_call(
        deployment,
        SIGN_BIDIRECTIONAL,
        sign_bidirectional_input(request_id, notification),
        |_| sign_bidirectional_misc(request_id, notification),
    )
}

fn signer_call<D: DB>(
    deployment: &Deployment,
    circuit: &'static str,
    input: AlignedValue,
    misc: impl FnOnce(&str) -> Vec<u8>,
) -> Result<SignerCall<D>, PublishError> {
    let key_location = deployment.key_location(circuit)?;
    let misc = misc(event_name(circuit)?);
    if misc.len() != MISC_SIZE {
        return Err(PublishError::MiscSize { got: misc.len(), want: MISC_SIZE });
    }
    Ok(SignerCall { circuit, input, ops: log_ops(&misc), misc, key_location })
}

/// The general form: ANY entry point, ANY argument value, ANY logged bytes.
///
/// The three typed builders above are what a publisher calls. This one exists
/// because `minocrab-contracts`' differential suites need to build calls that
/// a publisher never would — a tampered envelope, a swapped event name, a
/// flat `[Field; n]` alignment over the same limbs — through the SAME ledger
/// path, so that what they tamper with is the production preimage.
///
/// The `op` field of the prototype is left empty (`ContractOperation::new
/// (None, None)`): `Intent::add_call` does not read it, only the
/// `IntentBuilder`-style helpers in `construct.rs` do, and the deployed
/// operation is the chain's business, not the caller's.
pub fn call_prototype<D: DB>(
    entry_point: &str,
    address: ContractAddress,
    state: &ChargedState<D>,
    parameters: &LedgerParameters,
    input: AlignedValue,
    misc: &[u8],
    comm_rand: Fr,
) -> Result<ContractCallPrototype<D>, PublishError> {
    let output: AlignedValue = ().into();
    let comm = communication_commitment(input.clone(), output.clone(), comm_rand);
    let transcripts = partition_transcripts(
        &[PreTranscript {
            context: QueryContext::new(state.clone(), address),
            program: log_ops(misc),
            comm_comm: Some(comm),
        }],
        parameters,
    )
    .map_err(|e| PublishError::Partition(format!("{e:?}")))?;
    let (guaranteed, fallible) = transcripts
        .into_iter()
        .next()
        .ok_or_else(|| PublishError::NoTranscript(entry_point.to_string()))?;
    if guaranteed.is_none() {
        return Err(PublishError::NoTranscript(entry_point.to_string()));
    }
    Ok(ContractCallPrototype {
        address,
        entry_point: entry_point.as_bytes().into(),
        op: operation(None),
        guaranteed_public_transcript: guaranteed,
        fallible_public_transcript: fallible,
        private_transcript_outputs: vec![],
        input,
        output,
        communication_commitment_rand: comm_rand,
        key_location: KeyLocation(Cow::Owned(entry_point.to_string())),
    })
}
