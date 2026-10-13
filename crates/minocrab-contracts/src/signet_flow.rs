//! THE SIGNET ROUND TRIP'S SHARED MACHINERY — the block's configuration,
//! the record a request files, and the attested output a settle verifies.
//!
//! Every Sig Network operation a Midnight contract makes is one future split
//! across two transactions. A REQUEST circuit files a signing record and
//! cross-calls the Signet singleton so the MPC comes to read it; a SETTLE
//! circuit, in a later transaction, verifies the MPC's attestation over the
//! typed response and consumes the record. The ledger map entry IS the
//! suspended continuation; the attestation is the value the future resolves
//! with. (notes/signet-async.org is the design of record — M35.)
//!
//! THE VOCABULARY IS V1 SINCE M44 RUNG D — `@sig-net/midnight` 0.24.1, the
//! protocol the deployed flush-pattern vault speaks ([`crate::signet_v1`]).
//! What that changed here, and why each change is a SUBTRACTION from what a
//! contract author writes:
//!
//! - THE REQUEST NONCE IS GONE. The V1 request id hashes a preimage whose
//!   transaction enters as a digest, and the transaction's own EVM nonce is
//!   what makes two otherwise identical requests distinct — so the protocol
//!   counter that every filing used to read and bump is not in the record at
//!   all. With it went the one contended read every `Pending` request made
//!   (notes/nonce-admin.org §10.1's audited counter: there is nothing left
//!   to audit).
//! - THE CAIP2 CELL IS GONE. `executionDest` is the constant
//!   [`crate::signet_v1::ethereum_caip2_id`] — the MPC's routing key for
//!   every Ethereum network it watches, with the transaction's own chain id
//!   picking the network — so a cell that could be set wrong at deployment
//!   is a constant in the circuit instead.
//! - THE KEY VERSION IS A CELL, not an argument. No circuit takes one, so no
//!   caller can file a request against a key version the contract did not
//!   choose.
//! - THE RESPONSE KIND BYTE IS GONE, from the record and from the
//!   attestation both. A V1 attestation carries the MPC's VERDICT instead
//!   ([`crate::signet_v1::output_kind`]: executed, failed, unviable), and a
//!   slot is bound to its attestations by its own record map and by its
//!   ticket's type rather than by a byte a deployment allocated by hand.
//!
//! # What lives here, and why
//!
//! M35 put a `Pending<Env, Resp>` slot here, keyed by a hand-written
//! `Response` type per kind. M37 rung D replaced it with
//! [`crate::evm_flow::Pending<Call, Env, WORDS>`], which is keyed by the CALL
//! ([`crate::evm::EvmCall`]) and derives the response type, the ABI words,
//! the selector, the gas envelope, the output schema and the signing path
//! from it. What is left in this module is what the typed slot is BUILT ON,
//! and it is here rather than there because it is the WIRE — the MPC's side
//! of the protocol, which no contract-facing API gets to reshape:
//!
//! - [`Signet`] — the block's one configuration slot (signer address, MPC
//!   response key, MPC key version, EVM chain id). Four ledger fields a
//!   contract declares once; `#[derive(Ledger)]` threads its offset into
//!   every `Pending`, `Fired` and `Outbox` slot, which is why a typed
//!   request takes no `&SELF.signet`.
//! - `file_request` — the filing every request does, whatever the slot:
//!   read the context, assemble the V1 record, hash its id, assert
//!   freshness, store it, store the environment beside it, notify the
//!   singleton with the record map's own path. `evm_flow`'s request methods
//!   are this function plus a transaction.
//! - [`EvmTx`], [`Signing`] and [`SignRequest`] — the transaction shape the
//!   record holds, WHOSE KEY signs it, and the request that files both.
//!   `evm::build_tx` builds the first from a call type; nothing outside this
//!   crate writes any of them by hand.
//! - [`Outcome`] — what a settle hands back.
//! - The three disclosure labels and the [`Requested`] / [`Settled`] label
//!   sets a request and a settle publish.
//!
//! RETIRED IN M37 RUNG D, with the vault that used them: `Pending`, `Fired`,
//! the `Settle` ticket, the `Response` and `FailureResponse` traits, and
//! `Commit<T>` (whose domain was a `&str` at both ends —
//! [`crate::evm_flow::Commit<T, Tag>`] takes it as a type, so a `to` and an
//! `open` that disagree no longer compiles). RETIRED IN M44 RUNG D:
//! `Attested<R>` (the kind byte then the value — a V1 attestation's
//! `serializedOutput` is flat bytes at a width the digest commits to, so
//! there is no wrapper left to name).
//!
//! TYPES CONSTRAIN THE AUTHOR, ASSERTS CONSTRAIN THE PROVER: nothing in
//! either module removes an in-circuit check on untrusted input.
//!
//! NO TIMEOUT, by decision (dmd, 2026-09-05): a request with no response
//! stays pending; a refund happens only on an ATTESTED non-success
//! ([`crate::evm_flow::Pending::refund`]).
//!
//! # What does not compile
//!
//! An environment with a private field (`#[derive(LedgerRepr)]` has no impl
//! at `Private`, so a secret cannot be captured across the suspension by
//! accident — what Rust's own `async` would silently do):
//!
//! ```compile_fail
//! use minocrab::{Private, Public};
//! use minocrab_std::v3::{LedgerRepr, Uint, B32};
//!
//! #[derive(LedgerRepr)]
//! struct Env { amount: Uint<64, Public>, secret: B32<Private> }
//! ```
//!
//! THE SAME CODE WITH THE ONE CHANGE REVERTED compiles:
//!
//! ```
//! use minocrab::Public;
//! use minocrab_std::v3::{LedgerRepr, Uint, B32};
//!
//! #[derive(LedgerRepr)]
//! struct Env { amount: Uint<64, Public>, secret: B32<Public> }
//! ```

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Private, Public};
use minocrab_ledger::{XcallCommitment, XcallEntryPointHash};
use minocrab_std::v3::Assumed;
use minocrab_std::v3::{
    is_true, kernel, label, not, Disclose, LedgerCell, LedgerField, LedgerMap, LedgerRepr,
    LedgerWidth, Secp256k1Point, Uint,
};
use signet_signer_interface::notification::construct_notification_v1;
use signet_signer_interface::{RequestId, SignetSigner};

use crate::common::SigningPath;
use crate::signet_v1::{self, EventRecordV1, EvmType2TxParams, OutputSchema};

// ---- the shared configuration slot ------------------------------------------------

/// The block's ONE Signet configuration: four consecutive ledger fields a
/// contract declares once (`signet: Signet` in its `#[derive(Ledger)]`
/// block) and every typed slot reads through.
///
/// Holding these together is what lets a request take the sender, the chain
/// id and the key version from CONTEXT and a settle the MPC key — none of
/// them is an argument a circuit can pass wrongly. The `signer` cell is
/// `sealed` (written at deployment, never by a circuit).
///
/// FOUR, NOT FIVE (M44 rung D): the request nonce and the caip2 id went with
/// the `fff3421c` vocabulary, and `mpcKeyVersion` arrived as a cell — the
/// three changes the module header explains. The width is read through
/// [`LedgerWidth`], so `#[derive(Ledger)]` recomputed every slot's offset
/// from the type without being told.
pub struct Signet {
    /// `sealed ledger signetSigner: SignetSigner` — the singleton's address.
    pub signer: LedgerField,
    /// `mpcResponseKey: Secp256k1Point` — the key every attestation is
    /// verified under.
    pub mpc_response_key: LedgerCell<Secp256k1Point<Public>>,
    /// `mpcKeyVersion: Uint<8>` — which generation of the MPC's root key
    /// signs. A CELL, not a circuit argument: the version is in the record
    /// and therefore in the request id, so letting a caller choose it would
    /// let a caller file a request no MPC epoch will answer.
    pub mpc_key_version: LedgerCell<Uint<8, Public>>,
    /// `evmChainId: Uint<64>` — the destination chain, in the signed
    /// transaction.
    pub evm_chain_id: LedgerCell<Uint<64, Public>>,
}

impl Signet {
    /// The four fields from flat index `start` of a block of `total` fields
    /// (what `#[derive(Ledger)]` calls).
    pub const fn at_block(total: usize, start: usize) -> Self {
        Signet {
            signer: LedgerField::at_block(total, start),
            mpc_response_key: LedgerCell::at_block(total, start + 1),
            mpc_key_version: LedgerCell::at_block(total, start + 2),
            evm_chain_id: LedgerCell::at_block(total, start + 3),
        }
    }

    /// The deployment's writes, for a contract's `initialize`: the MPC key,
    /// its version and the destination chain id. The signer cell is sealed
    /// and set at deployment.
    pub fn initialize(
        &self,
        c: &mut Circuit3,
        mpc_response_key: &Secp256k1Point<Public>,
        mpc_key_version: &Uint<8, Public>,
        evm_chain_id: &Uint<64, Public>,
    ) {
        self.mpc_response_key.write(c, mpc_response_key);
        self.mpc_key_version.write(c, mpc_key_version);
        self.evm_chain_id.write(c, evm_chain_id);
    }

    /// The singleton's calling handle, by the sealed cell's path.
    fn signer(&self) -> SignetSigner {
        SignetSigner::at_field_path(self.signer.field_path().as_slice())
    }
}

impl LedgerWidth for Signet {
    const WIDTH: usize = 4;
}

// ---- the request ---------------------------------------------------------------------

/// The EVM transaction a request asks the MPC to sign, WITHOUT its chain
/// id: that is the block's ([`Signet::evm_chain_id`]), read by
/// `file_request`, so a request cannot name another chain than the one the
/// contract is configured for.
pub struct EvmTx<const WORDS: usize> {
    pub nonce: Wire3<FieldT, Private>,
    pub max_priority_fee_per_gas: Wire3<FieldT, Private>,
    pub max_fee_per_gas: Wire3<FieldT, Private>,
    pub gas_limit: Wire3<FieldT, Private>,
    pub to: Wire3<FieldT, Private>,
    pub value: Wire3<FieldT, Private>,
    /// `Maybe<EvmCalldata>`: the flag then the (always-present, zero-filled
    /// when absent) calldata.
    pub calldata_is_some: Wire3<FieldT, Private>,
    pub calldata: crate::signet::EvmCalldata<Private, WORDS>,
}

/// WHOSE KEY SIGNS, and whether the reserved-path assert is emitted.
///
/// `constructSignBidirectionalEventV1` refuses a request whose derivation
/// path is `pad(32, "midnight response key")` — the path the MPC's own
/// attestation key lives under, which a contract that could name it could
/// make the MPC sign arbitrary attestations with. compactc FOLDS that assert
/// away when the path is a constant of the contract (two constants compared),
/// and must NOT fold it when the path came from an input.
///
/// That distinction is a type here rather than a `bool`, because getting it
/// wrong in the unsafe direction is the hole above and not a cosmetic
/// difference in instruction count:
///
/// - [`Signing::contract`] — the contract's own `pad(32, "")` path. The
///   assert is over two constants and is not emitted, exactly as compactc's
///   artifact does not emit it.
/// - [`Signing::derived`] — a path this circuit derived from its inputs (a
///   deposit's depositor commitment). The assert is emitted.
pub enum Signing {
    /// A constant of the contract: the assert folds.
    Constant(SigningPath<Private>),
    /// Derived from inputs: the assert is emitted.
    Derived(SigningPath<Private>),
}

impl Signing {
    /// THE CONTRACT'S OWN KEY — `pad(32, "")`, the path
    /// [`SigningPath::contract_path`] names.
    pub fn contract(c: &mut Circuit3) -> Self {
        Signing::Constant(SigningPath::contract_path(c).private())
    }

    /// A PATH THIS CIRCUIT DERIVED from its inputs — a per-user commitment,
    /// typically. The reserved-path assert is emitted for it.
    pub fn derived(path: SigningPath<Private>) -> Self {
        Signing::Derived(path)
    }
}

/// What a request circuit supplies: whose key signs and what it signs. The
/// key VERSION is not here — it is the block's cell, read inside
/// [`file_request`].
pub struct SignRequest<const WORDS: usize> {
    pub signing: Signing,
    pub tx: EvmTx<WORDS>,
}

label! {
    /// The request id, disclosed on filing: the map key.
    pub RequestIdFiled = "request id";
    /// The whole signing record, disclosed on filing: what the MPC reads.
    pub RequestRecordFiled = "request record";
    /// The request id, disclosed on settling: which entry is consumed.
    pub RequestIdSettled = "settle request id";
    /// The attested block height, disclosed on settling: the height the MPC
    /// saw the transaction at, which an outbox's last-seen check consumes.
    pub BlockHeightSettled = "settle block height";
}

/// Everything `Pending::request` discloses — the label set a request
/// circuit declares, as one type.
pub type Requested = (
    RequestIdFiled,
    RequestRecordFiled,
    XcallEntryPointHash,
    XcallCommitment,
);

/// Everything `Pending::settle` discloses.
pub type Settled = (RequestIdSettled, BlockHeightSettled);

/// What a settle hands back: the consumed entry, typed.
///
/// WHAT WENT IN M44 RUNG D: the signing record. It was here so a settle
/// could read a field of the request back — in practice the request nonce,
/// which V1 does not have. Everything else a settle might have wanted off
/// the record (the EVM nonce, the signing path) is either the outbox's own
/// snapshot or a value the environment carried, so the field was read by
/// nothing and the two type parameters it cost every settle signature are
/// gone with it.
pub struct Outcome<Env, R> {
    /// The request id, disclosed.
    pub request_id: RequestId<Public>,
    /// The attested block height, disclosed — the height the MPC observed
    /// the transaction at (V1's `blockHeight`, spec M2), which is what an
    /// [`crate::evm_flow::Outbox`]'s last-seen check compares against.
    pub block_height: Uint<64, Public>,
    /// The environment the request filed — an inline read of the entry
    /// written at the request, so an assumption (M42 B): the proof uses it
    /// freely; writing it back is `.stale(c)`.
    pub env: Assumed<Env>,
    /// The attested output, decoded — verified, its verdict checked, its
    /// narrowing range-checked.
    pub output: R,
}

/// The filing every request does, whatever the slot: read the context,
/// assemble the V1 record under `S`'s output schema, hash its id, assert
/// freshness, store the record, run `after_insert` (a `Pending` stores its
/// environment there), notify the MPC with the record map's own path.
///
/// `words_used` is the calldata's word count when the circuit knows it — the
/// typed API always does, because the count is `<Call::Args as
/// AbiTuple>::WORDS`, a literal — so the transaction digest hashes exactly
/// those words with no per-slot select
/// ([`signet_v1::calculate_evm_type2_tx_params_digest_v1`]).
pub(crate) fn file_request<const WORDS: usize, S: OutputSchema>(
    c: &mut Circuit3,
    signet: &Signet,
    records: &LedgerMap<RequestId<Public>, EventRecordV1<WORDS, S::At<Public>>>,
    req: SignRequest<WORDS>,
    words_used: usize,
    after_insert: impl FnOnce(&mut Circuit3, RequestId<Public>),
) -> RequestId<Public> {
    let zero = c.constant(0u64);
    let me = kernel::cache_self_address(c);
    // Three stable reads, in the order the deployed `send*` circuits make
    // them: the chain id into the transaction, then the key version and the
    // constant destination into the record. None is a read-modify-write any
    // more — the counter that was is gone with the V1 vocabulary.
    let chain_id = signet.evm_chain_id.read(c).stale(c);
    let tx = req.tx;
    let tx_params = EvmType2TxParams::<Private, WORDS> {
        chain_id: chain_id.field().private(),
        nonce: tx.nonce,
        max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
        max_fee_per_gas: tx.max_fee_per_gas,
        gas_limit: tx.gas_limit,
        to: tx.to,
        value: tx.value,
        calldata_is_some: tx.calldata_is_some,
        calldata: tx.calldata,
        access_list_entry_count: zero.private(),
    };
    let key_version = signet.mpc_key_version.read(c).stale(c);
    let dest = signet_v1::ethereum_caip2_id::<Private>(c);
    let kv = key_version.field().private();
    let record: signet_v1::SignBidirectionalEventV1<Private, WORDS, S::At<Private>> =
        match req.signing {
            // The reserved-path assert folds for a constant path and is
            // emitted for a derived one — `Signing`'s whole reason to exist.
            Signing::Constant(path) => signet_v1::construct_sign_bidirectional_event_v1_const_path(
                c,
                kv,
                me.private(),
                path,
                tx_params,
                dest,
                S::BYTES,
            ),
            Signing::Derived(path) => signet_v1::construct_sign_bidirectional_event_v1(
                c,
                kv,
                me.private(),
                path,
                tx_params,
                dest,
                S::BYTES,
            ),
        };

    let request_id = c.region("signet flow: file", |c| {
        let request_id =
            signet_v1::calculate_evm_type2_request_id_v1(c, &record, Some(words_used))
                .disclose_as::<RequestIdFiled>(c);
        let exists = records.member(c, &request_id);
        c.assert(not(is_true(exists)).message("Request already exists"));
        let stored = EventRecordV1::<WORDS, S::At<Public>>::from_limbs(
            record.limbs().disclose_as::<RequestRecordFiled>(c),
        );
        records.insert(c, &request_id, &stored);
        after_insert(c, request_id);
        request_id
    });

    c.region("signet flow: notify", |c| {
        // Receiver first (compactc's order; the argument below emits).
        let signer = signet.signer().pin(c);
        let path = records.field_path();
        let mut bytes = [0u8; 4];
        bytes[..path.as_slice().len()].copy_from_slice(path.as_slice());
        let notification = construct_notification_v1::<Public>(c, &me.bytes(), path.depth(), bytes);
        signer.sign_bidirectional(c, request_id, notification);
    });
    request_id
}
